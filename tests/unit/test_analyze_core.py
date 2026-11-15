"""forensic-analyze core pieces: presets, registry, case and clock, output, cleanup, signing.

Tasks 4C.3, 4C.4, 4C.19, 4C.25, 4C.26, 2B.17, 4G.1.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

import pytest

from forensic_analyze import case, cleanup, output, presets, signing
from forensic_analyze import modules as registry

# ------------------------------------------------------------------------------------- presets

ALL = list(registry.KNOWN_ORDER)


def test_presets_match_the_contract() -> None:
    assert presets.QUICK == ("inventory", "recycle_bin", "deletion_history", "malware")
    assert set(presets.STANDARD) - set(presets.QUICK) == {
        "users",
        "images",
        "video",
        "audio",
        "documents",
        "timeline",
    }
    assert set(presets.FULL) - set(presets.STANDARD) == {"carve"}


def test_modules_for_keeps_run_order_and_reports_missing() -> None:
    available = ["inventory", "users", "carve"]
    planned, missing = presets.modules_for("standard", available)
    assert planned == ["inventory", "users"]
    assert "recycle_bin" in missing and "carve" not in missing
    planned, _ = presets.modules_for("full", ALL)
    assert planned == ALL


def test_custom_preset_needs_known_modules() -> None:
    planned, missing = presets.modules_for("custom", ALL, ["timeline", "inventory"])
    assert planned == ["inventory", "timeline"] and missing == []
    with pytest.raises(presets.PresetError):
        presets.modules_for("custom", ALL, [])
    with pytest.raises(presets.PresetError):
        presets.modules_for("custom", ALL, ["nonsense"])
    with pytest.raises(presets.PresetError):
        presets.modules_for("everything", ALL)


def test_estimates_grow_with_preset_and_mode() -> None:
    size = 500 * presets.GIB
    quick = presets.estimate(presets.QUICK, size)
    full = presets.estimate(presets.FULL, size)
    image = presets.estimate(presets.QUICK, size, image_mode=True)
    assert quick.minutes < full.minutes
    assert quick.output_bytes < full.output_bytes
    assert image.output_bytes >= size
    assert "min" in quick.describe()


# ------------------------------------------------------------------------------------ registry

TEST_MODULE = """
from forensic_analyze.api import Module, ModuleResult

class M(Module):
    name = "{name}"
    title = "T"
    order = {order}
    def run(self, ctx):
        return ModuleResult("ok")

MODULE = M()
"""


def test_registry_works_with_zero_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(registry.EXTRA_ENV, raising=False)
    mods = registry.all_modules()
    assert [m.order for m in mods] == sorted(m.order for m in mods)


def test_registry_extra_modules_sorted_and_broken_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = tmp_path / "a.py"
    a.write_text(TEST_MODULE.format(name="zz_late", order=900))
    b = tmp_path / "b.py"
    b.write_text(TEST_MODULE.format(name="zz_early", order=1))
    broken = tmp_path / "broken.py"
    broken.write_text("raise RuntimeError('boom')\n")
    monkeypatch.setenv(registry.EXTRA_ENV, f"{a}:{b}:{broken}")
    names = [m.name for m in registry.all_modules()]
    assert names.index("zz_early") < names.index("zz_late")
    assert any("boom" in v for v in registry.load_errors().values())


def test_registry_real_module_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = {m.name for m in registry.all_modules()}
    if not real:
        pytest.skip("no real module installed yet")
    name = sorted(real)[0]
    f = tmp_path / "dup.py"
    f.write_text(TEST_MODULE.format(name=name, order=1))
    monkeypatch.setenv(registry.EXTRA_ENV, str(f))
    mod = registry.by_name()[name]
    assert mod.title != "T"


# -------------------------------------------------------------------------------- case, clock


def test_safe_id_strips_path_tricks() -> None:
    assert case.safe_id("../../etc/x") == "etc_x"
    assert case.safe_id("C 2026/11") == "C_2026_11"
    with pytest.raises(case.CaseError):
        case.safe_id("../..")


def test_case_defaults_from_profile(airlock_env: Path) -> None:
    profile = airlock_env / "assets" / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "case_defaults": {
                    "examiner": "A. Examiner",
                    "agency": "Lab",
                    "case_id_prefix": "LAB-",
                }
            }
        )
    )
    d = case.case_defaults()
    assert d["examiner"] == "A. Examiner"
    cid = case.default_case_id(d, dt.datetime(2026, 11, 15, tzinfo=dt.UTC))
    assert cid == "LAB-20261115"


def test_case_defaults_missing_profile(airlock_env: Path) -> None:
    assert case.case_defaults() == {}
    assert case.default_case_id({}).startswith("CASE-")


def test_clock_offset_and_no_time_change() -> None:
    now = dt.datetime(2026, 11, 15, 12, 0, 30, tzinfo=dt.UTC)
    rec = case.clock_record("2026-11-15T12:00:00Z", "phone", system_now=now)
    assert rec.clock_offset_seconds == 30.0
    assert rec.reference_source == "phone"
    assert rec.system_time_changed is False
    rec.mark("module_start")
    case.finish_clock(rec)
    assert rec.duration_s is not None and rec.duration_s >= 0
    assert rec.events[0]["event"] == "module_start" and "monotonic" in rec.events[0]


def test_clock_needs_a_time_zone() -> None:
    with pytest.raises(case.CaseError, match="time zone"):
        case.clock_record("2026-11-15T12:00:00")
    with pytest.raises(case.CaseError):
        case.clock_record("yesterday-ish Z")
    rec = case.clock_record(
        "2026-11-15T13:00:00+01:00", system_now=dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=dt.UTC)
    )
    assert rec.clock_offset_seconds == 0.0
    assert case.clock_record().reference_source == "not given"


def test_authority_text_hash_is_stable() -> None:
    ack = case.AuthorityAck(True, "2026-11-15T00:00:00Z", "flag")
    assert ack.to_dict()["text_sha256"] == case.AUTHORITY_SHA256
    assert "permission" in case.AUTHORITY_TEXT and "legal authority" in case.AUTHORITY_TEXT


# -------------------------------------------------------------------------------------- output


def test_output_checks(tmp_path: Path) -> None:
    with pytest.raises(output.OutputError, match="does not exist"):
        output.check_writable(tmp_path / "missing")
    output.check_writable(tmp_path)
    chk = output.check_space(tmp_path, ["inventory"], 1024, image_mode=False)
    assert chk.enough_space
    huge = 10**18
    with pytest.raises(output.OutputError, match="full copy"):
        output.prepare(
            tmp_path,
            target_path="/x.img",
            target_kind="image",
            target_bytes=huge,
            modules=["inventory"],
            image_mode=True,
        )
    chk = output.prepare(
        tmp_path,
        target_path="/x.img",
        target_kind="image",
        target_bytes=huge,
        modules=["inventory"],
        image_mode=False,
    )
    assert not chk.enough_space and "free" in output.space_message(chk)


# ------------------------------------------------------------------------------------- cleanup


def test_purge_exports_keeps_findings_and_image(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "modules" / "images" / "export").mkdir(parents=True)
    (run / "modules" / "images" / "export" / "a.jpg").write_bytes(b"x" * 10)
    (run / "modules" / "carve" / "carved").mkdir(parents=True)
    (run / "modules" / "carve" / "carved" / "b.bin").write_bytes(b"y" * 5)
    (run / "modules" / "images" / "describe.csv").write_text("keep")
    (run / "extract" / "v0").mkdir(parents=True)
    (run / "extract" / "v0" / "$MFT").write_bytes(b"m")
    (run / "decrypted").mkdir()
    ro = run / "decrypted" / "decrypted.raw"
    ro.write_bytes(b"d")
    ro.chmod(0o444)
    (run / "image").mkdir()
    (run / "image" / "target.E01").write_bytes(b"e")
    (run / "findings.jsonl").write_text("{}\n")
    res = cleanup.purge_exports(run)
    assert res.removed_files == 4 and res.removed_bytes == 17
    assert not (run / "modules" / "images" / "export").exists()
    assert not (run / "extract").exists() and not (run / "decrypted").exists()
    assert (run / "modules" / "images" / "describe.csv").exists()
    assert (run / "image" / "target.E01").exists()
    assert (run / "findings.jsonl").exists()


def test_purge_does_not_follow_symlinks_out(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("k")
    run = tmp_path / "run"
    (run / "modules" / "x").mkdir(parents=True)
    (run / "modules" / "x" / "export").symlink_to(outside)
    cleanup.purge_exports(run)
    assert (outside / "keep").exists()


# ------------------------------------------------------------------------------------- signing

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


def _session(env: Path) -> list[dict]:
    log = env / "session" / "current.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _signed_run(out_root: Path, name: str = "R-1") -> Path:
    run = out_root / "cases" / "C" / name
    (run / "modules" / "m" / "export").mkdir(parents=True)
    (run / "logs").mkdir()
    (run / "run.json").write_text("{}")
    (run / "findings.csv").write_text("a,b\n")
    (run / "report.html").write_text("<p>old</p>")
    (run / "modules" / "m" / "export" / "copy.bin").write_text("exported")
    res = signing.hash_and_sign(run, out_root)
    assert res.error == ""
    return run


@needs_openssl
def test_hash_and_sign_then_verify(airlock_env: Path) -> None:
    out_root = airlock_env / "OUTPUT"
    run = out_root / "cases" / "C" / "R-1"
    (run / "modules" / "m").mkdir(parents=True)
    (run / "run.json").write_text("{}")
    (run / "modules" / "m" / "odd\nname.txt").write_text("hostile name")
    (run / "modules" / "m" / "back\\slash").write_text("b")
    res = signing.hash_and_sign(run, out_root)
    assert res.error == "" and res.sig_path is not None
    key = signing.key_dir(out_root) / "key.pem"
    assert key.stat().st_mode & 0o777 == 0o600
    listing = (run / signing.LIST_NAME).read_text()
    assert "\\" in listing.splitlines()[0] or any(
        ln.startswith("\\") for ln in listing.splitlines()
    )
    assert signing.verify(run) == []
    # Same key on the next run.
    run2 = out_root / "cases" / "C" / "R-2"
    run2.mkdir(parents=True)
    (run2 / "x").write_text("x")
    signing.hash_and_sign(run2, out_root)
    assert (run2 / signing.PUB_NAME).read_bytes() == (run / signing.PUB_NAME).read_bytes()


@needs_openssl
@pytest.mark.parametrize(
    "name", ["a\\nb", "a\\rb", "trail\\", "a\\\\nb", "mixed\\n\nline", "x\\\\\\n"]
)
def test_verify_backslash_names_round_trip(airlock_env: Path, name: str) -> None:
    """Finding 15: a literal backslash before n or r is unescaped in one pass, as GNU does."""
    out_root = airlock_env / "OUTPUT"
    run = out_root / "cases" / "C" / "R-1"
    (run / "modules" / "m").mkdir(parents=True)
    (run / "modules" / "m" / name).write_text("data")
    assert signing.hash_and_sign(run, out_root).error == ""
    assert signing.verify(run) == []
    assert signing._unescape(signing._escape(name)[1]) == name
    if shutil.which("sha256sum") and "\n" not in name:
        import subprocess  # noqa: PLC0415

        cp = subprocess.run(
            ["sha256sum", "--quiet", "-c", signing.LIST_NAME],
            cwd=run,
            capture_output=True,
            text=True,
            check=False,
        )
        assert cp.returncode == 0, cp.stdout + cp.stderr


@needs_openssl
def test_private_key_is_on_the_root_filesystem(airlock_env: Path) -> None:
    """Finding 13: the private key is under the state dir (root only), never on OUTPUT."""
    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    kid = signing.read_key_id(out_root)
    assert kid is not None and len(kid) == 32
    folder = signing.key_dir(out_root)
    assert folder == airlock_env / "state" / "signing" / kid
    assert (folder / "key.pem").stat().st_mode & 0o777 == 0o600
    assert folder.stat().st_mode & 0o777 == 0o700
    assert (folder.parent).stat().st_mode & 0o777 == 0o700
    assert not list(out_root.rglob("key.pem"))
    assert (signing.output_meta_dir(out_root) / "pub.pem").read_bytes() == (
        run / signing.PUB_NAME
    ).read_bytes()
    # The fingerprint is in the session log on the root filesystem, and in the sign record.
    fp = signing.public_key_sha256(run / signing.PUB_NAME)
    created = [r for r in _session(airlock_env) if r["event"] == "signing_key_created"]
    assert [(r["key_id"], r["public_key_sha256"]) for r in created] == [(kid, fp)]
    res = signing.hash_and_sign(run, out_root)
    assert (res.key_id, res.public_key_sha256) == (kid, fp)
    assert res.to_dict()["list_sha256"] == signing.hashing.sha256_file(run / signing.LIST_NAME)
    assert signing.known_key(run / signing.PUB_NAME) == kid


@needs_openssl
def test_unknown_or_bad_key_id_gets_a_new_key(airlock_env: Path) -> None:
    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    first = signing.read_key_id(out_root)
    # The drive moved to another AIRLOCK system: its key id is not held here.
    shutil.rmtree(airlock_env / "state" / "signing")
    signing.hash_and_sign(run, out_root)
    second = signing.read_key_id(out_root)
    assert second and second != first
    created = [r for r in _session(airlock_env) if r["event"] == "signing_key_created"]
    assert created[-1]["previous_key_id"] == first
    # A key id that is not 32 hex digits is never used as a path.
    (signing.output_meta_dir(out_root) / signing.ID_NAME).write_text("../../etc\n")
    assert signing.read_key_id(out_root) is None
    signing.hash_and_sign(run, out_root)
    assert signing.read_key_id(out_root) not in (None, first, second)
    assert signing.verify(run) == []


@needs_openssl
def test_signing_fails_cleanly_without_a_usable_key_store(airlock_env: Path) -> None:
    out_root = airlock_env / "OUTPUT"
    run = out_root / "cases" / "C" / "R"
    run.mkdir(parents=True)
    (run / "a").write_text("a")
    (airlock_env / "state").rmdir()
    (airlock_env / "state").write_text("not a folder")
    res = signing.hash_and_sign(run, out_root)
    assert res.sig_path is None and "signing key unavailable" in res.error


@needs_openssl
def test_verify_catches_changes(airlock_env: Path) -> None:
    out_root = airlock_env / "o"
    run = out_root / "cases" / "C" / "R"
    run.mkdir(parents=True)
    (run / "a.txt").write_text("a")
    signing.hash_and_sign(run, out_root)
    (run / "a.txt").write_text("b")
    (run / "new.txt").write_text("n")
    problems = signing.verify(run)
    assert "changed: a.txt" in problems and "not listed: new.txt" in problems
    signing.hash_and_sign(run, out_root)
    (run / signing.LIST_NAME).write_text((run / signing.LIST_NAME).read_text() + "\n")
    assert "signature does not verify" in signing.verify(run)


def _run_log(run: Path) -> list[dict]:
    path = run / signing.RUN_LOG
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@needs_openssl
def test_resign_refuses_a_changed_run(airlock_env: Path) -> None:
    """Finding 12: re-signing never blesses a file the command did not replace."""
    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    old_list = (run / signing.LIST_NAME).read_bytes()
    old_sig = (run / signing.SIG_NAME).read_bytes()
    (run / "findings.csv").write_text("a,b\nedited,in a spreadsheet\n")
    (run / "report.html").write_text("<p>new</p>")

    def report(rel: str) -> bool:
        return rel == "report.html"

    with pytest.raises(signing.ResignRefused, match=r"changed: findings\.csv"):
        signing.resign(run, out_root, report, reason="test")
    assert (run / signing.LIST_NAME).read_bytes() == old_list
    assert (run / signing.SIG_NAME).read_bytes() == old_sig
    assert signing.history_numbers(run) == []
    assert "changed: findings.csv" in signing.verify(run)
    # A changed list or signature is never something a command replaces.
    (run / signing.SIG_NAME).write_bytes(b"x" * 64)
    with pytest.raises(signing.ResignRefused, match="signature does not verify"):
        signing.resign(run, out_root, lambda _rel: True, reason="test")


@needs_openssl
def test_resign_keeps_history_and_force_is_logged(airlock_env: Path) -> None:
    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    first_list = (run / signing.LIST_NAME).read_bytes()
    first_sig = (run / signing.SIG_NAME).read_bytes()
    # Only the replaced file changed: re-signed without --force, history kept.
    (run / "report.html").write_text("<p>new</p>")
    res = signing.resign(run, out_root, lambda rel: rel == "report.html", reason="report")
    assert res.error == "" and signing.verify(run) == []
    assert signing.history_numbers(run) == [1]
    assert (run / "outputs.sha256.prev-1").read_bytes() == first_list
    assert (run / "outputs.sha256.prev-1.sig").read_bytes() == first_sig
    assert (run / "outputs.sha256.prev-1.pub.pem").is_file()
    listing = (run / signing.LIST_NAME).read_text()
    for name in ("outputs.sha256.prev-1", "outputs.sha256.prev-1.sig", "logs/run.jsonl"):
        assert f"  {name}\n" in listing
    rec = _run_log(run)[-1]
    assert (rec["event"], rec["forced"], rec["history"]) == (
        "outputs_resigned",
        False,
        "outputs.sha256.prev-1",
    )
    # The earlier list still verifies against its own key.
    import subprocess  # noqa: PLC0415

    cp = subprocess.run(
        [
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
            str(run / "outputs.sha256.prev-1.pub.pem"), "-rawin",
            "-in", str(run / "outputs.sha256.prev-1"),
            "-sigfile", str(run / "outputs.sha256.prev-1.sig"),
        ],
        capture_output=True,
        check=False,
    )  # fmt: skip
    assert cp.returncode == 0
    # A change outside the replaced files needs force; force is recorded with the problem.
    (run / "run.json").write_text('{"edited": true}')
    res = signing.resign(run, out_root, lambda _rel: False, force=True, reason="forced")
    assert res.error == "" and signing.verify(run) == []
    assert signing.history_numbers(run) == [1, 2]
    rec = _run_log(run)[-1]
    assert rec["forced"] is True and rec["problems_overridden"] == ["changed: run.json"]
    logged = [r for r in _session(airlock_env) if r["event"] == "outputs_resigned"]
    assert logged[-1]["forced"] is True and logged[-1]["public_key_sha256"]


@needs_openssl
def test_purge_run_verifies_first(airlock_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Finding 12: --purge-run refuses a changed run and keeps history when it re-signs."""
    from forensic_analyze import cli  # noqa: PLC0415

    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    (run / "findings.csv").write_text("tampered")
    assert cli.main(["--purge-run", str(run)]) == 1
    assert "Nothing was purged" in capsys.readouterr().out
    assert (run / "modules" / "m" / "export" / "copy.bin").exists()
    assert "changed: findings.csv" in signing.verify(run)
    assert signing.history_numbers(run) == []
    # With --force it purges, re-signs, keeps the earlier list and records the override.
    assert cli.main(["--purge-run", str(run), "--force"]) == 0
    assert not (run / "modules" / "m" / "export").exists()
    assert signing.verify(run) == [] and signing.history_numbers(run) == [1]
    rec = _run_log(run)[-1]
    assert rec["forced"] is True and rec["problems_overridden"] == ["changed: findings.csv"]


@needs_openssl
def test_purge_run_on_an_intact_run(airlock_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from forensic_analyze import cli  # noqa: PLC0415

    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    # An edited exported copy is deleted by the purge anyway, so it does not block it.
    (run / "modules" / "m" / "export" / "copy.bin").write_text("changed copy")
    assert cli.main(["--purge-run", str(run)]) == 0
    assert signing.verify(run) == []
    rec = _run_log(run)[-1]
    assert rec["forced"] is False and rec["problems_overridden"] == []
    assert cli.main(["--verify", str(run)]) == 0
    out = capsys.readouterr().out
    kid = signing.read_key_id(out_root)
    assert f"signing key {kid} held on this AIRLOCK system" in out


@needs_openssl
def test_evidence_report_refuses_a_changed_run(
    airlock_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 12: re-rendering a report checks the run before writing anything."""
    from evidence_report import cli as report_cli  # noqa: PLC0415

    out_root = airlock_env / "OUTPUT"
    run = _signed_run(out_root)
    old_list = (run / signing.LIST_NAME).read_bytes()
    (run / "run.json").write_text('{"edited": true}')
    assert report_cli.main([str(run), "--no-model"]) == 1
    err = capsys.readouterr().err
    assert "changed: run.json" in err and "--force" in err
    assert (run / "report.html").read_text() == "<p>old</p>"
    assert (run / signing.LIST_NAME).read_bytes() == old_list
    # An edit to the report itself does not block: the report replaces it.
    (run / "run.json").write_text("{}")
    (run / "report.html").write_text("<p>edited</p>")
    report_cli._precheck(run, force=False)
    # A run that is not under <output>/cases/ cannot be re-signed, so nothing is written.
    loose = airlock_env / "loose"
    loose.mkdir()
    (loose / "a").write_text("a")
    signing.hash_and_sign(loose, airlock_env / "OUTPUT")
    assert report_cli.main([str(loose), "--no-model"]) == 1
    assert "--no-resign" in capsys.readouterr().err


def test_verify_without_listing(tmp_path: Path) -> None:
    assert signing.verify(tmp_path) == [f"{signing.LIST_NAME} is missing"]


def test_output_on_the_evidence_drive_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(output, "disk_of", lambda root: "sdb")
    monkeypatch.setattr(output, "disk_of_device", lambda dev: "sdb")
    with pytest.raises(output.OutputError, match="on the evidence drive"):
        output.check_not_target(tmp_path, "/dev/sdb1", "device")
    output.check_not_target(tmp_path, "/x.img", "image")
    monkeypatch.setattr(output, "disk_of_device", lambda dev: "sdc")
    output.check_not_target(tmp_path, "/dev/sdc", "device")


def test_top_disk_of_a_partition(tmp_path: Path) -> None:
    part = tmp_path / "sdb" / "sdb1"
    part.mkdir(parents=True)
    (part / "partition").write_text("1")
    assert output._top_disk(part) == "sdb"
    assert output._top_disk(tmp_path / "sdb") == "sdb"
    assert output._top_disk(tmp_path / "missing") == ""
