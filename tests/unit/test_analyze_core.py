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


@needs_openssl
def test_hash_and_sign_then_verify(tmp_path: Path) -> None:
    out_root = tmp_path / "OUTPUT"
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
def test_verify_catches_changes(tmp_path: Path) -> None:
    run = tmp_path / "o" / "cases" / "C" / "R"
    run.mkdir(parents=True)
    (run / "a.txt").write_text("a")
    signing.hash_and_sign(run, tmp_path / "o")
    (run / "a.txt").write_text("b")
    (run / "new.txt").write_text("n")
    problems = signing.verify(run)
    assert "changed: a.txt" in problems and "not listed: new.txt" in problems
    signing.hash_and_sign(run, tmp_path / "o")
    (run / signing.LIST_NAME).write_text((run / signing.LIST_NAME).read_text() + "\n")
    assert "signature does not verify" in signing.verify(run)


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
