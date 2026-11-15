"""Hash sets and hash triage (tasks 4A.2-4A.6, 4D.8): ``airlock_hashsets``.

Fixtures are built at test time by ``tests/fixtures/hashsets/fixtures.py``: a synthetic
NSRL-schema SQLite, sample files, a MalwareBazaar-style export, and the EICAR test string
joined from parts. Tests that need ClamAV, YARA, or ssdeep skip when the tool is missing.
``hashset_env`` is imported by ``test_module_malware.py``.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from airlock_hashsets import build, scanners, triage
from airlock_hashsets import config as hcfg
from airlock_hashsets.nsrl import NsrlDb, NsrlError

REPO = Path(__file__).resolve().parents[2]
FIX_DIR = REPO / "tests" / "fixtures" / "hashsets"
sys.path.insert(0, str(FIX_DIR))
import fixtures as fx  # noqa: E402

HAVE_CLAM = shutil.which("clamscan") is not None
HAVE_YARA = shutil.which("yara") is not None and shutil.which("yarac") is not None
HAVE_SSDEEP = shutil.which("ssdeep") is not None
needs_clam = pytest.mark.skipif(not HAVE_CLAM, reason="needs clamscan (apt install clamav)")
needs_yara = pytest.mark.skipif(not HAVE_YARA, reason="needs yara and yarac")
needs_ssdeep = pytest.mark.skipif(not HAVE_SSDEEP, reason="needs ssdeep")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rule_pack(tmp: Path) -> Path:
    out = tmp / "pack.zip"
    with zipfile.ZipFile(out, "w") as zf:
        for rule in (fx.YARA_RULE, fx.YARA_EXTERNAL_RULE, fx.YARA_BROKEN_RULE):
            zf.write(rule, f"pack-main/yara/{rule.name}")
        zf.writestr("pack-main/README.md", "not a rule")
    return out


@pytest.fixture
def hashset_env(airlock_env: Path) -> dict[str, Path]:
    """Applied hash sets in a temporary tree, as provisioning would leave them."""
    root = airlock_env / "hs"
    clam, yara_dir, ssd = root / "clamav", root / "yara", root / "ssdeep"
    for d in (clam, yara_dir, ssd):
        d.mkdir(parents=True)
    samples = fx.write_samples(airlock_env / "samples")
    nsrl = fx.build_nsrl(root / "nsrl" / "RDS_test_modern_minimal.db")
    export = fx.write_mbz_export(
        airlock_env / "staged" / "full_sha256.zip", [sha256(fx.eicar()), "b" * 64]
    )
    build.step_mbz(export, None, clam, "2026-11-15")
    plain = samples["plain"].read_bytes()
    (clam / "local-test.hdb").write_text(
        f"{fx.digests(plain)['md5']}:{len(plain)}:Airlock.Test.Plain\n", encoding="ascii"
    )
    if HAVE_YARA:
        build.step_yara(rule_pack(airlock_env), None, yara_dir / "test", "AIRLOCK test", "t-1")
    if HAVE_SSDEEP:
        base = airlock_env / "base.bin"
        base.write_bytes(fx.fuzzy_pair()[0])
        out = subprocess.run(
            ["ssdeep", "-s", "-b", str(base)], capture_output=True, text=True, check=True
        )
        (ssd / "test-known.ssdeep").write_text(out.stdout, encoding="utf-8")
        (ssd / "test-known.json").write_text('{"name": "Test list", "version": "v1"}')
    (airlock_env / "etc" / "hashsets.json").write_text(
        json.dumps(
            {
                "clamav_dir": str(clam),
                "nsrl_dirs": [str(nsrl.parent)],
                "yara_dir": str(yara_dir),
                "ssdeep_dir": str(ssd),
                "ssdeep_threshold": 60,
            }
        ),
        encoding="utf-8",
    )
    return {"root": root, "nsrl": nsrl, "export": export, **samples}


def read_csv(path: Path) -> list[dict[str, str]]:
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- NSRL


def test_nsrl_sha256_first_legacy_fallback_and_no_collision(tmp_path: Path):
    db = fx.build_nsrl(tmp_path / "rds.db")
    files = {
        k: fx.digests(v) for k, v in {"g": fx.KNOWN_GOOD, "l": fx.LEGACY, "c": fx.COLLISION}.items()
    }
    with NsrlDb(db) as n:
        assert n.upper and n.version == fx.NSRL_VERSION
        assert {"sha256", "sha1", "md5"} <= n.indexed
        found = n.lookup(files)
    assert found["g"].algorithm == "sha256"
    assert found["l"].algorithm == "sha1"  # row without SHA-256: weaker hash, recorded
    assert "c" not in found  # MD5 in a row whose SHA-256 differs: never a match


def test_nsrl_without_index_scans_and_never_writes(tmp_path: Path):
    db = fx.build_nsrl(tmp_path / "rds.db", indexed=False)
    before = sha256(db.read_bytes())
    db.chmod(0o444)
    tmp_path.chmod(0o555)  # no journal or lock file can be created next to it
    try:
        with NsrlDb(db) as n:
            assert not n.indexed
            found = n.lookup({"g": fx.digests(fx.KNOWN_GOOD), "p": fx.digests(fx.PLAIN)})
    finally:
        tmp_path.chmod(0o755)
    assert set(found) == {"g"}
    assert sha256(db.read_bytes()) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["rds.db"]


def test_nsrl_rejects_non_rds(tmp_path: Path):
    bad = tmp_path / "x.db"
    conn = sqlite3.connect(bad)
    conn.execute("CREATE TABLE t (a TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(NsrlError, match="sha256"):
        NsrlDb(bad)
    (tmp_path / "y.db").write_bytes(b"not sqlite at all" * 100)
    with pytest.raises(NsrlError):
        NsrlDb(tmp_path / "y.db")


def test_nsrl_path_from_airlock_conf_wins(airlock_env: Path):
    off = fx.build_nsrl(airlock_env / "output" / "nsrl" / "RDS_off.db")
    on = fx.build_nsrl(airlock_env / "opt" / "nsrl" / "RDS_on.db")
    etc = airlock_env / "etc"
    (etc / "hashsets.json").write_text(json.dumps({"nsrl_dirs": [str(on.parent)]}))
    assert hcfg.find_nsrl(hcfg.load_raw()) == on
    (etc / "airlock.conf.json").write_text(json.dumps({"nsrl_path": str(off.parent)}))
    assert hcfg.find_nsrl(hcfg.load_raw()) == off
    (etc / "airlock.conf.json").write_text(json.dumps({"nsrl_path": str(on)}))
    assert hcfg.find_nsrl(hcfg.load_raw()) == on


# --------------------------------------------------------------------------- build steps


def test_mbz_hsb_format_snapshot_log_and_idempotence(airlock_env: Path, tmp_path: Path):
    export = fx.write_mbz_export(tmp_path / "e.zip", ["C" * 64, "a" * 64, "c" * 64])
    dest = tmp_path / "clamav"
    out = build.step_mbz(export, sha256(export.read_bytes()), dest, "2026-11-15")
    assert out["changed"] and out["entries"] == 2 and out["snapshot"].startswith("2026-11-14")
    lines = (dest / hcfg.MBZ_HSB).read_text().splitlines()
    assert lines == [
        f"{'a' * 64}:*:MalwareBazaar.{'a' * 16}:73",
        f"{'c' * 64}:*:MalwareBazaar.{'c' * 16}:73",
    ]
    log = (airlock_env / "session" / "current.log").read_text().splitlines()
    ev = json.loads(log[-1])
    assert ev["event"] == "hashset_applied" and ev["snapshot"].startswith("2026-11-14")
    assert ev["source_sha256"] == sha256(export.read_bytes()) and len(ev["hsb_sha256"]) == 64
    assert build.step_mbz(export, None, dest, "2026-11-16")["changed"] is False


def test_mbz_refuses_damaged_or_changed_export(tmp_path: Path):
    bad = tmp_path / "bad.txt"
    bad.write_text("# Last updated: 2026-11-14\nnot-a-hash\n")
    with pytest.raises(build.BuildError, match="line 2"):
        build.step_mbz(bad, None, tmp_path / "d", "x")
    good = fx.write_mbz_export(tmp_path / "g.zip", ["a" * 64])
    with pytest.raises(build.BuildError, match="does not match"):
        build.step_mbz(good, "0" * 64, tmp_path / "d", "x")
    empty = fx.write_mbz_export(tmp_path / "empty.zip", [])
    with pytest.raises(build.BuildError, match="no SHA-256"):
        build.step_mbz(empty, None, tmp_path / "d", "x")


@needs_clam
def test_clamscan_loads_generated_hsb_and_flags_eicar(tmp_path: Path):
    target = tmp_path / "e.com"
    target.write_bytes(fx.eicar())
    export = fx.write_mbz_export(tmp_path / "e.zip", [sha256(fx.eicar())])
    build.step_mbz(export, None, tmp_path / "db", "x")
    cp = subprocess.run(
        ["clamscan", "--no-summary", "-d", str(tmp_path / "db" / hcfg.MBZ_HSB), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 1, cp.stderr
    assert f"MalwareBazaar.{sha256(fx.eicar())[:16]}.UNOFFICIAL FOUND" in cp.stdout


@needs_yara
def test_yara_pack_compiles_with_empty_externals_and_skips_broken(tmp_path: Path):
    dest = tmp_path / "yara" / "pack"
    out = build.step_yara(rule_pack(tmp_path), None, dest, "Pack", "abc123")
    assert out["changed"] and out["rule_files"] == 2
    assert [s["file"] for s in out["skipped"]] == ["broken.yar"]
    assert (dest / hcfg.YARA_RULES).is_file()
    assert not list((dest / "src").rglob("README.md"))  # only rule files are unpacked
    assert build.step_yara(rule_pack(tmp_path), None, dest, "Pack", "abc123")["changed"] is False
    assert build.step_yara(rule_pack(tmp_path), None, dest, "Pack", "def456")["changed"] is True


def test_yara_unpack_refuses_unsafe_names(tmp_path: Path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escape.yar", "rule x { condition: true }")
        zf.writestr("/abs.yar", "rule y { condition: true }")
        zf.writestr("ok/fine.yar", "rule z { condition: true }")
    files = build.unpack_rules(evil, tmp_path / "out")
    assert [f.relative_to(tmp_path / "out").as_posix() for f in files] == ["ok/fine.yar"]
    assert not (tmp_path / "escape.yar").exists()


def test_nsrl_step_extracts_and_is_idempotent(airlock_env: Path, tmp_path: Path):
    db = fx.build_nsrl(tmp_path / "src" / "RDS_2026.06.1_modern_minimal.db")
    z = tmp_path / "rds.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(db, f"RDS_2026.06.1/{db.name}")
        zf.writestr("RDS_2026.06.1/README.txt", "x")
    dest = tmp_path / "nsrl"
    out = build.step_nsrl(z, sha256(z.read_bytes()), dest, "2026.06.1")
    assert out["changed"] and out["db_file"] == db.name and out["version"] == "2026.06.1"
    assert sha256((dest / db.name).read_bytes()) == sha256(db.read_bytes())
    assert build.step_nsrl(z, None, dest, "2026.06.1")["changed"] is False
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("RDS/x.db", "not sqlite" * 50)
    with pytest.raises(build.BuildError, match="not usable"):
        build.step_nsrl(bad, None, tmp_path / "n2", "")
    assert not list((tmp_path / "n2").glob("*.db"))


def _stub_sigtool(folder: Path, ok: bool) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    tail = "Verification OK." if ok else "ERROR: Verification failed"
    script = folder / "sigtool"
    script.write_text(
        "#!/bin/sh\n"
        "printf 'File: %s\\nBuild time: 14 Nov 2026 09:00 +0000\\nVersion: 27801\\n"
        f'Signatures: 2000\\n{tail}\\n\' "$1"\n' + ("exit 0\n" if ok else "exit 1\n"),
        encoding="ascii",
    )
    script.chmod(0o755)


def test_clamav_step_requires_vendor_signature(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "staged"
    src.mkdir()
    (src / "daily.cvd").write_bytes(b"ClamAV-VDB:fake" + b"\0" * 600)
    (src / "main.cvd").write_bytes(b"ClamAV-VDB:fake-main" + b"\0" * 600)
    dest = tmp_path / "clamav"
    dest.mkdir()
    (dest / "old.cld").write_bytes(b"stale")
    (dest / hcfg.MBZ_HSB).write_text("x")
    bad = tmp_path / "bad-bin"
    _stub_sigtool(bad, ok=False)
    monkeypatch.setenv("PATH", f"{bad}:/usr/bin:/bin")
    with pytest.raises(build.BuildError, match="signature check failed"):
        build.step_clamav([src / "daily.cvd"], dest)
    assert not (dest / "daily.cvd").exists()
    good = tmp_path / "good-bin"
    _stub_sigtool(good, ok=True)
    monkeypatch.setenv("PATH", f"{good}:/usr/bin:/bin")
    out = build.step_clamav([src / "main.cvd", src / "daily.cvd"], dest)
    assert out["changed"] and [r["name"] for r in out["databases"]] == ["daily", "main"]
    assert out["databases"][0]["version"] == "27801"
    assert {p.name for p in dest.iterdir()} == {
        hcfg.CLAMAV_META,
        "daily.cvd",
        "main.cvd",
        hcfg.MBZ_HSB,
    }  # the stale old.cld is gone, the generated .hsb is kept
    assert build.step_clamav([src / "main.cvd", src / "daily.cvd"], dest)["changed"] is False
    cfg = hcfg.load_raw()
    cfg["clamav_dir"] = str(dest)
    _dbs, clam, hsb = hcfg._clamav(cfg)
    assert clam is not None and clam.version == "daily 27801, main 27801"
    assert [h.name for h in hsb] == [hcfg.MBZ_NAME]


def test_build_cli_prints_json_and_fails_with_one_line(airlock_env: Path, tmp_path: Path, capsys):
    export = fx.write_mbz_export(tmp_path / "e.zip", ["a" * 64])
    assert build.main(["mbz-hsb", "--source", str(export), "--dest", str(tmp_path / "d")]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is True
    assert build.main(["mbz-hsb", "--source", str(tmp_path / "nope"), "--dest", "x"]) == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1 and "Restage the drive" in err[0]


# --------------------------------------------------------------------------- triage


@needs_clam
@needs_yara
@needs_ssdeep
def test_triage_end_to_end(hashset_env: dict[str, Path], airlock_env: Path):
    out = airlock_env / "output" / "triage.csv"
    folder = hashset_env["known"].parent
    files = sorted(p for p in folder.iterdir())
    work = airlock_env / "work"
    results = triage.triage_paths(files, out, runner=triage.plain_runner(work), workdir=work)
    by = {Path(r.path).name: r for r in results}
    assert by["known-good.txt"].verdict == "known_good"
    assert by["known-good.txt"].nsrl.match_algorithm == "sha256"
    assert by["legacy.txt"].nsrl.match_algorithm == "sha1"
    assert by["collision.txt"].verdict == "no_match"
    assert by["plain.txt"].of_kind("clamav_hit")[0].label == "Airlock.Test.Plain"
    eicar = by["eicar-test.com"].of_kind("hash_hit", algorithm="sha256")
    assert eicar and eicar[0].hashset_name == "MalwareBazaar" and eicar[0].derivation == "observed"
    assert eicar[0].hashset_version.startswith("2026-11-14")
    assert by["=marker,cmd.bin"].of_kind("yara_hit")[0].label == "Airlock_Test_Marker"
    fuzzy = by["variant.bin"].of_kind("hash_hit", algorithm="ssdeep")
    assert fuzzy and fuzzy[0].derivation == "inferred" and fuzzy[0].score > 60
    assert fuzzy[0].hashset_name == "Test list" and fuzzy[0].hashset_version == "v1"
    # Known software is not scanned further.
    assert by["known-good.txt"].ssdeep == "" and by["plain.txt"].ssdeep
    rows = {Path(r["path"]).name: r for r in read_csv(out)}
    assert rows["eicar-test.com"]["sha1"] == fx.digests(fx.eicar())["sha1"]
    assert rows["known-good.txt"]["nsrl_match_algorithm"] == "sha256"
    ev = json.loads((airlock_env / "session" / "current.log").read_text().splitlines()[-1])
    assert ev["event"] == "hash_triage" and ev["counts"]["flagged"] == 4
    assert ev["counts"]["known_good"] == 2 and ev["csv_sha256"] == sha256(out.read_bytes())
    assert {s["name"] for s in ev["hashsets"]} >= {"NSRL RDS", "MalwareBazaar", "AIRLOCK test"}
    assert not (work / "alias").exists()


@needs_clam
def test_hostile_names_never_reach_tools(hashset_env: dict[str, Path], airlock_env: Path):
    """Names with newlines, ': FOUND', and shell characters cannot fake or hide a result."""
    d = airlock_env / "hostile"
    d.mkdir()
    fake = d / "x: Fake.Sig FOUND\nplain.txt: Win.Test FOUND"
    fake.write_bytes(fx.PLAIN + b"x")  # in no hash set
    real = d / "$(touch pwned); `id`.com"
    real.write_bytes(fx.eicar())
    work = airlock_env / "w"
    seen: list[list[str]] = []
    base = triage.plain_runner(work)

    def spy(argv, **kw):
        seen.append([str(a) for a in argv])
        return base(argv, **kw)

    res = triage.triage_paths(
        [fake, real], airlock_env / "output" / "t.csv", runner=spy, workdir=work
    )
    assert res[0].verdict == "no_match" and res[1].verdict == "flagged"
    assert not (work / "pwned").exists() and not Path("pwned").exists()
    for argv in seen:
        assert all("FOUND" not in a and "$(" not in a for a in argv), argv


def test_csv_cells_are_neutralised(tmp_path: Path):
    r = triage.TriageResult('=HYPERLINK("x")', tmp_path / "f")
    r.sha256, r.md5, r.sha1, r.size_bytes = "a" * 64, "b" * 32, "c" * 40, 5
    r.notes.append("\tleading tab")
    r2 = triage.TriageResult("@SUM(1)\r\nrow", tmp_path / "g")
    out = triage.write_csv([r, r2], tmp_path / "t.csv")
    rows = read_csv(out)
    assert rows[0]["path"] == '\'=HYPERLINK("x")'
    assert rows[0]["notes"].startswith("'")
    assert rows[1]["path"].startswith("'@SUM(1)\\r\\n")  # newline shown escaped, not raw
    assert rows[1]["verdict"] == "error" and rows[0]["size_bytes"] == "5"


def test_large_files_checked_against_hsb_in_python(hashset_env: dict[str, Path], airlock_env: Path):
    cfg = hcfg.load()
    cfg.raw["clamscan_max_filesize_mib"] = 0  # every file counts as "too big for ClamAV"
    calls: list[list[str]] = []

    def runner(argv, **kw):
        calls.append([str(a) for a in argv])
        return subprocess.CompletedProcess(argv, 0, "", "")

    res = triage.triage_paths(
        [hashset_env["eicar"], hashset_env["plain"]],
        airlock_env / "output" / "big.csv",
        cfg=cfg,
        runner=runner,
        workdir=airlock_env / "w2",
    )
    hit = res[0].of_kind("hash_hit")
    assert hit and hit[0].source_tool == "hsb" and hit[0].match_algorithm == "sha256"
    assert "not scanned by ClamAV" in res[1].notes[0]
    assert not [c for c in calls if c[0] == "clamscan" and any("--file-list" in a for a in c)]


def test_missing_tools_are_reported_not_fatal(hashset_env: dict[str, Path], airlock_env: Path):
    def runner(argv, **kw):
        raise triage.proc.ToolError(f"{argv[0]}: not installed or not on PATH")

    run = triage.triage_run(
        [hashset_env["plain"], hashset_env["known"]],
        airlock_env / "output" / "m.csv",
        runner=runner,
        workdir=airlock_env / "w3",
    )
    assert run.counts["known_good"] == 1 and run.results[0].verdict == "no_match"
    assert any("ClamAV scan did not run" in w for w in run.warnings)
    assert run.tool_versions["clamscan"] == "missing"


def test_scanner_parsers_map_aliases(tmp_path: Path):
    files = [tmp_path / "a", tmp_path / "b"]
    for f in files:
        f.write_text("x")
    al = scanners.Aliases(files, tmp_path / "alias")
    out = (
        f"{al.paths[1]}: Win.Test.EICAR_HDB-1 FOUND\n"
        f"{al.paths[0]}: Can't open file ERROR\n"
        "/elsewhere/x: Fake FOUND\n"
    )

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, out, "")

    res = scanners.clamscan(
        runner, al, [0, 1], [tmp_path / "x.hsb"], list_path=tmp_path / "l", max_mib=10, timeout=5
    )
    assert res.hits == {1: ["Win.Test.EICAR_HDB-1"]} and 0 in res.errors
    assert (tmp_path / "l").read_text().splitlines() == [str(p) for p in al.paths]

    def broken(argv, **kw):
        return subprocess.CompletedProcess(argv, 2, "", "LibClamAV Error: Malformed database")

    with pytest.raises(scanners.ScanError, match="Malformed"):
        scanners.clamscan(
            broken, al, [0], [tmp_path / "x.hsb"], list_path=tmp_path / "l", max_mib=1, timeout=5
        )


def test_cli_inputs_list_and_refusals(hashset_env: dict[str, Path], airlock_env: Path, capsys):
    folder = hashset_env["known"].parent
    assert triage.main([str(folder), "-o", str(folder / "t.csv"), "--no-sandbox"]) == 1
    err = capsys.readouterr().err
    assert "inside the folder being checked" in err and not (folder / "t.csv").exists()
    assert triage.main(["-o", str(airlock_env / "output" / "x.csv")]) == 2
    assert triage.main([str(airlock_env / "missing"), "-o", "x.csv"]) == 2
    listing = airlock_env / "list.txt"
    listing.write_text(f"{hashset_env['known']}\n{hashset_env['plain']}\n")
    out = airlock_env / "output" / "list.csv"
    rc = triage.main(["--list", str(listing), "-o", str(out), "--no-sandbox", "--quiet"])
    assert rc == 0
    summary = capsys.readouterr().out.strip().splitlines()
    assert len(summary) == 1 and "2 files: 1 known software (NSRL)" in summary[0]
    assert len(read_csv(out)) == 2


def test_walk_skips_symlinks(tmp_path: Path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_text("a")
    (tmp_path / "d" / "link").symlink_to("/etc/hostname")
    files, roots = triage.collect_inputs([str(tmp_path / "d")], None)
    assert [f.name for f in files] == ["a"] and roots == [(tmp_path / "d").resolve()]
    with pytest.raises(FileNotFoundError, match="symbolic link"):
        triage.collect_inputs([str(tmp_path / "d" / "link")], None)


def test_config_without_sets_lists_problems(airlock_env: Path):
    (airlock_env / "etc" / "hashsets.json").write_text(
        json.dumps({"clamav_dir": "/nonexistent", "nsrl_dirs": [], "yara_dir": "/nonexistent"})
    )
    cfg = hcfg.load()
    assert cfg.sets() == [] and len(cfg.problems) == 3
    assert "nsrl_path" in cfg.problems[0]


@needs_clam
@needs_yara
@needs_ssdeep
def test_check_step_for_goss(hashset_env: dict[str, Path], capsys):
    """The goss check (4A.8): every staged set present and loadable, missing ones named."""
    ok, lines = build.step_check({"malwarebazaar": True, "yara": True, "nsrl": True})
    assert ok and lines[-1] == "hash sets: ok", lines
    assert "ok: clamscan loads malwarebazaar.hsb" in lines
    ok, lines = build.step_check({"clamav": True})
    assert not ok and "MISSING: no ClamAV .cvd or .cld databases" in lines
    assert build.main(["check", "--features", '{"yara": true}']) == 0
    assert "hash sets: ok" in capsys.readouterr().out
