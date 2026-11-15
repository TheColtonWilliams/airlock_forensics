"""scripts/fetch_assets.py, the core of fetch-assets.sh (tasks 2B.11, 4A.4, 4A.7): profile
resolution, refusal of unpinned files, the abuse.ch key never reaching the drive, staging from
the cache with hashes checked twice, profile.json. HTTP is covered by
tests/functional/test_fetch_assets.sh."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import fetch_assets as fa

KEY = "abuse-test-key-0123456789"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


MODEL = b"model-bytes" * 100
RULES = b"rule x { condition: true }\n"


def manifest() -> dict[str, Any]:
    files = [
        {"id": "model", "url": "https://h.invalid/m", "version": "1", "size": len(MODEL),
         "sha256": sha(MODEL), "target": "models/m.gguf", "profiles": ["ai_tier0"],
         "verify": "sha256", "license": "x"},
        {"id": "rules", "url": "https://h.invalid/r", "version": "1", "size": len(RULES),
         "sha256": sha(RULES), "target": "yara/r.yar", "profiles": ["yara"],
         "verify": "sha256", "license": "x"},
        {"id": "mb", "url": "https://h.invalid/mb", "version": "d", "size": None,
         "sha256": None, "target": "mb/full.zip", "profiles": ["malwarebazaar"],
         "verify": "trusted_at_staging", "license": "x"},
        {"id": "unpinned", "url": "https://h.invalid/u", "version": "1", "size": None,
         "sha256": None, "target": "u/u.bin", "profiles": ["yara"], "verify": "sha256",
         "license": "x"},
        {"id": "iso", "url": "https://h.invalid/iso", "version": "1", "size": 1,
         "sha256": "b" * 64, "target": None, "profiles": ["build"], "verify": "sha256",
         "license": "x"},
    ]  # fmt: skip
    feats = {"ai_tiers": ["tier0"], "yara": True, "malwarebazaar": True}
    return {
        "schema": 1,
        "release": "t",
        "files": files,
        "profiles": {
            "default": {"description": "d", "features": feats,
                        "files": ["mb", "model", "rules", "unpinned"]},
            "minimal": {"description": "m", "features": {"yara": True}, "files": ["rules"]},
        },
    }  # fmt: skip


def test_resolve_profile_by_name_and_file(tmp_path: Path) -> None:
    m = manifest()
    name, _feats, ids = fa.resolve_profile(m, "default")
    assert name == "default"
    assert ids == ["mb", "model", "rules", "unpinned"]
    custom = tmp_path / "lab.json"
    custom.write_text(json.dumps({"features": {"ai_tiers": ["tier0"]}}), encoding="utf-8")
    name, _feats, ids = fa.resolve_profile(m, str(custom))
    assert (name, ids) == ("lab", ["model"])
    yml = tmp_path / "p.yaml"
    yml.write_text("profiles:\n  mine:\n    features: {yara: true}\n", encoding="utf-8")
    assert fa.resolve_profile(m, str(yml))[:1] == ("mine",)
    assert fa.resolve_profile(m, str(yml))[2] == ["rules", "unpinned"]
    with pytest.raises(fa.UsageError, match="no profile named 'nope'"):
        fa.resolve_profile(m, "nope")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"files": ["iso"]}), encoding="utf-8")
    with pytest.raises(fa.UsageError, match="not ASSETS files"):
        fa.resolve_profile(m, str(bad))


def test_safe_target_rejects_escapes() -> None:
    for bad in ("../x", "/abs", "a//b", "a\\b", "C:/x", ""):
        with pytest.raises(fa.UsageError):
            fa.safe_target(bad)
    assert str(fa.safe_target("a/b.c")) == "a/b.c"


def seed_cache(cache: fa.Cache) -> None:
    for data in (MODEL, RULES):
        cache.blob(sha(data)).write_bytes(data)
    mb = b"mb-list\n"
    cache.blob(sha(mb)).write_bytes(mb)
    fa.write_json_atomic(
        cache.moving_record("mb"),
        {"sha256": sha(mb), "url": "https://h.invalid/mb", "size": len(mb), "fetched_at": "t"},
    )


def run_fetch(tmp_path: Path, *extra: str, env_key: str | None = None,
              monkeypatch: pytest.MonkeyPatch | None = None) -> int:  # fmt: skip
    mpath = tmp_path / "manifest.json"
    mpath.write_text(json.dumps(manifest()), encoding="utf-8")
    (tmp_path / "assets").mkdir(exist_ok=True)
    if env_key and monkeypatch:
        monkeypatch.setenv(fa.KEY_ENV, env_key)
    return fa.main([
        "--assets", str(tmp_path / "assets"), "--manifest", str(mpath), "--cache",
        str(tmp_path / "cache"), "--yes", *extra,
    ])  # fmt: skip


def test_stage_from_cache_writes_profile_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_cache(fa.Cache(tmp_path / "cache"))
    rc = run_fetch(tmp_path, "--profile", "default", "--examiner", "E. Xaminer",
                   env_key=KEY, monkeypatch=monkeypatch)  # fmt: skip
    assert rc == 0
    assets = tmp_path / "assets"
    prof = json.loads((assets / "profile.json").read_text(encoding="utf-8"))
    assert set(prof) == {"schema", "profile", "features", "staged_at", "fetcher", "files",
                         "skipped", "case_defaults"}  # fmt: skip
    assert prof["fetcher"].startswith("fetch-assets.sh ")
    assert [f["id"] for f in prof["files"]] == ["mb", "model", "rules"]
    assert prof["skipped"][0]["id"] == "unpinned"
    assert "not pinned yet" in prof["skipped"][0]["reason"]
    assert prof["case_defaults"]["examiner"] == "E. Xaminer"
    assert (assets / "files" / "models" / "m.gguf").read_bytes() == MODEL
    mb_row = next(f for f in prof["files"] if f["id"] == "mb")
    assert mb_row["sha256"] == sha(b"mb-list\n")
    assert mb_row["verify"] == "trusted_at_staging"
    # The key is never written anywhere: not on ASSETS, not in the cache, not in the env.
    for root in (assets, tmp_path / "cache"):
        for p in root.rglob("*"):
            if p.is_file():
                assert KEY.encode() not in p.read_bytes(), p
    assert fa.KEY_ENV not in fa.os.environ
    assert not list(assets.rglob(f"*{fa.TMP_SUFFIX}"))


def test_no_key_skips_malwarebazaar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(fa.KEY_ENV, raising=False)
    seed_cache(fa.Cache(tmp_path / "cache"))
    assert run_fetch(tmp_path, "--profile", "default") == 0
    prof = json.loads((tmp_path / "assets" / "profile.json").read_text(encoding="utf-8"))
    skipped = {s["id"]: s["reason"] for s in prof["skipped"]}
    assert "no abuse.ch key" in skipped["mb"]


def test_corrupt_cache_blob_is_not_staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = fa.Cache(tmp_path / "cache")
    seed_cache(cache)
    cache.blob(sha(RULES)).write_bytes(b"tampered")
    monkeypatch.delenv(fa.KEY_ENV, raising=False)
    assert run_fetch(tmp_path, "--profile", "minimal") == 1
    prof = json.loads((tmp_path / "assets" / "profile.json").read_text(encoding="utf-8"))
    assert prof["files"] == []
    assert "does not match its SHA-256" in prof["skipped"][0]["reason"]
    assert not (tmp_path / "assets" / "files" / "yara" / "r.yar").exists()
    assert not cache.blob(sha(RULES)).exists()


def test_changing_profile_prunes_old_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed_cache(fa.Cache(tmp_path / "cache"))
    assert run_fetch(tmp_path, "--profile", "default", env_key=KEY, monkeypatch=monkeypatch) == 0
    assert run_fetch(tmp_path, "--profile", "minimal") == 0
    assets = tmp_path / "assets"
    assert not (assets / "files" / "models" / "m.gguf").exists()
    assert (assets / "files" / "yara" / "r.yar").exists()
    prof = json.loads((assets / "profile.json").read_text(encoding="utf-8"))
    assert prof["profile"] == "minimal"


def test_dry_run_and_space_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(fa.KEY_ENV, raising=False)
    seed_cache(fa.Cache(tmp_path / "cache"))
    assert run_fetch(tmp_path, "--profile", "minimal", "--dry-run") == 0
    assert not (tmp_path / "assets" / "profile.json").exists()

    class Usage:
        free = 5

    monkeypatch.setattr(fa.shutil, "disk_usage", lambda _p: Usage)
    assert run_fetch(tmp_path, "--profile", "minimal") == 2
    assert not (tmp_path / "assets" / "profile.json").exists()


def test_key_file_is_read_not_copied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(fa.KEY_ENV, raising=False)
    keyfile = tmp_path / "key.txt"
    keyfile.write_text(KEY + "\n", encoding="utf-8")
    seed_cache(fa.Cache(tmp_path / "cache"))
    assert run_fetch(tmp_path, "--profile", "default", "--abuse-key-file", str(keyfile)) == 0
    prof = json.loads((tmp_path / "assets" / "profile.json").read_text(encoding="utf-8"))
    assert "mb" in [f["id"] for f in prof["files"]]
    assert KEY not in (tmp_path / "assets" / "profile.json").read_text(encoding="utf-8")


def test_version_matches_main_yml() -> None:
    import yaml  # noqa: PLC0415

    repo = Path(__file__).resolve().parents[2]
    main = yaml.safe_load(
        (repo / "ansible" / "group_vars" / "all" / "main.yml").read_text(encoding="utf-8")
    )
    assert main["airlock_version"] == fa.FETCHER_VERSION
    ps1 = (repo / "scripts" / "fetch-assets.ps1").read_text(encoding="utf-8")
    assert f"$FetcherVersion = '{fa.FETCHER_VERSION}'" in ps1
