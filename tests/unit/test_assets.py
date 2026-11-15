"""airlock_common.assets: trusted manifest, staged-file checks, verified paths (2B.14, 2B.15,
4G.4). Each tamper case must be detected, named, and turn off the feature that needs the file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_assets_support import (
    GOOD_MODEL,
    FakeDrive,
    build_drive,
    openssl,
    session_events,
)

from airlock_common import assets


@pytest.fixture
def drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDrive:
    return build_drive(tmp_path, monkeypatch)


def problems(report: assets.AssetReport) -> dict[str, str]:
    return dict(report.problems)


def test_good_drive_checks_out(drive: FakeDrive) -> None:
    report = assets.verify_staged()
    assert report.ok, report.problems
    assert report.checked == ["clamav_daily", "malwarebazaar_full", "model_tier0", "yara_rules"]
    assert report.disabled_features == []
    assert report.verified["model_tier0"]["sha256"] == assets.hashing.sha256_file(
        drive.assets / "files" / "models" / "tier0.gguf"
    )


def test_signature_verifies_and_rejects_edits(drive: FakeDrive) -> None:
    m = drive.state / "manifest.json"
    assert assets.verify_signature(m, f"{m}.sig", drive.pub)
    edited = drive.root / "edited.json"
    edited.write_bytes(m.read_bytes().replace(b'"v0.1.0"', b'"v9.9.9"'))
    assert not assets.verify_signature(edited, f"{m}.sig", drive.pub)
    assert not assets.verify_signature(m, drive.root / "missing.sig", drive.pub)


def test_swapped_file_detected_and_feature_disabled(drive: FakeDrive) -> None:
    path = drive.assets / "files" / "models" / "tier0.gguf"
    path.write_bytes(bytes(reversed(GOOD_MODEL)))  # same size, other content
    quick = assets.verify_staged(deep=False)
    assert quick.ok  # presence and size cannot see a same-size swap
    report = assets.verify_staged(deep=True)
    assert not report.ok
    assert "SHA-256 does not match the trusted manifest" in problems(report)["model_tier0"]
    assert report.disabled_features == ["ai_tier0"]
    assert "model_tier0" not in report.verified


def test_truncated_file_detected_even_by_quick_check(drive: FakeDrive) -> None:
    path = drive.assets / "files" / "yara" / "rules.yar"
    path.write_bytes(path.read_bytes()[:10])
    for deep in (False, True):
        report = assets.verify_staged(deep=deep)
        assert "truncated or replaced" in problems(report)["yara_rules"]
        assert report.disabled_features == ["yara"]


def test_edited_profile_hash_cannot_hide_a_swap(drive: FakeDrive) -> None:
    """Rewriting profile.json to match a swapped pinned file does not help: the manifest wins."""
    path = drive.assets / "files" / "models" / "tier0.gguf"
    path.write_bytes(b"x" * len(GOOD_MODEL))
    prof = json.loads((drive.assets / "profile.json").read_text(encoding="utf-8"))
    for row in prof["files"]:
        if row["id"] == "model_tier0":
            row["sha256"] = assets.hashing.sha256_file(path)
    (drive.assets / "profile.json").write_text(json.dumps(prof), encoding="utf-8")
    report = assets.verify_staged()
    assert "different SHA-256 than the trusted manifest" in problems(report)["model_tier0"]
    assert "ai_tier0" in report.disabled_features


def test_edited_assets_manifest_is_not_trusted(drive: FakeDrive) -> None:
    """An attacker edits the ASSETS manifest to bless a swapped file: signature fails."""
    swapped = b"y" * len(GOOD_MODEL)
    (drive.assets / "files" / "models" / "tier0.gguf").write_bytes(swapped)
    m = json.loads((drive.assets / "manifest.json").read_text(encoding="utf-8"))
    for f in m["files"]:
        if f["id"] == "model_tier0":
            f["sha256"] = assets.hashing.sha256_bytes(swapped)
    (drive.assets / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    info = assets.load_manifest_info()
    assert info.source == "baked"
    report = assets.verify_staged()
    found = problems(report)
    assert "signature does not verify" in found["manifest.json"]
    assert "model_tier0" in found
    assert "ai_tier0" in report.disabled_features


def test_bad_signature_from_another_key(drive: FakeDrive) -> None:
    other = drive.root / "other.key"
    openssl("genpkey", "-algorithm", "ed25519", "-out", str(other))
    m = drive.assets / "manifest.json"
    m.write_text(m.read_text(encoding="utf-8").replace("v0.1.0", "v0.2.0"), encoding="utf-8")
    openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(other), "-in", str(m),
            "-out", f"{m}.sig")  # fmt: skip
    report = assets.verify_staged()
    assert assets.load_manifest_info().source == "baked"
    assert "signature does not verify" in problems(report)["manifest.json"]


def test_newer_signed_manifest_on_assets_is_used(drive: FakeDrive) -> None:
    new_model = b"GGUF-v2" * 100
    manifest = drive.manifest(release="v0.2.0", model=new_model)
    contents = drive.default_contents() | {"model_tier0": new_model}
    drive.stage(manifest, contents)
    info = assets.load_manifest_info()
    assert info.source == "assets"
    assert info.release == "v0.2.0"
    assert assets.verify_staged().ok


def test_older_signed_manifest_is_refused(drive: FakeDrive) -> None:
    drive.stage(drive.manifest(release="v0.0.9"), drive.default_contents())
    info = assets.load_manifest_info()
    assert info.source == "baked"
    assert any("older" in why for _, why in info.notes)


def test_unsigned_assets_manifest_is_ignored(drive: FakeDrive) -> None:
    (drive.assets / "manifest.json.sig").unlink()
    m = drive.assets / "manifest.json"
    m.write_text(m.read_text(encoding="utf-8").replace("v0.1.0", "v0.3.0"), encoding="utf-8")
    report = assets.verify_staged()
    assert "no signature" in problems(report)["manifest.json"]
    assert report.manifest_source == "baked"


def test_missing_baked_manifest_disables_everything(drive: FakeDrive) -> None:
    (drive.state / "manifest.json").unlink()
    (drive.assets / "manifest.json.sig").unlink()
    report = assets.verify_staged()
    assert not report.ok
    assert "no trusted manifest" in problems(report)["manifest.json"]
    assert report.disabled_features == ["ai_tier0", "clamav", "malwarebazaar", "yara"]


def test_unstaged_drive_reports_profile_missing(drive: FakeDrive) -> None:
    (drive.assets / "profile.json").unlink()
    report = assets.verify_staged()
    assert "has not been staged" in problems(report)["profile.json"]


def test_skipped_and_missing_files_are_named(drive: FakeDrive) -> None:
    prof = json.loads((drive.assets / "profile.json").read_text(encoding="utf-8"))
    prof["files"] = [r for r in prof["files"] if r["id"] != "malwarebazaar_full"]
    prof["skipped"] = [{"id": "malwarebazaar_full", "reason": "no abuse.ch key given"}]
    (drive.assets / "profile.json").write_text(json.dumps(prof), encoding="utf-8")
    (drive.assets / "files" / "clamav" / "daily.cvd").unlink()
    report = assets.verify_staged()
    found = problems(report)
    assert found["malwarebazaar_full"] == "not staged: no abuse.ch key given"
    assert found["clamav_daily"].startswith("missing")
    assert report.disabled_features == ["clamav", "malwarebazaar"]


def test_daily_file_checked_against_applied_hash(drive: FakeDrive) -> None:
    """After provisioning, a daily file is checked against the hash on the root filesystem."""
    report = assets.verify_staged()
    applied = {"files": report.verified, "profile_sha256": assets.profile_sha256()}
    (drive.state / "applied-assets.json").write_text(json.dumps(applied), encoding="utf-8")
    daily = drive.assets / "files" / "clamav" / "daily.cvd"
    data = bytearray(daily.read_bytes())
    data[-1] ^= 0xFF
    daily.write_bytes(bytes(data))
    found = problems(assets.verify_staged())
    assert "hash recorded when it was applied" in found["clamav_daily"]
    # A restaged daily file (new hash in profile.json) is not used until imported.
    prof = json.loads((drive.assets / "profile.json").read_text(encoding="utf-8"))
    for row in prof["files"]:
        if row["id"] == "clamav_daily":
            row["sha256"] = assets.hashing.sha256_bytes(bytes(data))
    (drive.assets / "profile.json").write_text(json.dumps(prof), encoding="utf-8")
    found = problems(assets.verify_staged())
    assert "forensic-import" in found["clamav_daily"]


def test_asset_path_only_for_applied_files(drive: FakeDrive) -> None:
    assert assets.asset_path("model_tier0") is None  # nothing applied yet
    report = assets.verify_staged()
    (drive.state / "applied-assets.json").write_text(
        json.dumps({"files": report.verified}), encoding="utf-8"
    )
    path = assets.asset_path("model_tier0")
    assert path == drive.assets / "files" / "models" / "tier0.gguf"
    path.write_bytes(b"short")
    assert assets.asset_path("model_tier0") is None
    assert assets.asset_path("no_such_asset") is None


def test_effective_features_turns_off_disabled() -> None:
    feats = {"ai_tiers": ["tier0", "tier1"], "clamav": True, "yara": True}
    out = assets.effective_features(feats, ["ai_tier1", "clamav"])
    assert out == {"ai_tiers": ["tier0"], "clamav": False, "yara": True}


def test_unsafe_target_is_rejected(drive: FakeDrive) -> None:
    assert assets.staged_path("../etc/passwd") is None
    assert assets.staged_path("/abs") is None
    assert assets.staged_path("a/b.bin") == drive.assets / "files" / "a" / "b.bin"


def test_cli_and_session_log(drive: FakeDrive) -> None:
    """The session-start path: the result and every file's hash go to the session log."""
    assert assets.main(["verify", "--log-tool", "forensic-session-start"]) == 0
    events = [e for e in session_events(drive) if e["event"] == "assets_verified"]
    assert events[-1]["ok"] is True
    assert events[-1]["tool"] == "forensic-session-start"
    assert set(events[-1]["files"]) == {
        "clamav_daily", "malwarebazaar_full", "model_tier0", "yara_rules"
    }  # fmt: skip
    (drive.assets / "files" / "yara" / "rules.yar").write_bytes(b"tampered")
    assert assets.main(["verify", "--json", "--log-tool", "forensic-session-start"]) == 1
    last = [e for e in session_events(drive) if e["event"] == "assets_verified"][-1]
    assert last["ok"] is False
    assert last["disabled_features"] == ["yara"]
    assert last["problems"][0][0] == "yara_rules"


def test_report_summary_says_what_to_do(drive: FakeDrive) -> None:
    (drive.assets / "files" / "yara" / "rules.yar").unlink()
    text = assets.verify_staged().summary()
    assert "yara_rules: missing" in text
    assert "turned off: yara" in text
    assert "rerun the fetcher" in text
    assert Path(drive.assets / "profile.json").is_file()
