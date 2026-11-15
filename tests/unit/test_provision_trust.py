"""What provisioning trusts from ASSETS (tasks 2B.6, 2B.15, 4.9).

profile.json is unsigned and ASSETS is writable from any computer, so nothing from it may
reach Ansible's templating: features are checked against the fixed schema (contract section
6), free text is not passed as extra-vars, and template markup refuses the run. A newer signed
manifest is adopted only as the exact bytes the verify step accepted, never an older release.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from test_assets_support import FakeDrive, build_drive, session_events

from airlock_common import assets
from airlock_provision import cli, runner

INJECTED = "{{ lookup('pipe', 'touch /tmp/airlock-pwned') }}"


@pytest.fixture
def drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDrive:
    d = build_drive(tmp_path, monkeypatch)
    java = tmp_path / "jvm"
    (java / "bin").mkdir(parents=True)
    (java / "bin" / "java").write_text("", encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_JAVA_HOME", str(java))
    return d


def calls(drive: FakeDrive) -> list[str]:
    return drive.calls.read_text(encoding="utf-8").splitlines() if drive.calls.exists() else []


def vars_file(drive: FakeDrive) -> Path:
    return Path(f"{drive.calls}.vars.json")


def edit_profile(drive: FakeDrive, **changes: Any) -> None:
    path = drive.assets / "profile.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    for key, value in changes.items():
        if key == "features":
            doc["features"].update(value)
        else:
            doc[key] = value
    path.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")


def has_markup(value: Any) -> bool:
    return any(m in json.dumps(value) for m in ("{{", "{%", "{#"))


# ------------------------------------------------------------------ profile.json (finding 11)


@pytest.mark.parametrize(
    "change",
    [
        {"features": {"clamav": INJECTED}},
        {"features": {"ai_tiers": ["tier0", INJECTED]}},
        {"features": {"unknown_feature": "{% raw %}x{% endraw %}"}},
        {"profile": "{{ 7 * 7 }}"},
        {"case_defaults": {"examiner": INJECTED, "agency": "", "case_id_prefix": ""}},
        {"skipped": [{"id": "yara_rules", "reason": "{# note #}"}]},
    ],
    ids=["bool-feature", "ai-tier", "unknown-key", "profile-name", "case-defaults", "skipped"],
)
def test_template_text_in_profile_refuses_provisioning(
    drive: FakeDrive, change: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    edit_profile(drive, **change)
    assert cli.main_provision(["--no-reboot"]) == 1
    err = capsys.readouterr().err
    assert "template text" in err
    assert "Rerun the fetcher" in err
    assert not any(c.startswith("ansible-playbook") for c in calls(drive))
    assert not vars_file(drive).exists()
    assert not runner.vars_path().exists()
    assert any(e["event"] == "profile_refused" for e in session_events(drive))
    # Session start does not use it either.
    report = assets.verify_staged()
    assert not report.ok
    assert report.features == {}
    assert report.verified == {}
    assert any(a == "profile.json" and "template text" in r for a, r in report.problems)


def test_features_follow_the_fixed_schema(drive: FakeDrive) -> None:
    edit_profile(
        drive,
        features={
            "clamav": "yes",  # not a JSON boolean: off, and named
            "yara": 1,
            "ai_tiers": ["tier0", "tier9", 3],
            "extra_switch": True,  # not in the schema: dropped
        },
    )
    assert cli.main_provision(["--no-reboot"]) == 0
    v = json.loads(vars_file(drive).read_text(encoding="utf-8"))
    feats = v["airlock_features"]
    assert feats["clamav"] is False
    assert feats["yara"] is False
    assert feats["malwarebazaar"] is True
    assert feats["ai_tiers"] == ["tier0"]
    assert "extra_switch" not in feats
    assert {"clamav", "yara"} <= set(v["airlock_disabled_features"])
    for name in assets.BOOL_FEATURES:
        assert isinstance(feats.get(name, False), bool), name
    assert set(feats) <= {*assets.BOOL_FEATURES, "ai_tiers"}
    # Free text from profile.json is never handed to Ansible.
    assert "airlock_case_defaults" not in v
    assert "airlock_asset_problems" not in v
    assert not has_markup(v)
    report = assets.verify_staged()
    reasons = [r for a, r in report.problems if a == "profile.json"]
    assert "features.clamav is not true or false; turned off" in reasons
    assert "features.ai_tiers holds an unknown tier; it was dropped" in reasons


def test_sanitize_features_keeps_only_booleans_and_known_tiers() -> None:
    clean, off, reasons = assets.sanitize_features(
        {"autopsy": True, "nsrl": "false", "ai_tiers": ["tier2", "tier0", "tier2"], "x": 1}
    )
    assert clean == {"autopsy": True, "nsrl": False, "ai_tiers": ["tier0", "tier2"]}
    assert off == ["nsrl"]
    assert len(reasons) == 1
    assert assets.sanitize_features("{{ x }}") == (
        {},
        [],
        ["features is not an object; every feature is off"],
    )
    clean, _, reasons = assets.sanitize_features({"ai_tiers": "tier0"})
    assert clean == {"ai_tiers": []}
    assert reasons


def test_build_vars_refuses_template_text_from_any_source(drive: FakeDrive) -> None:
    report = assets.verify_staged(deep=True, for_apply=True)
    report.features = {"clamav": INJECTED, "ai_tiers": [INJECTED]}
    report.profile = INJECTED
    data = runner.build_vars(report)
    assert not has_markup(data)
    assert data["airlock_profile"] == ""
    assert data["airlock_features"]["clamav"] is False
    # Even a value from the signed manifest is refused if it carries markup.
    report.verified["yara_rules"]["version"] = "{{ 1 }}"
    with pytest.raises(runner.StepFailed, match="template text"):
        runner.build_vars(report)


# ------------------------------------------------------------------ Autopsy prerequisites (2)


def test_autopsy_turned_off_when_the_image_has_no_java(
    drive: FakeDrive, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edit_profile(drive, features={"autopsy": True})
    report = assets.verify_staged(deep=True, for_apply=True)
    assert runner.build_vars(report)["install_autopsy"] is True
    monkeypatch.setenv("AIRLOCK_JAVA_HOME", str(tmp_path / "no-java"))
    data = runner.build_vars(report)
    assert data["install_autopsy"] is False
    assert data["airlock_features"]["autopsy"] is False
    assert "autopsy" in data["airlock_disabled_features"]


def test_autopsy_without_java_is_named_in_the_report(
    drive: FakeDrive, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    edit_profile(drive, features={"autopsy": True})
    monkeypatch.setenv("AIRLOCK_JAVA_HOME", str(tmp_path / "no-java"))
    assert cli.main_provision(["--no-reboot"]) == 0
    out = capsys.readouterr().out
    assert "autopsy: this image has no Java 17" in out
    assert json.loads(vars_file(drive).read_text(encoding="utf-8"))["install_autopsy"] is False
    applied = json.loads((drive.state / "applied-assets.json").read_text(encoding="utf-8"))
    assert applied["features"]["autopsy"] is False


# ------------------------------------------------------------------ manifest adoption (14)


def stage_assets_manifest(drive: FakeDrive, release: str) -> bytes:
    """Put a genuine signed manifest of ``release`` on ASSETS (files unchanged)."""
    src = drive.root / "release" / f"manifest-{release}.json"
    drive.write_manifest(src, drive.manifest(release))
    (drive.assets / "manifest.json").write_bytes(src.read_bytes())
    (drive.assets / "manifest.json.sig").write_bytes(Path(f"{src}.sig").read_bytes())
    return src.read_bytes()


def baked(drive: FakeDrive) -> dict[str, Any]:
    return json.loads((drive.state / "manifest.json").read_text(encoding="utf-8"))


def test_newer_manifest_is_adopted_as_the_verified_bytes(drive: FakeDrive) -> None:
    body = stage_assets_manifest(drive, "v0.3.0")
    assert cli.main_provision(["--no-reboot"]) == 0
    assert (drive.state / "manifest.json").read_bytes() == body
    assert (drive.state / "manifest.json.sig").read_bytes() == (
        drive.assets / "manifest.json.sig"
    ).read_bytes()
    assert baked(drive)["release"] == "v0.3.0"


def test_manifest_swapped_before_a_resumed_run_is_not_adopted(
    drive: FakeDrive, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The finding: verify chose v0.3.0, the run was cut short, and ASSETS was then given a
    genuine signed v0.2.0 with profile.json unchanged. Record must not adopt it."""
    stage_assets_manifest(drive, "v0.3.0")
    monkeypatch.setenv("AIRLOCK_TEST_ANSIBLE_FAIL_ONCE", str(drive.root / "failed-once"))
    assert cli.main_provision(["--no-reboot"]) == 1
    run = runner.load_run()
    assert run is not None
    assert run.result("verify")["report"]["manifest_release"] == "v0.3.0"
    stage_assets_manifest(drive, "v0.2.0")
    assert runner.change_reason()[1].startswith("resuming")
    assert cli.main_provision(["--if-changed", "--no-reboot"]) == 1
    assert "changed since it was verified" in capsys.readouterr().err
    assert baked(drive)["release"] == "v0.1.0"
    assert not (drive.state / "manifest.json.previous").exists()
    assert not (drive.state / "applied-assets.json").exists()
    assert any(e["event"] == "manifest_not_adopted" for e in session_events(drive))
    # The next run checks ASSETS again from the start and adopts only what it verifies now.
    run = runner.load_run()
    assert run is not None
    assert not run.done("verify")
    assert cli.main_provision(["--if-changed", "--no-reboot"]) == 0
    assert baked(drive)["release"] == "v0.2.0"
    assert (drive.state / "manifest.json").read_bytes() == (
        drive.assets / "manifest.json"
    ).read_bytes()


def _report_for(body: bytes, release: str) -> dict[str, Any]:
    return {
        "manifest_source": "assets",
        "manifest_sha256": hashlib.sha256(body).hexdigest(),
        "manifest_release": release,
    }


def test_adopt_refuses_an_older_release_than_the_trusted_one(drive: FakeDrive) -> None:
    newer = drive.root / "release" / "baked.json"
    drive.write_manifest(newer, drive.manifest("v0.5.0"))
    (drive.state / "manifest.json").write_bytes(newer.read_bytes())
    body = stage_assets_manifest(drive, "v0.3.0")
    with pytest.raises(runner.ManifestChanged, match=r"older than the trusted v0\.5\.0"):
        runner._adopt_manifest(_report_for(body, "v0.3.0"))
    assert baked(drive)["release"] == "v0.5.0"


def test_adopt_rechecks_the_signature_over_the_same_bytes(drive: FakeDrive) -> None:
    body = stage_assets_manifest(drive, "v0.3.0")
    (drive.assets / "manifest.json.sig").write_bytes(b"\0" * 64)
    with pytest.raises(runner.ManifestChanged, match="signature does not verify"):
        runner._adopt_manifest(_report_for(body, "v0.3.0"))
    assert baked(drive)["release"] == "v0.1.0"
    assert not list(drive.state.glob(".manifest.json*"))


def test_adopt_refuses_bytes_other_than_the_verified_ones(drive: FakeDrive) -> None:
    body = stage_assets_manifest(drive, "v0.3.0")
    stage_assets_manifest(drive, "v0.4.0")  # genuine and newer, but not what verify chose
    with pytest.raises(runner.ManifestChanged, match="changed since it was verified"):
        runner._adopt_manifest(_report_for(body, "v0.3.0"))
    assert baked(drive)["release"] == "v0.1.0"
    (drive.assets / "manifest.json").unlink()
    with pytest.raises(runner.ManifestChanged, match="gone"):
        runner._adopt_manifest(_report_for(body, "v0.3.0"))
