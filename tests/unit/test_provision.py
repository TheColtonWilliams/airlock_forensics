"""forensic-provision and forensic-import (tasks 2B.4 to 2B.7, 2B.12, 4A.7): refusal checks,
checkpointed steps and resume, disabled features, change detection, the result manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_assets_support import (
    GOOD_MODEL,
    FakeDrive,
    build_drive,
    session_events,
)

from airlock_provision import cli, runner, system


@pytest.fixture
def drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDrive:
    return build_drive(tmp_path, monkeypatch)


def calls(drive: FakeDrive) -> list[str]:
    return drive.calls.read_text(encoding="utf-8").splitlines() if drive.calls.exists() else []


def vars_used(drive: FakeDrive) -> dict:
    return json.loads(Path(f"{drive.calls}.vars.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ refusal checks


def test_offline_machine_passes(drive: FakeDrive) -> None:
    assert system.network_problems() == []
    assert system.disk_problems() == []
    assert runner.preflight() == []


def test_interface_up_refused(drive: FakeDrive) -> None:
    drive.set_network(up=True)
    assert system.network_problems() == ["network interface eth0 is up"]


def test_default_route_refused(drive: FakeDrive) -> None:
    drive.set_network(default_route=True)
    assert "an IPv4 default route exists (via eth0)" in system.network_problems()


def test_ipv6_default_route_refused(drive: FakeDrive) -> None:
    route6 = drive.root / "proc" / "net" / "ipv6_route"
    route6.write_text(
        route6.read_text(encoding="utf-8")
        + "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n",
        encoding="utf-8",
    )
    assert system.network_problems() == ["an IPv6 default route exists (via eth0)"]


def test_extra_disk_refused(drive: FakeDrive, capsys: pytest.CaptureFixture[str]) -> None:
    drive.set_disks(extra=True)
    assert system.disk_problems() == ["/dev/sdb (500.0 GB, sata) is attached"]
    assert cli.main_provision(["--no-reboot"]) == 1
    err = capsys.readouterr().err
    assert "refused: /dev/sdb" in err
    assert "Unplug every other drive" in err
    assert not any(c.startswith("ansible-playbook") for c in calls(drive))
    assert cli.main_import([]) == 1


def test_not_root_refused(drive: FakeDrive, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIRLOCK_ALLOW_NONROOT")
    monkeypatch.setattr(system.os, "geteuid", lambda: 1000)
    assert system.root_problem() == "must run as root"


# ------------------------------------------------------------------ full run


def test_provision_runs_every_step_and_reboots(drive: FakeDrive) -> None:
    assert cli.main_provision([]) == 0
    seen = calls(drive)
    ansible = [c for c in seen if c.startswith("ansible-playbook")]
    assert len(ansible) == 1
    assert "-c local" in ansible[0]
    assert "-e airlock_phase=provision" in ansible[0]
    assert ansible[0].endswith("vars.json")
    assert any(c.startswith("goss -g") and "validate" in c for c in seen)
    assert seen[-1] == "systemctl reboot"
    v = vars_used(drive)
    assert v["airlock_phase"] == "provision"
    assert v["airlock_features"]["ai_tiers"] == ["tier0"]
    assert v["airlock_assets"]["model_tier0"]["path"].endswith("files/models/tier0.gguf")
    assert v["airlock_disabled_features"] == []
    manifest = json.loads((drive.state / "provision-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "ok"
    assert {a["id"] for a in manifest["assets"]} == set(v["airlock_assets"])
    assert manifest["hardware"]["cpu_model"] == "Test CPU"
    assert manifest["hardware"]["memory_bytes"] == 16384 * 1024
    assert "provisioned_at" in manifest
    applied = json.loads((drive.state / "applied-assets.json").read_text(encoding="utf-8"))
    assert applied["features"]["yara"] is True
    events = [e["event"] for e in session_events(drive)]
    for want in ("provision_start", "assets_verified", "asset_applied", "provision_manifest",
                 "provision_complete"):  # fmt: skip
        assert want in events
    report = (Path(drive.root) / "output" / runner.REPORT_NAME).read_text(encoding="utf-8")
    assert "Result: ok" in report


def test_no_reboot_flag(drive: FakeDrive) -> None:
    assert cli.main_provision(["--no-reboot"]) == 0
    assert "systemctl reboot" not in calls(drive)


def test_damaged_file_disables_feature_and_still_provisions(
    drive: FakeDrive, capsys: pytest.CaptureFixture[str]
) -> None:
    """2B.12: a missing or corrupt file is named, its feature is off, the rest is applied."""
    (drive.assets / "files" / "models" / "tier0.gguf").write_bytes(b"z" * len(GOOD_MODEL))
    assert cli.main_provision(["--no-reboot"]) == 0
    out = capsys.readouterr().out
    assert "model_tier0: SHA-256 does not match" in out
    assert "Turned off because of them: ai_tier0" in out
    v = vars_used(drive)
    assert v["airlock_features"]["ai_tiers"] == []
    assert v["airlock_profile_features"] == v["airlock_features"]
    assert "model_tier0" not in v["airlock_assets"]
    assert v["airlock_disabled_features"] == ["ai_tier0"]
    applied = json.loads((drive.state / "applied-assets.json").read_text(encoding="utf-8"))
    assert applied["disabled_features"] == ["ai_tier0"]
    assert applied["problems"][0][0] == "model_tier0"


def test_resume_after_failure(drive: FakeDrive, monkeypatch: pytest.MonkeyPatch) -> None:
    """2B.5: a failed (or power-cut) run resumes at the first unfinished step."""
    monkeypatch.setenv("AIRLOCK_TEST_ANSIBLE_FAIL_ONCE", str(drive.root / "failed-once"))
    assert cli.main_provision(["--no-reboot"]) == 1
    run = runner.load_run()
    assert run is not None
    assert not run.complete
    assert run.done("verify")
    assert not run.done("ansible")
    first_id = run.run_id
    # The boot unit picks the unfinished run up.
    mode, why = runner.change_reason()
    assert mode == "provision"
    assert "resuming" in why
    assert cli.main_provision(["--if-changed", "--no-reboot"]) == 0
    run = runner.load_run()
    assert run is not None
    assert run.run_id == first_id
    assert run.complete
    events = session_events(drive)
    starts = [e for e in events if e["event"] == "provision_start"]
    assert starts[-1]["resumed"] is True
    assert sum(1 for e in events if e["event"] == "assets_verified") == 1


def test_if_changed_does_nothing_when_unchanged(drive: FakeDrive) -> None:
    assert cli.main_provision(["--no-reboot"]) == 0
    before = len(calls(drive))
    assert runner.change_reason()[0] is None
    assert cli.main_provision(["--if-changed"]) == 0
    assert len(calls(drive)) == before


def test_if_changed_applies_a_new_profile_without_reboot(drive: FakeDrive) -> None:
    """2B.7: rerun the fetcher with another profile; the next boot applies it offline."""
    assert cli.main_provision(["--no-reboot"]) == 0
    manifest = drive.manifest()
    manifest["profiles"]["default"]["features"]["yara"] = False
    contents = drive.default_contents()
    del contents["yara_rules"]
    manifest["profiles"]["default"]["files"].remove("yara_rules")
    drive.stage(manifest, contents, copy_manifest=False)
    mode, why = runner.change_reason()
    assert mode == "update"
    assert "ASSETS set changed" in why
    n_before = len(calls(drive))
    assert cli.main_provision(["--if-changed"]) == 0
    new_calls = calls(drive)[n_before:]
    assert any(c.startswith("ansible-playbook") for c in new_calls)
    assert "systemctl reboot" not in new_calls
    assert vars_used(drive)["airlock_features"]["yara"] is False
    removed = [e for e in session_events(drive) if e["event"] == "asset_removed"]
    assert removed[-1]["id"] == "yara_rules"


def test_goss_failure_is_reported(drive: FakeDrive, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRLOCK_TEST_GOSS_FAIL", "1")
    assert cli.main_provision([]) == 1
    manifest = json.loads((drive.state / "provision-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "tests_failed"
    assert "systemctl reboot" not in calls(drive)


def test_goss_missing_is_recorded(drive: FakeDrive) -> None:
    for f in (drive.root / "repo" / "tests" / "goss").glob("*.yaml"):
        f.unlink()
    assert cli.main_provision(["--no-reboot"]) == 0
    manifest = json.loads((drive.state / "provision-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "tests_not_run"


def test_second_run_is_locked_out(drive: FakeDrive) -> None:
    with runner.lock(), pytest.raises(runner.Refused), runner.lock():
        pass


# ------------------------------------------------------------------ forensic-import


def test_import_nothing_new(drive: FakeDrive, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main_provision(["--no-reboot"]) == 0
    n = len(calls(drive))
    assert cli.main_import([]) == 0
    assert "nothing new" in capsys.readouterr().out
    assert len(calls(drive)) == n


def test_import_applies_restaged_daily_set_and_logs_hashes(
    drive: FakeDrive, capsys: pytest.CaptureFixture[str]
) -> None:
    """4A.7: a restaged signature set is verified, applied, and each SHA-256 logged."""
    assert cli.main_provision(["--no-reboot"]) == 0
    contents = drive.default_contents()
    contents["clamav_daily"] = b"ClamAV-VDB:test daily v2\n" + b"\x01" * 400
    drive.stage(drive.manifest(), contents, copy_manifest=False)
    assert cli.main_import(["--dry-run"]) == 0  # lists the change, applies nothing
    assert "clamav_daily: changed" in capsys.readouterr().out
    assert cli.main_import([]) == 0
    applied = [e for e in session_events(drive) if e["event"] == "asset_applied"]
    daily = [e for e in applied if e["id"] == "clamav_daily"][-1]
    assert daily["status"] == "changed"
    assert daily["sha256"] != daily["previous_sha256"]
    state = json.loads((drive.state / "applied-assets.json").read_text(encoding="utf-8"))
    assert state["mode"] == "import"
    assert state["files"]["clamav_daily"]["sha256"] == daily["sha256"]
    from airlock_common import assets  # noqa: PLC0415

    assert assets.verify_staged().ok  # session start is clean again after the import


def test_import_refuses_with_network_up(drive: FakeDrive) -> None:
    drive.set_network(up=True)
    assert cli.main_import([]) == 1
