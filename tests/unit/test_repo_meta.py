"""Repository meta files, CI workflows, release steps, and the live build configuration.

Tasks 0.3, 0.4, 0.5, 0.7, 0.8, 0.9, 2A.8, 2B.1, 2B.2, 2B.8, 2B.16, 2B.19, 4G.1, 4G.2, 4G.17,
5.6, 5.7, 6.3, 7.2. The workflows themselves run on GitHub; these tests check what can be
checked here: their structure, the exact commands they run, the check names branch protection
requires, the image split and SHA256SUMS steps (run for real on a small file), and the
live-build configuration stage.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def flat(rel: str) -> str:
    """The file's text with Markdown bold marks removed and all white space collapsed."""
    return re.sub(r"\s+", " ", read(rel).replace("**", ""))


def workflow(name: str) -> dict[str, Any]:
    data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    # PyYAML reads the bare key "on" as True.
    if True in data:
        data["on"] = data.pop(True)
    return data


def all_steps(wf: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for job in wf["jobs"].values() for s in job.get("steps", [])]


def step(wf: dict[str, Any], job: str, name_part: str) -> dict[str, Any]:
    for s in wf["jobs"][job]["steps"]:
        if name_part in s.get("name", ""):
            return s
    raise AssertionError(f"no step named like {name_part!r} in job {job}")


def run_text(wf: dict[str, Any]) -> str:
    return "\n".join(s.get("run", "") for s in all_steps(wf))


# ------------------------------------------------------------------ README, SECURITY, CONTRIBUTING


def test_readme_states_purpose_acronym_and_limits() -> None:
    raw = read("README.md")
    text = flat("README.md")
    assert (
        "**A**ir-gapped, **I**solated, **R**ead-only, **L**ocked-down, **O**ffline **C**ase **K**it"
        in raw
    )
    assert "**AIRLOCK is not a write blocker. AIRLOCK is not court-validated.**" in raw
    assert "software read-only policy" in text
    for link in (
        "docs/quickstart.md",
        "docs/controls.md",
        "docs/threat-model.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
    ):
        assert f"]({link})" in text, link
    assert "Pre-release" in text
    assert "Apache License 2.0" in text


DOCS_WITH_LINKS = [
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/index.md",
    "docs/threat-model.md",
    "docs/release-process.md",
    "docs/hardware-checklist.md",
    "docs/write-blockers.md",
    "docs/dev/repo-setup.md",
    "live/README.md",
]


@pytest.mark.parametrize("rel", DOCS_WITH_LINKS)
def test_relative_links_resolve(rel: str) -> None:
    base = (REPO / rel).parent
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", read(rel)):
        if re.match(r"^[a-z]+:", target):
            continue
        assert (base / target).exists(), f"{rel}: broken link {target}"


@pytest.mark.parametrize("rel", [*DOCS_WITH_LINKS, ".github/pull_request_template.md"])
def test_never_calls_the_software_policy_a_write_blocker(rel: str) -> None:
    text = flat(rel).lower()
    for bad in (
        "software write blocker",
        "software write-blocker",
        "airlock is a write blocker",
        "read-only policy is a write blocker",
        "acts as a write blocker",
    ):
        assert bad not in text, f"{rel}: '{bad}'"


def test_security_uses_private_reporting_and_lists_versions() -> None:
    text = read("SECURITY.md")
    assert "private vulnerability reporting" in text
    assert "Report a vulnerability" in text
    assert "## Supported versions" in text
    assert "| Version | Supported |" in text
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "no personal email address"


def test_contributing_rules() -> None:
    text = flat("CONTRIBUTING.md")
    assert "one control = one task + one test + one doc line" in text
    for cmd in (
        "scripts/lint.sh",
        "tests/run-unit.sh",
        "tests/run-functional.sh",
        "tests/run-qemu-tests.sh",
    ):
        assert cmd in text
    assert "starts with the task number" in text
    assert "## Hard rules" in text
    assert "10. No new third-party dependency" in text


def test_threat_model_copies_plan_section_1_4() -> None:
    plan = read("docs/build-plan.md")
    section = plan.split("## 1.4 Threat model", 1)[1].split("\n## ", 1)[0]
    items = re.findall(r"^\d+\. (.+)$", section, flags=re.M)
    assert len(items) == 10
    model = flat("docs/threat-model.md")
    for item in items:
        sentence = item.split(". ")[0].rstrip(".") + "."
        assert sentence in model, sentence
    for risk in ("| 1 |", "| 22 |", "| 25 |", "| 26 |"):
        assert risk in model


def test_write_blockers_lists_only_reported_blockers() -> None:
    assert "software read-only policy" in flat("docs/write-blockers.md")
    text = read("docs/write-blockers.md")
    table = text.split("| Make | Model |", 1)[1].splitlines()[2:]
    rows = [r for r in table if r.startswith("|")]
    for row in rows:
        assert re.search(r"https://\S*(nist\.gov|dhs\.gov)", row), (
            f"blocker row without a CFTT/DHS link: {row}"
        )


def test_hardware_checklist_covers_the_plan_items() -> None:
    text = flat("docs/hardware-checklist.md").lower()
    for item in (
        "uefi",
        "bios",
        "secure boot",
        "internal disk read-only",
        "not mounted and not writable",
        "tier chosen",
        "quick run completes",
        "opens on windows",
    ):
        assert item in text, item


def test_validation_guide_has_the_user_validation_section() -> None:
    text = flat("docs/validation-guide.md")
    assert "## Your own validation (task 6.4)" in text
    for needle in (
        "cosign signature",
        "validation-report.md",
        "forensic-analyze --preset quick",
        "write-request count of `0`",
        "### Validation record",
    ):
        assert needle in text, needle


def test_first_use_and_hardware_review_sections() -> None:
    checklist = flat("docs/hardware-checklist.md")
    assert "## First-use test on Windows (task 4G.18)" in checklist
    assert "Do not help." in checklist
    matrix = flat("docs/hardware-matrix.md")
    assert "## Secure Boot test matrix: three laptops (task 7.3)" in matrix
    assert "## Outside review (task 7.4)" in matrix
    assert "outside-review.yml" in matrix


def test_decision_log_records_live_build_and_ci_licences() -> None:
    log = flat("docs/decision-log.md")
    assert "Task 7.1: the amnesic live variant is built with live-build" in log
    for lic in ("cosign 2.6.5 and syft 1.57.1 (both Apache-2.0)", "actionlint 1.7.7 (MIT)"):
        assert lic in log


def test_repo_setup_and_issue_templates() -> None:
    setup = read("docs/dev/repo-setup.md")
    assert "Repository name: **`airlock`**" in setup
    assert "**Public**" in setup
    assert "scripts/setup-branch-protection.sh" in setup
    tdir = REPO / ".github" / "ISSUE_TEMPLATE"
    for name in ("bug.yml", "control-request.yml", "tool-request.yml", "outside-review.yml"):
        form = yaml.safe_load((tdir / name).read_text(encoding="utf-8"))
        assert form["name"] and form["description"] and form["body"], name
        ids = [b.get("id") for b in form["body"] if b.get("type") != "markdown"]
        assert len(ids) == len(set(ids)), name
    cfg = yaml.safe_load((tdir / "config.yml").read_text(encoding="utf-8"))
    assert cfg["blank_issues_enabled"] is False


# ------------------------------------------------------------------ workflows


@pytest.mark.parametrize("name", ["lint.yml", "build.yml", "release.yml", "windows.yml"])
def test_workflow_basics(name: str) -> None:
    wf = workflow(name)
    assert wf["permissions"] == {"contents": "read"}, "least privilege at the top"
    raw = (WORKFLOWS / name).read_text(encoding="utf-8")
    for s in all_steps(wf):
        if "uses" in s:
            assert SHA_PIN.match(s["uses"]), f"{name}: {s['uses']} is not pinned to a commit SHA"
    for line in raw.splitlines():
        if "uses:" in line:
            assert re.search(r"# v\d+\.\d+\.\d+$", line), f"{name}: no version comment: {line}"
    assert "secrets." not in raw or name == "release.yml", "only the release workflow reads secrets"


def test_lint_workflow_runs_lint_and_tests() -> None:
    wf = workflow("lint.yml")
    assert {"pull_request", "push"} <= set(wf["on"])
    text = run_text(wf)
    assert "scripts/lint.sh all" in text
    assert "actionlint" in text
    assert "tests/run-unit.sh" in text
    assert 'sudo --preserve-env=PATH env "PATH=$PATH" tests/run-functional.sh' in text
    assert "--require-hashes" in text


def test_build_workflow_jobs() -> None:
    wf = workflow("build.yml")
    jobs = wf["jobs"]
    assert set(jobs) == {"build", "make-usb-loop", "provision"}
    text = run_text(wf)
    assert "/dev/kvm" in text and "ACCEL=tcg" in text
    assert "scripts/build.sh --accel" in text
    assert "--firmware uefi,uefi-sb,bios" in text
    assert jobs["build"]["timeout-minutes"] == 360
    uploads = [s for s in jobs["build"]["steps"] if "upload-artifact" in s.get("uses", "")]
    assert any("raw.zst" in s["with"]["path"] for s in uploads)
    # 2B.19: monthly rebuild, and the release process says so.
    assert wf["on"]["schedule"] == [{"cron": "17 3 1 * *"}]
    process = flat("docs/release-process.md")
    assert "Monthly." in process and "Out of band." in process
    assert "Every release reruns the validation suite" in process
    # 2A.8
    mk = step(wf, "make-usb-loop", "./make-usb.sh")["run"]
    assert './make-usb.sh --yes --profile ci --target "$LOOP" --confirm "$LOOP_NAME"' in mk
    assert "AIRLOCK_FLASH_TEST=1" in mk
    assert "losetup" in step(wf, "make-usb-loop", "loop device")["run"]
    # 2B.8 and 2B.16
    matrix = jobs["provision"]["strategy"]["matrix"]["include"]
    assert {(m["task"], m["nic"]) for m in matrix} == {("2B.8", "1"), ("2B.16", "0")}
    stage = step(wf, "provision", "fetch-assets.sh")["run"]
    assert "scripts/fetch-assets.sh --yes --profile ci" in stage and '"${loop}p3"' in stage
    boot = step(wf, "provision", "forensic-provision")["run"]
    assert "provision-manifest.json" in boot and '"ok"' in boot and 'Q_NIC="$NIC"' in boot
    suite = step(wf, "provision", "Full test suite")["run"]
    assert "nic_flag=(--nic)" in suite and "tests/run-qemu-tests.sh" in suite


def test_release_workflow_steps() -> None:
    wf = workflow("release.yml")
    assert wf["on"] == {"push": {"tags": ["v*"]}}
    assert wf["jobs"]["publish"]["permissions"] == {"contents": "write", "id-token": "write"}
    text = run_text(wf)
    for needle in (
        "scripts/check-pins.py --strict",
        "scripts/sign-manifest.sh --key-env MANIFEST_SIGNING_KEY",
        "scripts/build.sh --accel",
        "tests/run-qemu-tests.sh",
        'syft)" scan dir:/mnt/airlock-root',
        "spdx-json=",
        'cosign" sign-blob --yes SHA256SUMS',
        "--output-signature SHA256SUMS.sig",
        "validation/run.sh --build",
        "validation/report/build.py",
        "check-pins.py --licences-table",
        "gh release create",
        "--draft",
    ):
        assert needle in text, needle
    assert wf["env"]["PART_MIB"] == "1900"


def test_ci_tool_pins_are_complete_and_used() -> None:
    pins = yaml.safe_load(read("ansible/group_vars/all/pins.yml"))["pins"]
    used = {
        "cosign_linux_amd64": "release.yml",
        "syft_linux_amd64": "release.yml",
        "actionlint_linux_amd64": "lint.yml",
    }
    for pin, wf in used.items():
        entry = pins[pin]
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), pin
        assert entry["stage"] == "build" and entry["target"] is None
        assert pin in (WORKFLOWS / wf).read_text(encoding="utf-8")


def test_windows_workflow() -> None:
    wf = workflow("windows.yml")
    text = run_text(wf)
    assert "Invoke-ScriptAnalyzer" in text and "-Severity Warning, Error" in text
    assert "tests/windows/Test-FetchAssets.ps1 -Engine" in text
    engines = wf["jobs"]["fetch-assets"]["strategy"]["matrix"]["engine"]
    assert set(engines) == {"powershell", "pwsh"}


# ------------------------------------------------------------------ branch protection (0.8)


def expanded_job_names() -> set[str]:
    names: set[str] = set()
    for path in WORKFLOWS.glob("*.yml"):
        wf = workflow(path.name)
        for key, job in wf["jobs"].items():
            name = job.get("name", key)
            matrix = (job.get("strategy") or {}).get("matrix")
            if not matrix:
                names.add(name)
                continue
            combos: list[dict[str, Any]] = [{}]
            for axis, values in matrix.items():
                if axis in ("include", "exclude"):
                    continue
                combos = [{**c, axis: v} for c in combos for v in values]
            if combos == [{}]:
                combos = []
            combos += list(matrix.get("include") or [])
            for combo in combos:
                names.add(
                    re.sub(
                        r"\$\{\{\s*matrix\.(\w+)\s*\}\}",
                        lambda m, c=combo: str(c[m.group(1)]),
                        name,
                    )
                )
    return names


def protection_lists() -> dict[str, list[str]]:
    text = read("scripts/setup-branch-protection.sh")
    out = {}
    for var in ("REQUIRED_CHECKS", "BUILD_CHECKS"):
        block = text.split(f"{var}=(", 1)[1].split("\n)", 1)[0]
        out[var] = re.findall(r'"([^"]+)"', block)
    return out


def test_branch_protection_checks_match_workflow_job_names() -> None:
    lists = protection_lists()
    jobs = expanded_job_names()
    for var, names in lists.items():
        assert names, var
        for n in names:
            assert n in jobs, f"{var}: '{n}' is not a job name in .github/workflows"
    release_jobs = {j.get("name", k) for k, j in workflow("release.yml")["jobs"].items()}
    assert not set(lists["REQUIRED_CHECKS"]) & release_jobs


def test_branch_protection_dry_run_body() -> None:
    script = REPO / "scripts" / "setup-branch-protection.sh"
    res = subprocess.run(
        ["bash", str(script), "--dry-run", "--repo", "owner/airlock", "--reviews", "1"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    body = json.loads(res.stdout.split("\n", 1)[1].rsplit("would run", 1)[0])
    assert body["required_status_checks"]["strict"] is True
    assert body["required_status_checks"]["contexts"] == protection_lists()["REQUIRED_CHECKS"]
    assert body["required_pull_request_reviews"]["required_approving_review_count"] == 1
    assert body["allow_force_pushes"] is False and body["enforce_admins"] is True
    assert "repos/owner/airlock/branches/main/protection" in res.stdout
    assert "private-vulnerability-reporting" in res.stdout


def test_branch_protection_applies_with_gh(tmp_path: Path) -> None:
    calls = tmp_path / "calls.log"
    stdin_copy = tmp_path / "body.json"
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >>"{calls}"\n'
        f'if [[ " $* " == *" --input - "* ]]; then cat >"{stdin_copy}"; fi\n'
        'if [[ "$1" == "repo" ]]; then echo owner/airlock; fi\n',
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{gh.parent}:{os.environ['PATH']}"}
    script = REPO / "scripts" / "setup-branch-protection.sh"
    res = subprocess.run(
        ["bash", str(script), "--yes", "--with-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    log = calls.read_text(encoding="utf-8")
    want = "repos/owner/airlock/branches/main/protection --input -"
    assert f"api --method PUT -H Accept: application/vnd.github+json {want}" in log
    assert "repos/owner/airlock/private-vulnerability-reporting" in log
    body = json.loads(stdin_copy.read_text(encoding="utf-8"))
    lists = protection_lists()
    assert (
        body["required_status_checks"]["contexts"]
        == lists["REQUIRED_CHECKS"] + lists["BUILD_CHECKS"]
    )
    # Without --yes and without a terminal it refuses and changes nothing.
    calls.unlink()
    res = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert res.returncode == 1 and "--yes" in res.stderr
    assert "--method PUT" not in (calls.read_text(encoding="utf-8") if calls.exists() else "")
    res = subprocess.run(
        ["bash", str(script), "--reviews", "x"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res.returncode == 2


# ------------------------------------------------------------------ release split and sums (2B.2)


def release_fixture(tmp_path: Path, size: int) -> tuple[Path, dict[str, str]]:
    version = "9.9.9"
    work = tmp_path / "ws"
    out = work / "output" / f"airlock-{version}"
    out.mkdir(parents=True)
    zst = out / f"airlock-{version}.raw.zst"
    zst.write_bytes(os.urandom(size))
    raw_line = "0" * 64 + f"  airlock-{version}.raw"
    zsum = subprocess.run(
        ["sha256sum", zst.name], cwd=out, capture_output=True, text=True, check=True
    ).stdout
    (out / "SHA256SUMS").write_text(raw_line + "\n" + zsum, encoding="utf-8")
    for rel in (
        "assets/manifest.json",
        "assets/manifest.json.sig",
        "assets/manifest-signing.pub.pem",
        "scripts/fetch-assets.ps1",
        "scripts/fetch-assets.sh",
        "scripts/fetch_assets.py",
    ):
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(rel + "\n", encoding="utf-8")
    env = {
        **os.environ,
        "VERSION": version,
        "DIST": str(work / "dist"),
        "PART_MIB": "1",
        "TAG": "v9.9.9",
    }
    return work, env


@pytest.mark.parametrize("size", [int(2.5 * 1024 * 1024), 300_000])
def test_release_split_and_sha256sums(tmp_path: Path, size: int) -> None:
    wf = workflow("release.yml")
    split_sh = step(wf, "image", "Split the image")["run"]
    sums_sh = step(wf, "publish", "SHA256SUMS over every release file")["run"]
    work, env = release_fixture(tmp_path, size)
    subprocess.run(
        ["bash", "-euo", "pipefail", "-c", split_sh],
        cwd=work,
        env=env,
        check=True,
        capture_output=True,
    )
    dist = work / "dist"
    (dist / "build-info.json").write_text("{}\n", encoding="utf-8")
    subprocess.run(
        ["bash", "-euo", "pipefail", "-c", sums_sh],
        cwd=dist,
        env=env,
        check=True,
        capture_output=True,
    )
    names = sorted(p.name for p in dist.iterdir())
    assert "build-info.json" not in names and "image.sha256" not in names
    parts = sorted(dist.glob("airlock-9.9.9.raw.zst.part*"))
    whole = work / "output" / "airlock-9.9.9" / "airlock-9.9.9.raw.zst"
    sums = (dist / "SHA256SUMS").read_text(encoding="utf-8")
    assert "airlock-9.9.9.raw.zst\n" in sums and "airlock-9.9.9.raw\n" in sums
    assert "manifest.json.sig" in sums
    if size > 1024 * 1024:
        assert len(parts) == 3 and not (dist / whole.name).exists()
        assert all(p.stat().st_size <= 1024 * 1024 for p in parts)
        for p in parts:
            assert p.name in sums
        # Reassemble as docs/release-process.md says, then check.
        subprocess.run(
            ["bash", "-c", f"cat {whole.name}.part* > {whole.name}"], cwd=dist, check=True
        )
    else:
        assert parts == []
    assert (dist / whole.name).read_bytes() == whole.read_bytes()
    res = subprocess.run(
        ["sha256sum", "-c", "--ignore-missing", "SHA256SUMS"],
        cwd=dist,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"{whole.name}: OK" in res.stdout


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="needs pwsh")
def test_release_doc_powershell_reassembly(tmp_path: Path) -> None:
    doc = read("docs/release-process.md")
    snippet = doc.split("```powershell\n", 1)[1].split("```", 1)[0].replace("<version>", "9.9.9")
    data = os.urandom(3 * 1000 + 17)
    for i, start in enumerate(range(0, len(data), 1000)):
        (tmp_path / f"airlock-9.9.9.raw.zst.part{i:02d}").write_bytes(data[start : start + 1000])
    script = "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n" + snippet
    res = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert (tmp_path / "airlock-9.9.9.raw.zst").read_bytes() == data


# ------------------------------------------------------------------ live build (7.2)


@pytest.mark.skipif(shutil.which("lb") is None, reason="needs live-build (apt install live-build)")
def test_live_build_config_stage(tmp_path: Path) -> None:
    out = tmp_path / "live"
    res = subprocess.run(
        ["bash", str(REPO / "live" / "build.sh"), "--config-only", "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    cfg = out / "lb" / "config"
    common = (cfg / "common").read_text(encoding="utf-8")
    bootstrap = (cfg / "bootstrap").read_text(encoding="utf-8")
    binary = (cfg / "binary").read_text(encoding="utf-8")
    snap = yaml.safe_load(read("ansible/group_vars/all/main.yml"))["apt_snapshot"]
    assert 'LB_MODE="ubuntu"' in common and 'LB_INITRAMFS="casper"' in common
    assert 'LB_DISTRIBUTION="noble"' in bootstrap
    assert f'LB_MIRROR_CHROOT="https://snapshot.ubuntu.com/ubuntu/{snap}"' in bootstrap
    assert "systemd.gpt_auto=0" in binary and "noresume" in binary
    hook = cfg / "hooks" / "0500-airlock-site.hook.chroot"
    assert (
        hook.read_bytes()
        == (REPO / "live" / "hooks" / "0500-airlock-site.hook.chroot").read_bytes()
    )
    assert os.access(hook, os.X_OK)
    inc = cfg / "includes.chroot" / "opt" / "airlock"
    assert (inc / "repo" / "ansible" / "site.yml").is_file()
    assert (
        json.loads((inc / "live-build-vars.json").read_text(encoding="utf-8"))["airlock_target"]
        == "live"
    )
    assert "ansible-core" in (cfg / "package-lists" / "airlock.list.chroot").read_text(
        encoding="utf-8"
    )
    # An existing output folder is refused without --force.
    res = subprocess.run(
        ["bash", str(REPO / "live" / "build.sh"), "--config-only", "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 1 and "--force" in res.stderr


def test_live_build_refuses_bad_usage() -> None:
    res = subprocess.run(
        ["bash", str(REPO / "live" / "build.sh"), "--snapshot", "yesterday"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 2
    assert "YYYYMMDDTHHMMSSZ" in res.stderr
