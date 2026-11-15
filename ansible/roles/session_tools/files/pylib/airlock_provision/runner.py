"""Checkpointed provisioning: verify ASSETS, run the Ansible roles offline, record, test.

Modes:

``provision``  first boot (task 2B.4 to 2B.6): verify, ansible, record, goss, manifest, reboot.
``update``     a later boot found a changed ASSETS set (task 2B.7): the same steps, no reboot.
``import``     ``forensic-import`` (task 4A.7): verify, ansible, record.

Each finished step writes ``<state>/provision/steps/<step>.json``. After a power cut the next
run (or the boot unit) finds ``run.json`` unfinished and resumes at the first step without a
file, as long as ASSETS has not changed meanwhile. Missing or damaged files never stop the
run: they are listed by name and the features that need them are turned off (task 2B.12).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import shutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock_common import assets, jsonio, paths, proc, sessionlog, timeutil
from airlock_provision import system

STEPS: dict[str, tuple[str, ...]] = {
    "provision": ("verify", "ansible", "record", "goss", "manifest"),
    "update": ("verify", "ansible", "record", "goss", "manifest"),
    "import": ("verify", "ansible", "record"),
}
PROVISION_MANIFEST = "provision-manifest.json"
REPORT_NAME = "airlock-provision-report.txt"


class Refused(Exception):
    """Provisioning must not start (network up, a disk attached, not root, running already)."""


class StepFailed(Exception):
    """A step failed; the run can be resumed after the cause is fixed."""


def provision_dir() -> Path:
    return paths.state_dir() / "provision"


def vars_path() -> Path:
    return provision_dir() / "vars.json"


# --------------------------------------------------------------------------- run state


@dataclass
class Run:
    root: Path
    data: dict[str, Any]

    @property
    def mode(self) -> str:
        return str(self.data["mode"])

    @property
    def tool(self) -> str:
        return str(self.data["tool"])

    @property
    def run_id(self) -> str:
        return str(self.data["run_id"])

    def step_file(self, name: str) -> Path:
        return self.root / "steps" / f"{name}.json"

    def done(self, name: str) -> bool:
        return self.step_file(name).is_file()

    def result(self, name: str) -> dict[str, Any]:
        try:
            data = jsonio.load_json(self.step_file(name))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def mark(self, name: str, result: dict[str, Any]) -> None:
        jsonio.dump_json(self.step_file(name), {"done_at": timeutil.iso(), **result})

    def save(self) -> None:
        jsonio.dump_json(self.root / "run.json", self.data)

    @property
    def complete(self) -> bool:
        return bool(self.data.get("completed_at"))


def load_run() -> Run | None:
    try:
        data = jsonio.load_json(provision_dir() / "run.json")
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("mode") not in STEPS:
        return None
    return Run(provision_dir(), data)


def new_run(mode: str, tool: str) -> Run:
    root = provision_dir()
    shutil.rmtree(root / "steps", ignore_errors=True)
    data = {
        "mode": mode,
        "profile_sha256": assets.profile_sha256(),
        "run_id": f"P-{timeutil.compact()}-{secrets.token_hex(3)}",
        "started_at": timeutil.iso(),
        "tool": tool,
    }
    run = Run(root, data)
    run.save()
    return run


@contextlib.contextmanager
def lock() -> Iterator[None]:
    root = provision_dir()
    root.mkdir(parents=True, exist_ok=True)
    with open(root / ".lock", "w", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Refused("another provisioning or import run is in progress") from exc
        yield


def preflight() -> list[str]:
    """Every reason not to start. Empty means go."""
    problems = []
    root = system.root_problem()
    if root:
        problems.append(root)
    problems += system.network_problems()
    problems += system.disk_problems()
    return problems


def change_reason() -> tuple[str | None, str]:
    """For ``--if-changed``: (mode to run, why) or (None, why nothing is needed)."""
    run = load_run()
    if run is not None and not run.complete:
        if run.data.get("profile_sha256") == assets.profile_sha256():
            return run.mode, f"resuming the unfinished {run.mode} run {run.run_id}"
        return ("provision" if run.mode == "provision" else "update"), "ASSETS changed mid-run"
    applied = assets.load_applied()
    if not (paths.state_dir() / PROVISION_MANIFEST).is_file() or applied is None:
        return "provision", "this drive has not been provisioned yet"
    reason = "nothing changed on ASSETS since it was last applied"
    if applied.get("profile_sha256") != assets.profile_sha256():
        reason = "the ASSETS set changed (profile.json differs from the applied one)"
    else:
        try:
            info = assets.load_manifest_info()
        except assets.AssetError:
            return None, "no trusted manifest; nothing can be applied"
        if info.sha256 != applied.get("manifest_sha256"):
            reason = "a newer signed manifest is on ASSETS"
    return (None if reason.startswith("nothing") else "update"), reason


# --------------------------------------------------------------------------- steps


def build_vars(report: assets.AssetReport) -> dict[str, Any]:
    """Extra variables for ansible-playbook (docs/assets.md, 'Provisioning variables').

    Ansible templates every string it is given, so nothing here may carry free text from the
    unsigned profile.json. Features are rebuilt from the fixed schema (booleans and known AI
    tiers only), the profile name must be a plain name, and free text (``case_defaults``, the
    reasons in the problem list) is not passed at all: forensic-analyze reads case_defaults
    from profile.json as data, and the problems are in the step results and the report. As a
    last check any string with template markup refuses the run.
    """
    clean, off, _ = assets.sanitize_features(report.features)
    disabled = sorted(set(report.disabled_features) | set(off))
    if clean.get("autopsy") is True and not system.autopsy_prerequisites_present():
        # The image lacks Java 17 (built before base baked it in): turn Autopsy off rather
        # than let apt try the network (it would fail offline and stop provisioning).
        disabled = sorted({*disabled, "autopsy"})
    features = assets.effective_features(clean, disabled)
    data = {
        "airlock_phase": "provision",
        "airlock_profile": assets.profile_name(report.profile) or "",
        "airlock_features": features,
        # Same value under the name the tools_ai role reads (its profile_features.yml).
        "airlock_profile_features": features,
        "airlock_disabled_features": disabled,
        "airlock_assets": {k: dict(v) for k, v in sorted(report.verified.items())},
        "install_autopsy": features.get("autopsy") is True,
    }
    marked = assets.template_markup(data)
    if marked:
        raise StepFailed(
            f"refusing to pass template text to Ansible ({len(marked)} value(s), first "
            f"{marked[0][:80]!r}). Rerun the fetcher on the host computer to restage the drive."
        )
    return data


def step_verify(run: Run) -> dict[str, Any]:
    profile = assets.read_profile() or {}
    marked = assets.template_markup(profile)
    if marked:
        sessionlog.log_event(run.tool, "profile_refused", run_id=run.run_id,
                             reason="template markup", count=len(marked))  # fmt: skip
        raise StepFailed(
            f"ASSETS/profile.json holds template text in {len(marked)} value(s) (first "
            f"{marked[0][:80]!r}); it was refused and nothing was applied. profile.json is not "
            "signed: someone may have edited the drive. Rerun the fetcher on the host computer "
            "to restage it, then boot again."
        )
    report = assets.verify_staged(deep=True, for_apply=True)
    assets.log_report(report, run.tool)
    data = build_vars(report)
    if "autopsy" in data["airlock_disabled_features"] and "autopsy" not in report.disabled_features:
        reason = "this image has no Java 17 for Autopsy; reflash with a current image"
        report.problems.append(("autopsy", reason))
        report.disabled_features = list(data["airlock_disabled_features"])
        report.ok = False
    jsonio.dump_json(vars_path(), data)
    os.chmod(vars_path(), 0o600)
    print(report.summary())
    return {"profile_sha256": assets.profile_sha256(), "report": report.to_dict()}


def step_ansible(run: Run) -> dict[str, Any]:
    repo = paths.repo_dir()
    playbook = repo / "ansible" / "site.yml"
    if not playbook.is_file():
        raise StepFailed(f"{playbook} is missing; the image is incomplete. Reflash the drive.")
    log = provision_dir() / f"ansible-{run.run_id}.log"
    argv = [
        "ansible-playbook", "-c", "local", "-i", str(repo / "ansible" / "inventory.ini"),
        str(playbook), "-e", "airlock_phase=provision", "-e", f"@{vars_path()}",
    ]  # fmt: skip
    env = dict(os.environ)
    env.update(
        {
            "ANSIBLE_CONFIG": str(repo / "ansible" / "ansible.cfg"),
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_NOCOLOR": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    print(f"{run.tool}: running the Ansible roles offline (log: {log})", flush=True)
    sessionlog.log_event(run.tool, "ansible_start", argv=argv, log=str(log), run_id=run.run_id)
    try:
        res = proc.run(argv, check=False, env=env, cwd=repo / "ansible", stdout_path=log)
    except proc.ToolError as exc:
        raise StepFailed(f"ansible-playbook could not start ({exc}). Reflash the drive.") from exc
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(res.stderr)
    sessionlog.log_event(run.tool, "ansible_done", rc=res.returncode, run_id=run.run_id)
    if res.returncode != 0:
        raise StepFailed(
            f"ansible-playbook failed (exit {res.returncode}); the failed task is near the end "
            f"of {log}. Fix the cause and run 'sudo {run.tool}' again: it resumes."
        )
    return {"log": str(log), "rc": res.returncode}


class ManifestChanged(Exception):
    """The ASSETS manifest is no longer the one the verify step chose."""


def _adopt_manifest(report: dict[str, Any]) -> None:
    """Keep the newer signed ASSETS manifest the verify step chose as the trusted one.

    Only the exact bytes verify accepted are adopted: they are read once, their SHA-256 must
    equal the one recorded by verify, the signature is checked again over that same copy, and
    an older release than the trusted one is refused. The copy is what gets installed, so a
    manifest swapped on ASSETS after verify (say before a resumed run) is never adopted.
    """
    if report.get("manifest_source") != "assets":
        return
    src = paths.assets_dir() / "manifest.json"
    sig = paths.assets_dir() / "manifest.json.sig"
    dest = paths.baked_manifest()
    try:
        body, signature = src.read_bytes(), sig.read_bytes()
    except OSError as exc:
        raise ManifestChanged(f"the ASSETS manifest or its signature is gone ({exc})") from exc
    if hashlib.sha256(body).hexdigest() != report.get("manifest_sha256"):
        raise ManifestChanged("the ASSETS manifest changed since it was verified")
    try:
        candidate = json.loads(body)
    except ValueError as exc:
        raise ManifestChanged("the ASSETS manifest is not valid JSON") from exc
    release = str(candidate.get("release", "")) if isinstance(candidate, dict) else ""
    if release != str(report.get("manifest_release") or ""):
        raise ManifestChanged("the ASSETS manifest release differs from the verified one")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.adopt")
    tmp_sig = dest.with_name(f".{dest.name}.sig.adopt")
    try:
        for path, data in ((tmp, body), (tmp_sig, signature)):
            path.write_bytes(data)
            os.chmod(path, 0o644)
        if not assets.verify_signature(tmp, tmp_sig, paths.manifest_public_key()):
            raise ManifestChanged("the ASSETS manifest signature does not verify")
        current = ""
        with contextlib.suppress(OSError, ValueError, AttributeError):
            current = str(jsonio.load_json(dest).get("release", ""))
        if assets.is_older_release(release, current):
            raise ManifestChanged(f"ASSETS manifest {release} is older than the trusted {current}")
        if dest.is_file():
            shutil.copyfile(dest, dest.with_name(dest.name + ".previous"))
        tmp.replace(dest)
        tmp_sig.replace(dest.with_name(dest.name + ".sig"))
    finally:
        for path in (tmp, tmp_sig):
            path.unlink(missing_ok=True)


def step_record(run: Run) -> dict[str, Any]:
    verify = run.result("verify")
    report = verify.get("report") or {}
    try:
        _adopt_manifest(report)
    except ManifestChanged as exc:
        # Start again from verify next time, so the manifest now on ASSETS is checked afresh.
        for name in STEPS[run.mode]:
            run.step_file(name).unlink(missing_ok=True)
        sessionlog.log_event(run.tool, "manifest_not_adopted", reason=str(exc), run_id=run.run_id)
        raise StepFailed(
            f"{exc}; nothing was recorded and the trusted manifest is unchanged. Run "
            f"'sudo {run.tool}' again: it checks ASSETS again from the start."
        ) from exc
    previous = (assets.load_applied() or {}).get("files") or {}
    current: dict[str, Any] = report.get("verified") or {}
    changes = []
    for aid in sorted(set(current) | set(previous)):
        new, old = current.get(aid), previous.get(aid)
        if new is None:
            status = "removed"
        elif old is None:
            status = "new"
        else:
            status = "unchanged" if old.get("sha256") == new.get("sha256") else "changed"
        rec = {
            "id": aid,
            "previous_sha256": (old or {}).get("sha256"),
            "sha256": (new or {}).get("sha256"),
            "status": status,
            "target": (new or old or {}).get("target"),
            "verify": (new or old or {}).get("verify"),
            "version": (new or old or {}).get("version"),
        }
        changes.append(rec)
        event = "asset_removed" if status == "removed" else "asset_applied"
        sessionlog.log_event(run.tool, event, run_id=run.run_id, **rec)
    features = assets.effective_features(
        report.get("features") or {}, report.get("disabled_features") or []
    )
    applied = {
        "schema": 1,
        "applied_at": timeutil.iso(),
        "run_id": run.run_id,
        "mode": run.mode,
        "profile": report.get("profile", ""),
        "profile_sha256": verify.get("profile_sha256"),
        "manifest_source": report.get("manifest_source"),
        "manifest_release": report.get("manifest_release"),
        "manifest_sha256": report.get("manifest_sha256"),
        "features": features,
        "disabled_features": report.get("disabled_features") or [],
        "problems": report.get("problems") or [],
        "files": current,
    }
    jsonio.dump_json(assets.applied_path(), applied)
    counts = {s: sum(1 for c in changes if c["status"] == s) for s in
              ("new", "changed", "unchanged", "removed")}  # fmt: skip
    print(
        f"{run.tool}: applied {len(current)} file(s): {counts['new']} new, {counts['changed']} "
        f"changed, {counts['unchanged']} unchanged, {counts['removed']} removed",
        flush=True,
    )
    return {"changes": changes, "counts": counts}


def _goss_binary() -> str | None:
    found = proc.which("goss")
    if found:
        return found
    candidate = paths.opt_dir() / "bin" / "goss"
    return str(candidate) if candidate.is_file() else None


def step_goss(run: Run) -> dict[str, Any]:
    goss = _goss_binary()
    gdir = paths.repo_dir() / "tests" / "goss"
    files = sorted(gdir.glob("*.yaml")) if gdir.is_dir() else []
    if goss is None or not files:
        reason = "goss is not installed" if goss is None else f"no goss files in {gdir}"
        print(f"{run.tool}: self-test not run: {reason}", flush=True)
        sessionlog.log_event(run.tool, "goss_not_run", reason=reason, run_id=run.run_id)
        return {"ran": False, "reason": reason, "files": {}, "failed": 0}
    inline = json.dumps(
        {"disks": {}, "firmware": system.firmware(), "nic": system.has_nic(), "provision": True},
        sort_keys=True,
    )
    results: dict[str, Any] = {}
    failed = 0
    for f in files:
        argv = [goss, "-g", str(f), "--vars-inline", inline, "validate", "--format", "json",
                "--no-color"]  # fmt: skip
        try:
            res = proc.run(argv, check=False, timeout=1800)
        except proc.ToolError as exc:
            results[f.name] = {"ok": False, "error": str(exc)}
            failed += 1
            continue
        summary: dict[str, Any] = {}
        with contextlib.suppress(ValueError):
            summary = json.loads(res.stdout).get("summary") or {}
        ok = res.returncode == 0
        failed += 0 if ok else 1
        results[f.name] = {
            "failed_count": summary.get("failed-count"),
            "ok": ok,
            "rc": res.returncode,
            "test_count": summary.get("test-count"),
        }
    sessionlog.log_event(run.tool, "goss_done", failed_files=failed, files=results,
                         run_id=run.run_id)  # fmt: skip
    print(f"{run.tool}: self-test: {len(files) - failed} of {len(files)} goss file(s) passed",
          flush=True)  # fmt: skip
    return {"ran": True, "files": results, "failed": failed}


def _asset_row(aid: str, rec: dict[str, Any]) -> dict[str, Any]:
    keys = ("sha256", "target", "verify", "version")
    return {"id": aid, **{k: rec.get(k) for k in keys}}


def provision_manifest(run: Run) -> dict[str, Any]:
    report = run.result("verify").get("report") or {}
    goss = run.result("goss")
    verified = report.get("verified") or {}
    if not goss.get("ran"):
        status = "tests_not_run"
    elif goss.get("failed"):
        status = "tests_failed"
    else:
        status = "ok"
    return {
        "schema": 1,
        "run_id": run.run_id,
        "mode": run.mode,
        "provisioned_at": timeutil.iso(),
        "status": status,
        "build": system.build_info(),
        "kernel": os.uname().release,
        "hardware": system.hardware_summary(),
        "tool_versions": system.tool_versions(),
        "profile": report.get("profile", ""),
        "features": assets.effective_features(
            report.get("features") or {}, report.get("disabled_features") or []
        ),
        "disabled_features": report.get("disabled_features") or [],
        "problems": report.get("problems") or [],
        "manifest": {
            "release": report.get("manifest_release"),
            "sha256": report.get("manifest_sha256"),
            "source": report.get("manifest_source"),
        },
        "assets": [_asset_row(k, v) for k, v in sorted(verified.items())],
        "tests": goss,
    }


def text_report(doc: dict[str, Any]) -> str:
    lines = [
        "AIRLOCK provisioning report",
        f"Date (UTC): {doc['provisioned_at']}",
        f"Run: {doc['run_id']} ({doc['mode']})",
        f"Profile: {doc['profile'] or '(none staged)'}",
        f"Result: {doc['status']}",
        f"Files checked and in use: {len(doc['assets'])}",
    ]
    if doc["problems"]:
        lines.append("Problems found on ASSETS:")
        lines += [f"  - {aid}: {why}" for aid, why in doc["problems"]]
        lines.append("Turned off because of them: " + (", ".join(doc["disabled_features"]) or
                                                        "nothing"))  # fmt: skip
        lines.append(
            "What to do: rerun the fetcher (fetch-assets.ps1 or fetch-assets.sh) on the host "
            "computer with this drive plugged in, then boot the drive again. It applies the "
            "files by itself, offline."
        )
    if doc["status"] == "tests_failed":
        lines.append(
            "The self-test failed. Do not use this drive for casework until it passes. Run "
            "'sudo forensic-provision' again, or reflash the drive."
        )
    elif doc["status"] == "tests_not_run":
        lines.append("The self-test did not run: " + str(doc["tests"].get("reason", "")))
    return "\n".join(lines) + "\n"


def step_manifest(run: Run) -> dict[str, Any]:
    doc = provision_manifest(run)
    jsonio.dump_json(paths.state_dir() / PROVISION_MANIFEST, doc)
    text = text_report(doc)
    (provision_dir() / "report.txt").write_text(text, encoding="utf-8")
    out = paths.output_dir()
    if out.is_dir():
        with contextlib.suppress(OSError):
            (out / REPORT_NAME).write_text(text, encoding="utf-8")
    sessionlog.log_event(run.tool, "provision_manifest", manifest=doc, run_id=run.run_id)
    print(text, end="", flush=True)
    return {"status": doc["status"]}


STEP_FUNCS: dict[str, Callable[[Run], dict[str, Any]]] = {
    "verify": step_verify,
    "ansible": step_ansible,
    "record": step_record,
    "goss": step_goss,
    "manifest": step_manifest,
}


def unchanged_since_applied(run: Run) -> bool:
    """For import: the verified set and features equal what is already applied."""
    applied = assets.load_applied()
    if applied is None:
        return False
    report = run.result("verify").get("report") or {}
    now = {k: v.get("sha256") for k, v in (report.get("verified") or {}).items()}
    before = {k: v.get("sha256") for k, v in (applied.get("files") or {}).items()}
    feats = assets.effective_features(
        report.get("features") or {}, report.get("disabled_features") or []
    )
    return now == before and feats == applied.get("features")


def execute(run: Run, *, force: bool = False) -> dict[str, Any]:
    """Run every unfinished step of ``run`` in order. Returns the last step's results."""
    sessionlog.log_event(run.tool, f"{run.mode}_start", run_id=run.run_id,
                         resumed=any(run.done(s) for s in STEPS[run.mode]))  # fmt: skip
    results: dict[str, Any] = {}
    for name in STEPS[run.mode]:
        if run.done(name):
            print(f"{run.tool}: step {name}: already done (resumed run)", flush=True)
            results[name] = run.result(name)
            continue
        print(f"{run.tool}: step {name}", flush=True)
        result = STEP_FUNCS[name](run)
        run.mark(name, result)
        sessionlog.log_event(run.tool, "step_done", step=name, run_id=run.run_id)
        results[name] = result
        if name == "verify" and run.mode == "import" and not force and unchanged_since_applied(run):
            print(f"{run.tool}: nothing new on ASSETS; everything is already applied", flush=True)
            results["unchanged"] = True
            break
    run.data["completed_at"] = timeutil.iso()
    run.save()
    sessionlog.log_event(run.tool, f"{run.mode}_complete", run_id=run.run_id)
    return results
