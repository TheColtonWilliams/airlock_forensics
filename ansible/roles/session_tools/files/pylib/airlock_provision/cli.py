"""``forensic-provision`` and ``forensic-import``: offline setup and refresh from ASSETS.

forensic-provision [--if-changed] [--no-reboot] [--restart]
    Unattended, no prompts, no network. Refuses while a network interface is up, a default
    route exists, or any disk other than the boot drive is attached. Verifies ASSETS against
    the trusted manifest, turns off the features whose files are missing or damaged, runs the
    Ansible roles offline, runs the self-test, writes /var/lib/airlock/provision-manifest.json
    and reboots. ``--if-changed`` (the boot unit) does nothing unless this drive was never
    provisioned, a run was cut short, or the ASSETS set changed; a changed set is applied
    without a reboot. ``--restart`` ignores the checkpoints of an unfinished run.

forensic-import [--dry-run] [--force]
    Verifies and applies files restaged on ASSETS with ``fetch-assets --refresh`` (signatures,
    hash sets, models) and logs each file's SHA-256. Refuses while an evidence disk is attached.

Exit status: 0 done (or nothing to do), 1 refused or failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import contextlib
import sys

from airlock_common import assets, proc, sessionlog
from airlock_provision import runner

PROVISION = "forensic-provision"
IMPORT = "forensic-import"


def _fail(tool: str, msg: str, *, event: str, **fields: object) -> int:
    print(f"{tool}: {msg}", file=sys.stderr, flush=True)
    with contextlib.suppress(OSError):
        sessionlog.log_event(tool, event, message=msg, **fields)
    return 1


def _refusal(tool: str, problems: list[str]) -> int:
    what = "; ".join(problems)
    if any("attached" in p for p in problems):
        nxt = "Unplug every other drive (only the AIRLOCK drive may be connected) and rerun."
    elif any("network" in p or "route" in p for p in problems):
        nxt = "This system must stay offline: unplug network cables and reboot, then rerun."
    elif any("root" in p for p in problems):
        nxt = f"Run it as 'sudo {tool}'."
    else:
        nxt = "Fix the cause and rerun."
    return _fail(tool, f"refused: {what}. {nxt}", event="refused", problems=problems)


def _choose_run(mode: str, tool: str, *, restart: bool) -> runner.Run:
    run = runner.load_run()
    if (
        run is not None
        and not run.complete
        and not restart
        and run.mode == mode
        and run.data.get("profile_sha256") == assets.profile_sha256()
    ):
        print(f"{tool}: resuming run {run.run_id} after an interruption", flush=True)
        return run
    return runner.new_run(mode, tool)


def main_provision(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog=PROVISION, description="Set up this drive offline.")
    ap.add_argument(
        "--if-changed",
        action="store_true",
        help="only run when ASSETS changed or a run was cut short (boot unit)",
    )
    ap.add_argument("--no-reboot", action="store_true", help="do not reboot at the end")
    ap.add_argument("--restart", action="store_true", help="ignore an unfinished run")
    args = ap.parse_args(argv)  # fmt: skip

    mode = "provision"
    if args.if_changed:
        chosen, why = runner.change_reason()
        if chosen is None:
            print(f"{PROVISION}: {why}", flush=True)
            return 0
        mode = chosen
        print(f"{PROVISION}: {why}", flush=True)
    problems = runner.preflight()
    if problems:
        return _refusal(PROVISION, problems)
    try:
        with runner.lock():
            run = _choose_run(mode, PROVISION, restart=args.restart)
            results = runner.execute(run)
    except runner.Refused as exc:
        return _refusal(PROVISION, [str(exc)])
    except runner.StepFailed as exc:
        return _fail(PROVISION, str(exc), event="step_failed")
    status = (results.get("manifest") or {}).get("status")
    if status == "tests_failed":
        return _fail(
            PROVISION,
            "the self-test failed (see /var/lib/airlock/provision/report.txt). Do not use the "
            "drive for casework until 'sudo forensic-provision' passes.",
            event="tests_failed",
        )
    if mode == "provision" and not args.no_reboot:
        print(f"{PROVISION}: done; rebooting into the finished system", flush=True)
        try:
            proc.run(["systemctl", "reboot"], check=False, timeout=60)
        except proc.ToolError:
            print(f"{PROVISION}: could not reboot by itself; restart the PC now.", flush=True)
    else:
        print(f"{PROVISION}: done", flush=True)
    return 0


def _print_plan() -> int:
    report = assets.verify_staged(deep=True, for_apply=True)
    print(report.summary())
    applied = (assets.load_applied() or {}).get("files") or {}
    for aid, rec in sorted(report.verified.items()):
        old = (applied.get(aid) or {}).get("sha256")
        state = "new" if old is None else ("unchanged" if old == rec["sha256"] else "changed")
        print(f"  {aid}: {state} {rec['sha256']}")
    for aid in sorted(set(applied) - set(report.verified)):
        print(f"  {aid}: no longer staged (would be dropped)")
    return 0 if report.ok else 1


def main_import(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog=IMPORT, description="Apply restaged ASSETS files offline.")
    ap.add_argument("--dry-run", action="store_true", help="check and list changes only")
    ap.add_argument("--force", action="store_true", help="apply even when nothing changed")
    args = ap.parse_args(argv)
    problems = runner.preflight()
    if problems:
        return _refusal(IMPORT, problems)
    if args.dry_run:
        return _print_plan()
    try:
        with runner.lock():
            run = _choose_run("import", IMPORT, restart=False)
            runner.execute(run, force=args.force)
    except runner.Refused as exc:
        return _refusal(IMPORT, [str(exc)])
    except runner.StepFailed as exc:
        return _fail(IMPORT, str(exc), event="step_failed")
    report = assets.verify_staged(deep=False)
    if report.problems:
        print(f"{IMPORT}: applied what checked out; problems remain:")
        print(report.summary())
    print(f"{IMPORT}: done", flush=True)
    return 0
