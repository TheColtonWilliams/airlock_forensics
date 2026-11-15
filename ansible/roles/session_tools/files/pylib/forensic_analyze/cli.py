"""``forensic-analyze``: the guided analysis wizard (tasks 4C.1, 4C.18, 4C.22).

Every prompt has a flag, so the same code path serves the menus and the test suite::

    forensic-analyze --authority-ack --target /dev/sdb --preset standard \\
        --output /srv/airlock/output --examiner "J. Smith" --case-id C-1 --yes

    forensic-analyze --config /srv/airlock/output/cases/C-1/R-.../run.json --authority-ack --yes
    forensic-analyze --resume /srv/airlock/output/cases/C-1/R-...
    forensic-analyze --verify /srv/airlock/output/cases/C-1/R-...

Exit codes: 0 complete; 1 stopped (the message says why and what to do); 2 a flag or answer is
missing; 3 complete with integrity warnings (hash changed, write requests seen, copy unverified).
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from airlock_common import jsonio, sessionlog, timeutil, ui
from forensic_analyze import case as case_mod
from forensic_analyze import cleanup, fsdetect, mode, output, presets, runner, signing
from forensic_analyze import sandbox as sb
from forensic_analyze import target as target_mod
from forensic_analyze.context import TOOL_NAME
from forensic_analyze.modules import all_modules

TITLE = "forensic-analyze"


class UsageError(RuntimeError):
    """A value is missing or wrong. Exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forensic-analyze",
        description="Guided analysis of one drive or image. Every prompt has a flag.",
    )
    g = p.add_argument_group("what to analyse")
    g.add_argument("--target", help="device (/dev/sdb) or image file (E01, raw) to analyse")
    g.add_argument("--images-dir", help="folder with image files to offer in the target list")
    g.add_argument("--mode", choices=mode.MODES, help="direct (default) or image (copy first)")
    g.add_argument("--imager", choices=mode.IMAGERS, help="copy-first tool: ewf or ddrescue")
    g.add_argument("--output", help="output folder (default: the OUTPUT partition)")
    g.add_argument("--preset", choices=presets.PRESET_NAMES, help="quick, standard, full, custom")
    g.add_argument("--modules", help="comma-separated module names for --preset custom")
    g.add_argument("--bitlocker-key-file", help="file holding the BitLocker recovery key")
    g.add_argument(
        "--purge-exports",
        action="store_true",
        default=None,
        help="after the run, delete exported file copies and keep findings and the report",
    )
    c = p.add_argument_group("case record")
    c.add_argument("--case-id")
    c.add_argument("--exhibit-id")
    c.add_argument("--examiner")
    c.add_argument("--agency")
    c.add_argument("--authority-ref", help="warrant, order, or consent reference")
    c.add_argument("--notes")
    c.add_argument(
        "--authority-ack",
        action="store_true",
        help="confirm you have the owner's permission or legal authority to examine the drive",
    )
    c.add_argument(
        "--reference-time", help="time from a trusted clock, UTC, e.g. 2026-11-15T14:03:00Z"
    )
    c.add_argument("--reference-source", help="where the reference time came from")
    b = p.add_argument_group("hardware write blocker")
    b.add_argument("--write-blocker", choices=target_mod.BLOCKER_ANSWERS)
    b.add_argument("--blocker-make")
    b.add_argument("--blocker-model")
    b.add_argument("--blocker-firmware")
    b.add_argument("--blocker-report-url", help="link to the blocker's NIST CFTT or DHS report")
    r = p.add_argument_group("run control")
    r.add_argument("--yes", action="store_true", help="answer yes to every confirmation")
    r.add_argument("--config", help="replay the configuration from an earlier run.json")
    r.add_argument("--resume", metavar="RUN_DIR", help="continue an interrupted run")
    r.add_argument("--dry-run", action="store_true", help="show the plan, analyse nothing")
    r.add_argument(
        "--sandbox", choices=("bwrap", "systemd-run", "unshare", "none"), help=argparse.SUPPRESS
    )
    t = p.add_argument_group("other actions")
    t.add_argument("--list-targets", action="store_true", help="list drives and images, then exit")
    t.add_argument("--list-modules", action="store_true", help="list modules on this build")
    t.add_argument("--verify", metavar="RUN_DIR", help="check a run's hashes and signature")
    t.add_argument(
        "--purge-run", metavar="RUN_DIR", help="purge exported copies from a finished run"
    )
    return p


def say(text: str) -> None:
    print(text, flush=True)


# -- prompt helpers ----------------------------------------------------------------------------


def _interactive(args: argparse.Namespace) -> bool:
    return ui.interactive() and not args.yes


def _text(
    args: argparse.Namespace, value: str | None, title: str, prompt: str, *, default: str, flag: str
) -> str:
    if value is not None:
        return value
    if _interactive(args):
        return ui.ask_text(title, prompt, default, flag=flag)
    return default


# -- steps -------------------------------------------------------------------------------------


def authority(args: argparse.Namespace) -> case_mod.AuthorityAck:
    if args.authority_ack:
        ack = case_mod.AuthorityAck(True, timeutil.iso(), "flag")
    elif _interactive(args):
        ui.info("Authority to examine", case_mod.AUTHORITY_TEXT)
        if not ui.ask_yes_no(
            "Authority to examine",
            "Do you have the owner's permission or legal authority to examine this drive?",
            flag="--authority-ack",
        ):
            sessionlog.log_event(TOOL_NAME, "authority_declined")
            raise runner.RunAborted(
                "Stopped: no permission or authority confirmed. Nothing was read."
            )
        ack = case_mod.AuthorityAck(True, timeutil.iso(), "prompt")
    else:
        raise UsageError(
            "Authority not confirmed. Pass --authority-ack once you have the owner's permission "
            "or legal authority."
        )
    sessionlog.log_event(TOOL_NAME, "authority_ack", via=ack.via, text_sha256=ack.text_sha256)
    return ack


def case_fields(args: argparse.Namespace, base: dict[str, Any]) -> dict[str, str]:
    defaults = case_mod.case_defaults()
    examiner = _text(
        args,
        args.examiner,
        "Examiner",
        "Examiner name (recorded in every output):",
        default=base.get("examiner") or defaults.get("examiner", ""),
        flag="--examiner",
    )
    case_id = _text(
        args,
        args.case_id,
        "Case",
        "Case ID:",
        default=base.get("case_id") or case_mod.default_case_id(defaults),
        flag="--case-id",
    )
    exhibit = _text(
        args,
        args.exhibit_id,
        "Exhibit",
        "Exhibit ID:",
        default=base.get("exhibit_id", ""),
        flag="--exhibit-id",
    )
    authority_ref = _text(
        args,
        args.authority_ref,
        "Authority",
        "Authority reference (warrant, order, or consent number):",
        default=base.get("authority_ref", ""),
        flag="--authority-ref",
    )
    notes = _text(
        args,
        args.notes,
        "Notes",
        "Notes (optional):",
        default=base.get("notes", ""),
        flag="--notes",
    )
    agency = (
        args.agency if args.agency is not None else base.get("agency") or defaults.get("agency", "")
    )
    return {
        "examiner": examiner.strip(),
        "case_id": case_mod.safe_id(case_id),
        "exhibit_id": case_mod.safe_id(exhibit, what="exhibit ID") if exhibit.strip() else "",
        "authority_ref": authority_ref.strip(),
        "notes": notes.strip(),
        "agency": agency.strip(),
    }


def clock(args: argparse.Namespace) -> case_mod.ClockRecord:
    ref = args.reference_time
    src = args.reference_source or ""
    if ref is None and _interactive(args):
        ref = ui.ask_text(
            "Clock check",
            "Enter the time from a trusted clock in UTC (for example 2026-11-15T14:03:00Z), "
            "or leave empty to skip. The system time is never changed.",
            "",
            flag="--reference-time",
        )
        if ref:
            src = ui.ask_text(
                "Clock check", "Where did that time come from?", "phone", flag="--reference-source"
            )
    now = timeutil.utcnow()
    try:
        return case_mod.clock_record(ref or "", src, system_now=now)
    except case_mod.CaseError as exc:
        raise UsageError(str(exc)) from exc


def blocker(args: argparse.Namespace, base: dict[str, Any]) -> target_mod.BlockerRecord:
    answer = args.write_blocker or (base.get("write_blocker") if args.config else None)
    via = "flag"
    if answer is None and _interactive(args):
        ui.info("Hardware write blocker", target_mod.ADVISORY_TEXT)
        answer = ui.ask_choice(
            "Hardware write blocker",
            "Is the evidence drive connected through a hardware write blocker?",
            [("yes", "Yes"), ("no", "No"), ("unknown", "I do not know")],
            default="unknown",
            flag="--write-blocker",
        )
        via = "prompt"
    elif answer is None:
        say(target_mod.ADVISORY_TEXT.replace("\n\n", " "))
    details = {
        "make": args.blocker_make
        if args.blocker_make is not None
        else base.get("blocker_make", ""),
        "model": args.blocker_model
        if args.blocker_model is not None
        else base.get("blocker_model", ""),
        "firmware": args.blocker_firmware
        if args.blocker_firmware is not None
        else base.get("blocker_firmware", ""),
        "report_url": args.blocker_report_url
        if args.blocker_report_url is not None
        else base.get("blocker_report_url", ""),
    }
    if answer == "yes" and via == "prompt":
        details["make"] = ui.ask_text("Write blocker", "Make:", details["make"])
        details["model"] = ui.ask_text("Write blocker", "Model:", details["model"])
        details["firmware"] = ui.ask_text("Write blocker", "Firmware version:", details["firmware"])
        details["report_url"] = ui.ask_text(
            "Write blocker",
            "Link to its CFTT or DHS test report (optional):",
            details["report_url"],
        )
    try:
        return target_mod.blocker_record(answer, via=via, **details)
    except target_mod.TargetError as exc:
        raise UsageError(str(exc)) from exc


def pick_target(args: argparse.Namespace, base: dict[str, Any]) -> target_mod.Candidate:
    path = args.target or base.get("target")
    images_dir = (
        Path(args.images_dir or base.get("images_dir") or "")
        if (args.images_dir or base.get("images_dir"))
        else None
    )
    if not path:
        if not _interactive(args):
            raise UsageError("No target given. Pass --target /dev/sdX or --target IMAGE.")
        cands = target_mod.candidates(images_dir)
        if not cands:
            raise runner.RunAborted(
                "No evidence drive or image found. Plug in the drive (through a write blocker "
                "if you have one) or pass --images-dir, then try again."
            )
        path = ui.ask_choice(
            "Evidence",
            "Which drive or image should be analysed? (The AIRLOCK drive is never listed.)",
            [(c.path, c.label()) for c in cands],
            flag="--target",
        )
    try:
        cand = target_mod.resolve(path)
        target_mod.require_readonly(cand)
    except target_mod.TargetError as exc:
        raise runner.RunAborted(str(exc)) from exc
    return cand


def confirm_target(args: argparse.Namespace, cand: target_mod.Candidate) -> None:
    if args.yes:
        return
    if not ui.interactive():
        raise UsageError(f"Confirm the target: pass --yes with --target {cand.path} exactly.")
    if not ui.confirm_typed(
        "Confirm the evidence", f"Analyse {cand.path}: {cand.label()}", cand.name
    ):
        raise runner.RunAborted("Stopped: the name typed did not match. Nothing was read.")


def pick_mode(args: argparse.Namespace, base: dict[str, Any]) -> tuple[str, str]:
    m = args.mode or base.get("mode")
    if m is None:
        m = (
            ui.ask_choice(
                "Mode",
                "How should the drive be read?",
                [
                    ("direct", "Read directly (default, no copy kept)"),
                    ("image", "Copy first, then analyse the copy (needs a large output drive)"),
                ],
                default="direct",
                flag="--mode",
            )
            if _interactive(args)
            else "direct"
        )
    imager = args.imager or base.get("imager") or "ewf"
    if m == "image" and args.imager is None and not base.get("imager") and _interactive(args):
        imager = ui.ask_choice(
            "Copy tool",
            "Which copy tool?",
            [
                ("ewf", "E01 with ewfacquire"),
                ("ddrescue", "ddrescue with a map file, for weak drives"),
            ],
            default="ewf",
            flag="--imager",
        )
    return m, imager


def pick_output(args: argparse.Namespace, base: dict[str, Any]) -> Path:
    default = str(output.default_root())
    value = args.output or base.get("output")
    if not value:
        value = _text(
            args,
            None,
            "Output",
            "Where should results go? (default: the drive's OUTPUT partition; use "
            "evidence-unlock-output first for another drive)",
            default=default,
            flag="--output",
        )
    return Path(value).resolve()


def pick_preset(
    args: argparse.Namespace, base: dict[str, Any], available: list[str]
) -> tuple[str, list[str]]:
    preset = args.preset or base.get("preset")
    mods = (
        [m for m in (args.modules or "").split(",") if m.strip()]
        if args.modules
        else list(base.get("modules") or [])
    )
    if preset is None:
        preset = (
            ui.ask_choice(
                "What to look at",
                "Pick a preset. Every module runs unattended and the run ends with one report.",
                [(n, presets.PRESET_HELP[n]) for n in presets.PRESET_NAMES],
                default="quick",
                flag="--preset",
            )
            if _interactive(args)
            else "quick"
        )
    if preset == "custom" and not mods:
        if not _interactive(args):
            raise UsageError("--preset custom needs --modules a,b,c")
        titles = {m.name: m.title for m in all_modules()}
        mods = ui.ask_checklist(
            "Custom",
            "Pick the categories to run:",
            [(n, titles.get(n, n), n in presets.QUICK) for n in available],
            flag="--modules",
        )
    return preset, [m.strip() for m in mods]


# -- other actions -----------------------------------------------------------------------------


def do_verify(run_dir: Path) -> int:
    problems = signing.verify(run_dir)
    if problems:
        for p in problems:
            say(f"problem: {p}")
        say(f"Run folder {run_dir} does NOT verify. Do not rely on it until this is explained.")
        return 1
    say(f"Run folder {run_dir} verifies: every hash matches and the signature is valid.")
    return 0


def do_purge(run_dir: Path) -> int:
    doc_path = run_dir / "run.json"
    if not doc_path.exists():
        say(f"{run_dir} has no run.json. Check the folder name.")
        return 1
    res = cleanup.purge_exports(run_dir)
    doc = jsonio.load_json(doc_path)
    doc["purge"] = res.to_dict()
    jsonio.dump_json(doc_path, doc)
    out_root = run_dir.parents[2]
    sign = signing.hash_and_sign(run_dir, out_root)
    sessionlog.log_event(TOOL_NAME, "purged_exports", run_dir=str(run_dir), **res.to_dict())
    say(f"Removed {res.removed_files} exported files ({res.removed_bytes} bytes).")
    say("Outputs re-hashed and re-signed.")
    return 0 if not sign.error else 1


def do_list_targets(args: argparse.Namespace) -> int:
    images_dir = Path(args.images_dir) if args.images_dir else None
    for c in target_mod.candidates(images_dir):
        say(f"{c.path}\t{c.label()}")
    return 0


def do_list_modules() -> int:
    for m in all_modules():
        fs = ",".join(sorted(m.fs_types)) if m.fs_types else "any"
        say(f"{m.order:4d}  {m.name:18s} {m.title} (filesystems: {fs})")
    return 0


def plan_only(cfg: runner.RunConfig, cand: target_mod.Candidate) -> dict[str, Any]:
    """The run plan without a run folder: volumes, modules, and skip reasons."""
    with tempfile.TemporaryDirectory(prefix="airlock-plan.") as tmp:
        work = Path(tmp)
        sandbox = sb.Sandbox(method=cfg.sandbox or None)
        try:
            handle = sb.open_evidence(
                cand.path, raw=fsdetect.image_type(cand.path) == "raw", sandbox=sandbox
            )
        except sb.SandboxError as exc:
            raise runner.RunAborted(f"{exc}. Nothing was read.") from exc
        sandbox.devices = [handle.path] if handle.method == "ro_loop" else []
        if handle.method == "path":
            sandbox.ro_paths.append(str(Path(handle.path).parent))
        try:

            def tool(argv: list[str], **kw: Any) -> Any:
                cp, _rec = sandbox.run(argv, workdir=work, stdout_path=kw.get("stdout_path"))
                return cp

            volumes = fsdetect.detect(
                handle.path, tool=tool, workdir=work, size_bytes=cand.size_bytes
            )
        finally:
            handle.close()
    from forensic_analyze.api import Target  # noqa: PLC0415

    tgt = Target(
        Path(cand.path),
        "device" if cand.kind == "device" else "image",
        cand.name,
        volumes=tuple(volumes),
    )
    registry = all_modules()
    planned, missing = presets.modules_for(cfg.preset, [m.name for m in registry], cfg.modules)
    rows = []
    for m in registry:
        if m.name not in planned:
            continue
        ok, why = m.applicable(tgt)
        rows.append({"name": m.name, "runs": ok, "reason": why})
    est = presets.estimate(planned, cand.size_bytes, image_mode=cfg.mode == "image")
    return {
        "target": cand.to_dict(),
        "mode": cfg.mode,
        "preset": cfg.preset,
        "volumes": [v.__dict__ for v in volumes],
        "modules": rows,
        "not_available": missing,
        "estimate": est.describe(),
        "sandbox": sandbox.describe(),
    }


# -- main --------------------------------------------------------------------------------------


def _notify(text: str) -> None:
    say(text)


def _confirm_factory(args: argparse.Namespace) -> runner.Confirm:
    def confirm(title: str, text: str) -> bool:
        if args.yes:
            return True
        if ui.interactive():
            return ui.ask_yes_no(title, f"{text}\n\nGo ahead anyway?", flag="--yes")
        return False

    return confirm


def configure(
    args: argparse.Namespace,
) -> tuple[runner.RunConfig, runner.RunInputs, target_mod.Candidate]:
    base: dict[str, Any] = {}
    if args.config:
        try:
            loaded = jsonio.load_json(args.config)
        except (OSError, ValueError) as exc:
            raise UsageError(f"Cannot read --config {args.config}: {exc}") from exc
        base = loaded.get("config", loaded) if isinstance(loaded, dict) else {}
    ack = authority(args)
    fields = case_fields(args, base)
    clk = clock(args)
    blk = blocker(args, base)
    cand = pick_target(args, base)
    m, imager = pick_mode(args, base)
    out_root = pick_output(args, base)
    available = [x.name for x in all_modules()]
    preset, mods = pick_preset(args, base, available)
    try:
        planned, _missing = presets.modules_for(preset, available, mods)
    except presets.PresetError as exc:
        raise UsageError(str(exc)) from exc
    key = args.bitlocker_key_file or base.get("bitlocker_key_file") or ""
    purge = (
        args.purge_exports if args.purge_exports is not None else bool(base.get("purge_exports"))
    )
    cfg = runner.RunConfig(
        target=cand.path,
        mode=m,
        imager=imager,
        output=str(out_root),
        preset=preset,
        modules=mods if preset == "custom" else [],
        bitlocker_key_file=str(Path(key).resolve()) if key else "",
        purge_exports=purge,
        images_dir=args.images_dir or base.get("images_dir", ""),
        sandbox=args.sandbox or base.get("sandbox", ""),
        write_blocker=blk.in_use,
        blocker_make=blk.make,
        blocker_model=blk.model,
        blocker_firmware=blk.firmware,
        blocker_report_url=blk.report_url,
        **fields,
    )
    try:
        chk = output.prepare(
            out_root,
            target_path=cand.path,
            target_kind=cand.kind,
            target_bytes=cand.size_bytes,
            modules=planned,
            image_mode=m == "image",
        )
    except output.OutputError as exc:
        raise runner.RunAborted(str(exc)) from exc
    deviations: list[str] = []
    if not chk.enough_space:
        text = (
            output.space_message(chk) + " The run may stop when the drive fills; it can be resumed."
        )
        if not _confirm_factory(args)("Output space", text):
            raise runner.RunAborted(text + " Use a larger output drive or pass --yes.")
        deviations.append(f"started with less output space than estimated: {text}")
    inputs = runner.RunInputs(
        authority=ack,
        clock=clk,
        blocker=blk,
        argv=list(sys.argv),
        accept_smart_warning=bool(args.yes),
        deviations=deviations,
    )
    return cfg, inputs, cand


def _other_action(args: argparse.Namespace) -> int | None:
    """--verify, --purge-run, --list-targets, --list-modules; None when none was asked for."""
    if args.verify:
        return do_verify(Path(args.verify))
    if args.purge_run:
        return do_purge(Path(args.purge_run))
    if args.list_targets:
        return do_list_targets(args)
    if args.list_modules:
        return do_list_modules()
    return None


def _resume(args: argparse.Namespace) -> int:
    inputs = runner.RunInputs(
        authority=case_mod.AuthorityAck(True, timeutil.iso(), "resume"),
        clock=case_mod.clock_record(),
        blocker=target_mod.BlockerRecord(),
        argv=list(sys.argv),
        accept_smart_warning=bool(args.yes),
    )
    run = runner.Run.resume(
        Path(args.resume).resolve(), inputs, notify=_notify, confirm=_confirm_factory(args)
    )
    if args.sandbox:
        run.cfg.sandbox = args.sandbox
    outcome = run.execute()
    say(outcome.message)
    return outcome.exit_code


def _new_run(args: argparse.Namespace) -> int:
    cfg, inputs, cand = configure(args)
    if args.dry_run:
        say(jsonio.dumps(plan_only(cfg, cand)))
        return 0
    confirm_target(args, cand)
    if os.geteuid() != 0 and cand.kind == "device":
        raise runner.RunAborted("Reading a drive needs root. Run: sudo forensic-analyze ...")
    run = runner.Run.start(cfg, inputs, notify=_notify, confirm=_confirm_factory(args))
    say(f"Run {run.run_id}: results go to {run.run_dir}")
    outcome = run.execute()
    say(outcome.message)
    return outcome.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int
    try:
        other = _other_action(args)
        if other is not None:
            code = other
        elif args.resume:
            code = _resume(args)
        else:
            code = _new_run(args)
    except (UsageError, ui.NonInteractiveError, presets.PresetError, case_mod.CaseError) as exc:
        say(f"forensic-analyze: {exc}")
        code = runner.EXIT_USAGE
    except runner.RunAborted as exc:
        say(f"forensic-analyze: {exc}")
        sessionlog.log_event(TOOL_NAME, "run_stopped", reason=str(exc))
        code = runner.EXIT_FATAL
    except KeyboardInterrupt:
        say("forensic-analyze: stopped by the operator. Continue later with --resume RUN_DIR.")
        code = 130
    return code


if __name__ == "__main__":
    raise SystemExit(main())
