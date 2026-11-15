"""forensic-session-start: open a new session log and record the state of this PC.

Tasks 4.10, 4.11, 4.15 (clock), 4F.6 (image age), 2B.14 (ASSETS hash check), 4C.22 (hardware
write blocker advisory), and surviving risk 14 (authority acknowledgement on the first screen).

Order: the questions come first (authority, clock, hardware write blocker) so the operator can walk
away while the long checks run (tool versions, disks, radios, network, image age, ASSETS).
Every question has a flag; ``--yes`` takes the default for every question except authority,
which always needs ``--authority-ack`` or a typed answer.

The system clock is never changed. The operator's reference time and the difference are logged.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import re
import sys
from typing import Any

from airlock_common import hashing, sessionlog, timeutil, ui
from airlock_session import system
from airlock_session.common import CommandError, load_config, log, run_main

TOOL = "forensic-session-start"

AUTHORITY_TEXT = (
    "Only examine a drive when you have the owner's permission or the legal authority to do so "
    "(for example a warrant, a court order, or written consent). AIRLOCK records your answer "
    "in the session log."
)
AUTHORITY_SHA256 = hashing.sha256_bytes(AUTHORITY_TEXT.encode("utf-8"))

ADVISORY_TEXT = (
    "Connect each evidence drive through a hardware write blocker, ideally one with a "
    "published NIST CFTT or DHS test report.\n\n"
    "AIRLOCK also sets a software read-only flag on every attached drive. That flag is a "
    "second layer of protection. It is not a substitute for a hardware write blocker: root can "
    "clear it, and some drive commands go around it."
)
ADVISORY_SHA256 = hashing.sha256_bytes(ADVISORY_TEXT.encode("utf-8"))

BLOCKER_ANSWERS = ("yes", "no", "unknown")
CLOCK_WARN_SECONDS = 60.0

_TZ_SUFFIX = re.compile(r"(Z|z|[+-]\d{2}:?\d{2})$")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Start a new AIRLOCK session: record the time, the hardware clock, the kernel, tool "
            "versions, attached drives and their read-only flags, radios, network, image age, "
            "and the ASSETS check in a new session log. Changes nothing on the system."
        ),
    )
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="do not ask; use the default for every question (authority still needs "
        "--authority-ack)",
    )
    p.add_argument(
        "--authority-ack",
        action="store_true",
        help="confirm you have the owner's permission or legal authority to examine drives",
    )
    clock = p.add_mutually_exclusive_group()
    clock.add_argument(
        "--clock-ok",
        action="store_true",
        help="you checked the system time against a trusted clock and it is right",
    )
    clock.add_argument(
        "--reference-time",
        metavar="ISO",
        help="the correct time now in UTC from a trusted clock, e.g. 2026-11-15T09:30:00Z",
    )
    p.add_argument(
        "--reference-source",
        metavar="TEXT",
        default="",
        help="where the reference time came from (phone, radio clock, time signal)",
    )
    p.add_argument(
        "--write-blocker",
        choices=BLOCKER_ANSWERS,
        help="is the evidence drive connected through a hardware write blocker?",
    )
    p.add_argument(
        "--blocker-model", metavar="TEXT", help="make and model of the hardware write blocker"
    )
    p.add_argument(
        "--quick-asset-check",
        action="store_true",
        help="check ASSETS files by size only instead of hashing every file",
    )
    p.add_argument(
        "--pause-at-end",
        action="store_true",
        help="wait for Enter before exiting (used by the login launcher)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code = run_main(TOOL, lambda: run(args))
    if args.pause_at_end and sys.stdin.isatty():
        with contextlib.suppress(EOFError):
            input("\nPress Enter to close this window. ")
    return code


# ------------------------------------------------------------------ questions


def _show(title: str, text: str, dialog: bool) -> None:
    """A dialog when a question follows on a terminal; plain text otherwise (kept in logs)."""
    if dialog:
        ui.info(title, text)
    else:
        print(f"== {title} ==\n{text}\n")


def authority(args: argparse.Namespace, ask: bool) -> dict[str, Any]:
    """First screen (surviving risk 14). Stops the session start unless acknowledged."""
    _show("Authority to examine", AUTHORITY_TEXT, ask and not args.authority_ack)
    if args.authority_ack:
        via = "flag"
    elif ask:
        if not ui.ask_yes_no(
            "Authority to examine",
            "Do you have the owner's permission or legal authority to examine the drives "
            "you will use in this session?",
            flag="--authority-ack",
        ):
            log(TOOL, "authority_declined", text_sha256=AUTHORITY_SHA256)
            raise CommandError(
                "stopped: permission or legal authority was not confirmed. "
                "Run forensic-session-start again once you have it."
            )
        via = "prompt"
    else:
        log(TOOL, "authority_missing", text_sha256=AUTHORITY_SHA256)
        raise CommandError(
            "the authority question was not answered. Pass --authority-ack once you have the "
            "owner's permission or legal authority."
        )
    return log(
        TOOL,
        "authority_ack",
        acknowledged=True,
        via=via,
        text=AUTHORITY_TEXT,
        text_sha256=AUTHORITY_SHA256,
    )


def parse_reference(value: str) -> dt.datetime:
    """An operator-entered UTC time. It must carry ``Z`` or an explicit offset."""
    text = value.strip()
    if not text:
        raise ValueError("the reference time is empty")
    if not _TZ_SUFFIX.search(text):
        raise ValueError(
            "the reference time has no time zone. Write it in UTC with a Z at the end, "
            "for example 2026-11-15T09:30:00Z"
        )
    try:
        return timeutil.parse_iso(text.replace(" ", "T", 1))
    except ValueError as exc:
        raise ValueError(
            f"{text!r} is not a date and time. Use the form 2026-11-15T09:30:00Z"
        ) from exc


def clock_check(args: argparse.Namespace, ask: bool) -> tuple[dict[str, Any], list[str]]:
    """Task 4.15: show the clocks, ask for confirmation or a reference time, log the offset."""
    hw = system.hardware_clock()
    system_utc = timeutil.iso()
    hw_minus_sys = system.seconds_between(hw["utc"], system_utc)
    shown = (
        f"System time (UTC):   {timeutil.iso(micro=False)}\n"
        f"Hardware clock (UTC): {hw['utc'] or 'could not be read'}\n\n"
        "There is no network, so nothing sets the clock. Check the time against a trusted "
        "clock (a phone on network time, a radio clock). AIRLOCK never changes the clock; it "
        "records the difference so times in the logs can be corrected."
    )
    flagged = bool(args.reference_time or args.clock_ok)
    _show("Clock check", shown, ask and not flagged)
    fields: dict[str, Any] = {
        "system_utc": system_utc,
        "hardware_clock": hw,
        "hardware_minus_system_seconds": hw_minus_sys,
        "system_time_changed": False,
        "reference_time": "",
        "reference_source": args.reference_source,
        "offset_seconds": None,
        "offset_meaning": "reference minus system time; corrected time = system time + offset",
    }
    if args.reference_time:
        try:
            ref = parse_reference(args.reference_time)
        except ValueError as exc:
            raise CommandError(f"--reference-time: {exc}") from exc
        fields.update(status="reference_entered", via="flag")
        _apply_reference(fields, ref)
        fields["reference_source"] = fields["reference_source"] or "operator"
    elif args.clock_ok:
        fields.update(status="confirmed", via="flag", offset_seconds=0.0)
    elif ask:
        if ui.ask_yes_no(
            "Clock check",
            "Is the system time right to within a minute, compared with a trusted clock?",
            default=True,
            flag="--clock-ok",
        ):
            fields.update(status="confirmed", via="prompt", offset_seconds=0.0)
        else:
            ref = _ask_reference()
            fields.update(status="reference_entered", via="prompt")
            _apply_reference(fields, ref)
            if not fields["reference_source"]:
                fields["reference_source"] = ui.ask_text(
                    "Clock check",
                    "Where did you read the correct time (phone, radio clock, time signal)?",
                    "operator's trusted clock",
                    flag="--reference-source",
                )
    else:
        fields.update(status="not_checked", via="default")
    warnings = _clock_warnings(fields)
    log(TOOL, "clock_check", **fields)
    return fields, warnings


def _ask_reference() -> dt.datetime:
    for _ in range(3):
        answer = ui.ask_text(
            "Clock check",
            "Enter the correct time now, in UTC, like 2026-11-15T09:30:00Z:",
            flag="--reference-time",
        )
        try:
            return parse_reference(answer)
        except ValueError as exc:
            print(str(exc))
    raise CommandError(
        "no usable reference time after three tries. Run again with --reference-time "
        "2026-11-15T09:30:00Z (your trusted clock's UTC time)."
    )


def _apply_reference(fields: dict[str, Any], ref: dt.datetime) -> None:
    entered_at = timeutil.utcnow()
    fields["reference_time"] = timeutil.iso(ref)
    fields["system_utc_at_entry"] = timeutil.iso(entered_at)
    fields["offset_seconds"] = round((ref - entered_at).total_seconds(), 3)


def _clock_warnings(fields: dict[str, Any]) -> list[str]:
    out: list[str] = []
    off = fields.get("offset_seconds")
    if fields["status"] == "not_checked":
        out.append(
            "The clock was not checked. Times in this session are the PC's own time. "
            "Run forensic-session-start again with --reference-time to record the difference."
        )
    elif off is not None and abs(off) > CLOCK_WARN_SECONDS:
        out.append(
            f"The system clock is off by {off:+.0f} seconds. Add this to times in the logs to "
            "correct them."
        )
    hw = fields.get("hardware_minus_system_seconds")
    if system.looks_like_local_time(hw):
        out.append(
            "The hardware clock differs from the system time by whole quarter hours. The PC may "
            "keep its clock in local time (Windows does). Times in this session are UTC as set "
            "at boot; check them against your trusted clock."
        )
    return out


def write_blocker(args: argparse.Namespace, ask: bool) -> tuple[dict[str, Any], list[str]]:
    """Task 4C.22, session half: advise a hardware write blocker and log the answer."""
    answer = args.write_blocker
    _show("Hardware write blocker", ADVISORY_TEXT, ask and answer is None)
    via = "flag"
    if answer is None:
        if ask:
            answer = ui.ask_choice(
                "Hardware write blocker",
                "Are evidence drives connected through a hardware write blocker?",
                [
                    ("yes", "a hardware write blocker is in use"),
                    ("no", "drives are connected directly"),
                    ("unknown", "not sure, or no evidence drive yet"),
                ],
                default="unknown",
                flag="--write-blocker",
            )
            via = "prompt"
        else:
            answer, via = "unknown", "default"
    model = (args.blocker_model or "").strip()
    if answer == "yes" and not model and ask:
        model = ui.ask_text(
            "Hardware write blocker",
            "Make and model of the hardware write blocker (leave empty to skip):",
            flag="--blocker-model",
        ).strip()
    fields = {
        "answer": answer,
        "model": model,
        "via": via,
        "advisory_sha256": ADVISORY_SHA256,
        "software_flag_role": "second layer, not a substitute",
    }
    log(TOOL, "write_blocker", **fields)
    warnings: list[str] = []
    if answer != "yes":
        warnings.append(
            "No hardware write blocker recorded. The software read-only flag is a second layer "
            "only; use a hardware write blocker for evidence drives."
        )
    return fields, warnings


# ------------------------------------------------------------------ the run


def run(args: argparse.Namespace) -> int:
    ask = ui.interactive() and not args.yes
    cfg = load_config()
    max_age = int(cfg.get("image_max_age_days") or 90)
    age = system.image_age(max_age)
    try:
        path = sessionlog.new_session(
            TOOL,
            airlock_version=age.get("version", ""),
            build_date=age.get("build_date", ""),
            git_commit=age.get("git_commit", ""),
        )
    except PermissionError as exc:
        raise CommandError(
            "cannot create the session log. Run it again with sudo: sudo forensic-session-start"
        ) from exc
    print(f"AIRLOCK session log: {path}\n")
    if cfg.get("config_error"):
        log(TOOL, "config_error", reason=cfg["config_error"])

    warnings: list[str] = []
    authority(args, ask)
    _, w = clock_check(args, ask)
    warnings += w
    _, w = write_blocker(args, ask)
    warnings += w

    print("Recording the kernel, tool versions, drives, radios, and network ...")
    log(TOOL, "kernel", **system.kernel_info())
    versions = system.tool_versions()
    absent = sorted(k for k, v in versions["commands"].items() if v["status"] == "absent")
    log(TOOL, "tool_versions", absent=absent, **versions)
    log(TOOL, "lsblk", devices=system.lsblk_tree())
    warnings += _record_disks()
    warnings += _record_radios_and_network()
    warnings += _record_image_age(age)

    deep = not args.quick_asset_check
    if deep:
        print("Checking every file on ASSETS against the signed manifest. This can take minutes.")
    event, data = system.asset_check(deep=deep)
    log(TOOL, event, **data)
    warnings += _asset_warnings(event, data)

    log(TOOL, "session_ready", warnings=warnings, log_path=str(path))
    _summary(path, age, warnings)
    return 0


def _record_disks() -> list[str]:
    flags = system.readonly_flags()
    log(TOOL, "readonly_flags", **flags)
    return [
        f"{dev} is writable. The software read-only flag is off for it. If it is evidence, "
        "unplug it and plug it in again; if it is an output drive, that is expected."
        for dev in flags["writable_unexpected"]
    ]


def _record_radios_and_network() -> list[str]:
    out: list[str] = []
    radios = system.rfkill_state()
    log(TOOL, "rfkill", **radios)
    if radios["unblocked"]:
        out.append(
            "A radio is not blocked: " + ", ".join(radios["unblocked"]) + ". Stop, and report "
            "this: AIRLOCK should block every radio."
        )
    net = system.network_state()
    log(TOOL, "network_state", **net)
    if not net["ok"]:
        out.append(
            "A network interface is up or a route exists ("
            + ", ".join(net["up_besides_loopback"] + net["default_routes"])
            + "). AIRLOCK should have no network. Stop and reflash the drive."
        )
    return out


def _record_image_age(age: dict[str, Any]) -> list[str]:
    log(TOOL, "image_age", **age)
    status = age["status"]
    if status == "too_old":
        return [
            f"This AIRLOCK image is {age['age_days']} days old (limit {age['max_age_days']}). "
            "It has no security fixes since it was built. Reflash from a current base image."
        ]
    if status == "clock_before_build":
        return ["The PC clock is earlier than the image build date. Check the clock."]
    if status != "ok":
        return [f"The image build date could not be read ({status}). Its age is unknown."]
    return []


def _asset_warnings(event: str, data: dict[str, Any]) -> list[str]:
    if event == "asset_check_unavailable":
        return ["The ASSETS check is not available on this image. Staged files were not checked."]
    if event == "asset_check_failed":
        return [f"The ASSETS check failed: {data.get('reason', '')}. Staged files may be wrong."]
    if data.get("ok"):
        return []
    problems = data.get("problems") or []
    names = ", ".join(str(p[0]) if isinstance(p, list | tuple) else str(p) for p in problems)
    disabled = ", ".join(str(f) for f in data.get("disabled_features") or [])
    msg = f"ASSETS files missing or changed: {names or 'see the session log'}."
    if disabled:
        msg += f" Turned off: {disabled}."
    return [msg + " Rerun the fetcher on the host computer to restage them."]


def _summary(path: object, age: dict[str, Any], warnings: list[str]) -> None:
    print()
    print("AIRLOCK session started.")
    print(f"Session log: {path}")
    if age.get("build_date"):
        days = age.get("age_days")
        print(
            f"Image: {age.get('version') or 'unknown version'}, built {age['build_date']}", end=""
        )
        print(f" ({days} days ago)." if days is not None else ".")
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("No warnings.")
    print("\nNext: run forensic-analyze to examine a drive or image, or evidence-hash to hash one.")


if __name__ == "__main__":
    raise SystemExit(main())
