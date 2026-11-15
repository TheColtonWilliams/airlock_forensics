"""Read-only collectors for ``forensic-session-start``: clock, kernel, tools, disks, radios,
network, image age, and the ASSETS check. Nothing in this module changes the system.
"""

from __future__ import annotations

import datetime as dt
import importlib
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from airlock_common import devices, jsonio, paths, proc, timeutil
from airlock_session.common import procfs, readonly_flag, sysfs

VERSION_TIMEOUT = 15.0

# Commands whose version is logged at session start. Tools that are not installed are logged
# as absent. Every command here only prints a version; none reads a target or the network.
# Names match what the tool roles install (checked by tests/unit/test_session_helpers.py
# against ansible/roles/tools_*/defaults): Plaso's venv commands are linked into
# /usr/local/bin without ".py" (tools_timeline_commands), llama.cpp lives under /opt/llama/bin
# (tools_ai_llama_prefix, not on PATH), bulk_extractor is built from source, and each EZ tool
# has a /usr/local/bin/<Tool> wrapper (tools_eztools_tools) on the .NET runtime.
LLAMA_SERVER = "/opt/llama/bin/llama-server"
EZTOOLS: tuple[str, ...] = (
    "MFTECmd",
    "RBCmd",
    "LECmd",
    "JLECmd",
    "PECmd",
    "EvtxECmd",
    "AmcacheParser",
    "AppCompatCacheParser",
    "RECmd",
    "SBECmd",
    "bstrings",
)
VERSION_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("python3", ("python3", "--version")),
    ("mmls", ("mmls", "-V")),
    ("fls", ("fls", "-V")),
    ("fsstat", ("fsstat", "-V")),
    ("ewfacquire", ("ewfacquire", "-V")),
    ("dc3dd", ("dc3dd", "--version")),
    ("ddrescue", ("ddrescue", "--version")),
    ("hashdeep", ("hashdeep", "-V")),
    ("ssdeep", ("ssdeep", "-V")),
    ("target-query", ("target-query", "--version")),
    ("log2timeline", ("log2timeline", "--version")),
    ("psort", ("psort", "--version")),
    ("exiftool", ("exiftool", "-ver")),
    ("mediainfo", ("mediainfo", "--Version")),
    ("ffmpeg", ("ffmpeg", "-version")),
    ("exiv2", ("exiv2", "--version")),
    ("photorec", ("photorec", "/version")),
    ("foremost", ("foremost", "-V")),
    ("scalpel", ("scalpel", "-V")),
    ("bulk_extractor", ("bulk_extractor", "-V")),
    ("clamscan", ("clamscan", "--version")),
    ("yara", ("yara", "--version")),
    ("ntfs-3g", ("ntfs-3g", "--version")),
    ("dotnet", ("dotnet", "--list-runtimes")),
    *((name, (name, "--version")) for name in EZTOOLS),
    ("llama-server", (LLAMA_SERVER, "--version")),
)

# Ubuntu packages whose installed version is logged (one dpkg-query call). Every name is one a
# tools role installs (tools_*_packages, or a pinned .deb); optional ones (Autopsy, SIFT, EZ
# Tools) are logged as absent when the profile left them out.
DPKG_PACKAGES: tuple[str, ...] = (
    "sleuthkit",
    "libfsntfs-utils",
    "python3-libfsntfs",
    "ntfs-3g",
    "ewf-tools",
    "dc3dd",
    "gddrescue",
    "afflib-tools",
    "guymager",
    "hashdeep",
    "ssdeep",
    "libvshadow-utils",
    "testdisk",
    "scalpel",
    "foremost",
    "libimage-exiftool-perl",
    "mediainfo",
    "ffmpeg",
    "exiv2",
    "vinetto",
    "poppler-utils",
    "regripper",
    "libregf-utils",
    "libhivex-bin",
    "clamav",
    "yara",
    "python3-tlsh",
    "mesa-vulkan-drivers",
    "dotnet-runtime-9.0",
    "openjdk-17-jre",
    "sleuthkit-java",
    "python3",
)

_QUIET_ENV = {
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_NOLOGO": "1",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
    "NO_COLOR": "1",
}


# ------------------------------------------------------------------ kernel


def kernel_info() -> dict[str, Any]:
    u = os.uname()
    out: dict[str, Any] = {
        "sysname": u.sysname,
        "release": u.release,
        "version": u.version,
        "machine": u.machine,
    }
    try:
        out["cmdline"] = (procfs() / "cmdline").read_text(encoding="utf-8").strip()
    except OSError:
        out["cmdline"] = ""
    return out


# ------------------------------------------------------------------ clocks


def _parse_hwclock(text: str) -> dt.datetime:
    """``hwclock --show --utc`` output, e.g. ``2026-11-15 10:00:00.123456+00:00``."""
    value = text.strip().splitlines()[0].strip()
    ts = dt.datetime.fromisoformat(value)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.UTC)
    return ts.astimezone(dt.UTC)


def hardware_clock() -> dict[str, Any]:
    """The PC's hardware clock read as UTC. Never sets it.

    ``hwclock --show --utc`` when it works (needs root), else ``/sys/class/rtc/rtc0``.
    """
    errors: list[str] = []
    if proc.which("hwclock"):
        try:
            res = proc.run(["hwclock", "--show", "--utc"], timeout=VERSION_TIMEOUT, input_text="")
            ts = _parse_hwclock(res.stdout)
            return {"source": "hwclock", "utc": timeutil.iso(ts), "raw": res.stdout.strip()}
        except (proc.ToolError, ValueError, IndexError) as exc:
            errors.append(f"hwclock: {exc}")
    else:
        errors.append("hwclock: not installed")
    rtc = sysfs() / "class" / "rtc" / "rtc0"
    try:
        date = (rtc / "date").read_text().strip()
        time_ = (rtc / "time").read_text().strip()
        ts = dt.datetime.fromisoformat(f"{date}T{time_}").replace(tzinfo=dt.UTC)
        return {
            "source": "sysfs",
            "utc": timeutil.iso(ts),
            "raw": f"{date} {time_}",
            "errors": errors,
        }
    except (OSError, ValueError) as exc:
        errors.append(f"sysfs rtc0: {exc}")
    return {"source": "none", "utc": "", "raw": "", "errors": errors}


def seconds_between(later: str, earlier: str) -> float | None:
    """``later - earlier`` in seconds for two ISO times; None if either is empty."""
    if not later or not earlier:
        return None
    delta = timeutil.parse_iso(later) - timeutil.parse_iso(earlier)
    return round(delta.total_seconds(), 3)


def looks_like_local_time(offset_seconds: float | None) -> bool:
    """A whole number of quarter hours off (and at least 15 min) suggests a local-time RTC."""
    if offset_seconds is None or abs(offset_seconds) < 900 - 60:
        return False
    rem = abs(offset_seconds) % 900
    return min(rem, 900 - rem) <= 60


# ------------------------------------------------------------------ tool versions


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def tool_versions(
    commands: tuple[tuple[str, tuple[str, ...]], ...] = VERSION_COMMANDS,
    packages: tuple[str, ...] = DPKG_PACKAGES,
) -> dict[str, Any]:
    """Version of every listed command and package; missing ones are recorded as absent."""
    env = {**os.environ, **_QUIET_ENV}
    found: dict[str, Any] = {}
    for name, argv in commands:
        path = proc.which(argv[0])
        if not path:
            found[name] = {"status": "absent"}
            continue
        try:
            res = proc.run(argv, check=False, timeout=VERSION_TIMEOUT, input_text="", env=env)
        except proc.ToolError as exc:
            found[name] = {"status": "error", "path": path, "error": str(exc)}
            continue
        if name == "dotnet":
            version = "; ".join(ln.strip() for ln in res.stdout.splitlines() if ln.strip())[:300]
        else:
            version = _first_line(res.stdout) or _first_line(res.stderr)
        found[name] = {
            "status": "present",
            "path": path,
            "version": version,
            "returncode": res.returncode,
        }
    return {"commands": found, "packages": dpkg_versions(packages)}


def dpkg_versions(packages: tuple[str, ...]) -> dict[str, str]:
    out = dict.fromkeys(packages, "absent")
    if not packages:
        return out
    if not proc.which("dpkg-query"):
        return dict.fromkeys(packages, "unknown (no dpkg-query)")
    fmt = "${Package}\t${Version}\t${db:Status-Abbrev}\n"
    try:
        res = proc.run(
            ["dpkg-query", "-W", f"-f={fmt}", *packages],
            check=False,
            timeout=VERSION_TIMEOUT,
            input_text="",
        )
    except proc.ToolError:
        return dict.fromkeys(packages, "unknown (dpkg-query failed)")
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in out and parts[2].startswith("ii"):
            out[parts[0]] = parts[1]
    return out


# ------------------------------------------------------------------ disks


def lsblk_tree() -> list[dict[str, Any]]:
    return [asdict(d) for d in devices.lsblk()]


def readonly_flags() -> dict[str, Any]:
    """The read-only flag of every disk and partition, and which ones are writable."""
    tree = devices.lsblk()
    boot = devices.boot_disk(tree)
    rw_allow = paths.rw_allow_dir()
    rows: list[dict[str, Any]] = []
    writable: list[str] = []
    for top in tree:
        if top.type not in {"disk", "loop"} or top.name.startswith(("zram", "ram")):
            continue
        is_boot = boot is not None and top.name == boot.name
        for d in top.walk():
            flag = readonly_flag(d.name)
            ro = d.ro if flag is None else flag
            unlocked = (rw_allow / d.name).exists() or (rw_allow / top.name).exists()
            rows.append(
                {
                    "name": d.name,
                    "path": d.path,
                    "type": d.type,
                    "disk": top.name,
                    "readonly": ro,
                    "boot_disk": is_boot,
                    "unlocked_for_output": unlocked,
                }
            )
            if not ro and not is_boot and not unlocked and top.type == "disk":
                writable.append(d.path)
    return {
        "boot_disk": boot.path if boot else "",
        "devices": rows,
        "writable_unexpected": writable,
    }


# ------------------------------------------------------------------ radios and network


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def rfkill_state() -> dict[str, Any]:
    """Every radio from ``/sys/class/rfkill``; a radio is unblocked if soft and hard are 0."""
    base = sysfs() / "class" / "rfkill"
    radios: list[dict[str, Any]] = []
    unblocked: list[str] = []
    for entry in sorted(base.glob("rfkill*")) if base.is_dir() else []:
        soft, hard = _read(entry / "soft"), _read(entry / "hard")
        radio = {
            "id": entry.name,
            "type": _read(entry / "type"),
            "name": _read(entry / "name"),
            "soft_blocked": soft == "1",
            "hard_blocked": hard == "1",
        }
        radios.append(radio)
        if soft != "1" and hard != "1":
            unblocked.append(f"{radio['id']} ({radio['type'] or 'unknown'})")
    return {"radios": radios, "unblocked": unblocked, "rfkill_tool": proc.which("rfkill") or ""}


def _default_routes() -> list[str]:
    routes: list[str] = []
    for line in _read(procfs() / "net" / "route").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 2 and cols[1] == "00000000":
            routes.append(f"ipv4 via {cols[0]}")
    for line in _read(procfs() / "net" / "ipv6_route").splitlines():
        cols = line.split()
        if len(cols) >= 10 and set(cols[0]) == {"0"} and cols[1] == "00" and cols[9] != "lo":
            routes.append(f"ipv6 via {cols[9]}")
    return routes


def network_state() -> dict[str, Any]:
    """Network interfaces from ``/sys/class/net``. AIRLOCK expects only ``lo`` to be up."""
    base = sysfs() / "class" / "net"
    interfaces: list[dict[str, Any]] = []
    up: list[str] = []
    for entry in sorted(base.iterdir()) if base.is_dir() else []:
        flags_text = _read(entry / "flags")
        try:
            flags = int(flags_text, 16) if flags_text else 0
        except ValueError:
            flags = 0
        is_up = bool(flags & 0x1)
        interfaces.append(
            {
                "name": entry.name,
                "operstate": _read(entry / "operstate"),
                "admin_up": is_up,
                "address": _read(entry / "address"),
                "wireless": (entry / "wireless").exists() or (entry / "phy80211").exists(),
            }
        )
        if is_up and entry.name != "lo":
            up.append(entry.name)
    routes = _default_routes()
    return {
        "interfaces": interfaces,
        "up_besides_loopback": up,
        "default_routes": routes,
        "expected": "only lo up, no default route",
        "ok": not up and not routes,
    }


# ------------------------------------------------------------------ image age (task 4F.6)


def image_age(max_age_days: int = 90, now: dt.datetime | None = None) -> dict[str, Any]:
    """Build date and age of this image from ``/etc/airlock/build-info.json``.

    Also used by the report to record image age. ``status`` is ``ok``, ``too_old``, ``missing``,
    ``unreadable``, ``unknown_date``, or ``clock_before_build``.
    """
    path = paths.build_info()
    out: dict[str, Any] = {
        "build_info": str(path),
        "build_date": "",
        "age_days": None,
        "max_age_days": max_age_days,
        "too_old": False,
        "version": "",
        "git_commit": "",
    }
    try:
        info = jsonio.load_json(path)
    except FileNotFoundError:
        return {**out, "status": "missing"}
    except (OSError, ValueError) as exc:
        return {**out, "status": "unreadable", "error": str(exc)}
    if not isinstance(info, dict):
        return {**out, "status": "unreadable", "error": "not a JSON object"}
    out["version"] = str(info.get("version", ""))
    out["git_commit"] = str(info.get("git_commit", ""))
    raw = str(info.get("build_date", ""))
    out["build_date"] = raw
    try:
        built = timeutil.parse_iso(raw)
    except ValueError:
        return {**out, "status": "unknown_date"}
    age = (now or timeutil.utcnow()) - built
    days = age.days
    out["age_days"] = days
    if age.total_seconds() < -86400:
        return {**out, "status": "clock_before_build"}
    out["too_old"] = days > max_age_days
    return {**out, "status": "too_old" if out["too_old"] else "ok"}


# ------------------------------------------------------------------ ASSETS check (task 2B.14)


def asset_check(*, deep: bool = True) -> tuple[str, dict[str, Any]]:
    """Run ``airlock_common.assets.verify_staged``. Returns (event name, fields).

    The assets module is imported lazily: if it is missing or lacks ``verify_staged`` the event
    is ``asset_check_unavailable``; if it raises, ``asset_check_failed``.
    """
    try:
        module = importlib.import_module("airlock_common.assets")
        verify = module.verify_staged
    except (ImportError, AttributeError) as exc:
        return "asset_check_unavailable", {"reason": f"{type(exc).__name__}: {exc}"}
    try:
        report = verify(deep=deep)
    except Exception as exc:  # the session must go on; the failure is logged
        return "asset_check_failed", {"deep": deep, "reason": f"{type(exc).__name__}: {exc}"}
    to_dict = getattr(report, "to_dict", None)
    if callable(to_dict):
        data = dict(to_dict())
    else:
        data = {
            k: getattr(report, k, None) for k in ("ok", "checked", "problems", "disabled_features")
        }
    data["deep"] = deep
    return "asset_check", data
