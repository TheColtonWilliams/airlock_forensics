"""Analysis mode (task 4C.24).

``direct`` (default): read the device directly, keep no copy. Each run prints a one-line warning
that nothing can be re-examined later, and the report states the limits (SWGDE 17-F-002-2.1,
documented triage).

``image``: copy first, then analyse the copy (SWGDE 18-F-001-2.0). ``ewfacquire`` makes an E01;
``ddrescue`` with a map file is for weak drives (it reads the good areas first and retries bad
areas later). The copy is verified against the target's hash and then analysed. The output drive
must have room for the whole target.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing, proc

MODES = ("direct", "image")
IMAGERS = ("ewf", "ddrescue")

DIRECT_WARNING = (
    "Read-directly mode: no copy is kept. If the drive fails or is returned, nothing from this "
    "run can be re-examined, and no other tool can be run on it later."
)
DIRECT_LIMITS = [
    "The drive was read directly; no forensic copy was made (documented triage).",
    "Results cannot be re-examined from a copy, and a second tool cannot be run later.",
    "The before and after hashes show whether the drive changed during the run.",
]
IMAGE_LIMITS = [
    "The drive was copied first and the analysis ran on the copy.",
    "The copy's hash was checked against the drive's hash before analysis.",
]


class ModeError(RuntimeError):
    """Imaging failed or could not be verified."""


@dataclass
class ImageResult:
    imager: str
    image_path: str
    files: list[str] = field(default_factory=list)
    command_lines: list[str] = field(default_factory=list)
    sha256: str = ""
    md5: str = ""
    verified: bool = False
    verify_method: str = ""
    bad_bytes: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Runner = Callable[..., proc.Result]


def _run(argv: Sequence[str], **kw: Any) -> proc.Result:
    return proc.run(argv, **kw)


def parse_ewfverify(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for algo in ("MD5", "SHA1", "SHA256"):
        m = re.search(rf"{algo} hash calculated over data:\s*([0-9a-fA-F]+)", text)
        if m:
            out[algo.lower()] = m.group(1).lower()
    return out


def parse_ddrescue_map(text: str) -> tuple[int, int]:
    """(bytes finished, bytes not finished) from a ddrescue map file."""
    good = bad = 0
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    for ln in lines[1:]:  # first data line is the current position and status
        parts = ln.split()
        if len(parts) < 3:
            continue
        size = int(parts[1], 0)
        if parts[2] == "+":
            good += size
        else:
            bad += size
    return good, bad


def acquire_ewf(
    source: str,
    out_dir: Path,
    *,
    case_id: str,
    exhibit_id: str,
    examiner: str,
    notes: str,
    expected: dict[str, str],
    run: Runner = _run,
) -> ImageResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / "target"
    argv = [
        "ewfacquire",
        "-u",
        "-t",
        str(base),
        "-f",
        "encase6",
        "-c",
        "deflate:fast",
        "-d",
        "sha256",
        "-C",
        case_id,
        "-D",
        f"AIRLOCK copy of {exhibit_id}",
        "-E",
        exhibit_id,
        "-e",
        examiner or "not recorded",
        "-N",
        notes or "-",
        "-S",
        "2GiB",
        "-l",
        str(out_dir / "ewfacquire.log"),
        source,
    ]
    res = ImageResult(imager="ewf", image_path=str(base) + ".E01")
    acq = run(argv, check=False, stdout_path=out_dir / "ewfacquire.out")
    res.command_lines.append(acq.command_line)
    if acq.returncode != 0:
        raise ModeError(f"ewfacquire failed (exit {acq.returncode}); see {out_dir}/ewfacquire.out")
    res.files = sorted(p.name for p in out_dir.glob("target.E*"))
    ver = run(["ewfverify", "-q", "-d", "sha256", res.image_path], check=False)
    res.command_lines.append(ver.command_line)
    digests = parse_ewfverify(ver.stdout + "\n" + ver.stderr)
    res.sha256, res.md5 = digests.get("sha256", ""), digests.get("md5", "")
    res.verify_method = "ewfverify media hash"
    res.verified = (
        ver.returncode == 0
        and bool(res.sha256)
        and res.sha256 == expected.get("sha256")
        and (not res.md5 or res.md5 == expected.get("md5"))
    )
    if not res.verified:
        res.notes.append("the copy's hash does not match the drive's before hash")
    return res


def acquire_ddrescue(
    source: str, out_dir: Path, *, expected: dict[str, str], run: Runner = _run
) -> ImageResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    image = out_dir / "target.dd"
    mapfile = out_dir / "target.map"
    res = ImageResult(imager="ddrescue", image_path=str(image), files=[image.name, mapfile.name])
    # Pass 1: copy the easy areas, skip slow ones. Pass 2: retry bad areas three times.
    for argv in (
        ["ddrescue", "-n", source, str(image), str(mapfile)],
        ["ddrescue", "-r3", source, str(image), str(mapfile)],
    ):
        r = run(argv, check=False)
        res.command_lines.append(r.command_line)
        if r.returncode != 0:
            raise ModeError(f"ddrescue failed (exit {r.returncode}): {r.stderr.strip()[-200:]}")
    _good, bad = parse_ddrescue_map(mapfile.read_text(encoding="utf-8"))
    res.bad_bytes = bad
    digests = hashing.hash_file(image)
    res.sha256, res.md5 = digests["sha256"], digests["md5"]
    res.verify_method = "sha256 and md5 of the copy against the drive's before hash"
    res.verified = res.sha256 == expected.get("sha256") and res.md5 == expected.get("md5")
    if bad:
        res.notes.append(
            f"{bad} bytes could not be read and are zero in the copy; the copy's hash cannot "
            "match the drive's hash"
        )
    elif not res.verified:
        res.notes.append("the copy's hash does not match the drive's before hash")
    image.chmod(0o444)
    return res


def acquire(
    imager: str,
    source: str,
    out_dir: Path,
    *,
    expected: dict[str, str],
    case_id: str = "",
    exhibit_id: str = "",
    examiner: str = "",
    notes: str = "",
    run: Runner = _run,
) -> ImageResult:
    if imager == "ewf":
        if not proc.which("ewfacquire"):
            raise ModeError("ewfacquire is not installed. Use --imager ddrescue.")
        return acquire_ewf(
            source,
            out_dir,
            case_id=case_id,
            exhibit_id=exhibit_id,
            examiner=examiner,
            notes=notes,
            expected=expected,
            run=run,
        )
    if imager == "ddrescue":
        if not proc.which("ddrescue"):
            raise ModeError("ddrescue is not installed. Use --imager ewf.")
        return acquire_ddrescue(source, out_dir, expected=expected, run=run)
    raise ModeError(f"unknown imager {imager!r}; use ewf or ddrescue")
