#!/usr/bin/python3
"""Check the Secure Boot chain on the AIRLOCK drive (task 1.13).

Reads each EFI binary (PE/COFF) given on the command line and reports:

* its SBAT entries (the .sbat section), compared with the lowest generations accepted
  (``--min-sbat shim=4 --min-sbat grub=5``). Firmware and shim refuse binaries whose SBAT
  generation is below the revocation level they carry, so an old shim or grub would not
  boot on an updated PC.
* who signed it: the subject and issuer common names in its Authenticode signatures, and
  whether one chains to the Microsoft UEFI CA 2011 or the Microsoft UEFI CA 2023. Firmware
  that trusts only the 2023 CA refuses a shim signed only under the 2011 CA.

Prints one JSON object (sorted keys). Exit status: 0 when every SBAT minimum is met,
1 when one is not (or a file cannot be read), 2 on bad usage. A missing 2023 signature is
reported (``ms_uefi_ca_2023``) but is not a failure: docs/hardware-matrix.md explains.

Installed by the base role as /opt/airlock/libexec/airlock-check-boot-chain; standard
library only, plus the openssl command for reading signatures.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field

PE32_PLUS = 0x20B
PE32 = 0x10B
CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
SECURITY_DIRECTORY = 4


class PEError(Exception):
    """The file is not a PE image this checker can read."""


@dataclass
class SbatEntry:
    component: str
    generation: int
    vendor: str
    package: str
    version: str


@dataclass
class PEInfo:
    sections: dict[str, bytes] = field(default_factory=dict)
    signatures: list[bytes] = field(default_factory=list)


def parse_pe(data: bytes) -> PEInfo:
    """Return the section contents and the PKCS#7 signature blobs of a PE image."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("no MZ header")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise PEError("no PE signature")
    coff = pe_off + 4
    n_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == PE32_PLUS:
        dirs = opt + 112
    elif magic == PE32:
        dirs = opt + 96
    else:
        raise PEError(f"unknown optional header magic {magic:#x}")
    info = PEInfo()
    sec_table = opt + opt_size
    for i in range(n_sections):
        off = sec_table + 40 * i
        name = data[off : off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, _vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        size = min(vsize, raw_size) if vsize else raw_size
        info.sections[name] = data[raw_ptr : raw_ptr + size]
    n_dirs = struct.unpack_from("<I", data, dirs - 4)[0]
    if n_dirs > SECURITY_DIRECTORY:
        cert_off, cert_size = struct.unpack_from("<II", data, dirs + 8 * SECURITY_DIRECTORY)
        pos, end = cert_off, cert_off + cert_size
        while cert_size and pos + 8 <= min(end, len(data)):
            length, _rev, ctype = struct.unpack_from("<IHH", data, pos)
            if length < 8:
                break
            if ctype == CERT_TYPE_PKCS_SIGNED_DATA:
                info.signatures.append(data[pos + 8 : pos + length])
            pos += (length + 7) // 8 * 8
    return info


def parse_sbat(section: bytes) -> list[SbatEntry]:
    entries = []
    text = section.split(b"\0", 1)[0].decode("utf-8", "replace")
    for line in text.splitlines():
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 2 or not cols[1].isdigit():
            continue
        cols += [""] * (6 - len(cols))
        entries.append(SbatEntry(cols[0], int(cols[1]), cols[2], cols[3], cols[4]))
    return entries


_CN_RE = re.compile(r"CN\s*=\s*([^,/\n]+)")


def signer_names(blob: bytes) -> list[str]:
    """Subject and issuer common names of every certificate in a PKCS#7 blob."""
    res = subprocess.run(
        ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-noout"],
        input=blob,
        capture_output=True,
        check=False,
    )
    if res.returncode != 0:
        return []
    out = res.stdout.decode("utf-8", "replace")
    names: list[str] = []
    for line in out.splitlines():
        if line.startswith(("subject=", "issuer=")):
            names += [m.strip() for m in _CN_RE.findall(line)]
    return sorted(set(names))


def check_file(path: str) -> dict[str, object]:
    with open(path, "rb") as fh:
        info = parse_pe(fh.read())
    sbat = parse_sbat(info.sections.get(".sbat", b""))
    names: list[str] = []
    for blob in info.signatures:
        names += signer_names(blob)
    names = sorted(set(names))
    return {
        "ms_uefi_ca_2011": any("UEFI CA 2011" in n for n in names),
        "ms_uefi_ca_2023": any("UEFI CA 2023" in n for n in names),
        "path": path,
        "sbat": [e.__dict__ for e in sbat],
        "signature_count": len(info.signatures),
        "signer_names": names,
    }


def parse_min(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in values:
        comp, sep, gen = item.partition("=")
        if not sep or not comp or not gen.isdigit():
            raise ValueError(f"--min-sbat {item!r} is not COMPONENT=GENERATION")
        out[comp] = int(gen)
    return out


def evaluate(files: list[dict[str, object]], minimum: dict[str, int]) -> list[str]:
    """Problems: every minimum component must appear in some file at or above its level."""
    found: dict[str, int] = {}
    for f in files:
        for e in f["sbat"]:  # type: ignore[union-attr]
            comp, gen = e["component"], e["generation"]  # type: ignore[index]
            found[comp] = max(found.get(comp, 0), gen)
    problems = []
    for comp, want in sorted(minimum.items()):
        have = found.get(comp)
        if have is None:
            problems.append(f"no SBAT entry for {comp}")
        elif have < want:
            problems.append(f"SBAT {comp} generation {have} is below {want}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="airlock-check-boot-chain",
        description="Report SBAT levels and signers of EFI binaries (shim, grub).",
    )
    ap.add_argument("files", nargs="+", help="EFI binaries, for example EFI/BOOT/BOOTX64.EFI")
    ap.add_argument(
        "--min-sbat", action="append", default=[], metavar="COMP=GEN", help="lowest generation"
    )
    args = ap.parse_args(argv)
    try:
        minimum = parse_min(args.min_sbat)
    except ValueError as exc:
        print(f"airlock-check-boot-chain: {exc}", file=sys.stderr)
        return 2
    results = []
    problems: list[str] = []
    for path in args.files:
        try:
            results.append(check_file(path))
        except (OSError, PEError, struct.error) as exc:
            problems.append(f"{path}: {exc}")
    problems += evaluate(results, minimum)
    report = {
        "files": results,
        "min_sbat": minimum,
        "ms_uefi_ca_2023_any": any(r["ms_uefi_ca_2023"] for r in results),
        "problems": problems,
        "sbat_ok": not problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if problems:
        print(
            "airlock-check-boot-chain: " + "; ".join(problems) + ". Move apt_snapshot to a "
            "date with a newer shim-signed and grub-efi-amd64-signed, then rebuild.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
