"""Per-run output hashes and signature (tasks 2B.17, 4C.25).

``outputs.sha256`` lists every file in the run folder in ``sha256sum`` format, so
``sha256sum -c outputs.sha256`` checks it on Linux. ``outputs.sha256.sig`` is a raw Ed25519
signature of that list made with the per-OUTPUT key at ``<OUTPUT>/.airlock/signing/key.pem``.
The public key is copied into each run as ``outputs.sha256.pub.pem``.

Verify a run folder by hand (from inside it)::

    sha256sum -c outputs.sha256
    openssl pkeyutl -verify -pubin -inkey outputs.sha256.pub.pem -rawin \\
        -in outputs.sha256 -sigfile outputs.sha256.sig
"""

from __future__ import annotations

import contextlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from airlock_common import hashing, proc

LIST_NAME = "outputs.sha256"
SIG_NAME = "outputs.sha256.sig"
PUB_NAME = "outputs.sha256.pub.pem"
# forensic-analyze.pid exists only while the run is going; it is removed when the run ends.
EXCLUDED = frozenset({LIST_NAME, SIG_NAME, "forensic-analyze.pid"})


class SigningError(RuntimeError):
    """The key could not be made or used."""


def key_dir(output_root: Path) -> Path:
    return output_root / ".airlock" / "signing"


def ensure_key(output_root: Path) -> tuple[Path, Path]:
    """Return (private key, public key) for this output drive, creating them on first use."""
    folder = key_dir(output_root)
    key = folder / "key.pem"
    pub = folder / "pub.pem"
    if not key.exists():
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        old = os.umask(0o077)
        try:
            proc.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)])
        finally:
            os.umask(old)
    # exFAT keeps no Unix modes; chmod is best effort there.
    with contextlib.suppress(OSError):
        os.chmod(key, 0o600)
    if not pub.exists():
        proc.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    return key, pub


def _escape(rel: str) -> tuple[str, str]:
    """GNU sha256sum escaping: names with ``\\`` or newline get a leading backslash."""
    if "\\" in rel or "\n" in rel or "\r" in rel:
        return "\\", rel.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
    return "", rel


def list_files(run_dir: Path) -> list[str]:
    out: list[str] = []
    for root, dirs, files in os.walk(run_dir):
        dirs.sort()
        for name in files:
            full = Path(root) / name
            rel = full.relative_to(run_dir).as_posix()
            if rel in EXCLUDED or full.is_symlink():
                continue
            out.append(rel)
    return sorted(out)


def write_list(run_dir: Path) -> Path:
    lines = []
    for rel in list_files(run_dir):
        digest = hashing.sha256_file(run_dir / rel)
        prefix, name = _escape(rel)
        lines.append(f"{prefix}{digest}  {name}\n")
    target = run_dir / LIST_NAME
    tmp = run_dir / f".{LIST_NAME}.tmp"
    tmp.write_text("".join(lines), encoding="utf-8", newline="\n")
    tmp.replace(target)
    return target


@dataclass
class SignResult:
    list_path: Path
    sig_path: Path | None
    pub_path: Path | None
    files: int
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "list": self.list_path.name,
            "signature": self.sig_path.name if self.sig_path else None,
            "public_key": self.pub_path.name if self.pub_path else None,
            "files": self.files,
            "error": self.error,
            "verify_commands": [
                "sha256sum -c outputs.sha256",
                "openssl pkeyutl -verify -pubin -inkey outputs.sha256.pub.pem -rawin "
                "-in outputs.sha256 -sigfile outputs.sha256.sig",
            ],
        }


def hash_and_sign(run_dir: Path, output_root: Path) -> SignResult:
    """Write ``outputs.sha256`` for ``run_dir`` and sign it with the OUTPUT key."""
    pub_copy: Path | None = None
    error = ""
    try:
        key, pub = ensure_key(output_root)
        pub_copy = run_dir / PUB_NAME
        shutil.copyfile(pub, pub_copy)
    except (proc.ToolError, OSError) as exc:
        key = None
        error = f"signing key unavailable: {exc}"
    listing = write_list(run_dir)
    count = len(listing.read_text(encoding="utf-8").splitlines())
    sig = run_dir / SIG_NAME
    if key is None:
        sig.unlink(missing_ok=True)
        return SignResult(listing, None, pub_copy, count, error)
    try:
        proc.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(listing),
                "-out",
                str(sig),
            ]
        )
    except proc.ToolError as exc:
        sig.unlink(missing_ok=True)
        return SignResult(listing, None, pub_copy, count, f"signing failed: {exc}")
    return SignResult(listing, sig, pub_copy, count)


def verify(run_dir: Path) -> list[str]:
    """Check every hash and the signature. Returns problems; empty means the run verifies."""
    problems: list[str] = []
    listing = run_dir / LIST_NAME
    if not listing.exists():
        return [f"{LIST_NAME} is missing"]
    listed: set[str] = set()
    for line in listing.read_text(encoding="utf-8").splitlines():
        escaped = line.startswith("\\")
        body = line[1:] if escaped else line
        digest, _, name = body.partition("  ")
        if escaped:
            name = name.replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\")
        listed.add(name)
        path = run_dir / name
        if not path.is_file():
            problems.append(f"missing: {name}")
        elif hashing.sha256_file(path) != digest:
            problems.append(f"changed: {name}")
    for rel in list_files(run_dir):
        if rel not in listed:
            problems.append(f"not listed: {rel}")
    sig, pub = run_dir / SIG_NAME, run_dir / PUB_NAME
    if not sig.exists() or not pub.exists():
        problems.append("signature or public key is missing")
        return problems
    res = proc.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(pub),
            "-rawin",
            "-in",
            str(listing),
            "-sigfile",
            str(sig),
        ],
        check=False,
    )
    if res.returncode != 0:
        problems.append("signature does not verify")
    return problems
