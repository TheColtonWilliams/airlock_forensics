"""Per-run output hashes and signature (tasks 2B.17, 4C.25).

``outputs.sha256`` lists every file in the run folder in ``sha256sum`` format, so
``sha256sum -c outputs.sha256`` checks it on Linux. ``outputs.sha256.sig`` is a raw Ed25519
signature of that list. The public key is copied into each run as ``outputs.sha256.pub.pem``.

The private key is not on the output drive. It lives on the AIRLOCK root filesystem at
``/var/lib/airlock/signing/<key id>/key.pem`` (root:root, 0600, folder 0700), one key per output
drive. The output drive holds only ``.airlock/signing/key-id`` (which key signs for it) and a copy
of the public key. A key is made the first time an output drive is used on this system, and its
public-key fingerprint is written to the session log on the root filesystem
(``signing_key_created``), so the fingerprint can be checked against a record that is not on the
output drive. See docs/known-limitations.md for what the signature does and does not show.

Re-signing a finished run (``evidence-report RUN_DIR``, ``forensic-analyze --purge-run``) goes
through :func:`resign`: the run is verified first and the command refuses when anything other
than the files it replaces has changed, unless forced (which is logged). The previous list,
signature and public key are kept as ``outputs.sha256.prev-<n>``, ``outputs.sha256.prev-<n>.sig``
and ``outputs.sha256.prev-<n>.pub.pem``. Those history files are listed in the new
``outputs.sha256``, so the newer signature covers them; only the current list and signature are
left out of the list.

Verify a run folder by hand (from inside it)::

    sha256sum -c outputs.sha256
    openssl pkeyutl -verify -pubin -inkey outputs.sha256.pub.pem -rawin \\
        -in outputs.sha256 -sigfile outputs.sha256.sig
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock_common import hashing, jsonio, paths, proc, sessionlog, timeutil

LIST_NAME = "outputs.sha256"
SIG_NAME = "outputs.sha256.sig"
PUB_NAME = "outputs.sha256.pub.pem"
HISTORY_PREFIX = "outputs.sha256.prev-"
RUN_LOG = "logs/run.jsonl"
# forensic-analyze.pid exists only while the run is going; it is removed when the run ends.
EXCLUDED = frozenset({LIST_NAME, SIG_NAME, "forensic-analyze.pid"})
ID_NAME = "key-id"
DEFAULT_TOOL = "forensic-analyze"
_ID_RE = re.compile(r"[0-9a-f]{32}")
_HISTORY_RE = re.compile(re.escape(HISTORY_PREFIX) + r"([0-9]+)")
_UNESCAPE_RE = re.compile(r"\\(\\|n|r)")
_UNESCAPES = {"\\": "\\", "n": "\n", "r": "\r"}
_PROBLEM_PREFIXES = ("changed: ", "missing: ", "not listed: ")
_LOGGED_PROBLEMS = 100


class SigningError(RuntimeError):
    """The key could not be made or used."""


class ResignRefused(SigningError):
    """The run folder fails verification beyond the files the command replaces."""

    def __init__(self, blocking: list[str]) -> None:
        self.blocking = list(blocking)
        shown = "; ".join(self.blocking[:10])
        more = f" (and {len(self.blocking) - 10} more)" if len(self.blocking) > 10 else ""
        super().__init__(
            f"the run folder does not verify: {shown}{more}. It was not re-signed, so the earlier "
            "signed list still shows the difference"
        )


# ----------------------------------------------------------------------------------- keys


def output_meta_dir(output_root: Path) -> Path:
    """``<OUTPUT>/.airlock/signing``: the key id and a public-key copy. Never the private key."""
    return output_root / ".airlock" / "signing"


def key_store() -> Path:
    """Private keys on the root filesystem (``/var/lib/airlock/signing``), root only."""
    return paths.state_dir() / "signing"


def read_key_id(output_root: Path) -> str | None:
    """The key id recorded on the output drive, or None when there is none or it is malformed."""
    try:
        text = (output_meta_dir(output_root) / ID_NAME).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return text if _ID_RE.fullmatch(text) else None


def key_dir(output_root: Path) -> Path:
    """The root-filesystem folder that holds this output drive's private key."""
    kid = read_key_id(output_root)
    if kid is None:
        raise SigningError(f"{output_root} has no signing key id yet")
    return key_store() / kid


def public_key_sha256(pub: Path) -> str:
    """SHA-256 of the public-key PEM file: the fingerprint recorded in run.json and the logs."""
    return hashing.sha256_file(pub)


def _root_only(path: Path, mode: int) -> None:
    os.chmod(path, mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def _publish(output_root: Path, kid: str, pub: Path) -> None:
    """Write the key id and a public-key copy to the output drive (the id last)."""
    meta = output_meta_dir(output_root)
    meta.mkdir(parents=True, exist_ok=True)
    pub_copy = meta / "pub.pem"
    if not pub_copy.is_file() or pub_copy.read_bytes() != pub.read_bytes():
        shutil.copyfile(pub, pub_copy)
    id_file = meta / ID_NAME
    if read_key_id(output_root) != kid:
        tmp = meta / f".{ID_NAME}.tmp"
        tmp.write_text(kid + "\n", encoding="ascii")
        tmp.replace(id_file)


def _new_key(output_root: Path, previous: str | None, tool: str) -> tuple[Path, Path]:
    store = key_store()
    store.mkdir(parents=True, exist_ok=True)
    _root_only(store, 0o700)
    kid = secrets.token_hex(16)
    folder = store / kid
    folder.mkdir(mode=0o700)
    _root_only(folder, 0o700)
    key, pub = folder / "key.pem", folder / "pub.pem"
    old = os.umask(0o077)
    try:
        proc.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)])
        proc.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    finally:
        os.umask(old)
    _root_only(key, 0o600)
    _root_only(pub, 0o600)
    fp = public_key_sha256(pub)
    info = {
        "key_id": kid,
        "created": timeutil.iso(),
        "output_root": str(output_root),
        "public_key_sha256": fp,
        "previous_key_id": previous,
    }
    jsonio.dump_json(folder / "key.json", info)
    _publish(output_root, kid, pub)
    with contextlib.suppress(OSError):
        sessionlog.log_event(tool, "signing_key_created", **info)
    return key, pub


def ensure_key(output_root: Path, *, tool: str = DEFAULT_TOOL) -> tuple[Path, Path]:
    """Return (private key, public key) for this output drive, creating them on first use.

    The private key is on the root filesystem. When the output drive names a key this system
    does not hold (first use here, or the drive was used on another AIRLOCK drive), a new key
    and id are made and logged.
    """
    kid = read_key_id(output_root)
    if kid is not None:
        folder = key_store() / kid
        key, pub = folder / "key.pem", folder / "pub.pem"
        if key.is_file():
            if key.stat().st_mode & 0o077:
                _root_only(key, 0o600)
            if not pub.is_file():
                proc.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
            _publish(output_root, kid, pub)
            return key, pub
    return _new_key(output_root, kid, tool)


def known_key(pub: Path) -> str | None:
    """The id of the key on this system whose public key is ``pub``, or None."""
    try:
        want = pub.read_bytes()
        for cand in sorted(key_store().glob("*/pub.pem")):
            if _ID_RE.fullmatch(cand.parent.name) and cand.read_bytes() == want:
                return cand.parent.name
    except OSError:
        return None
    return None


# ----------------------------------------------------------------------------------- lists


def _escape(rel: str) -> tuple[str, str]:
    """GNU sha256sum escaping: names with ``\\`` or newline get a leading backslash."""
    if "\\" in rel or "\n" in rel or "\r" in rel:
        return "\\", rel.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
    return "", rel


def _unescape(name: str) -> str:
    """Undo :func:`_escape` in one left-to-right pass, as GNU sha256sum does."""
    return _UNESCAPE_RE.sub(lambda m: _UNESCAPES[m.group(1)], name)


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
    key_id: str = ""
    public_key_sha256: str = ""
    list_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "list": self.list_path.name,
            "signature": self.sig_path.name if self.sig_path else None,
            "public_key": self.pub_path.name if self.pub_path else None,
            "files": self.files,
            "error": self.error,
            "key_id": self.key_id,
            "public_key_sha256": self.public_key_sha256,
            "list_sha256": self.list_sha256,
            "verify_commands": [
                "sha256sum -c outputs.sha256",
                "openssl pkeyutl -verify -pubin -inkey outputs.sha256.pub.pem -rawin "
                "-in outputs.sha256 -sigfile outputs.sha256.sig",
            ],
        }


def hash_and_sign(run_dir: Path, output_root: Path) -> SignResult:
    """Write ``outputs.sha256`` for ``run_dir`` and sign it with this output drive's key."""
    pub_copy: Path | None = None
    error = ""
    kid = fp = ""
    try:
        key, pub = ensure_key(output_root)
        kid = key.parent.name
        fp = public_key_sha256(pub)
        pub_copy = run_dir / PUB_NAME
        shutil.copyfile(pub, pub_copy)
    except (proc.ToolError, OSError, SigningError) as exc:
        key = None
        error = f"signing key unavailable: {exc}"
    listing = write_list(run_dir)
    count = len(listing.read_text(encoding="utf-8").splitlines())
    list_fp = hashing.sha256_file(listing)
    sig = run_dir / SIG_NAME
    if key is None:
        sig.unlink(missing_ok=True)
        return SignResult(listing, None, pub_copy, count, error, kid, fp, list_fp)
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
        return SignResult(
            listing, None, pub_copy, count, f"signing failed: {exc}", kid, fp, list_fp
        )
    return SignResult(listing, sig, pub_copy, count, "", kid, fp, list_fp)


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
            name = _unescape(name)
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


# ----------------------------------------------------------------------------------- re-signing


def problem_path(problem: str) -> str | None:
    """The run-relative file a :func:`verify` problem is about, or None for list/signature."""
    for prefix in _PROBLEM_PREFIXES:
        if problem.startswith(prefix):
            return problem[len(prefix) :]
    return None


def blocking_problems(problems: list[str], replaces: Callable[[str], bool]) -> list[str]:
    """Problems that are not about a file the command itself replaces or removes."""
    out = []
    for p in problems:
        rel = problem_path(p)
        if rel is None or not replaces(rel):
            out.append(p)
    return out


def history_numbers(run_dir: Path) -> list[int]:
    nums = []
    for p in run_dir.glob(f"{HISTORY_PREFIX}*"):
        m = _HISTORY_RE.fullmatch(p.name)
        if m:
            nums.append(int(m.group(1)))
    return sorted(nums)


def keep_history(run_dir: Path) -> str | None:
    """Copy the current list, signature and public key to the next ``outputs.sha256.prev-<n>``."""
    listing = run_dir / LIST_NAME
    if not listing.is_file():
        return None
    nums = history_numbers(run_dir)
    base = f"{HISTORY_PREFIX}{(nums[-1] + 1) if nums else 1}"
    for src, suffix in (
        (listing, ""),
        (run_dir / SIG_NAME, ".sig"),
        (run_dir / PUB_NAME, ".pub.pem"),
    ):
        if src.is_file():
            shutil.copyfile(src, run_dir / f"{base}{suffix}")
    return base


def check_before_resign(
    run_dir: Path,
    output_root: Path,
    replaces: Callable[[str], bool],
    *,
    force: bool = False,
    tool: str = DEFAULT_TOOL,
) -> list[str]:
    """Verify ``run_dir`` as it stands and make sure the signing key can be used.

    Returns every problem :func:`verify` found. Raises :class:`ResignRefused` when a problem is
    about anything other than a file ``replaces`` accepts (or about the list or signature
    itself) and ``force`` is false, and :class:`SigningError` (or ``OSError``) when the key
    cannot be used, so nothing is rewritten that could not be signed again.
    """
    problems = verify(run_dir)
    blocking = blocking_problems(problems, replaces)
    if blocking and not force:
        raise ResignRefused(blocking)
    try:
        ensure_key(output_root, tool=tool)
    except proc.ToolError as exc:
        raise SigningError(f"signing key unavailable: {exc}") from exc
    return problems


def resign(
    run_dir: Path,
    output_root: Path,
    replaces: Callable[[str], bool],
    *,
    force: bool = False,
    tool: str = DEFAULT_TOOL,
    reason: str,
) -> SignResult:
    """Re-hash and re-sign a finished run after ``tool`` replaced some of its files.

    Checks first (:func:`check_before_resign`), keeps the previous list, signature and public
    key as history files, records the re-sign in the run log (before hashing, so the record is
    covered) and in the session log on the root filesystem, then signs.
    """
    problems = check_before_resign(run_dir, output_root, replaces, force=force, tool=tool)
    forced = blocking_problems(problems, replaces)
    history = keep_history(run_dir)
    record: dict[str, Any] = {
        "tool": tool,
        "reason": reason,
        "forced": bool(forced),
        "problems_overridden": forced[:_LOGGED_PROBLEMS],
        "problems_overridden_count": len(forced),
        "replaced_count": len(problems) - len(forced),
        "history": history,
    }
    jsonio.append_line(
        run_dir / RUN_LOG,
        {"ts": timeutil.iso(), "event": "outputs_resigned", "run_id": run_dir.name, **record},
    )
    res = hash_and_sign(run_dir, output_root)
    with contextlib.suppress(OSError):
        fields = {k: v for k, v in record.items() if k != "tool"}
        sessionlog.log_event(
            tool, "outputs_resigned", run_dir=str(run_dir), **fields, **res.to_dict()
        )
    return res
