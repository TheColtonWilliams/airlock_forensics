#!/usr/bin/env python3
"""Host-side asset fetcher core (tasks 2B.11, 4A.4, 4A.7, 4B.15). Run by scripts/fetch-assets.sh.

Downloads every file the chosen profile needs from the manifest into a download cache, checks
its SHA-256, copies it onto the ASSETS partition, checks it again there, and writes
``profile.json`` last (docs/dev/contract.md section 6). scripts/fetch-assets.ps1 does the same
on Windows; tests/functional/test_fetch_assets.sh runs both against the same server.

Rules this file keeps:

* It writes only below ``--assets`` (the ASSETS mount) and ``--cache``.
* A file whose pin has ``sha256: null`` and ``verify: sha256`` is refused (not pinned yet).
  ``verify: vendor_signature`` and ``trusted_at_staging`` files change daily; their observed
  SHA-256 is recorded in profile.json and checked again on the drive.
* The abuse.ch key arrives in the ``AIRLOCK_ABUSECH_KEY`` environment variable, a key file
  (``--abuse-key-file``) or a hidden prompt. It is sent only as the ``Auth-Key`` header of the
  files tagged ``malwarebazaar``, never across a redirect, and never written anywhere.
* Downloads resume from ``<cache>/partial/<id>.part`` with an HTTP Range request.

Standard library only, except PyYAML when ``--profile`` names a YAML file.

Usage:
  fetch_assets.py --assets DIR --manifest FILE [--profile NAME|FILE] [--cache DIR]
                  [--refresh] [--yes] [--abuse-key-file FILE] [--examiner TEXT]
                  [--agency TEXT] [--case-prefix TEXT] [--dry-run] [--fetcher-name NAME]
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import getpass
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

FETCHER_VERSION = "0.1.0-dev"
USER_AGENT = f"airlock-fetch-assets/{FETCHER_VERSION}"
CHUNK = 1024 * 1024
KEY_ENV = "AIRLOCK_ABUSECH_KEY"
KEY_TAG = "malwarebazaar"
KEY_HEADER = "Auth-Key"
MOVING = frozenset({"vendor_signature", "trusted_at_staging"})
TIERS: tuple[str, ...] = ("tier0", "tier1", "tier2", "tier3", "tier4")
BOOL_FEATURES: tuple[str, ...] = (
    "autopsy",
    "classifiers",
    "clamav",
    "eztools",
    "malwarebazaar",
    "nsrl",
    "nvidia_proprietary",
    "sift",
    "whisper",
    "yara",
)
TMP_SUFFIX = ".airlock-tmp"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TIMEOUT = float(os.environ.get("AIRLOCK_FETCH_TIMEOUT", "60"))
ATTEMPTS = 3


class FetchError(Exception):
    """One file could not be fetched or staged; the message says why."""


class CacheCorrupt(FetchError):
    """A file in the download cache no longer matches its SHA-256."""


class UsageError(Exception):
    """The command line or an input file is wrong; the run stops before writing anything."""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def human(n: int | None) -> str:
    if n is None:
        return "unknown size"
    size = float(n)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{n} bytes"  # pragma: no cover


def say(msg: str) -> None:
    print(f"fetch-assets: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"fetch-assets: warning: {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- profile resolution


def active_tags(name: str, features: dict[str, Any]) -> set[str]:
    """Same rule as scripts/gen-manifest.py: the profile name, ``all``, and enabled features."""
    tags = {name, "all"}
    for tier in features.get("ai_tiers") or []:
        tags.add(f"ai_{tier}")
    for key in BOOL_FEATURES:
        if features.get(key) is True:
            tags.add(key)
    return tags


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(
            f"cannot read the manifest {path} ({exc.strerror}). Run scripts/gen-manifest.py or "
            "pass --manifest with the manifest.json from the release."
        ) from exc
    except ValueError as exc:
        raise UsageError(f"the manifest {path} is not valid JSON. Download it again.") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema") != 1
        or not isinstance(data.get("files"), list)
    ):
        raise UsageError(f"{path} is not an AIRLOCK manifest (schema 1). Download it again.")
    return data


def _read_profile_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml  # noqa: PLC0415 - optional, only for YAML profile files
    except ImportError as exc:
        raise UsageError(
            f"{path} is not JSON and PyYAML is not installed to read it as YAML. "
            "Install python3-yaml or write the profile as JSON."
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise UsageError(f"{path} is neither valid JSON nor valid YAML: {exc}") from exc


def resolve_profile(manifest: dict[str, Any], arg: str) -> tuple[str, dict[str, Any], list[str]]:
    """Return (name, features, file ids) for a profile name or a profile file."""
    profiles: dict[str, Any] = manifest.get("profiles") or {}
    files = {f["id"]: f for f in manifest["files"]}
    path = Path(arg)
    if path.is_file():
        data = _read_profile_file(path)
        name = ""
        if isinstance(data, dict) and isinstance(data.get("profiles"), dict):
            if len(data["profiles"]) != 1:
                raise UsageError(f"{path} holds several profiles; keep exactly one.")
            name, data = next(iter(data["profiles"].items()))
        if not isinstance(data, dict):
            raise UsageError(
                f"{path} must hold a mapping with 'features' (and optionally 'files')."
            )
        name = str(data.get("name") or name or re.sub(r"\.(json|ya?ml)$", "", path.name))
        base = profiles.get(name) or {}
        features = data.get("features")
        if not isinstance(features, dict):
            features = dict(base.get("features") or {})
        if isinstance(data.get("files"), list):
            ids = sorted({str(i) for i in data["files"]})
        else:
            want = active_tags(name, features)
            ids = sorted(
                fid
                for fid, f in files.items()
                if f.get("stage", "assets") == "assets"
                and f.get("target")
                and want & set(f.get("profiles") or [])
            )
    else:
        name = re.sub(r"\.(json|ya?ml)$", "", arg)
        if name not in profiles:
            known = ", ".join(sorted(profiles)) or "none"
            raise UsageError(f"no profile named '{arg}' in the manifest (known: {known}).")
        features = dict(profiles[name].get("features") or {})
        ids = sorted(str(i) for i in profiles[name].get("files") or [])
    unknown = [i for i in ids if i not in files]
    if unknown:
        raise UsageError(
            "the profile names files the manifest does not have: " + ", ".join(unknown)
        )
    not_assets = [i for i in ids if not files[i].get("target")]
    if not_assets:
        raise UsageError("these are not ASSETS files (no target): " + ", ".join(not_assets))
    return name, features, ids


def safe_target(target: str) -> PurePosixPath:
    p = PurePosixPath(target)
    if (
        not target
        or p.is_absolute()
        or "\\" in target
        or ":" in target
        or "//" in target
        or target.endswith("/")
        or any(part in ("", ".", "..") for part in p.parts)
    ):
        raise UsageError(f"unsafe target path {target!r} in the manifest; refusing to stage it.")
    return p


# --------------------------------------------------------------------------- HTTP


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs (never a downgrade to http)."""

    def redirect_request(  # noqa: PLR0917 - signature fixed by urllib
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, "redirect to a non-https URL refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect())


def _request(
    url: str,
    *,
    key: str | None,
    method: str = "GET",
    range_from: int = 0,
    if_range: str | None = None,
) -> Any:
    if not url.lower().startswith("https://"):
        raise FetchError(f"refusing a non-https URL: {url}")
    # The scheme is checked just above: only https URLs reach urllib.
    req = urllib.request.Request(  # noqa: S310
        url, method=method, headers={"User-Agent": USER_AGENT}
    )
    if key:
        # Unredirected: urllib does not copy it to a redirected request, whatever the host.
        req.add_unredirected_header(KEY_HEADER, key)
    if range_from > 0:
        req.add_header("Range", f"bytes={range_from}-")
        if if_range:
            req.add_header("If-Range", if_range)
    return _OPENER.open(req, timeout=TIMEOUT)


def remote_size(url: str, key: str | None) -> int | None:
    try:
        with _request(url, key=key, method="HEAD") as resp:
            length = resp.headers.get("Content-Length")
            return int(length) if length and length.isdigit() else None
    except (OSError, ValueError, FetchError):
        return None


# --------------------------------------------------------------------------- files


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _fsync_dir(path: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _drop_cache(path: Path) -> None:
    """Ask the kernel to forget cached pages so the re-hash reads from the device."""
    if not hasattr(os, "posix_fadvise"):
        return
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)


def write_json_atomic(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=TMP_SUFFIX, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def copy_verified(src: Path, dest: Path, expected: str) -> None:
    """Copy src to dest via a temp file, checking the SHA-256 of src while reading it and of dest
    after it is on disk. Raises FetchError (and leaves nothing behind) on a mismatch."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + TMP_SUFFIX)
    h = hashlib.sha256()
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            for block in iter(lambda: fin.read(CHUNK), b""):
                h.update(block)
                fout.write(block)
            fout.flush()
            os.fsync(fout.fileno())
        if h.hexdigest() != expected:
            raise CacheCorrupt(
                f"the cached copy {src} does not match its SHA-256 any more; it was removed. "
                "Rerun to download it again."
            )
        _drop_cache(tmp)
        if sha256_of(tmp) != expected:
            raise FetchError(
                f"the copy on ASSETS ({dest}) did not read back with the right SHA-256. "
                "The drive may be failing; try another drive or rerun."
            )
        os.replace(tmp, dest)
        _fsync_dir(dest.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- cache


@dataclass
class Cache:
    root: Path

    def __post_init__(self) -> None:
        for sub in ("blobs", "partial", "moving"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def blob(self, sha: str) -> Path:
        return self.root / "blobs" / sha

    def part(self, fid: str) -> Path:
        return self.root / "partial" / f"{fid}.part"

    def part_meta(self, fid: str) -> Path:
        return self.root / "partial" / f"{fid}.part.json"

    def moving_record(self, fid: str) -> Path:
        return self.root / "moving" / f"{fid}.json"

    def blob_in_use(self, sha: str) -> bool:
        """True when a daily-file record still points at this blob."""
        for rec in (self.root / "moving").glob("*.json"):
            with contextlib.suppress(OSError, ValueError):
                if json.loads(rec.read_text(encoding="utf-8")).get("sha256") == sha:
                    return True
        return False

    def cached_moving(self, fid: str, url: str) -> tuple[Path, str] | None:
        try:
            rec = json.loads(self.moving_record(fid).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        sha = str(rec.get("sha256") or "")
        if rec.get("url") != url or not SHA_RE.match(sha) or not self.blob(sha).is_file():
            return None
        return self.blob(sha), sha


def _progress(fid: str, total: int | None) -> Callable[[int], None]:
    tty = sys.stderr.isatty()
    last = [-1]

    def report(done: int) -> None:
        if not tty:
            return
        pct = int(done * 100 / total) if total else -1
        if pct == last[0]:
            return
        last[0] = pct
        shown = f"{pct:3d}% " if pct >= 0 else ""
        print(f"\r  {fid}: {shown}{human(done)}", end="", file=sys.stderr, flush=True)

    return report


def _attempts(
    entry: dict[str, Any], part: Path, meta: dict[str, Any], meta_path: Path, key: str | None
) -> None:
    """Try the download up to ATTEMPTS times, resuming the partial file each time."""
    expected = entry.get("sha256")
    last_error = "no data"
    for _attempt in range(ATTEMPTS):
        have = part.stat().st_size if part.exists() else 0
        validator = None if expected else (meta.get("etag") or meta.get("last_modified"))
        if have and not expected and not validator:
            part.unlink()  # a daily file without a validator cannot be resumed safely
            have = 0
        try:
            _fetch_into(
                entry,
                part,
                meta=meta,
                meta_path=meta_path,
                key=key,
                have=have,
                validator=validator,
            )
            return
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and have:
                return  # the partial file is already complete; the hash check decides
            last_error = f"the server answered HTTP {exc.code}"
            if exc.code in (401, 403) and entry_needs_key(entry):
                last_error += " (check the abuse.ch key)"
            if 400 <= exc.code < 500 and exc.code not in (408, 429):
                break
        except FetchError as exc:
            part.unlink(missing_ok=True)
            last_error = str(exc)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            last_error = str(getattr(exc, "reason", None) or exc) or type(exc).__name__
    raise FetchError(f"download failed: {last_error}. Rerun the same command to resume.")


def download(entry: dict[str, Any], cache: Cache, key: str | None) -> tuple[Path, str]:
    """Download one manifest file into the cache, resuming a partial file. Returns (blob, sha)."""
    fid, url = entry["id"], entry["url"]
    expected = entry.get("sha256")
    part, meta_path = cache.part(fid), cache.part_meta(fid)
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    if meta.get("url") != url or meta.get("sha256") != expected:
        part.unlink(missing_ok=True)
        meta = {"url": url, "sha256": expected}
    _attempts(entry, part, meta, meta_path, key)
    if not part.exists():
        raise FetchError("download failed: no data. Rerun the same command to resume.")
    sha = sha256_of(part)
    if expected and sha != expected:
        part.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)
        raise FetchError(
            "the download does not match its pinned SHA-256 (got "
            f"{sha[:16]}..., want {expected[:16]}...). It was deleted. The file on the server "
            "changed or was tampered with; do not use it. Report it, or retry later."
        )
    size = entry.get("size")
    if expected is None and isinstance(size, int) and size and part.stat().st_size != size:
        warn(f"{fid}: size {part.stat().st_size} differs from the manifest's {size}")
    blob = cache.blob(sha)
    os.replace(part, blob)
    meta_path.unlink(missing_ok=True)
    if expected is None:
        old = cache.cached_moving(fid, url)
        write_json_atomic(
            cache.moving_record(fid),
            {"fetched_at": utc_now(), "sha256": sha, "size": blob.stat().st_size, "url": url},
        )
        if old and old[1] != sha and not cache.blob_in_use(old[1]):
            old[0].unlink(missing_ok=True)
    return blob, sha


def _fetch_into(
    entry: dict[str, Any],
    part: Path,
    *,
    meta: dict[str, Any],
    meta_path: Path,
    key: str | None,
    have: int,
    validator: str | None,
) -> None:
    with _request(
        entry["url"],
        key=key if entry_needs_key(entry) else None,
        range_from=have,
        if_range=validator,
    ) as resp:
        status = getattr(resp, "status", 200)
        mode = "wb"
        if have and status == 206:
            crange = resp.headers.get("Content-Range", "")
            if not crange.startswith(f"bytes {have}-"):
                raise FetchError(f"the server sent an unexpected range ({crange}); rerun.")
            mode = "ab"
        else:
            have = 0
        meta["etag"] = resp.headers.get("ETag")
        meta["last_modified"] = resp.headers.get("Last-Modified")
        write_json_atomic(meta_path, meta)
        length = resp.headers.get("Content-Length")
        total = have + int(length) if length and length.isdigit() else entry.get("size")
        report = _progress(entry["id"], total)
        done = have
        with open(part, mode) as out:
            for block in iter(lambda: resp.read(CHUNK), b""):
                out.write(block)
                done += len(block)
                report(done)
            out.flush()
            os.fsync(out.fileno())
        if sys.stderr.isatty():
            print(file=sys.stderr)
        if total and done < total:
            raise OSError(f"connection closed after {done} of {total} bytes")


def entry_needs_key(entry: dict[str, Any]) -> bool:
    return KEY_TAG in (entry.get("profiles") or [])


# --------------------------------------------------------------------------- plan


@dataclass
class Item:
    entry: dict[str, Any]
    dest: Path
    action: str = ""  # keep | copy | download
    source: Path | None = None
    sha: str = ""
    size: int | None = None
    staged_at: str = ""


@dataclass
class Plan:
    items: list[Item] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    prune: list[Path] = field(default_factory=list)


def read_old_profile(assets: Path) -> dict[str, Any]:
    try:
        data = json.loads((assets / "profile.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _try_keep(item: Item, prev: dict[str, Any]) -> bool:
    """True when the file already on ASSETS is the one wanted (checked by SHA-256)."""
    expected = item.entry.get("sha256")
    want = expected or str(prev.get("sha256") or "")
    if not want or not item.dest.is_file():
        return False
    size_ok = expected is None or item.size is None or item.dest.stat().st_size == item.size
    if not size_ok or sha256_of(item.dest) != want:
        return False
    item.action, item.sha, item.size = "keep", want, item.dest.stat().st_size
    if prev.get("sha256") == want and prev.get("target") == item.entry["target"]:
        item.staged_at = str(prev.get("staged_at") or "")
    return True


def _choose_source(item: Item, cache: Cache, *, key: str | None, refresh: bool) -> None:
    entry = item.entry
    expected = entry.get("sha256")
    if expected and cache.blob(expected).is_file():
        item.action, item.source, item.sha = "copy", cache.blob(expected), expected
        item.size = cache.blob(expected).stat().st_size
    elif not expected and not refresh and (hit := cache.cached_moving(entry["id"], entry["url"])):
        item.action, item.source, item.sha = "copy", hit[0], hit[1]
        item.size = hit[0].stat().st_size
    else:
        item.action = "download"
        if item.size is None:
            item.size = remote_size(entry["url"], key if entry_needs_key(entry) else None)


def plan_items(
    entries: list[dict[str, Any]],
    assets: Path,
    cache: Cache,
    *,
    key: str | None,
    refresh: bool,
) -> Plan:
    plan = Plan()
    old = read_old_profile(assets)
    old_files = {
        str(f.get("id")): f for f in old.get("files") or [] if isinstance(f, dict) and f.get("id")
    }
    for entry in entries:
        fid = entry["id"]
        dest = assets / "files" / Path(*safe_target(entry["target"]).parts)
        moving = entry.get("verify") in MOVING
        item = Item(entry=entry, dest=dest, size=entry.get("size"))
        prev = old_files.get(fid) or {}
        if entry.get("sha256") is None and not moving:
            plan.skipped[fid] = (
                "not pinned yet: the manifest has no SHA-256 for it, so it cannot be checked"
            )
        elif entry_needs_key(entry) and not key:
            if _try_keep(item, prev):
                warn(f"{fid}: no abuse.ch key given; keeping the copy staged {item.staged_at}")
                plan.items.append(item)
            else:
                plan.skipped[fid] = "no abuse.ch key given; rerun with a key to stage it"
        elif not (moving and refresh) and _try_keep(item, prev):
            plan.items.append(item)
        else:
            _choose_source(item, cache, key=key, refresh=refresh)
            plan.items.append(item)
    kept = {i.entry["target"] for i in plan.items}
    for prev in old_files.values():
        target = str(prev.get("target") or "")
        if not target or target in kept:
            continue
        try:
            path = assets / "files" / Path(*safe_target(target).parts)
        except UsageError:
            continue
        if path.is_file():
            plan.prune.append(path)
    return plan


def check_space(plan: Plan, assets: Path, cache: Cache) -> None:
    to_copy = [i for i in plan.items if i.action in ("copy", "download")]
    unknown = [i.entry["id"] for i in to_copy if i.size is None]
    need = sum(i.size or 0 for i in to_copy)
    reclaim = sum(i.dest.stat().st_size for i in to_copy if i.dest.is_file())
    reclaim += sum(p.stat().st_size for p in plan.prune)
    free = shutil.disk_usage(assets).free
    net = max(0, need - reclaim)
    say(f"ASSETS ({assets}): {human(free)} free; this profile needs {human(net)} more")
    downloads = [i for i in plan.items if i.action == "download"]
    dl_need = sum(i.size or 0 for i in downloads) - sum(
        cache.part(i.entry["id"]).stat().st_size
        for i in downloads
        if cache.part(i.entry["id"]).exists()
    )
    cache_free = shutil.disk_usage(cache.root).free
    say(f"download cache ({cache.root}): {human(cache_free)} free; downloads need {human(dl_need)}")
    if unknown:
        warn(
            f"{len(unknown)} file(s) have no known size ({', '.join(unknown)}); "
            "the space check cannot count them"
        )
    if net > free:
        raise UsageError(
            f"not enough space on ASSETS: {human(free)} free, {human(net)} needed. "
            "Pick a smaller profile (--profile minimal) or use a larger drive."
        )
    if dl_need > cache_free:
        raise UsageError(
            f"not enough space for the download cache: {human(cache_free)} free, "
            f"{human(dl_need)} needed. Free some space or pass --cache DIR on a larger disk."
        )


# --------------------------------------------------------------------------- main


def read_key(args: argparse.Namespace, needs_key: bool, interactive: bool) -> str | None:
    key = os.environ.pop(KEY_ENV, "") or ""
    if args.abuse_key_file:
        try:
            with open(args.abuse_key_file, encoding="utf-8") as fh:
                key = fh.readline().strip()
        except OSError as exc:
            raise UsageError(
                f"cannot read the key file {args.abuse_key_file} ({exc.strerror})."
            ) from exc
    if not key and needs_key and interactive:
        key = getpass.getpass(
            "abuse.ch Auth-Key for the MalwareBazaar hash list (input hidden; "
            "press Enter to skip it): "
        ).strip()
    if key and not re.fullmatch(r"[\x21-\x7e]{8,200}", key):
        raise UsageError("the abuse.ch key has spaces or odd characters; check it and rerun.")
    return key or None


def choose_profile(args: argparse.Namespace, manifest: dict[str, Any], interactive: bool) -> str:
    if args.profile:
        return str(args.profile)
    if not interactive:
        return "default"
    profiles = manifest.get("profiles") or {}
    print("Profiles:")
    for name in sorted(profiles):
        print(f"  {name}: {profiles[name].get('description', '')}")
    answer = input("Which profile? [default]: ").strip()
    return answer or "default"


def confirm(question: str, interactive: bool) -> bool:
    if not interactive:
        return True
    answer = input(f"{question} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def copy_release_manifest(manifest_path: Path, assets: Path) -> None:
    dest = assets / "manifest.json"
    sig = manifest_path.with_name(manifest_path.name + ".sig")
    with contextlib.suppress(OSError):
        if dest.exists() and os.path.samefile(manifest_path, dest):
            return
    if not sig.is_file():
        (assets / "manifest.json.sig").unlink(missing_ok=True)
        warn(
            "the manifest has no signature file (manifest.json.sig); the drive will check "
            "staged files against the manifest built into it instead"
        )
    for src, name in ((manifest_path, "manifest.json"), (sig, "manifest.json.sig")):
        target = assets / name
        if not src.is_file():
            continue
        tmp = target.with_name(name + TMP_SUFFIX)
        shutil.copyfile(src, tmp)
        with open(tmp, "rb+") as fh:
            os.fsync(fh.fileno())
        os.replace(tmp, target)


def clean_leftovers(assets: Path) -> None:
    files = assets / "files"
    if not files.is_dir():
        return
    for path in sorted(files.rglob(f"*{TMP_SUFFIX}")):
        if path.is_file():
            path.unlink()
    for path in sorted((p for p in files.rglob("*") if p.is_dir()), reverse=True):
        with contextlib.suppress(OSError):
            path.rmdir()  # only empty folders


def stage_items(plan: Plan, cache: Cache, key: str | None, now: str) -> list[str]:
    """Download and copy every planned file. Returns the ids that failed."""
    failures: list[str] = []
    for item in plan.items:
        fid = item.entry["id"]
        try:
            if item.action == "download":
                say(f"downloading {fid} ({human(item.size)})")
                item.source, item.sha = download(item.entry, cache, key)
            if item.action in ("copy", "download"):
                if item.source is None:
                    raise FetchError("no source file (internal error); rerun")
                copy_verified(item.source, item.dest, item.sha)
                if not item.entry.get("sha256"):
                    say(f"{fid}: recorded SHA-256 {item.sha} ({item.entry.get('verify')})")
                item.staged_at = now
                say(f"staged {fid} -> files/{item.entry['target']} (SHA-256 checked twice)")
            item.staged_at = item.staged_at or now
        except (FetchError, OSError) as exc:
            if isinstance(exc, CacheCorrupt) and item.source:
                item.source.unlink(missing_ok=True)
            failures.append(fid)
            plan.skipped[fid] = f"failed: {exc}"
            warn(f"{fid}: {exc}")
    return failures


def profile_document(
    args: argparse.Namespace,
    name: str,
    features: dict[str, Any],
    plan: Plan,
    *,
    failures: list[str],
    now: str,
) -> dict[str, Any]:
    """profile.json (docs/dev/contract.md section 6). Never holds the abuse.ch key."""
    staged = [i for i in plan.items if i.entry["id"] not in failures]
    files = [
        {
            "id": i.entry["id"],
            "sha256": i.sha,
            "target": i.entry["target"],
            "verify": i.entry.get("verify", "sha256"),
            "staged_at": i.staged_at,
        }
        for i in staged
    ]
    return {
        "schema": 1,
        "profile": name,
        "features": features,
        "staged_at": now,
        "fetcher": f"{args.fetcher_name} {FETCHER_VERSION}",
        "files": sorted(files, key=lambda f: f["id"]),
        "skipped": [{"id": k, "reason": v} for k, v in sorted(plan.skipped.items())],
        "case_defaults": {
            "examiner": args.examiner,
            "agency": args.agency,
            "case_id_prefix": args.case_prefix,
        },
    }


def run(args: argparse.Namespace) -> int:
    interactive = sys.stdin.isatty() and not args.yes
    assets = Path(args.assets)
    if not assets.is_dir():
        raise UsageError(f"{assets} is not a folder. Pass the mount point of the ASSETS partition.")
    manifest_path = Path(args.manifest)
    manifest = load_manifest(manifest_path)
    name, features, ids = resolve_profile(manifest, choose_profile(args, manifest, interactive))
    by_id = {f["id"]: f for f in manifest["files"]}
    entries = [by_id[i] for i in ids]
    key = read_key(args, any(entry_needs_key(e) for e in entries), interactive)
    cache = Cache(Path(args.cache).expanduser())
    say(f"profile '{name}': {len(entries)} file(s); manifest release {manifest.get('release')}")
    plan = plan_items(entries, assets, cache, key=key, refresh=args.refresh)
    for fid, reason in sorted(plan.skipped.items()):
        warn(f"skipping {fid}: {reason}")
    counts = {a: sum(1 for i in plan.items if i.action == a) for a in ("keep", "copy", "download")}
    say(
        f"{counts['keep']} already on ASSETS and checked, {counts['copy']} to copy from the "
        f"cache, {counts['download']} to download, {len(plan.prune)} old file(s) to remove"
    )
    check_space(plan, assets, cache)
    if args.dry_run:
        say("dry run: nothing written")
        return 0
    if not confirm(f"Stage these files onto {assets}?", interactive):
        say("stopped; nothing was written")
        return 1
    clean_leftovers(assets)
    for path in plan.prune:
        path.unlink(missing_ok=True)
        say(f"removed {path.relative_to(assets)} (not in this profile)")
    now = utc_now()
    failures = stage_items(plan, cache, key, now)
    clean_leftovers(assets)
    copy_release_manifest(manifest_path, assets)
    doc = profile_document(args, name, features, plan, failures=failures, now=now)
    write_json_atomic(assets / "profile.json", doc)
    say(f"wrote profile.json: {len(doc['files'])} file(s) staged, {len(doc['skipped'])} skipped")
    if failures:
        print(
            f"fetch-assets: {len(failures)} file(s) failed ({', '.join(failures)}). "
            "The rest are staged. Rerun the same command to resume.",
            file=sys.stderr,
        )
        return 1
    say("done. Safely eject the drive, then boot it; it sets itself up offline.")
    return 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="fetch_assets.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--assets", required=True, help="mount point of the ASSETS partition")
    ap.add_argument("--manifest", required=True, help="manifest.json from the repo or release")
    ap.add_argument("--profile", help="profile name, or a JSON/YAML profile file")
    ap.add_argument("--cache", default=str(default_cache()), help="download cache folder")
    ap.add_argument("--refresh", action="store_true", help="restage daily-changing files")
    ap.add_argument("--yes", action="store_true", help="ask nothing; use defaults")
    ap.add_argument("--abuse-key-file", help="file holding the abuse.ch Auth-Key (first line)")
    ap.add_argument("--examiner", default="", help="case default: examiner name")
    ap.add_argument("--agency", default="", help="case default: agency")
    ap.add_argument("--case-prefix", default="", help="case default: case ID prefix")
    ap.add_argument("--dry-run", action="store_true", help="plan and check space only")
    ap.add_argument("--fetcher-name", default="fetch-assets.sh", help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "airlock" / "assets"


@contextlib.contextmanager
def _umask(mask: int) -> Iterator[None]:
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        with _umask(0o022):
            return run(args)
    except UsageError as exc:
        print(f"fetch-assets: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("fetch-assets: stopped. Rerun the same command to resume.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
