#!/usr/bin/env python3
"""Download and verify the public reference sets listed in sets.json (task 4F.2).

Host side only. It refuses to run on an AIRLOCK drive (the image has no network, and this
tool downloads). Run it through ``validation/reference/fetch.sh``.

Each set is downloaded to ``OUT/downloads/``, checked against its SHA-256, unpacked to
``OUT/<id>/<image_name>``, and listed in ``OUT/fetched.json`` for ``validation/run.sh``.

A set whose ``sha256`` is null is skipped unless ``--record`` is given. ``--record`` downloads
it, writes the hash and size it saw into sets.json (trust on first use), and says so; a person
must compare that hash with the publisher's page before committing it.
"""

from __future__ import annotations

import argparse
import bz2
import datetime as dt
import gzip
import hashlib
import json
import os
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CHUNK = 4 * 1024 * 1024
ARCHIVES = {"none", "bz2", "gz", "zip"}


class FetchError(RuntimeError):
    """A set could not be fetched or verified."""


def on_airlock_drive() -> bool:
    etc = Path(os.environ.get("AIRLOCK_ETC_DIR", "/etc/airlock"))
    return (etc / "build-info.json").is_file()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def load_sets(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    problems = check_sets(doc)
    if problems:
        raise FetchError(f"{path} is not valid: " + "; ".join(problems))
    return doc


def check_sets(doc: dict[str, Any]) -> list[str]:
    """Problems with a sets.json document (empty list = fine)."""
    problems: list[str] = []
    if doc.get("schema") != 1:
        problems.append("schema must be 1")
    seen: set[str] = set()
    for s in doc.get("sets", []):
        sid = s.get("id", "?")
        if sid in seen:
            problems.append(f"{sid}: duplicate id")
        seen.add(sid)
        for key in ("url", "image_name", "archive", "classes", "ground_truth", "license"):
            if not s.get(key):
                problems.append(f"{sid}: {key} is missing")
        if not str(s.get("url", "")).startswith(("https://", "file://")):
            problems.append(f"{sid}: url must be https")
        if s.get("archive") not in ARCHIVES:
            problems.append(f"{sid}: archive must be one of {sorted(ARCHIVES)}")
        digest = s.get("sha256")
        if digest is not None and (
            len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
        ):
            problems.append(f"{sid}: sha256 must be 64 lower-case hex characters or null")
        truth = (s.get("ground_truth") or {}).get("scoring_truth", "")
        if not str(truth).startswith("validation/reference/truth/"):
            problems.append(
                f"{sid}: ground_truth.scoring_truth must be under validation/reference/truth/"
            )
        name = str(s.get("image_name", ""))
        if "/" in name or name.startswith("."):
            problems.append(f"{sid}: image_name must be a plain file name")
    return problems


def download(url: str, dest: Path) -> None:
    part = dest.with_suffix(dest.suffix + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "airlock-validation-fetch/1"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(part, "wb") as fh:  # noqa: S310
            shutil.copyfileobj(resp, fh, CHUNK)
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise FetchError(f"download of {url} failed: {exc}") from exc
    part.replace(dest)


def unpack(archive: str, src: Path, image_name: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / image_name
    tmp = out.with_suffix(out.suffix + ".part")
    if archive == "none":
        shutil.copyfile(src, tmp)
    elif archive in {"bz2", "gz"}:
        opener = bz2.open if archive == "bz2" else gzip.open
        with opener(src, "rb") as fin, open(tmp, "wb") as fout:
            shutil.copyfileobj(fin, fout, CHUNK)
    else:
        with zipfile.ZipFile(src) as zf:
            members = [m for m in zf.namelist() if Path(m).name == image_name]
            if len(members) != 1:
                raise FetchError(f"{src.name} does not hold exactly one {image_name}")
            with zf.open(members[0]) as fin, open(tmp, "wb") as fout:
                shutil.copyfileobj(fin, fout, CHUNK)
    tmp.replace(out)
    out.chmod(0o444)
    return out


def fetch_one(s: dict[str, Any], out: Path, *, record: bool) -> dict[str, Any]:
    sid = s["id"]
    if s.get("sha256") is None and not record:
        return {"id": sid, "status": "skipped", "reason": "not pinned (sha256 null); see --record"}
    name = s["url"].rsplit("/", 1)[-1] or f"{sid}.download"
    dl = out / "downloads" / f"{sid}--{name}"
    if not (dl.is_file() and s.get("sha256") and sha256_file(dl) == s["sha256"]):
        download(s["url"], dl)
    got = sha256_file(dl)
    status = "verified"
    if s.get("sha256") is None:
        status = "recorded"
        s["sha256"] = got
        s["size"] = dl.stat().st_size
        s["hash_recorded"] = {
            "date": dt.datetime.now(dt.UTC).strftime("%Y-%m-%d"),
            "by": (
                "fetch.sh --record (trust on first use; "
                "compare with the publisher before committing)"
            ),
        }
    elif got != s["sha256"]:
        dl.unlink(missing_ok=True)
        raise FetchError(
            f"{sid}: SHA-256 of the download is {got}, expected {s['sha256']}. "
            "The file was deleted; do not use this set until the publisher's hash is checked"
        )
    image = unpack(s["archive"], dl, s["image_name"], out / sid)
    return {
        "id": sid,
        "status": status,
        "download_sha256": got,
        "image": str(image),
        "image_sha256": sha256_file(image),
        "fs_type": s.get("fs_type"),
        "classes": s.get("classes"),
        "scoring_truth": s["ground_truth"]["scoring_truth"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch and verify validation reference sets.")
    ap.add_argument("--sets", type=Path, default=HERE / "sets.json")
    ap.add_argument("--out", type=Path, default=HERE.parent / "out" / "reference")
    ap.add_argument("--only", action="append", help="fetch only this set id (repeatable)")
    ap.add_argument("--record", action="store_true", help="record hashes of unpinned sets")
    ap.add_argument("--check", action="store_true", help="only check sets.json, fetch nothing")
    args = ap.parse_args(argv)
    try:
        doc = load_sets(args.sets)
        if args.check:
            pinned = sum(1 for s in doc["sets"] if s.get("sha256"))
            print(f"fetch: {args.sets} is valid: {len(doc['sets'])} sets, {pinned} pinned")
            return 0
        if on_airlock_drive():
            raise FetchError(
                "this is an AIRLOCK drive, which never downloads. Run fetch.sh on the host computer"
            )
        wanted = set(args.only or [])
        unknown = wanted - {s["id"] for s in doc["sets"]}
        if unknown:
            raise FetchError(f"unknown set id: {', '.join(sorted(unknown))}")
        results = []
        failed = 0
        for s in doc["sets"]:
            if wanted and s["id"] not in wanted:
                continue
            try:
                res = fetch_one(s, args.out, record=args.record)
            except FetchError as exc:
                failed += 1
                res = {"id": s["id"], "status": "failed", "reason": str(exc)}
            results.append(res)
            print(f"fetch: {res['id']}: {res['status']} {res.get('reason', '')}".rstrip())
        if args.record and any(r["status"] == "recorded" for r in results):
            args.sets.write_text(json.dumps(doc, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(f"fetch: recorded new hashes in {args.sets}; check them against the publisher")
        args.out.mkdir(parents=True, exist_ok=True)
        fetched = {
            "schema": 1,
            "sets": [r for r in results if r["status"] in {"verified", "recorded"}],
            "skipped": [r for r in results if r["status"] not in {"verified", "recorded"}],
        }
        (args.out / "fetched.json").write_text(
            json.dumps(fetched, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        if failed:
            print(f"fetch: {failed} set(s) failed; see the lines above.", file=sys.stderr)
            return 1
        return 0
    except (FetchError, OSError, ValueError) as exc:
        print(f"fetch: {exc}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
