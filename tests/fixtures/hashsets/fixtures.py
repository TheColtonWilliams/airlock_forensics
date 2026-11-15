#!/usr/bin/env python3
"""Build the hash-triage test fixtures at test time (nothing binary is committed).

* ``build_nsrl(path)``: a tiny SQLite database with the NSRL RDSv3 table layout (``FILE``,
  ``PKG``, ``OS``, ``MFG``, ``VERSION``), upper-case hex like the RDS, listing the synthetic
  known-good file, one legacy row with no SHA-256 (matched on SHA-1), and one row whose MD5
  equals the "collision" file's but whose SHA-256 differs (must not match).
* ``eicar()``: the EICAR anti-virus test string, assembled from parts so the repository never
  holds it whole.
* ``write_samples(folder)``: the sample files the tests triage.
* ``write_mbz_export(path, hashes)``: a MalwareBazaar-style full SHA-256 export (zip).

Run as a script to write everything into a folder: ``fixtures.py OUTDIR``.
"""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
YARA_RULE = HERE / "airlock-test.yar"
YARA_EXTERNAL_RULE = HERE / "needs-external.yar"
YARA_BROKEN_RULE = HERE / "broken.yar"
NSRL_VERSION = "2026.06.1-test"
YARA_MARKER = b"AIRLOCK-YARA-TEST-MARKER-7f3c"

KNOWN_GOOD = b"AIRLOCK synthetic known-good file. Plain text, listed in the test NSRL.\n"
LEGACY = b"AIRLOCK synthetic legacy file. Its NSRL row has no SHA-256.\n"
COLLISION = b"AIRLOCK synthetic file whose MD5 is in a row with another SHA-256.\n"
PLAIN = b"AIRLOCK synthetic plain file. In no hash set.\n"


def eicar() -> bytes:
    """The EICAR test string (68 bytes), joined at run time."""
    parts = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*")
    return "".join(parts).encode("ascii")


def digests(data: bytes) -> dict[str, str]:
    return {a: hashlib.new(a, data).hexdigest() for a in ("sha256", "sha1", "md5")}


SCHEMA = """
CREATE TABLE FILE (sha256 VARCHAR NOT NULL, sha1 VARCHAR NOT NULL, md5 VARCHAR NOT NULL,
  crc32 VARCHAR NOT NULL, file_name VARCHAR NOT NULL, file_size INTEGER NOT NULL,
  package_id INTEGER NOT NULL);
CREATE TABLE PKG (package_id INTEGER NOT NULL, name VARCHAR NOT NULL, version VARCHAR NOT NULL,
  operating_system_id INTEGER NOT NULL, manufacturer_id INTEGER NOT NULL,
  language VARCHAR NOT NULL, application_type VARCHAR NOT NULL);
CREATE TABLE OS (operating_system_id INTEGER NOT NULL, name VARCHAR NOT NULL,
  version VARCHAR NOT NULL, manufacturer_id INTEGER NOT NULL);
CREATE TABLE MFG (manufacturer_id INTEGER NOT NULL, name VARCHAR NOT NULL);
CREATE TABLE VERSION (version VARCHAR UNIQUE NOT NULL, build_set VARCHAR NOT NULL,
  build_date TIMESTAMP NOT NULL, release_date TIMESTAMP NOT NULL, description VARCHAR NOT NULL);
"""


def build_nsrl(path: Path, *, indexed: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    rows = []
    good = digests(KNOWN_GOOD)
    rows.append(
        (good["sha256"], good["sha1"], good["md5"], "00000000", "known.txt", len(KNOWN_GOOD))
    )
    legacy = digests(LEGACY)
    rows.append(("", legacy["sha1"], legacy["md5"], "00000000", "legacy.txt", len(LEGACY)))
    other = hashlib.sha256(b"some other content").hexdigest()
    coll = digests(COLLISION)
    rows.append((other, "0" * 40, coll["md5"], "00000000", "other.txt", 18))
    conn.executemany(
        "INSERT INTO FILE VALUES (?, ?, ?, ?, ?, ?, 1)",
        [(a.upper(), b.upper(), c.upper(), d, e, f) for a, b, c, d, e, f in rows],
    )
    conn.execute("INSERT INTO PKG VALUES (1, 'AIRLOCK test package', '1', 1, 1, 'English', 'x')")
    conn.execute("INSERT INTO OS VALUES (1, 'TestOS', '1', 1)")
    conn.execute("INSERT INTO MFG VALUES (1, 'AIRLOCK test')")
    conn.execute(
        "INSERT INTO VERSION VALUES (?, 'modern minimal', '2026-06-01', '2026-06-01', 'test')",
        (NSRL_VERSION,),
    )
    if indexed:
        for col in ("sha256", "sha1", "md5"):
            conn.execute(f"CREATE INDEX FILE_{col} ON FILE ({col})")
    conn.commit()
    conn.close()
    return path


def fuzzy_pair() -> tuple[bytes, bytes]:
    """Two 48 KiB pseudo-random blobs that differ only near the end (ssdeep scores them high)."""
    blocks = [hashlib.sha256(f"airlock-fuzzy-{i}".encode()).digest() for i in range(1536)]
    base = b"".join(blocks)
    return base, base[:-200] + b"\x00" * 200


def write_samples(folder: Path) -> dict[str, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    files = {
        "known": KNOWN_GOOD,
        "legacy": LEGACY,
        "collision": COLLISION,
        "plain": PLAIN,
        "eicar": eicar(),
        "marker": b"header " + YARA_MARKER + b" trailer\n",
        "fuzzy": fuzzy_pair()[1],
    }
    out = {}
    names = {
        "known": "known-good.txt",
        "legacy": "legacy.txt",
        "collision": "collision.txt",
        "plain": "plain.txt",
        "eicar": "eicar-test.com",
        "marker": "=marker,cmd.bin",  # formula-like name: must be neutralised in the CSV
        "fuzzy": "variant.bin",
    }
    for key, data in files.items():
        p = folder / names[key]
        p.write_bytes(data)
        out[key] = p
    return out


def write_mbz_export(path: Path, hashes: list[str], *, snapshot: str = "2026-11-14") -> Path:
    header = (
        "################################################################\n"
        "# MalwareBazaar full malware samples dump (SHA256 hashes)        #\n"
        f"# Last updated: {snapshot} 07:15:03 UTC                          #\n"
        "################################################################\n"
        "#\n"
        "# sha256_hash\n"
    )
    body = "".join(f"{h}\n" for h in hashes)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("full_sha256.txt", header + body)
    return path


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: fixtures.py OUTDIR", file=sys.stderr)
        return 2
    out = Path(argv[0])
    build_nsrl(out / "nsrl" / "RDS_test_modern_minimal.db")
    samples = write_samples(out / "samples")
    write_mbz_export(
        out / "mbz" / "full_sha256.zip",
        [hashlib.sha256(samples["eicar"].read_bytes()).hexdigest(), "a" * 64],
    )
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
