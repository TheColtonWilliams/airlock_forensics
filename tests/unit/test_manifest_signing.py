"""scripts/gen-signing-key.sh and scripts/sign-manifest.sh (task 2B.15): the signature they
make is the one airlock_common.assets accepts on the drive. Keys are made per test, never
committed."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from airlock_common import assets

REPO = Path(__file__).resolve().parents[2]


def sh(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", *args], capture_output=True, text=True, check=False,
        env={**os.environ, **(env or {})},
    )  # fmt: skip


def test_keygen_sign_verify_roundtrip(tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    res = sh(str(REPO / "scripts" / "gen-signing-key.sh"), "--out-dir", str(keys))
    assert res.returncode == 0, res.stderr
    key, pub = keys / "manifest-signing.key.pem", keys / "manifest-signing.pub.pem"
    assert key.stat().st_mode & 0o777 == 0o600
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema": 1, "files": [], "release": "t"}\n', encoding="utf-8")
    sign = str(REPO / "scripts" / "sign-manifest.sh")
    res = sh(sign, "--key", str(key), "--manifest", str(manifest), "--pub", str(pub))
    assert res.returncode == 0, res.stderr
    sig = Path(f"{manifest}.sig")
    assert sig.stat().st_size == 64
    assert assets.verify_signature(manifest, sig, pub)
    assert sh(sign, "--verify", "--pub", str(pub), "--manifest", str(manifest)).returncode == 0
    # From a CI secret in the environment: same signature (Ed25519 is deterministic).
    first = sig.read_bytes()
    res = sh(sign, "--key-env", "SECRET_KEY", "--manifest", str(manifest),
             env={"SECRET_KEY": key.read_text(encoding="utf-8")})  # fmt: skip
    assert res.returncode == 0, res.stderr
    assert sig.read_bytes() == first
    # An edited manifest no longer verifies.
    manifest.write_text('{"schema": 1, "files": [], "release": "u"}\n', encoding="utf-8")
    assert not assets.verify_signature(manifest, sig, pub)
    res = sh(sign, "--verify", "--pub", str(pub), "--manifest", str(manifest))
    assert res.returncode == 1
    assert "does NOT verify" in res.stderr


def test_keygen_refuses_repo_folder_and_overwrite(tmp_path: Path) -> None:
    gen = str(REPO / "scripts" / "gen-signing-key.sh")
    inside = REPO / "assets" / "never-created-key-dir"
    res = sh(gen, "--out-dir", str(inside))
    assert res.returncode == 1
    assert "inside the repository" in res.stderr
    assert not inside.exists()
    assert sh(gen, "--out-dir", str(tmp_path)).returncode == 0
    again = sh(gen, "--out-dir", str(tmp_path))
    assert again.returncode == 1
    assert "already exists" in again.stderr


def test_sign_refuses_wrong_public_key(tmp_path: Path) -> None:
    gen = str(REPO / "scripts" / "gen-signing-key.sh")
    assert sh(gen, "--out-dir", str(tmp_path / "a")).returncode == 0
    assert sh(gen, "--out-dir", str(tmp_path / "b")).returncode == 0
    manifest = tmp_path / "m.json"
    manifest.write_text("{}\n", encoding="utf-8")
    res = sh(str(REPO / "scripts" / "sign-manifest.sh"),
             "--key", str(tmp_path / "a" / "manifest-signing.key.pem"),
             "--pub", str(tmp_path / "b" / "manifest-signing.pub.pem"),
             "--manifest", str(manifest))  # fmt: skip
    assert res.returncode == 1
    assert "does not match the public key" in res.stderr
    assert not Path(f"{manifest}.sig").exists()
