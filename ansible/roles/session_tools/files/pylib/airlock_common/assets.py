"""The ASSETS partition: trusted manifest, staged-file checks, verified paths.

Contract: docs/dev/contract.md sections 6 and 8a. Used by ``forensic-provision`` and
``forensic-import`` (deep check before applying) and by ``forensic-session-start`` at every
boot (task 2B.14). Nothing here writes to ASSETS; it is mounted read-only.

Trust chain (task 2B.15): the manifest baked into the image (``/var/lib/airlock/manifest.json``)
is trusted. A manifest on ASSETS is used instead only when ``manifest.json.sig`` verifies against
the public key baked in at ``/etc/airlock/manifest-signing.pub.pem`` and it is not an older
release. Pinned files are checked against the trusted manifest's SHA-256. Files that change
daily (``verify: vendor_signature`` or ``trusted_at_staging``) have no pinned hash: they are
checked against the hash recorded when they were applied (``applied-assets.json`` on the root
filesystem, which ASSETS cannot rewrite), or before the first apply against ``profile.json``.

CLI (bash and tests): ``python3 -m airlock_common.assets verify [--quick] [--json]
[--log-tool NAME]`` exits 0 when every staged file checks out, 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from airlock_common import hashing, jsonio, paths, proc, sessionlog

APPLIED_FILE = "applied-assets.json"
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
_RELEASE_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-f]+)?")


class AssetError(RuntimeError):
    """No trusted manifest could be loaded."""


# --------------------------------------------------------------------------- manifest


def verify_signature(
    manifest_path: str | Path, sig_path: str | Path, pubkey_path: str | Path
) -> bool:
    """True when ``sig_path`` is a valid raw Ed25519 signature of the manifest (openssl)."""
    for p in (manifest_path, sig_path, pubkey_path):
        if not Path(p).is_file():
            return False
    argv = [
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pubkey_path),
        "-rawin", "-in", str(manifest_path), "-sigfile", str(sig_path),
    ]  # fmt: skip
    try:
        res = proc.run(argv, check=False, timeout=60)
    except proc.ToolError:
        return False
    return res.returncode == 0 and "Signature Verified Successfully" in res.stdout


def _release_key(release: str) -> tuple[int, ...] | None:
    m = _RELEASE_RE.match(release or "")
    if not m:
        return None
    return tuple(int(g or 0) for g in m.groups())


@dataclass
class ManifestInfo:
    """The manifest in use and why. ``notes`` hold problems seen while choosing it."""

    manifest: dict[str, Any]
    source: str  # "baked" | "assets"
    path: Path
    sha256: str
    release: str
    notes: list[tuple[str, str]] = field(default_factory=list)


def _read_manifest(path: Path) -> dict[str, Any] | None:
    try:
        data = jsonio.load_json(path)
    except (OSError, ValueError):
        return None
    if (
        not isinstance(data, dict)
        or data.get("schema") != 1
        or not isinstance(data.get("files"), list)
    ):
        return None
    return data


def load_manifest_info() -> ManifestInfo:
    """Choose the trusted manifest: the baked one, or a newer signed one from ASSETS."""
    baked_path = paths.baked_manifest()
    baked = _read_manifest(baked_path)
    notes: list[tuple[str, str]] = []
    on_assets = paths.assets_dir() / "manifest.json"
    sig = paths.assets_dir() / "manifest.json.sig"
    same = (
        baked is not None
        and on_assets.is_file()
        and hashing.sha256_file(on_assets) == hashing.sha256_file(baked_path)
    )
    if on_assets.is_file() and not same:
        candidate = _read_manifest(on_assets)
        if not sig.is_file():
            notes.append(("manifest.json", "ASSETS manifest has no signature; not used"))
        elif not verify_signature(on_assets, sig, paths.manifest_public_key()):
            notes.append(
                ("manifest.json", "ASSETS manifest signature does not verify (edited?); not used")
            )
        elif candidate is None:
            notes.append(("manifest.json", "ASSETS manifest is signed but not a valid manifest"))
        else:
            old = _release_key(str((baked or {}).get("release", "")))
            new = _release_key(str(candidate.get("release", "")))
            if baked is not None and old is not None and new is not None and new < old:
                notes.append(
                    (
                        "manifest.json",
                        f"ASSETS manifest {candidate.get('release')} is older "
                        f"than the trusted {baked.get('release')}; not used",
                    )
                )
            else:
                return ManifestInfo(
                    candidate, "assets", on_assets, hashing.sha256_file(on_assets),
                    str(candidate.get("release", "")), notes,
                )  # fmt: skip
    if baked is None:
        raise AssetError(
            f"no trusted manifest: {baked_path} is missing or damaged and ASSETS has no valid "
            "signed one. Reflash the drive with a released image."
        )
    return ManifestInfo(
        baked, "baked", baked_path, hashing.sha256_file(baked_path),
        str(baked.get("release", "")), notes,
    )  # fmt: skip


def load_manifest() -> dict[str, Any]:
    """The trusted manifest (baked, or a newer signed one from ASSETS)."""
    return load_manifest_info().manifest


# --------------------------------------------------------------------------- staged files


def read_profile() -> dict[str, Any] | None:
    """ASSETS ``profile.json`` written by the fetcher, or None when absent or unreadable."""
    try:
        data = jsonio.load_json(paths.assets_dir() / "profile.json")
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def profile_sha256() -> str | None:
    path = paths.assets_dir() / "profile.json"
    return hashing.sha256_file(path) if path.is_file() else None


def applied_path() -> Path:
    return paths.state_dir() / APPLIED_FILE


def load_applied() -> dict[str, Any] | None:
    try:
        data = jsonio.load_json(applied_path())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def staged_path(target: str) -> Path | None:
    """``files/<target>`` on ASSETS, or None for an unsafe target."""
    p = PurePosixPath(str(target or ""))
    if not p.parts or p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        return None
    if "\\" in str(target) or "//" in str(target) or str(target).endswith("/"):
        return None
    return paths.assets_files_dir().joinpath(*p.parts)


def feature_names(tags: list[str] | tuple[str, ...]) -> list[str]:
    """Feature names a file serves, from its manifest tags (``clamav``, ``ai_tier2``, ...)."""
    tier_tags = {f"ai_{t}" for t in TIERS}
    return sorted({t for t in tags if t in BOOL_FEATURES or t in tier_tags})


def effective_features(features: dict[str, Any], disabled: list[str]) -> dict[str, Any]:
    """The profile's features with every disabled one turned off."""
    out = dict(features or {})
    off = set(disabled)
    out["ai_tiers"] = [t for t in out.get("ai_tiers") or [] if f"ai_{t}" not in off]
    for name in BOOL_FEATURES:
        if name in off:
            out[name] = False
    return out


@dataclass
class AssetReport:
    """Result of :func:`verify_staged`. ``problems`` are (asset id, reason) pairs."""

    ok: bool
    checked: list[str] = field(default_factory=list)
    problems: list[tuple[str, str]] = field(default_factory=list)
    disabled_features: list[str] = field(default_factory=list)
    deep: bool = True
    profile: str = ""
    features: dict[str, Any] = field(default_factory=dict)
    manifest_source: str = ""
    manifest_release: str = ""
    manifest_sha256: str = ""
    verified: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "deep": self.deep,
            "checked": list(self.checked),
            "problems": [[a, r] for a, r in self.problems],
            "disabled_features": list(self.disabled_features),
            "profile": self.profile,
            "features": dict(self.features),
            "manifest_source": self.manifest_source,
            "manifest_release": self.manifest_release,
            "manifest_sha256": self.manifest_sha256,
            "verified": {k: dict(v) for k, v in sorted(self.verified.items())},
        }

    def summary(self) -> str:
        if self.ok:
            return f"ASSETS: all {len(self.checked)} staged file(s) check out ({self._mode()})"
        lines = [f"ASSETS: {len(self.problems)} problem(s) ({self._mode()}):"]
        lines += [f"  {aid}: {why}" for aid, why in self.problems]
        if self.disabled_features:
            lines.append("  turned off: " + ", ".join(self.disabled_features))
        lines.append(
            "  Fix: rerun the fetcher on the host computer (scripts/fetch-assets.sh or "
            "fetch-assets.ps1), then boot again."
        )
        return "\n".join(lines)

    def _mode(self) -> str:
        return "SHA-256 of every file" if self.deep else "presence and size only"


def _vendor_signature_ok(path: Path) -> bool | None:
    """ClamAV databases carry ClamAV's own signature; sigtool checks it when installed."""
    if path.suffix not in (".cvd", ".cld") or proc.which("sigtool") is None:
        return None
    try:
        res = proc.run(["sigtool", f"--info={path}"], check=False, timeout=600)
    except proc.ToolError:
        return False
    return res.returncode == 0 and "Verification OK" in res.stdout


class _Bad(Exception):
    """One staged file failed a check; the message is the reason."""


def _reference(
    entry: dict[str, Any], staged: dict[str, Any], applied: dict[str, Any] | None
) -> tuple[str, int | None, str]:
    """The SHA-256 and size a staged file must have, and where that value comes from."""
    pinned = entry.get("sha256")
    if pinned:
        if str(staged.get("sha256") or "") != pinned:
            raise _Bad("profile.json lists a different SHA-256 than the trusted manifest")
        size = entry.get("size")
        return str(pinned), size if isinstance(size, int) else None, "the trusted manifest"
    if str(entry.get("verify") or "sha256") not in MOVING:
        raise _Bad("not pinned in the trusted manifest (no SHA-256)")
    want = str(staged.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        raise _Bad("profile.json has no valid SHA-256 for it")
    prev = ((applied or {}).get("files") or {}).get(entry["id"])
    if not isinstance(prev, dict):
        return want, None, "the hash recorded at staging"
    if prev.get("sha256") != want:
        raise _Bad(
            "restaged since it was last applied; run 'sudo forensic-import' to check and apply it"
        )
    size = prev.get("size")
    return want, size if isinstance(size, int) else None, "the hash recorded when it was applied"


def _check_file(
    entry: dict[str, Any],
    staged: dict[str, Any],
    applied: dict[str, Any] | None,
    *,
    deep: bool,
) -> dict[str, Any]:
    """Check one staged file. Returns its verified record; raises _Bad with the reason."""
    target = str(entry.get("target") or "")
    if str(staged.get("target") or "") != target:
        raise _Bad("profile.json gives a different target than the trusted manifest")
    path = staged_path(target)
    if path is None:
        raise _Bad("unsafe target path in the manifest")
    if not path.is_file():
        raise _Bad(f"missing (files/{target} is not on ASSETS)")
    size = path.stat().st_size
    verify = str(entry.get("verify") or "sha256")
    want, want_size, why = _reference(entry, staged, applied)
    if want_size is not None and size != want_size:
        raise _Bad(f"size {size} differs from {want_size} (truncated or replaced)")
    if deep:
        if hashing.sha256_file(path) != want:
            raise _Bad(f"SHA-256 does not match {why} (file changed or replaced)")
        if verify == "vendor_signature" and _vendor_signature_ok(path) is False:
            raise _Bad("vendor signature check failed (sigtool)")
    return {
        "path": str(path),
        "sha256": want,
        "size": size,
        "target": target,
        "verify": verify,
        "version": str(entry.get("version") or ""),
    }


def _expected_ids(
    profile: dict[str, Any], manifest: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[str]]:
    staged = {
        str(f.get("id")): f
        for f in profile.get("files") or []
        if isinstance(f, dict) and f.get("id")
    }
    skipped = {
        str(s.get("id")): str(s.get("reason") or "")
        for s in profile.get("skipped") or []
        if isinstance(s, dict) and s.get("id")
    }
    ids = set(staged) | set(skipped)
    mprof = (manifest.get("profiles") or {}).get(str(profile.get("profile") or ""))
    if isinstance(mprof, dict):
        ids |= {str(i) for i in mprof.get("files") or []}
    return staged, skipped, sorted(ids)


def verify_staged(*, deep: bool = True, for_apply: bool = False) -> AssetReport:
    """Check every file the ASSETS profile names against the trusted manifest.

    ``deep`` hashes every file (provisioning, import, session start); otherwise presence and
    size only. Problems name the asset and the reason; the features those assets serve are
    listed in ``disabled_features``. Daily-changing files are checked against the hash
    recorded when they were last applied; ``for_apply`` (provisioning and import, which apply
    a restaged set) checks them against the hash the fetcher recorded in profile.json instead.
    """
    report = AssetReport(ok=False, deep=deep)
    profile = read_profile()
    try:
        info = load_manifest_info()
    except AssetError as exc:
        report.problems.append(("manifest.json", str(exc)))
        feats = (profile or {}).get("features") or {}
        report.disabled_features = sorted(
            [f"ai_{t}" for t in feats.get("ai_tiers") or []]
            + [k for k in BOOL_FEATURES if feats.get(k) is True]
        )
        return report
    report.manifest_source, report.manifest_release = info.source, info.release
    report.manifest_sha256 = info.sha256
    report.problems += info.notes
    if profile is None:
        report.problems.append(
            ("profile.json", "missing or unreadable: ASSETS has not been staged. Run the fetcher "
             "on the host computer.")
        )  # fmt: skip
        return report
    report.profile = str(profile.get("profile") or "")
    report.features = dict(profile.get("features") or {})
    manifest_files = {str(f.get("id")): f for f in info.manifest["files"] if isinstance(f, dict)}
    applied = None if for_apply else load_applied()
    staged, skipped, ids = _expected_ids(profile, info.manifest)
    disabled: set[str] = set()
    for aid in ids:
        entry = manifest_files.get(aid)
        if entry is None:
            report.problems.append((aid, "not in the trusted manifest"))
            continue
        if aid not in staged:
            reason = skipped.get(aid) or "missing from profile.json"
            report.problems.append((aid, f"not staged: {reason}"))
            disabled |= set(feature_names(entry.get("profiles") or []))
            continue
        try:
            record = _check_file(entry, staged[aid], applied, deep=deep)
        except _Bad as bad:
            report.problems.append((aid, str(bad)))
            disabled |= set(feature_names(entry.get("profiles") or []))
            continue
        report.checked.append(aid)
        report.verified[aid] = record
    report.disabled_features = sorted(disabled)
    report.ok = not report.problems
    return report


def asset_path(asset_id: str) -> Path | None:
    """The on-ASSETS path of a staged file that provisioning or import verified and applied.

    Cheap: checks the file is still there with the applied size. Session start re-hashes
    everything (``verify_staged``); a file that failed there is not applied.
    """
    applied = load_applied()
    rec = ((applied or {}).get("files") or {}).get(asset_id)
    if not isinstance(rec, dict):
        return None
    path = staged_path(str(rec.get("target") or ""))
    if path is None or not path.is_file():
        return None
    if isinstance(rec.get("size"), int) and path.stat().st_size != rec["size"]:
        return None
    return path


def log_report(report: AssetReport, tool: str) -> None:
    """Record a check in the session log: event ``assets_verified`` with every file's hash."""
    sessionlog.log_event(
        tool,
        "assets_verified",
        ok=report.ok,
        deep=report.deep,
        profile=report.profile,
        manifest_source=report.manifest_source,
        manifest_release=report.manifest_release,
        manifest_sha256=report.manifest_sha256,
        checked=len(report.checked),
        problems=[[a, r] for a, r in report.problems],
        disabled_features=report.disabled_features,
        files={k: v["sha256"] for k, v in sorted(report.verified.items())},
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m airlock_common.assets")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check the staged ASSETS files")
    v.add_argument("--quick", action="store_true", help="presence and size only")
    v.add_argument("--json", action="store_true", help="print the report as JSON")
    v.add_argument("--log-tool", help="also record the result in the session log as TOOL")
    args = ap.parse_args(argv)
    report = verify_staged(deep=not args.quick)
    if args.log_tool:
        log_report(report, args.log_tool)
    if args.json:
        print(jsonio.dumps(report.to_dict()))
    else:
        print(report.summary())
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
