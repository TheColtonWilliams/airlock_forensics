#!/usr/bin/env python3
"""Check ansible/group_vars/all/pins.yml against docs/dev/contract.md section 5 (task 6.2).

Every external download has one entry with every field present. This script checks each
entry's shape, the tags in its ``profiles`` list, the model references in ai_models.yml and the
feature names in profiles.yml, then lists the pins that are not pinned yet (``sha256: null``
with ``verify: sha256``).

Exit status: 0 when every entry is well formed (unpinned entries are listed but allowed),
1 when an entry is malformed or, with ``--strict`` (the release workflow), when any entry is
still unpinned, 2 for a usage error.

Host-side tool: needs PyYAML (Ubuntu package python3-yaml).

``--licences-table`` prints the Markdown table of every pin, its licence, and whether it may be
baked into the published image (task 2B.18); docs/licenses.md holds a copy between the
``pins-table`` markers.

Usage:
  scripts/check-pins.py [--strict] [--list-unpinned] [--json] [--licences-table]
                        [--pins FILE] [--profiles FILE] [--ai-models FILE]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
GROUP_VARS = REPO_ROOT / "ansible" / "group_vars" / "all"

REQUIRED_FIELDS: tuple[str, ...] = (
    "url",
    "version",
    "sha256",
    "size",
    "stage",
    "target",
    "profiles",
    "verify",
    "license",
    "notes",
)
STAGES: frozenset[str] = frozenset({"build", "image", "assets"})
VERIFY_MODES: frozenset[str] = frozenset({"sha256", "vendor_signature", "trusted_at_staging"})
TIERS: tuple[str, ...] = ("tier0", "tier1", "tier2", "tier3", "tier4")
# Boolean features of a profile (contract section 6). Each is also a pin tag.
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
FEATURE_KEYS: frozenset[str] = frozenset({"ai_tiers", *BOOL_FEATURES})
# Tags that are not profile names: where a file is used, or which feature needs it.
#   build  build host only        image  baked into the base image by a role
#   all    every staging profile  ai_tierN / <feature>  profiles with that feature on
FIXED_TAGS: frozenset[str] = frozenset(
    {"build", "image", "all", *BOOL_FEATURES, *(f"ai_{t}" for t in TIERS)}
)
ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def load_yaml(path: Path) -> Any:
    try:
        import yaml  # noqa: PLC0415 - host-side dependency, imported where needed
    except ImportError as exc:  # pragma: no cover - depends on the host
        raise SystemExit(
            "check-pins: PyYAML is missing. "
            "Install it (sudo apt-get install python3-yaml) and rerun."
        ) from exc
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except OSError as exc:
        raise SystemExit(f"check-pins: cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise SystemExit(f"check-pins: {path} is not valid YAML: {exc}") from exc


def model_pin_id(entry: Any) -> str | None:
    """A model in ai_models.yml is a pin id string or a mapping with ``pin`` or ``id``."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in ("pin", "id", "asset"):
            if isinstance(entry.get(key), str):
                return entry[key]
    return None


def check_target(target: Any) -> str | None:
    """Return an error for a bad ASSETS target path, else None."""
    if not isinstance(target, str) or not target:
        return "target is required for stage=assets (a path under the ASSETS files/ folder)"
    if "\\" in target or target.startswith("/") or ":" in target:
        return f"target {target!r} must be a relative path with forward slashes"
    parts = PurePosixPath(target).parts
    if any(p in ("", ".", "..") for p in parts) or target.endswith("/") or "//" in target:
        return f"target {target!r} must not contain empty, '.' or '..' parts"
    if not re.fullmatch(r"[A-Za-z0-9._+/-]+", target):
        return f"target {target!r} may only use letters, digits, '.', '_', '+', '-' and '/'"
    return None


def _check_basic(pin: dict[str, Any]) -> list[str]:
    """url, version, sha256, size, license and notes."""
    errs: list[str] = []
    url = pin.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        errs.append(f"url must be an https:// URL, got {url!r}")
    version = pin.get("version")
    if not isinstance(version, str) or not version.strip():
        errs.append(f"version must be a non-empty quoted string, got {version!r}")
    sha = pin.get("sha256")
    if sha is not None and not (isinstance(sha, str) and SHA_RE.match(sha)):
        errs.append("sha256 must be 64 lower-case hex characters or null")
    size = pin.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        errs.append(f"size must be a whole number of bytes or null, got {size!r}")
    lic = pin.get("license")
    if not isinstance(lic, str) or not lic.strip():
        errs.append("license must name the licence (a non-empty string)")
    notes = pin.get("notes")
    if notes is not None and not isinstance(notes, str):
        errs.append("notes must be a string")
    if sha is None and not (isinstance(notes, str) and notes.strip()):
        errs.append("sha256 is null: notes must say why (for example 'host unreachable ...')")
    return errs


def _check_staging(pin: dict[str, Any]) -> list[str]:
    """stage, verify and target."""
    errs: list[str] = []
    stage = pin.get("stage")
    if stage not in STAGES:
        errs.append(f"stage must be one of {', '.join(sorted(STAGES))}, got {stage!r}")
    verify = pin.get("verify")
    if verify not in VERIFY_MODES:
        errs.append(f"verify must be one of {', '.join(sorted(VERIFY_MODES))}, got {verify!r}")
    elif verify != "sha256" and stage != "assets":
        errs.append(f"verify={verify} is only allowed for stage=assets (builds pin by SHA-256)")
    target = pin.get("target")
    if stage == "assets":
        terr = check_target(target)
        if terr:
            errs.append(terr)
    elif target is not None and not isinstance(target, str):
        errs.append("target must be a string or null")
    return errs


def _check_tags(pin: dict[str, Any], known_tags: frozenset[str]) -> list[str]:
    tags = pin.get("profiles")
    if not isinstance(tags, list) or not tags or not all(isinstance(t, str) for t in tags):
        return ["profiles must be a non-empty list of profile names or tags"]
    errs: list[str] = []
    unknown = sorted(set(tags) - known_tags)
    if unknown:
        errs.append(
            "unknown profile tag(s): "
            + ", ".join(unknown)
            + " (use a profile name, build, image, all, ai_tier0..ai_tier4 or a feature name)"
        )
    if len(set(tags)) != len(tags):
        errs.append("profiles lists a tag twice")
    return errs


def check_pin(pid: str, pin: Any, known_tags: frozenset[str]) -> list[str]:
    errs: list[str] = []
    if not ID_RE.match(pid):
        errs.append("id must be snake_case (lower-case letters, digits, '_')")
    if not isinstance(pin, dict):
        return [*errs, "entry must be a mapping"]
    missing = [f for f in REQUIRED_FIELDS if f not in pin]
    if missing:
        errs.append("missing field(s): " + ", ".join(missing))
    extra = sorted(set(pin) - set(REQUIRED_FIELDS))
    if extra:
        errs.append("unknown field(s): " + ", ".join(extra))
    return errs + _check_basic(pin) + _check_staging(pin) + _check_tags(pin, known_tags)


def check_profiles(profiles: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(profiles, dict) or not profiles:
        return ["profiles.yml: 'profiles' must be a non-empty mapping"]
    for name, prof in sorted(profiles.items()):
        where = f"profiles.yml {name}"
        if not isinstance(name, str) or not ID_RE.match(name):
            errs.append(f"{where}: profile names must be snake_case")
        if name in FIXED_TAGS:
            errs.append(f"{where}: '{name}' is a reserved tag and cannot be a profile name")
        if not isinstance(prof, dict):
            errs.append(f"{where}: must be a mapping")
            continue
        if not isinstance(prof.get("description"), str) or not prof["description"].strip():
            errs.append(f"{where}: description is required")
        feats = prof.get("features")
        if not isinstance(feats, dict):
            errs.append(f"{where}: features must be a mapping")
            continue
        for key in sorted(set(feats) - FEATURE_KEYS):
            errs.append(f"{where}: unknown feature '{key}'")
        tiers = feats.get("ai_tiers", [])
        if not isinstance(tiers, list) or any(t not in TIERS for t in tiers):
            errs.append(f"{where}: ai_tiers must be a list drawn from {', '.join(TIERS)}")
        for key in BOOL_FEATURES:
            if key in feats and not isinstance(feats[key], bool):
                errs.append(f"{where}: feature '{key}' must be true or false")
    return errs


def check_ai_models(ai: Any, pins: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    tiers = (ai or {}).get("ai_tiers") if isinstance(ai, dict) else None
    if tiers is None:
        return errs
    if not isinstance(tiers, dict):
        return ["ai_models.yml: 'ai_tiers' must be a mapping"]
    for tier, spec in sorted(tiers.items()):
        if tier not in TIERS:
            errs.append(f"ai_models.yml: unknown tier '{tier}'")
            continue
        models = (spec or {}).get("models") or [] if isinstance(spec, dict) else []
        for entry in models:
            pid = model_pin_id(entry)
            if pid is None:
                errs.append(f"ai_models.yml {tier}: model entry {entry!r} names no pin")
            elif pid not in pins:
                errs.append(f"ai_models.yml {tier}: model pin '{pid}' is not in pins.yml")
            elif (pins[pid] or {}).get("stage") != "assets":
                errs.append(f"ai_models.yml {tier}: model pin '{pid}' must have stage=assets")
    return errs


def analyse(pins_doc: Any, profiles_doc: Any, ai_doc: Any) -> dict[str, Any]:
    """Return {"errors": [...], "unpinned": [...], "moving": [...], "count": n}."""
    errors: list[str] = []
    if not isinstance(pins_doc, dict) or not isinstance(pins_doc.get("pins"), dict):
        return {
            "errors": ["pins.yml: top level must be a mapping with a 'pins' mapping"],
            "unpinned": [],
            "moving": [],
            "count": 0,
        }
    pins: dict[str, Any] = pins_doc["pins"]
    profiles = (profiles_doc or {}).get("profiles") if isinstance(profiles_doc, dict) else None
    errors += check_profiles(profiles)
    profile_names = frozenset(profiles) if isinstance(profiles, dict) else frozenset()
    known = FIXED_TAGS | profile_names
    targets: dict[str, str] = {}
    for pid in sorted(pins):
        pin = pins[pid]
        errors += [f"pins.yml {pid}: {e}" for e in check_pin(str(pid), pin, known)]
        if (
            isinstance(pin, dict)
            and pin.get("stage") == "assets"
            and isinstance(pin.get("target"), str)
        ):
            other = targets.setdefault(pin["target"], pid)
            if other != pid:
                errors.append(f"pins.yml {pid}: target {pin['target']!r} is also used by {other}")
    errors += check_ai_models(ai_doc, pins)
    unpinned = sorted(
        pid
        for pid, pin in pins.items()
        if isinstance(pin, dict) and pin.get("sha256") is None and pin.get("verify") == "sha256"
    )
    moving = sorted(
        pid
        for pid, pin in pins.items()
        if isinstance(pin, dict) and pin.get("verify") in ("vendor_signature", "trusted_at_staging")
    )
    return {"errors": errors, "unpinned": unpinned, "moving": moving, "count": len(pins)}


def bake_policy(pin: dict[str, Any]) -> str:
    """Plan 2B.18: where a pinned item lives and whether a published image may carry it."""
    stage = pin.get("stage")
    tags = set(pin.get("profiles") or [])
    if stage == "build":
        # A build-host download that scripts/build.sh hands to the image build (tag ``image``),
        # such as goss for the provisioning self-test, ends up in the image.
        if "image" in tags:
            return "yes: fetched on the build host, baked by the build"
        return "n/a: build host only"
    if stage == "image":
        return "yes: baked by the build"
    if "nvidia_proprietary" in tags:
        return "no: opt-in NVIDIA driver set (4B.15); staged only when turned on"
    if "eztools" in tags:
        return "allowed once each repo's MIT licence is confirmed (6.6, unconfirmed)"
    return "no: user-fetched onto ASSETS (2B.18)"


def licences_table(pins: dict[str, Any]) -> str:
    rows = [
        "| Pin | Version | Licence | Stage | May be baked into the published image |",
        "|---|---|---|---|---|",
    ]
    for pid in sorted(pins):
        pin = pins[pid] if isinstance(pins[pid], dict) else {}
        lic = str(pin.get("license") or "").replace("|", "/")
        rows.append(
            f"| `{pid}` | {pin.get('version')} | {lic} | {pin.get('stage')} | {bake_policy(pin)} |"
        )
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check pins.yml (docs/dev/contract.md section 5).")
    ap.add_argument("--pins", type=Path, default=GROUP_VARS / "pins.yml")
    ap.add_argument("--profiles", type=Path, default=GROUP_VARS / "profiles.yml")
    ap.add_argument("--ai-models", type=Path, default=GROUP_VARS / "ai_models.yml")
    ap.add_argument("--strict", action="store_true", help="fail when any pin is still unpinned")
    ap.add_argument("--list-unpinned", action="store_true", help="print unpinned ids only")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument(
        "--licences-table", action="store_true", help="print the licence table for docs"
    )
    args = ap.parse_args(argv)
    if args.licences_table:
        doc = load_yaml(args.pins)
        sys.stdout.write(licences_table((doc or {}).get("pins") or {}))
        return 0

    ai_doc = load_yaml(args.ai_models) if args.ai_models.exists() else None
    result = analyse(load_yaml(args.pins), load_yaml(args.profiles), ai_doc)
    failed = bool(result["errors"]) or (args.strict and bool(result["unpinned"]))

    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    elif args.list_unpinned:
        for pid in result["unpinned"]:
            print(pid)
    else:
        for err in result["errors"]:
            print(f"check-pins: {err}", file=sys.stderr)
        print(
            f"check-pins: {result['count']} pins, {len(result['errors'])} error(s), "
            f"{len(result['unpinned'])} not pinned yet, {len(result['moving'])} checked by "
            "vendor signature or recorded at staging"
        )
        if result["unpinned"]:
            print("check-pins: not pinned yet (sha256 null): " + ", ".join(result["unpinned"]))
    if result["errors"]:
        print(
            "check-pins: pins.yml has errors (listed above). Fix those entries and rerun.",
            file=sys.stderr,
        )
    elif args.strict and result["unpinned"]:
        print(
            "check-pins: release blocked: fill in the SHA-256 of every unpinned entry "
            "(download each file, check it against the vendor's checksum, record it) and rerun.",
            file=sys.stderr,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
