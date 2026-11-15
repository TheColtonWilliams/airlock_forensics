#!/usr/bin/env python3
"""Write assets/manifest.json from pins.yml, profiles.yml and ai_models.yml (task 2B.10).

Format: docs/dev/contract.md section 6. Every pin becomes one entry in ``files`` (sorted by
id). Each profile in profiles.yml lists the ``stage: assets`` pins it needs:

* a pin tagged with the profile's own name, or with ``all``;
* a pin tagged with a feature the profile turns on (``clamav``, ``eztools``, ...);
* a pin tagged ``ai_tierN`` when the profile's ``ai_tiers`` holds ``tierN``; a model named
  in ai_models.yml under ``tierN`` gets the ``ai_tierN`` tag automatically;
* the tools_ai role's own pins get their feature tag automatically (``--ai-role``, default
  ansible/roles/tools_ai/defaults/main.yml): the classifier wheels and SigLIP files get
  ``classifiers``, the speech wheels and the faster-whisper model files get ``whisper``. So a
  custom profile file (``fetch-assets --profile FILE``) that turns a feature on stages the
  wheels and models it needs, whatever the profile is called.

The output is deterministic: the same inputs and release string give the same bytes.
``--check`` compares with the file on disk and fails when it is out of date.

Host-side tool: needs PyYAML (Ubuntu package python3-yaml).

Usage:
  scripts/gen-manifest.py [--out FILE | --stdout] [--release STR] [--check]
                          [--pins FILE] [--profiles FILE] [--ai-models FILE] [--main FILE]
                          [--ai-role FILE]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
GROUP_VARS = REPO_ROOT / "ansible" / "group_vars" / "all"
AI_ROLE_DEFAULTS = REPO_ROOT / "ansible" / "roles" / "tools_ai" / "defaults" / "main.yml"
FILE_KEYS: tuple[str, ...] = (
    "id",
    "url",
    "version",
    "size",
    "sha256",
    "target",
    "profiles",
    "verify",
    "license",
)


def _check_pins() -> ModuleType:
    """Load scripts/check-pins.py (hyphenated, so not importable by name)."""
    path = Path(__file__).resolve().with_name("check-pins.py")
    spec = importlib.util.spec_from_file_location("airlock_check_pins", path)
    if spec is None or spec.loader is None:  # pragma: no cover - file shipped beside this one
        raise SystemExit(f"gen-manifest: cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CP = _check_pins()


def active_tags(name: str, features: dict[str, Any]) -> set[str]:
    """Tags a profile pulls in: its name, ``all``, and one tag per feature that is on."""
    tags = {name, "all"}
    for tier in features.get("ai_tiers") or []:
        tags.add(f"ai_{tier}")
    for key in CP.BOOL_FEATURES:
        if features.get(key) is True:
            tags.add(key)
    return tags


def file_tags(
    pid: str,
    pin: dict[str, Any],
    model_tiers: dict[str, set[str]],
    feature_pins: dict[str, set[str]] | None = None,
) -> list[str]:
    tags = set(pin.get("profiles") or [])
    tags |= {f"ai_{t}" for t in model_tiers.get(pid, set())}
    tags |= (feature_pins or {}).get(pid, set())
    return sorted(tags)


def feature_pins_of(role_doc: Any, pins: dict[str, Any]) -> dict[str, set[str]]:
    """Feature tags for the pins the tools_ai role installs: ``classifiers`` for the classifier
    venv's wheels and the SigLIP files, ``whisper`` for the speech venv's wheels and every file
    under the faster-whisper model folder. Ids not in ``pins`` are ignored."""
    out: dict[str, set[str]] = {}
    if not isinstance(role_doc, dict):
        return out

    def add(pid: Any, tag: str) -> None:
        if isinstance(pid, str) and pid in pins:
            out.setdefault(pid, set()).add(tag)

    for pid in role_doc.get("tools_ai_triage_wheel_pins") or []:
        add(pid, "classifiers")
    siglip = role_doc.get("tools_ai_siglip_pins")
    for pid in siglip.values() if isinstance(siglip, dict) else []:
        add(pid, "classifiers")
    for pid in role_doc.get("tools_ai_whisper_wheel_pins") or []:
        add(pid, "whisper")
    add(role_doc.get("tools_ai_whisper_model_pin"), "whisper")
    model_dir = str(role_doc.get("tools_ai_whisper_model_dir_target") or "").strip("/")
    if model_dir:
        for pid, pin in pins.items():
            if str((pin or {}).get("target") or "").startswith(model_dir + "/"):
                add(pid, "whisper")
    return out


def model_tiers_of(ai_doc: Any) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    tiers = (ai_doc or {}).get("ai_tiers") if isinstance(ai_doc, dict) else None
    for tier, spec in (tiers or {}).items():
        for entry in (spec or {}).get("models") or [] if isinstance(spec, dict) else []:
            pid = CP.model_pin_id(entry)
            if pid:
                out.setdefault(pid, set()).add(str(tier))
    return out


def build_manifest(
    pins_doc: Any, profiles_doc: Any, ai_doc: Any, release: str, role_doc: Any = None
) -> dict[str, Any]:
    pins: dict[str, Any] = pins_doc["pins"]
    profiles: dict[str, Any] = profiles_doc["profiles"]
    tiers = model_tiers_of(ai_doc)
    features = feature_pins_of(role_doc, pins)
    files: list[dict[str, Any]] = []
    for pid in sorted(pins):
        pin = pins[pid]
        entry = {k: pin.get(k) for k in FILE_KEYS if k != "id"}
        entry["id"] = pid
        entry["profiles"] = file_tags(pid, pin, tiers, features)
        files.append(entry)
    out_profiles: dict[str, Any] = {}
    for name in sorted(profiles):
        prof = profiles[name]
        features = dict(prof.get("features") or {})
        want = active_tags(name, features)
        ids = sorted(
            f["id"]
            for f in files
            if pins[f["id"]].get("stage") == "assets" and want & set(f["profiles"])
        )
        out_profiles[name] = {
            "description": prof.get("description", ""),
            "features": features,
            "files": ids,
        }
    return {"schema": 1, "release": release, "files": files, "profiles": out_profiles}


def git_release(main_path: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "describe", "--tags", "--always", "--dirty"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    version = "unknown"
    if main_path.exists():
        main = CP.load_yaml(main_path) or {}
        version = str(main.get("airlock_version") or version)
    return f"{version}-nogit"


def render(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write assets/manifest.json (contract section 6).")
    ap.add_argument("--pins", type=Path, default=GROUP_VARS / "pins.yml")
    ap.add_argument("--profiles", type=Path, default=GROUP_VARS / "profiles.yml")
    ap.add_argument("--ai-models", type=Path, default=GROUP_VARS / "ai_models.yml")
    ap.add_argument("--main", type=Path, default=GROUP_VARS / "main.yml")
    ap.add_argument(
        "--ai-role",
        type=Path,
        default=AI_ROLE_DEFAULTS,
        help="tools_ai role defaults: feature tags for its wheel and model pins",
    )
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "assets" / "manifest.json")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing --out")
    ap.add_argument("--release", help="release string (default: git describe)")
    ap.add_argument("--check", action="store_true", help="fail if --out is out of date")
    args = ap.parse_args(argv)

    pins_doc = CP.load_yaml(args.pins)
    profiles_doc = CP.load_yaml(args.profiles)
    ai_doc = CP.load_yaml(args.ai_models) if args.ai_models.exists() else None
    role_doc = CP.load_yaml(args.ai_role) if args.ai_role.exists() else None
    result = CP.analyse(pins_doc, profiles_doc, ai_doc)
    if result["errors"]:
        for err in result["errors"]:
            print(f"gen-manifest: {err}", file=sys.stderr)
        print(
            "gen-manifest: pins.yml or profiles.yml has errors. Fix them and rerun.",
            file=sys.stderr,
        )
        return 1

    release = args.release
    existing: dict[str, Any] | None = None
    if args.check:
        try:
            existing = json.loads(args.out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print(
                f"gen-manifest: {args.out} is missing or not JSON. Run scripts/gen-manifest.py.",
                file=sys.stderr,
            )
            return 1
        release = release or str(existing.get("release", ""))
    release = release or git_release(args.main)
    text = render(build_manifest(pins_doc, profiles_doc, ai_doc, release, role_doc))

    if args.check:
        if args.out.read_text(encoding="utf-8") != text:
            print(
                f"gen-manifest: {args.out} is out of date. Run scripts/gen-manifest.py.",
                file=sys.stderr,
            )
            return 1
        print(f"gen-manifest: {args.out} is up to date")
        return 0
    if args.stdout:
        sys.stdout.write(text)
        return 0
    write_atomic(args.out, text)
    n_profiles = len(json.loads(text)["profiles"])
    print(
        f"gen-manifest: wrote {args.out} ({result['count']} files, {n_profiles} profiles, "
        f"release {release})"
    )
    if result["unpinned"]:
        print("gen-manifest: not pinned yet, fetchers will skip: " + ", ".join(result["unpinned"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
