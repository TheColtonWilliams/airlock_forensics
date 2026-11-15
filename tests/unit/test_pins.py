"""The real pins.yml, profiles.yml and the lists that follow them (tasks 6.2, 2B.18, 4B.15)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
GV = REPO / "ansible" / "group_vars" / "all"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CP = load("check-pins")
GM = load("gen-manifest")


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


PINS: dict[str, dict[str, Any]] = _yaml(GV / "pins.yml")["pins"]


def _manifest() -> dict[str, Any]:
    return GM.build_manifest(
        _yaml(GV / "pins.yml"), _yaml(GV / "profiles.yml"), _yaml(GV / "ai_models.yml"), "test"
    )


def test_ci_profile_stages_at_least_one_real_pinned_file() -> None:
    """CI staging must exercise a real download, not only skipped null-hash pins."""
    man = _manifest()
    files = {f["id"]: f for f in man["files"]}
    ci = man["profiles"]["ci"]["files"]
    pinned = [i for i in ci if files[i]["sha256"] and files[i]["verify"] == "sha256"]
    assert pinned, f"ci profile resolves only to unpinned files: {ci}"
    for pid in pinned:
        # Small enough for every CI run.
        assert files[pid]["size"] and files[pid]["size"] < 50 * 1024 * 1024, pid


def test_pinned_entries_record_size_and_source() -> None:
    for pid in ("goss_linux_amd64", "yara_forge_core"):
        pin = PINS[pid]
        assert SHA_RE.match(pin["sha256"] or ""), pid
        assert isinstance(pin["size"], int) and pin["size"] > 0, pid
        assert pin["notes"], pid


def test_no_placeholder_versions_or_urls() -> None:
    for pid, pin in PINS.items():
        for key in ("url", "version"):
            assert "commit-to-pin" not in str(pin[key]), f"{pid}.{key} is a placeholder"


def test_goss_is_marked_as_baked() -> None:
    goss = PINS["goss_linux_amd64"]
    assert goss["stage"] == "build" and "image" in goss["profiles"]
    assert CP.bake_policy(goss).startswith("yes:")
    assert "never baked" not in goss["license"]


def test_bake_policy_build_stage() -> None:
    base = {"stage": "build", "target": None}
    assert CP.bake_policy({**base, "profiles": ["build"]}) == "n/a: build host only"
    assert CP.bake_policy({**base, "profiles": ["build", "image"]}).startswith("yes:")


def test_llama_tag_is_at_or_after_plan_minimum() -> None:
    pin = PINS["llama_cpp_source"]
    m = re.fullmatch(r"b(\d+)", pin["version"])
    assert m and int(m.group(1)) >= 9562
    assert pin["url"].endswith(f"/archive/refs/tags/{pin['version']}.tar.gz")


def test_llama_build_fetches_nothing() -> None:
    defaults = _yaml(REPO / "ansible" / "roles" / "tools_ai" / "defaults" / "main.yml")
    flags = defaults["tools_ai_llama_cmake_flags"]
    for off in (
        "-DLLAMA_CURL=OFF",
        "-DLLAMA_OPENSSL=OFF",
        "-DLLAMA_BUILD_UI=OFF",
        "-DLLAMA_USE_PREBUILT_UI=OFF",
    ):
        assert off in flags, off


def test_tools_ai_nvidia_list_matches_the_nvidia_pins() -> None:
    defaults = _yaml(REPO / "ansible" / "roles" / "tools_ai" / "defaults" / "main.yml")
    want = sorted(pid for pid in PINS if pid.startswith("nvidia_deb_"))
    assert want, "no nvidia_deb_* pins"
    assert sorted(defaults["tools_ai_nvidia_deb_pins"]) == want
    for pid in want:
        assert PINS[pid]["stage"] == "assets" and "nvidia_proprietary" in PINS[pid]["profiles"]


def test_licences_doc_table_is_current() -> None:
    text = (REPO / "docs" / "licenses.md").read_text(encoding="utf-8")
    start, end = "<!-- pins-table:start -->\n", "<!-- pins-table:end -->"
    table = text[text.index(start) + len(start) : text.index(end)]
    assert table == CP.licences_table(PINS), (
        "docs/licenses.md is out of date: run 'python3 scripts/check-pins.py --licences-table' "
        "and paste it between the pins-table markers."
    )
