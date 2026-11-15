"""scripts/check-pins.py (task 6.2) and scripts/gen-manifest.py (tasks 2B.10, 2B.18, 4B.15)."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

import fetch_assets

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
GV = REPO / "ansible" / "group_vars" / "all"
SHA = "a" * 64


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CP = load("check-pins")
GM = load("gen-manifest")


def pin(**kw: Any) -> dict[str, Any]:
    base = {
        "url": "https://example.org/x.bin", "version": "1.0", "sha256": SHA, "size": 10,
        "stage": "assets", "target": "x/x.bin", "profiles": ["default"], "verify": "sha256",
        "license": "MIT", "notes": "",
    }  # fmt: skip
    base.update(kw)
    return base


PROFILES = {
    "profiles": {
        "default": {"description": "d", "features": {
            "ai_tiers": ["tier0"], "clamav": True, "yara": True, "malwarebazaar": True,
            "nvidia_proprietary": False, "nsrl": False}},
        "minimal": {"description": "m", "features": {"ai_tiers": [], "yara": True}},
        "gpu": {"description": "g", "features": {"ai_tiers": ["tier0"],
                                                 "nvidia_proprietary": True}},
        "ci": {"description": "c", "features": {"ai_tiers": []}},
    }
}  # fmt: skip


def pins_doc() -> dict[str, Any]:
    return {
        "pins": {
            "iso": pin(stage="build", target=None, profiles=["build"]),
            "model_a": pin(target="models/a.gguf", profiles=["ai_tier1"]),
            "model_b": pin(target="models/b.gguf", profiles=["full"]),
            "clam_daily": pin(target="clamav/daily.cvd", sha256=None, size=None,
                              verify="vendor_signature", profiles=["clamav"], notes="daily"),
            "mb": pin(target="mb/full.zip", sha256=None, verify="trusted_at_staging",
                      profiles=["malwarebazaar"], notes="daily, needs key"),
            "yara": pin(target="yara/rules.yar", profiles=["yara"]),
            "nvidia_modules": pin(target="nvidia/modules.deb", profiles=["nvidia_proprietary"]),
            "ci_data": pin(target="ci/data.bin", profiles=["ci"]),
            "everyone": pin(target="common/readme.txt", profiles=["all"]),
            "unpinned": pin(target="u/u.bin", sha256=None, notes="host unreachable"),
        }
    }  # fmt: skip


AI = {"ai_tiers": {"tier0": {"models": [{"pin": "model_a"}]}, "tier1": {"models": []}}}


# ------------------------------------------------------------------ check-pins


def test_repo_pins_are_well_formed() -> None:
    res = CP.analyse(
        yaml.safe_load((GV / "pins.yml").read_text(encoding="utf-8")),
        yaml.safe_load((GV / "profiles.yml").read_text(encoding="utf-8")),
        yaml.safe_load((GV / "ai_models.yml").read_text(encoding="utf-8")),
    )
    assert res["errors"] == []


def test_good_doc_has_no_errors_and_lists_unpinned() -> None:
    profiles = copy.deepcopy(PROFILES)
    profiles["profiles"]["full"] = {"description": "f", "features": {"ai_tiers": []}}
    res = CP.analyse(pins_doc(), profiles, AI)
    assert res["errors"] == []
    assert res["unpinned"] == ["unpinned"]
    assert res["moving"] == ["clam_daily", "mb"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"url": "http://example.org/x"}, "https:// URL"),
        ({"stage": "download"}, "stage must be one of"),
        ({"verify": "md5"}, "verify must be one of"),
        ({"target": None}, "target is required"),
        ({"target": "../etc/passwd"}, "must not contain"),
        ({"target": "C:\\x"}, "relative path"),
        ({"sha256": "ABC"}, "64 lower-case hex"),
        ({"size": -1}, "whole number"),
        ({"version": 1.0}, "quoted string"),
        ({"profiles": ["defualt"]}, "unknown profile tag"),
        ({"profiles": []}, "non-empty list"),
        ({"license": ""}, "licence"),
        ({"sha256": None, "notes": ""}, "notes must say why"),
        ({"stage": "build", "verify": "vendor_signature", "target": None}, "only allowed"),
        ({"extra": 1}, "unknown field"),
    ],
)
def test_each_bad_field_is_reported(change: dict[str, Any], message: str) -> None:
    doc = pins_doc()
    doc["pins"]["yara"].update(change)
    res = CP.analyse(doc, PROFILES | {}, AI)
    assert any(e.startswith("pins.yml yara:") and message in e for e in res["errors"]), res
    assert any("yara" in e for e in res["errors"])


def test_missing_field_and_duplicate_target() -> None:
    doc = pins_doc()
    del doc["pins"]["yara"]["notes"]
    doc["pins"]["model_b"]["target"] = "models/a.gguf"
    res = CP.analyse(doc, PROFILES, AI)
    assert any("missing field(s): notes" in e for e in res["errors"])
    assert any("is also used by" in e for e in res["errors"])


def test_ai_models_must_name_asset_pins() -> None:
    ai = {"ai_tiers": {"tier0": {"models": ["nope", {"pin": "iso"}]}}}
    res = CP.analyse(pins_doc(), PROFILES, ai)
    assert any("'nope' is not in pins.yml" in e for e in res["errors"])
    assert any("'iso' must have stage=assets" in e for e in res["errors"])


def test_profiles_are_checked() -> None:
    bad = {
        "profiles": {
            "x": {
                "description": "",
                "features": {"ai_tiers": ["tier9"], "clamav": "yes", "warp": True},
            }
        }
    }
    res = CP.analyse(pins_doc(), bad, None)
    text = "\n".join(res["errors"])
    for want in (
        "description is required",
        "ai_tiers must be a list",
        "must be true or false",
        "unknown feature 'warp'",
    ):
        assert want in text


def test_cli_exit_codes(tmp_path: Path) -> None:
    pins = tmp_path / "pins.yml"
    profiles = tmp_path / "profiles.yml"
    full = copy.deepcopy(PROFILES)
    full["profiles"]["full"] = {"description": "f", "features": {}}
    pins.write_text(yaml.safe_dump(pins_doc()), encoding="utf-8")
    profiles.write_text(yaml.safe_dump(full), encoding="utf-8")
    base = [sys.executable, str(SCRIPTS / "check-pins.py"), "--pins", str(pins),
            "--profiles", str(profiles), "--ai-models", str(tmp_path / "none.yml")]  # fmt: skip
    ok = subprocess.run(base, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    assert "not pinned yet (sha256 null): unpinned" in ok.stdout
    strict = subprocess.run([*base, "--strict"], capture_output=True, text=True, check=False)
    assert strict.returncode == 1
    assert "release blocked" in strict.stderr
    listed = subprocess.run([*base, "--list-unpinned"], capture_output=True, text=True,
                            check=False)  # fmt: skip
    assert listed.stdout.split() == ["unpinned"]
    doc = pins_doc()
    doc["pins"]["yara"]["url"] = "ftp://x"
    pins.write_text(yaml.safe_dump(doc), encoding="utf-8")
    bad = subprocess.run(base, capture_output=True, text=True, check=False)
    assert bad.returncode == 1
    assert "pins.yml yara: url must be an https:// URL" in bad.stderr


# ------------------------------------------------------------------ gen-manifest


def build(release: str = "v0.1.0") -> dict[str, Any]:
    profiles = copy.deepcopy(PROFILES)
    profiles["profiles"]["full"] = {"description": "f", "features": {"ai_tiers": ["tier0"]}}
    return GM.build_manifest(pins_doc(), profiles, AI, release)


def test_manifest_shape_follows_contract() -> None:
    m = build()
    assert m["schema"] == 1
    assert m["release"] == "v0.1.0"
    assert [f["id"] for f in m["files"]] == sorted(f["id"] for f in m["files"])
    for f in m["files"]:
        assert set(f) == {"id", "url", "version", "size", "sha256", "target", "profiles",
                          "verify", "license"}  # fmt: skip
    assert set(m["profiles"]["default"]) == {"description", "features", "files"}


def test_profile_resolution_by_tag_feature_and_model_tier() -> None:
    m = build()
    files = m["profiles"]
    # tier0 model from ai_models.yml, clamav and malwarebazaar features, yara, 'all'.
    assert files["default"]["files"] == ["clam_daily", "everyone", "mb", "model_a", "unpinned",
                                         "yara"]  # fmt: skip
    assert files["minimal"]["files"] == ["everyone", "yara"]
    assert files["ci"]["files"] == ["ci_data", "everyone"]
    assert "model_b" in files["full"]["files"]
    # Build pins never go to ASSETS.
    assert all("iso" not in p["files"] for p in files.values())
    by_id = {f["id"]: f for f in m["files"]}
    assert by_id["model_a"]["profiles"] == ["ai_tier0", "ai_tier1"]


def test_nvidia_packages_only_when_the_feature_is_on() -> None:
    """4B.15: the proprietary driver packages are staged only for nvidia_proprietary: true."""
    m = build()
    assert "nvidia_modules" not in m["profiles"]["default"]["files"]
    assert "nvidia_modules" in m["profiles"]["gpu"]["files"]


def test_render_is_deterministic() -> None:
    a, b = GM.render(build()), GM.render(build())
    assert a == b
    assert a.endswith("}\n")
    assert json.loads(a)["files"][0]["id"] == "ci_data"


def test_fetcher_resolves_like_gen_manifest() -> None:
    """A profile file with only features gets the same files as the manifest profile."""
    m = build()
    for name, prof in m["profiles"].items():
        assert sorted(fetch_assets.active_tags(name, prof["features"])) == sorted(
            GM.active_tags(name, prof["features"])
        )


def test_gen_manifest_cli_write_and_check(tmp_path: Path) -> None:
    out = tmp_path / "manifest.json"
    cmd = [sys.executable, str(SCRIPTS / "gen-manifest.py"), "--out", str(out)]
    res = subprocess.run([*cmd, "--release", "v-test"], capture_output=True, text=True,
                         check=False)  # fmt: skip
    assert res.returncode == 0, res.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert set(data["profiles"]) >= {"default", "minimal", "full", "ci"}
    chk = subprocess.run([*cmd, "--check"], capture_output=True, text=True, check=False)
    assert chk.returncode == 0, chk.stderr
    data["profiles"]["default"]["files"].append("stale")
    out.write_text(json.dumps(data), encoding="utf-8")
    chk = subprocess.run([*cmd, "--check"], capture_output=True, text=True, check=False)
    assert chk.returncode == 1
    assert "out of date" in chk.stderr


def test_gen_manifest_refuses_bad_pins(tmp_path: Path) -> None:
    doc = pins_doc()
    doc["pins"]["yara"]["stage"] = "nowhere"
    pins = tmp_path / "pins.yml"
    pins.write_text(yaml.safe_dump(doc), encoding="utf-8")
    res = subprocess.run(
        [sys.executable, str(SCRIPTS / "gen-manifest.py"), "--pins", str(pins), "--stdout"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert res.returncode == 1
    assert "stage must be one of" in res.stderr


# ------------------------------------------------------------------ licences (2B.18)


def test_every_pin_is_in_the_licence_table() -> None:
    """docs/licenses.md lists every pin with its licence and whether it may be baked."""
    text = (REPO / "docs" / "licenses.md").read_text(encoding="utf-8")
    start, end = text.index("<!-- pins-table:start -->"), text.index("<!-- pins-table:end -->")
    table = text[start:end]
    pins = yaml.safe_load((GV / "pins.yml").read_text(encoding="utf-8"))["pins"]
    missing = [pid for pid in pins if f"| `{pid}` |" not in table]
    assert not missing, (
        f"pins missing from docs/licenses.md: {missing}. "
        "Run 'python3 scripts/check-pins.py --licences-table' and paste it between the markers."
    )


def test_bake_policy_follows_2b18() -> None:
    assert CP.bake_policy(pin(stage="image", target=None)) == "yes: baked by the build"
    assert CP.bake_policy(pin(profiles=["clamav"])).startswith("no: user-fetched")
    assert CP.bake_policy(pin(profiles=["ai_tier0"])).startswith("no: user-fetched")
    assert CP.bake_policy(pin(profiles=["nvidia_proprietary"])).startswith("no: opt-in NVIDIA")
    assert "unconfirmed" in CP.bake_policy(pin(profiles=["eztools"]))
    table = CP.licences_table(pins_doc()["pins"])
    assert "| `mb` | 1.0 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |" in table


def test_manifest_carries_each_files_licence() -> None:
    for f in build()["files"]:
        assert f["license"]
