"""Tier selection from recorded and synthesised vulkaninfo outputs (tasks 4B.3, 4G.9)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from airlock_ai import config as cfgmod
from airlock_ai import probe

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "vulkaninfo"

# The table 4G.9 asks for: recorded hardware profile -> tier.
# Default image: tier0..tier2 ship (ai_tiers_on_image), integrated margin 8 GiB.
TABLE = [
    # (vulkaninfo fixture, meminfo fixture, expected tier, expected backend, device index)
    ("recorded-llvmpipe-no-gpu.txt", "meminfo-16gb.txt", "tier0", "cpu", None),
    ("recorded-llvmpipe-summary.txt", "meminfo-16gb.txt", "tier0", "cpu", None),
    ("recorded-llvmpipe-profile.json", "meminfo-16gb.txt", "tier0", "cpu", None),
    ("discrete-8gb.txt", "meminfo-16gb.txt", "tier2", "vulkan", 0),
    ("discrete-4gb.legacy.json", "meminfo-16gb.txt", "tier1", "vulkan", 0),
    ("integrated-shared.txt", "meminfo-16gb.txt", "tier2", "vulkan", 0),
    ("integrated-shared.txt", "meminfo-8gb.txt", "tier0", "cpu", None),
    ("multi-gpu.txt", "meminfo-16gb.txt", "tier2", "vulkan", 1),
    ("two-discrete-24gb.list.json", "meminfo-64gb.txt", "tier2", "vulkan", 1),
]
# With every tier on the image (the "full" profile).
TABLE_ALL_TIERS = [
    ("discrete-8gb.txt", "tier2"),
    ("multi-gpu.txt", "tier3"),
    ("two-discrete-24gb.list.json", "tier4"),
    ("recorded-llvmpipe-no-gpu.txt", "tier0"),
]


def _cfg(tiers_on_image: list[str] | None = None) -> dict:
    cfg = json.loads(json.dumps(cfgmod.DEFAULT_AI_CONFIG))
    if tiers_on_image is not None:
        cfg["tiers_on_image"] = tiers_on_image
    for t in cfg["tiers"]:
        cfg["tiers"][t]["model_id"] = f"model-{t}"
        cfg["tiers"][t]["models"] = [
            {"id": f"{t}_gguf", "role": "model", "target": f"models/{t}/model.gguf"},
            {"id": f"{t}_mmproj", "role": "mmproj", "target": f"models/{t}/mmproj.gguf"},
        ]
    return cfg


def _stage(assets: Path, tiers: list[str]) -> None:
    for t in tiers:
        d = assets / "files" / "models" / t
        d.mkdir(parents=True, exist_ok=True)
        (d / "model.gguf").write_bytes(b"GGUF" + t.encode())
        (d / "mmproj.gguf").write_bytes(b"GGUF-mm" + t.encode())


def _choose(vk: str, mem: str, cfg: dict, **kw: object) -> probe.TierChoice:
    return probe.choose_tier(
        vulkaninfo_text=(FIX / vk).read_text(encoding="utf-8"),
        meminfo_text=(FIX / mem).read_text(encoding="utf-8"),
        config=cfg,
        **kw,
    )


@pytest.mark.parametrize(("vk", "mem", "tier", "backend", "dev"), TABLE)
def test_tier_table(airlock_env: Path, vk: str, mem: str, tier: str, backend: str, dev: object):
    _stage(airlock_env / "assets", ["tier0", "tier1", "tier2", "tier3", "tier4"])
    choice = _choose(vk, mem, _cfg())
    assert (choice.tier, choice.backend) == (tier, backend), choice.steps
    assert (choice.device.index if choice.device else None) == dev
    assert choice.n_gpu_layers == (99 if backend == "vulkan" else 0)
    roles = sorted(m["role"] for m in choice.models)
    assert roles == ["mmproj", "model"]


@pytest.mark.parametrize(("vk", "tier"), TABLE_ALL_TIERS)
def test_tier_table_full_profile(airlock_env: Path, vk: str, tier: str):
    all_tiers = ["tier0", "tier1", "tier2", "tier3", "tier4"]
    _stage(airlock_env / "assets", all_tiers)
    assert _choose(vk, "meminfo-64gb.txt", _cfg(all_tiers)).tier == tier


def test_vendor_name_never_matters(airlock_env: Path):
    """Same capacities, different names and vendor IDs: same choice."""
    _stage(airlock_env / "assets", ["tier0", "tier1", "tier2"])
    text = (FIX / "discrete-8gb.txt").read_text(encoding="utf-8")
    renamed = re.sub(r"deviceName\s*=.*", "deviceName        = Some Brand X9000", text)
    renamed = re.sub(r"vendorID\s*=.*", "vendorID          = 0x10de", renamed)
    a = probe.choose_tier(vulkaninfo_text=text, meminfo_text="MemTotal: 16000000 kB", config=_cfg())
    b = probe.choose_tier(
        vulkaninfo_text=renamed, meminfo_text="MemTotal: 16000000 kB", config=_cfg()
    )
    assert (a.tier, a.n_gpu_layers) == (b.tier, b.n_gpu_layers) == ("tier2", 99)


def test_integrated_cap_uses_ram_margin(airlock_env: Path):
    _stage(airlock_env / "assets", ["tier0", "tier1", "tier2"])
    cfg = _cfg()
    cfg["integrated_ram_margin_gib"] = 10  # 15.7 GiB - 10 = 5.7 GiB -> tier1
    choice = _choose("integrated-shared.txt", "meminfo-16gb.txt", cfg)
    assert choice.tier == "tier1"
    assert "capped at RAM minus 10 GiB" in choice.device.note


def test_steps_down_when_models_not_staged(airlock_env: Path):
    _stage(airlock_env / "assets", ["tier0", "tier1"])  # tier2 missing
    choice = _choose("discrete-8gb.txt", "meminfo-16gb.txt", _cfg())
    assert choice.tier == "tier1"
    assert any("tier2 skipped" in s for s in choice.steps)


def test_no_models_at_all_gives_none(airlock_env: Path):
    choice = _choose("discrete-8gb.txt", "meminfo-16gb.txt", _cfg())
    assert choice.tier == "none"
    assert choice.n_gpu_layers == 0


def test_no_vulkaninfo_is_cpu(airlock_env: Path):
    _stage(airlock_env / "assets", ["tier0"])
    choice = probe.choose_tier(vulkaninfo_text="", meminfo_text="", config=_cfg())
    assert (choice.tier, choice.backend) == ("tier0", "cpu")


def test_garbage_json_is_cpu(airlock_env: Path):
    _stage(airlock_env / "assets", ["tier0"])
    choice = probe.choose_tier(vulkaninfo_text="{not json", meminfo_text="", config=_cfg())
    assert choice.tier == "tier0"
    assert choice.source_format == "unreadable"


def test_parse_recorded_text_heaps():
    devices, fmt = probe.parse_vulkaninfo(
        (FIX / "recorded-llvmpipe-no-gpu.txt").read_text(encoding="utf-8")
    )
    assert fmt == "text"
    assert len(devices) == 1
    assert devices[0].device_type == "cpu"
    assert devices[0].device_local_bytes == 16869146624


def test_parse_multi_gpu_heaps():
    devices, _ = probe.parse_vulkaninfo((FIX / "multi-gpu.txt").read_text(encoding="utf-8"))
    assert [d.device_type for d in devices] == ["integrated", "discrete", "discrete", "cpu"]
    assert devices[1].device_local_bytes == 12 * 1024**3
    # The second heap of a discrete card is system memory, not device-local.
    assert [h.device_local for h in devices[1].heaps] == [True, False]


def test_cli_write_and_json(airlock_env: Path, capsys: pytest.CaptureFixture[str]):
    _stage(airlock_env / "assets", ["tier0", "tier1", "tier2"])
    cfg_path = airlock_env / "etc" / "ai-tiers.json"
    cfg_path.write_text(json.dumps(_cfg()), encoding="utf-8")
    rc = probe.main(
        [
            "--vulkaninfo",
            str(FIX / "discrete-8gb.txt"),
            "--meminfo",
            str(FIX / "meminfo-16gb.txt"),
            "--write",
            "--json",
        ]
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["tier"] == "tier2"
    saved = json.loads((airlock_env / "state" / "ai-tier.json").read_text(encoding="utf-8"))
    assert saved["tier"] == "tier2"
    assert saved["vulkan_device_index"] == 0
    assert probe.load_choice()["tier"] == "tier2"


def test_shipped_tiers_config_matches_group_vars():
    """ai_models.yml thresholds equal the built-in defaults the probe falls back to."""
    yml = (
        Path(__file__).resolve().parents[2] / "ansible" / "group_vars" / "all" / "ai_models.yml"
    ).read_text(encoding="utf-8")
    for tier, spec in cfgmod.DEFAULT_AI_CONFIG["tiers"].items():
        block = yml.split(f"  {tier}:", 1)[1]
        assert f"min_vram_gib: {spec['min_vram_gib']}" in block.split("\n  tier")[0]


@pytest.mark.skipif(__import__("shutil").which("ansible") is None, reason="needs ansible-core")
def test_rendered_role_config_drives_the_probe(airlock_env: Path):
    """The tools_ai template renders ai-tiers.json from ai_models.yml + pins.yml; the probe
    reads it and picks tier2 for an 8 GB card once tier0..2 are staged at their pin targets."""
    import os  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    repo = Path(__file__).resolve().parents[2]
    gv = repo / "ansible" / "group_vars" / "all"
    role = repo / "ansible" / "roles" / "tools_ai"
    out = airlock_env / "etc" / "ai-tiers.json"
    subprocess.run(
        [
            "ansible",
            "localhost",
            "-c",
            "local",
            "-o",
            "-m",
            "ansible.builtin.template",
            "-a",
            f"src={role / 'templates' / 'ai-tiers.json.j2'} dest={out}",
            "-e",
            f"@{gv / 'main.yml'}",
            "-e",
            f"@{gv / 'pins.yml'}",
            "-e",
            f"@{gv / 'ai_models.yml'}",
            "-e",
            f"@{role / 'defaults' / 'main.yml'}",
        ],
        check=True,
        capture_output=True,
        env={**os.environ, "ANSIBLE_LOCALHOST_WARNING": "False"},
    )
    cfg = cfgmod.load_ai_config()
    assert cfg["tiers_on_image"] == ["tier0", "tier1", "tier2"]
    assert cfg["llama"]["listen"] == "127.0.0.1:8088"
    for tier in ("tier0", "tier1", "tier2"):
        for m in cfg["tiers"][tier]["models"]:
            p = airlock_env / "assets" / "files" / m["target"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"GGUF")
    choice = _choose("discrete-8gb.txt", "meminfo-16gb.txt", cfg)
    assert choice.tier == "tier2" and choice.model_id == "Qwen3-VL-8B-Instruct Q4_K_M"
    assert {m["role"] for m in choice.models} == {"model", "mmproj"}
