"""ansible/roles/tools_ai: structure and the values its controls write (4B.1, 4B.2, 4B.5,
4B.7, 4B.10, 4B.15). The behaviour checks are goss (tests/goss/ai.yaml) in the booted image."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "tools_ai"
GV = REPO / "ansible" / "group_vars" / "all"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
PINS = yaml.safe_load((GV / "pins.yml").read_text())["pins"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _tasks(name: str) -> list[dict]:
    return yaml.safe_load((ROLE / "tasks" / name).read_text())


def test_every_task_file_is_imported_and_names_its_test():
    imported = [t["ansible.builtin.import_tasks"] for t in _tasks("main.yml")]
    on_disk = sorted(
        p.name for p in (ROLE / "tasks").glob("*.yml") if p.name not in {"main.yml", "_venv.yml"}
    )
    assert sorted(imported) == on_disk
    for name in imported:
        head = (ROLE / "tasks" / name).read_text().split("\n- ", 1)[0]
        assert re.search(r"Control 4B\.\d+", head), name
        assert "Test:" in head, name


def test_defaults_use_the_role_prefix():
    assert all(k.startswith("tools_ai_") for k in DEFAULTS)


def test_llama_build_is_vulkan_only_portable_and_offline():
    flags = DEFAULTS["tools_ai_llama_cmake_flags"]
    assert "-DGGML_VULKAN=ON" in flags
    for off in ("-DGGML_CUDA=OFF", "-DGGML_HIP=OFF", "-DGGML_NATIVE=OFF", "-DLLAMA_CURL=OFF"):
        assert off in flags
    assert not any(re.search(r"CUDA=ON|HIP=ON|HIPBLAS|ROCM", f) for f in flags)
    get = next(t for t in _tasks("llama_build.yml") if "ansible.builtin.get_url" in t)
    assert get["ansible.builtin.get_url"]["checksum"].startswith("sha256:{{ pins[")
    assert PINS[DEFAULTS["tools_ai_llama_pin"]]["license"] == "MIT"
    version = PINS[DEFAULTS["tools_ai_llama_pin"]]["version"]
    assert int(version.lstrip("b")) >= 9562  # native video input through mtmd
    assert DEFAULTS["tools_ai_llama_targets"] == ["llama-server", "llama-mtmd-cli"]


def test_vulkan_packages_name_no_vendor():
    pkgs = DEFAULTS["tools_ai_vulkan_packages"]
    assert "mesa-vulkan-drivers" in pkgs and "vulkan-tools" in pkgs
    assert not any(re.search(r"nvidia|amdgpu|intel|cuda|rocm", p) for p in pkgs)


def test_units_bind_loopback_only_and_socket_is_off():
    sock = (ROLE / "templates" / "llama-server.socket.j2").read_text()
    assert "ListenStream={{ tools_ai_llama_listen_host }}:{{ tools_ai_llama_listen_port }}" in sock
    assert DEFAULTS["tools_ai_llama_listen_host"] == "127.0.0.1"
    for unit in ("llama-server.service.j2", "llama-server-proxy.service.j2"):
        text = (ROLE / "templates" / unit).read_text()
        assert "IPAddressDeny=any" in text and "IPAddressAllow=localhost" in text
    enable = [t for t in _tasks("llama_server_unit.yml") if "ansible.builtin.systemd_service" in t]
    assert enable[0]["ansible.builtin.systemd_service"] == {
        "name": "llama-server.socket",
        "enabled": False,
    }


def test_wheel_pins_are_real_hashes_and_staged_on_assets():
    for key in ("tools_ai_triage_wheel_pins", "tools_ai_whisper_wheel_pins"):
        for pid in DEFAULTS[key]:
            pin = PINS[pid]
            assert HEX64.match(pin["sha256"] or ""), pid
            assert pin["stage"] == "assets" and pin["target"].startswith("wheels/"), pid
            assert pin["url"].startswith("https://files.pythonhosted.org/"), pid
            assert (
                "cp312" in pin["target"]
                or "py3-none-any" in pin["target"]
                or "py2.py3" in pin["target"]
                or "abi3" in pin["target"]
            ), pid
    assert "AGPL-3.0" in PINS["wheel_nudenet"]["license"]


def test_venvs_install_offline_with_hashes():
    text = (ROLE / "tasks" / "_venv.yml").read_text()
    for flag in ("--no-index", "--no-deps", "--require-hashes"):
        assert flag in text
    req = (ROLE / "templates" / "requirements.txt.j2").read_text()
    assert "--hash=sha256:{{ pins[pin].sha256 }}" in req
    for name in ("triage_venv.yml", "whisper_venv.yml"):
        assert "airlock_phase == 'provision'" in (ROLE / "tasks" / name).read_text()


def test_nvidia_proprietary_is_off_offline_and_without_dkms():
    assert DEFAULTS["tools_ai_nvidia_proprietary"] is False
    profiles = yaml.safe_load((GV / "profiles.yml").read_text())["profiles"]
    assert all(p["features"].get("nvidia_proprietary") is False for p in profiles.values())
    text = (ROLE / "tasks" / "nvidia_proprietary.yml").read_text()
    assert "--no-download" in text and "dkms" in text and "mokutil" not in text
    assert "airlock_phase == 'provision'" in text


def test_screen_thresholds_installed_from_session_tools():
    task = _tasks("screen_thresholds.yml")[0]["ansible.builtin.copy"]
    src = task["src"].replace("{{ role_path }}", str(ROLE))
    assert Path(src).resolve().is_file()
    assert task["dest"].endswith("/screen-thresholds.json")


@pytest.mark.skipif(shutil.which("ansible") is None, reason="needs ansible-core")
def test_requirements_template_renders(tmp_path: Path):
    out = tmp_path / "req.txt"
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
            f"src={ROLE / 'templates' / 'requirements.txt.j2'} dest={out}",
            "-e",
            f"@{GV / 'main.yml'}",
            "-e",
            f"@{GV / 'pins.yml'}",
            "-e",
            f"@{ROLE / 'defaults' / 'main.yml'}",
            "-e",
            '{"tools_ai_venv_pins": ["wheel_nudenet", "wheel_numpy"]}',
        ],
        check=True,
        capture_output=True,
        env={"ANSIBLE_LOCALHOST_WARNING": "False", "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    lines = [ln for ln in out.read_text().splitlines() if not ln.startswith("#")]
    assert lines == [
        f"/srv/airlock/assets/files/{PINS[p]['target']} --hash=sha256:{PINS[p]['sha256']}"
        for p in ("wheel_nudenet", "wheel_numpy")
    ]
