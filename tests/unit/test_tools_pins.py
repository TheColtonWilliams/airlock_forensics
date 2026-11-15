"""Tasks 4.3, 4.5, 4.6 (and 6.2 for the tool roles): every download the tool roles make is in
pins.yml, and every PyPI venv is fully pinned by hash.

* each files/requirements.txt line is ``name==version`` with exactly one SHA-256 hash, no
  package twice, and the top-level package agrees with its pins.yml entry;
* the build backend list is the same in every venv role;
* every pin a tool role names exists, image-stage pins are hashed, and every get_url in a tool
  role checks a pinned SHA-256.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLES = REPO / "ansible" / "roles"
PINS: dict[str, dict[str, Any]] = yaml.safe_load(
    (REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text()
)["pins"]
VENV_ROLES = {
    "tools_dissect": ("dissect_pypi", "dissect"),
    "tools_timeline": ("plaso_pypi", "plaso"),
    "tools_carve": ("usncarve_pypi", "usncarve"),
}
TOOL_ROLES = sorted(
    p.name for p in ROLES.glob("tools_*") if p.name not in {"tools_ai", "tools_hashsets"}
)
REQ_RE = re.compile(
    r"^([a-z0-9][a-z0-9-]*)==([^\s\\]+) \\\n" r"    --hash=sha256:([0-9a-f]{64})$", re.M
)


def parse_requirements(path: Path) -> dict[str, tuple[str, str]]:
    text = path.read_text()
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
    found = REQ_RE.findall(body)
    # Nothing else than the matched entries may be in the file.
    rest = REQ_RE.sub("", body).strip()
    assert not rest, f"{path}: unparsed lines: {rest[:200]!r}"
    names = [n for n, _, _ in found]
    assert len(names) == len(set(names)), f"{path}: a package is listed twice"
    return {n: (v, h) for n, v, h in found}


@pytest.mark.parametrize("role", sorted(VENV_ROLES))
def test_requirements_are_fully_hashed_and_agree_with_the_pin(role: str) -> None:
    pin_id, top = VENV_ROLES[role]
    reqs = parse_requirements(ROLES / role / "files" / "requirements.txt")
    assert top in reqs, f"{role}: {top} is not in requirements.txt"
    version, sha = reqs[top]
    assert PINS[pin_id]["version"] == version, f"pins.{pin_id}.version != requirements.txt"
    assert PINS[pin_id]["sha256"] == sha, f"pins.{pin_id}.sha256 != requirements.txt"
    assert PINS[pin_id]["stage"] == "image"
    assert PINS[pin_id]["url"].startswith("https://files.pythonhosted.org/")
    assert PINS[pin_id]["url"].rsplit("/", 1)[-1].startswith(f"{top}-{version}")


def test_requirement_closures_are_complete() -> None:
    dissect = parse_requirements(ROLES / "tools_dissect" / "files" / "requirements.txt")
    assert {
        "dissect-target",
        "dissect-ntfs",
        "dissect-thumbcache",
        "dissect-fve",
        "dissect-regf",
        "dissect-evidence",
        "flow-record",
    } <= set(dissect)
    plaso = parse_requirements(ROLES / "tools_timeline" / "files" / "requirements.txt")
    assert {
        "dfvfs",
        "dfdatetime",
        "dfwinreg",
        "pytsk3",
        "libfsntfs-python",
        "libevtx-python",
        "artifacts",
    } <= set(plaso)


def test_build_backend_is_the_same_everywhere() -> None:
    texts = {(ROLES / r / "files" / "build-requirements.txt").read_text() for r in VENV_ROLES}
    assert len(texts) == 1
    reqs = parse_requirements(ROLES / "tools_dissect" / "files" / "build-requirements.txt")
    assert {"setuptools", "wheel"} <= set(reqs)


def _pin_names(obj: Any) -> set[str]:
    """Every string in a role's defaults that names a pins.yml entry."""
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "pin" or k.endswith("_pin"):
                out.add(v)
            elif k.endswith("_pins") and isinstance(v, list):
                out.update(v)
            else:
                out |= _pin_names(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _pin_names(v)
    return out


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_every_named_pin_exists_and_image_pins_are_hashed(role: str) -> None:
    defaults_file = ROLES / role / "defaults" / "main.yml"
    if not defaults_file.exists():
        pytest.skip(f"{role} has no defaults")
    for pin_id in _pin_names(yaml.safe_load(defaults_file.read_text())):
        assert pin_id in PINS, f"{role} names pins.{pin_id}, which does not exist"
        pin = PINS[pin_id]
        if pin["stage"] == "image":
            assert pin["sha256"] and len(pin["sha256"]) == 64, f"pins.{pin_id} is not hashed"
        else:
            assert (
                pin["sha256"] or "verify" in pin["notes"].lower() or "unreachable" in pin["notes"]
            ), pin_id


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_every_download_checks_a_pinned_hash(role: str) -> None:
    for f in sorted((ROLES / role / "tasks").glob("*.yml")):
        for task in yaml.safe_load(f.read_text()) or []:
            get_url = task.get("ansible.builtin.get_url")
            if get_url is None:
                continue
            assert get_url["url"].startswith("{{ pins["), (f, task["name"])
            assert get_url["checksum"].startswith("sha256:{{ pins["), (f, task["name"])
            # The same file refuses a null hash before downloading.
            assert "sha256 is not none" in f.read_text(), f


def test_no_tool_role_adds_an_apt_source_or_downloads_at_provision() -> None:
    for role in TOOL_ROLES:
        for f in sorted((ROLES / role / "tasks").glob("*.yml")):
            text = f.read_text()
            assert "apt_repository" not in text and "deb822_repository" not in text, f
            for task in yaml.safe_load(text) or []:
                if "ansible.builtin.get_url" in task:
                    when = task.get("when", "")
                    assert "airlock_phase == 'image'" in str(when), (f, task["name"])
