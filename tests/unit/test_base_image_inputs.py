"""ansible/roles/base/tasks/image_inputs.yml (tasks 2B.15, 2B.6): the trusted manifest, its
signature and public key, and goss are baked in from what scripts/build.sh staged.

The task file runs for real with ansible-playbook against temporary folders (the staged inputs,
/var/lib/airlock, /etc/airlock, /opt/airlock), with keys and manifests made here with the repo's
own scripts. Nothing on the host is touched.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "base"
GROUP_VARS = REPO / "ansible" / "group_vars" / "all" / "main.yml"
SCRIPTS = REPO / "scripts"

pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None
    or shutil.which("openssl") is None
    or os.geteuid() != 0,
    reason="needs ansible-playbook, openssl and root (the task file sets owner root)",
)

FAKE_GOSS = b"#!/bin/sh\necho fake goss for the unit test\n"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(scope="module")
def signed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A manifest signed with a throwaway key, as build.sh --dev makes it."""
    d = tmp_path_factory.mktemp("signed")
    subprocess.run([str(SCRIPTS / "gen-signing-key.sh"), "--out-dir", str(d / "key")],
                   check=True, capture_output=True)  # fmt: skip
    subprocess.run(
        ["python3", str(SCRIPTS / "gen-manifest.py"), "--release", "0.0.0-test",
         "--out", str(d / "manifest.json")],
        check=True, capture_output=True,
    )  # fmt: skip
    subprocess.run(
        [str(SCRIPTS / "sign-manifest.sh"), "--key", str(d / "key" / "manifest-signing.key.pem"),
         "--manifest", str(d / "manifest.json")],
        check=True, capture_output=True,
    )  # fmt: skip
    shutil.copy(d / "key" / "manifest-signing.pub.pem", d / "manifest-signing.pub.pem")
    shutil.rmtree(d / "key")
    return d


def stage(tmp_path: Path, signed: Path, kind: str | None, *, goss: bytes | None) -> Path:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in ("manifest.json", "manifest.json.sig", "manifest-signing.pub.pem"):
        shutil.copy(signed / name, inputs / name)
    if goss is not None:
        (inputs / "goss").write_bytes(goss)
    if kind is not None:
        (inputs / "build-kind.json").write_text(json.dumps({"kind": kind, "schema": 1}))
    return inputs


def run_inputs(tmp_path: Path, inputs: Path, **extra: object) -> tuple[int, str, dict]:
    roots = {
        "airlock_state_dir": str(tmp_path / "var" / "lib" / "airlock"),
        "airlock_etc_dir": str(tmp_path / "etc" / "airlock"),
        "airlock_opt_dir": str(tmp_path / "opt" / "airlock"),
        "base_image_inputs_dir": str(inputs),
        "pins": {"goss_linux_amd64": {"sha256": _sha256(FAKE_GOSS)}},
        **extra,
    }
    play = [
        {
            "name": "image_inputs unit test",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [str(ROLE / "defaults" / "main.yml"), str(GROUP_VARS)],
            "tasks": [
                {"ansible.builtin.import_tasks": str(ROLE / "tasks" / "image_inputs.yml")},
                {"ansible.builtin.debug": {"msg": "KIND={{ base_build_kind | default('none') }}"}},
            ],
        }
    ]
    playbook = tmp_path / "play.yml"
    playbook.write_text(yaml.safe_dump(play), encoding="utf-8")
    extra_file = tmp_path / "extra.json"
    extra_file.write_text(json.dumps(roots), encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
            "ANSIBLE_CONFIG": str(tmp_path / "none.cfg"),
        }
    )
    argv = ["ansible-playbook", "-i", "localhost,", str(playbook), "-e", f"@{extra_file}"]
    res = subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=300)
    return res.returncode, res.stdout + res.stderr, roots


def test_release_inputs_are_baked_at_the_contract_paths(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "release", goss=FAKE_GOSS)
    rc, out, roots = run_inputs(tmp_path, inputs)
    assert rc == 0, out
    assert "KIND=release" in out
    state, etc, opt = (Path(roots[k]) for k in ("airlock_state_dir", "airlock_etc_dir",
                                                 "airlock_opt_dir"))  # fmt: skip
    # airlock_common.paths.baked_manifest() and manifest_public_key().
    assert (state / "manifest.json").read_bytes() == (signed / "manifest.json").read_bytes()
    assert (state / "manifest.json.sig").read_bytes() == (signed / "manifest.json.sig").read_bytes()
    assert (etc / "manifest-signing.pub.pem").read_bytes() == (
        signed / "manifest-signing.pub.pem"
    ).read_bytes()
    goss = opt / "bin" / "goss"
    assert goss.read_bytes() == FAKE_GOSS
    assert os.access(goss, os.X_OK)
    assert oct(state.stat().st_mode & 0o777) == "0o750"


def test_dev_build_without_goss_bakes_the_manifest_only(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "dev", goss=None)
    rc, out, roots = run_inputs(tmp_path, inputs)
    assert rc == 0, out
    assert "KIND=dev" in out
    assert (Path(roots["airlock_state_dir"]) / "manifest.json").is_file()
    assert not (Path(roots["airlock_opt_dir"]) / "bin" / "goss").exists()


def test_release_build_without_goss_fails(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "release", goss=None)
    rc, out, roots = run_inputs(tmp_path, inputs)
    assert rc != 0
    assert "release build has no goss" in out
    assert not (Path(roots["airlock_state_dir"]) / "manifest.json").exists()


def test_goss_that_differs_from_its_pin_is_refused(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "release", goss=FAKE_GOSS + b"#changed\n")
    rc, out, roots = run_inputs(tmp_path, inputs)
    assert rc != 0
    assert "does not match pins.goss_linux_amd64" in out
    assert not (Path(roots["airlock_opt_dir"]) / "bin" / "goss").exists()


def test_unpinned_goss_is_refused(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "dev", goss=FAKE_GOSS)
    rc, out, _ = run_inputs(tmp_path, inputs, pins={"goss_linux_amd64": {"sha256": None}})
    assert rc != 0
    assert "does not match pins.goss_linux_amd64" in out


def test_edited_manifest_is_refused(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "release", goss=FAKE_GOSS)
    with (inputs / "manifest.json").open("a", encoding="utf-8") as fh:
        fh.write(" ")
    rc, out, roots = run_inputs(tmp_path, inputs)
    assert rc != 0
    assert "Check the manifest signature" in out
    assert not (Path(roots["airlock_state_dir"]) / "manifest.json").exists()


def test_missing_public_key_is_refused(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "dev", goss=None)
    (inputs / "manifest-signing.pub.pem").unlink()
    rc, out, _ = run_inputs(tmp_path, inputs)
    assert rc != 0
    assert "missing the trusted manifest, its signature or the public key" in out


def test_nothing_staged_fails_for_a_drive_and_is_skipped_for_live(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    rc, out, _ = run_inputs(tmp_path, empty)
    assert rc != 0
    assert "Build with scripts/build.sh" in out
    rc, out, roots = run_inputs(tmp_path, empty, airlock_target="live")
    assert rc == 0, out
    assert "KIND=none" in out
    assert not Path(roots["airlock_state_dir"]).exists()


def test_bad_build_kind_is_refused(tmp_path: Path, signed: Path) -> None:
    inputs = stage(tmp_path, signed, "nightly", goss=None)
    rc, out, _ = run_inputs(tmp_path, inputs)
    assert rc != 0
    assert "must say release or dev" in out


def test_main_imports_image_inputs_in_the_image_phase_only() -> None:
    entries = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    names = [e.get("ansible.builtin.import_tasks") for e in entries]
    entry = entries[names.index("image_inputs.yml")]
    assert entry["when"] == "airlock_phase == 'image'"
    assert names.index("image_inputs.yml") < names.index("build_info.yml")
    info = (ROLE / "tasks" / "build_info.yml").read_text(encoding="utf-8")
    assert "build_kind: \"{{ base_build_kind | default('none') }}\"" in info
