"""tests/vm/lib: the parts of the QEMU test harness that run on the host (tasks 1.11, 3.9, 3A.10).

* qga.py, the guest agent client, against a fake agent on a Unix socket: sync with stale
  replies, exec with output and exit codes, timeouts, file upload, errors, wait-for-boot.
* mdsb.py, which writes mdraid v1.2 superblocks for the LVM/mdraid/swap test disk.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import ModuleType

import pytest

LIB = Path(__file__).resolve().parents[2] / "tests" / "vm" / "lib"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, LIB / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


qga = load("qga")
mdsb = load("mdsb")


class FakeAgent:
    """Speaks enough of the guest agent protocol for the client."""

    def __init__(self, path: Path, *, stale_first: bool = False, slow_exec: float = 0.0) -> None:
        self.path = str(path)
        self.stale_first = stale_first
        self.slow_exec = slow_exec
        self.files: dict[str, bytes] = {}
        self.handles: dict[int, str] = {}
        self.procs: dict[int, dict] = {}
        self.calls: list[str] = []
        self.shutdown_requested = False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.srv.close()

    def serve(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn: socket.socket) -> None:
        buf = b""
        if self.stale_first:
            conn.sendall(b'\xff{"return": 999}\n')
        with conn:
            while True:
                try:
                    chunk = conn.recv(1 << 20)
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    reply = self.answer(json.loads(line))
                    if reply is not None:
                        conn.sendall(json.dumps(reply).encode() + b"\n")

    def answer(self, msg: dict) -> dict | None:
        cmd, args = msg["execute"], msg.get("arguments", {})
        self.calls.append(cmd)
        if cmd == "guest-sync":
            return {"return": args["id"]}
        if cmd == "guest-ping":
            return {"return": {}}
        if cmd == "guest-exec":
            pid = len(self.procs) + 100
            argv = [args["path"], *args.get("arg", [])]
            env = dict(e.split("=", 1) for e in args.get("env", []))
            if argv[0] == "fail-to-start":
                return {"error": {"class": "GenericError", "desc": "Failed to execute child"}}
            res = subprocess.run(argv, capture_output=True, env={**os.environ, **env}, check=False)
            self.procs[pid] = {"res": res, "done_at": time.monotonic() + self.slow_exec}
            return {"return": {"pid": pid}}
        if cmd == "guest-exec-status":
            proc = self.procs[args["pid"]]
            if time.monotonic() < proc["done_at"]:
                return {"return": {"exited": False}}
            res = proc["res"]
            return {
                "return": {
                    "exited": True,
                    "exitcode": res.returncode,
                    "out-data": base64.b64encode(res.stdout).decode(),
                    "err-data": base64.b64encode(res.stderr).decode(),
                }
            }
        if cmd == "guest-file-open":
            h = len(self.handles) + 1
            self.handles[h] = args["path"]
            self.files[args["path"]] = b""
            return {"return": h}
        if cmd == "guest-file-write":
            path = self.handles[args["handle"]]
            self.files[path] += base64.b64decode(args["buf-b64"])
            return {"return": {"count": len(args["buf-b64"]), "eof": False}}
        if cmd == "guest-file-close":
            self.handles.pop(args["handle"])
            return {"return": {}}
        if cmd == "guest-shutdown":
            self.shutdown_requested = True
            return None
        return {"error": {"class": "CommandNotFound", "desc": f"{cmd} not allowed"}}


@pytest.fixture
def sock() -> Path:
    # AF_UNIX paths are limited to about 107 bytes; pytest tmp paths can be longer.
    d = Path(tempfile.mkdtemp(prefix="qga"))
    yield d / "s"
    shutil.rmtree(d, ignore_errors=True)


def client(sock: Path) -> object:
    c = qga.QGA(str(sock))
    c.connect()
    c.sync()
    return c


def test_sync_drops_stale_replies(sock: Path) -> None:
    agent = FakeAgent(sock, stale_first=True)
    try:
        c = client(sock)
        assert c.call("guest-ping") == {}
        c.close()
    finally:
        agent.close()


def test_exec_returns_output_and_exit_code(sock: Path) -> None:
    agent = FakeAgent(sock)
    try:
        c = client(sock)
        code, out, err = c.exec(["/bin/sh", "-c", "echo out; echo err >&2; exit 3"])
        assert (code, out, err) == (3, b"out\n", b"err\n")
        code, out, _ = c.exec(
            ["/bin/sh", "-c", 'echo "$AIRLOCK_TEST_FIRMWARE"'], env=["AIRLOCK_TEST_FIRMWARE=uefi"]
        )
        assert (code, out) == (0, b"uefi\n")
        c.close()
    finally:
        agent.close()


def test_exec_times_out(sock: Path) -> None:
    agent = FakeAgent(sock, slow_exec=30)
    try:
        c = client(sock)
        code, _, err = c.exec(["/bin/true"], timeout=0.5, poll=0.1)
        assert code == qga.EXIT_TIMEOUT
        assert b"timed out" in err
        c.close()
    finally:
        agent.close()


def test_agent_errors_raise(sock: Path) -> None:
    agent = FakeAgent(sock)
    try:
        c = client(sock)
        with pytest.raises(qga.QGAError, match="CommandNotFound"):
            c.call("guest-set-user-password", {})
        with pytest.raises(qga.QGAError, match="Failed to execute"):
            c.exec(["fail-to-start"])
        c.close()
    finally:
        agent.close()


def test_put_uploads_in_chunks(sock: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qga, "CHUNK", 1000)
    payload = os.urandom(4321)
    src = tmp_path / "payload.tgz"
    src.write_bytes(payload)
    agent = FakeAgent(sock)
    try:
        c = client(sock)
        assert c.put(str(src), "/run/airlock-tests.tgz") == len(payload)
        assert agent.files["/run/airlock-tests.tgz"] == payload
        assert agent.calls.count("guest-file-write") == 5
        assert agent.handles == {}, "file handle closed"
        c.close()
    finally:
        agent.close()


def test_wait_ready_until_the_agent_appears(sock: Path) -> None:
    holder: dict[str, FakeAgent] = {}

    def later() -> None:
        time.sleep(0.6)
        holder["agent"] = FakeAgent(sock)

    t = threading.Thread(target=later)
    t.start()
    try:
        c = qga.QGA(str(sock))
        c.wait_ready(timeout=10, poll=0.2)
        c.close()
    finally:
        t.join()
        if "agent" in holder:
            holder["agent"].close()


def test_wait_ready_gives_up(sock: Path) -> None:
    c = qga.QGA(str(sock))
    with pytest.raises(qga.QGAError, match="did not answer"):
        c.wait_ready(timeout=0.5, poll=0.1)


def test_cli_exec_passes_the_exit_code(
    sock: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    agent = FakeAgent(sock)
    try:
        rc = qga.main(["--socket", str(sock), "exec", "--", "/bin/sh", "-c", "printf hi; exit 77"])
        assert rc == 77
        assert capsysbinary.readouterr().out == b"hi"
        assert qga.main(["--socket", str(sock), "shutdown"]) == 0
        time.sleep(0.2)
        assert agent.shutdown_requested
    finally:
        agent.close()


def test_cli_reports_a_missing_agent(sock: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert qga.main(["--socket", str(sock), "exec", "--", "/bin/true"]) == qga.EXIT_AGENT
    assert "qga:" in capsys.readouterr().err


# --------------------------------------------------------------------------- mdsb.py


def test_mdraid_superblock_format(tmp_path: Path) -> None:
    members = []
    for i in range(2):
        f = tmp_path / f"m{i}.img"
        f.write_bytes(b"\0" * (32 << 20))
        members.append(str(f))
    assert (
        mdsb.main(["--name", "test:md", "--uuid", "12345678-1234-5678-1234-567812345678", *members])
        == 0
    )
    for i, path in enumerate(members):
        sb = Path(path).read_bytes()[4096 : 4096 + mdsb.SB_SIZE]
        magic, major = struct.unpack_from("<II", sb, 0)
        assert magic == 0xA92B4EFC and major == 1
        assert sb[16:32] == bytes.fromhex("12345678123456781234567812345678")
        assert sb[32:39] == b"test:md"
        level, raid_disks = struct.unpack_from("<I", sb, 72)[0], struct.unpack_from("<I", sb, 92)[0]
        assert (level, raid_disks) == (1, 2)
        data_offset, data_size, super_offset = struct.unpack_from("<QQQ", sb, 128)
        assert (data_offset, super_offset) == (2048, 8)
        assert data_size == (32 << 20) // 512 - 2048
        assert struct.unpack_from("<I", sb, 160)[0] == i  # dev_number
        assert struct.unpack_from("<I", sb, 216)[0] == mdsb.checksum(sb)
        roles = struct.unpack_from("<4H", sb, 256)
        assert roles == (0, 1, 0xFFFF, 0xFFFF)


def test_mdraid_checksum_changes_with_content() -> None:
    sb = bytearray(
        mdsb.superblock(
            set_uuid=b"\1" * 16,
            name="x",
            level=1,
            raid_disks=2,
            dev_number=0,
            dev_sectors=65536,
            when=1,
        )
    )
    before = mdsb.checksum(bytes(sb))
    sb[100] ^= 0xFF
    assert mdsb.checksum(bytes(sb)) != before


def test_mdraid_refuses_a_tiny_member() -> None:
    with pytest.raises(ValueError, match="too small"):
        mdsb.superblock(
            set_uuid=b"\0" * 16,
            name="x",
            level=1,
            raid_disks=2,
            dev_number=0,
            dev_sectors=100,
            when=0,
        )


# ---------------------------------------------------- goss variables (harness and provisioning)

GOSS_DIR = LIB.parents[1] / "goss"
HARNESS_VARS = {
    "disks": {"ext4": "/dev/disk/by-id/virtio-airlock-ext4", "ntfs": "", "sig": "", "swap": ""},
    "firmware": "uefi",
    "nic": False,
    "provision": False,
}
PROVISION_VARS = {"disks": {}, "firmware": "uefi", "nic": False, "provision": True}


def _render(path: Path, variables: dict | None) -> str:
    argv = ["goss", "-g", str(path)]
    if variables is not None:
        argv += ["--vars-inline", json.dumps(variables)]
    res = subprocess.run([*argv, "render"], capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"{path.name}: {res.stderr}"
    return res.stdout


def test_every_goss_file_is_plain_yaml_before_rendering() -> None:
    """Template directives live in YAML comments, so unit tests can read the files directly."""
    yaml = pytest.importorskip("yaml")
    for path in sorted(GOSS_DIR.glob("*.yaml")):
        assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict), path.name


@pytest.mark.skipif(shutil.which("goss") is None, reason="needs goss")
@pytest.mark.parametrize(
    "variables", [None, HARNESS_VARS, PROVISION_VARS], ids=["no-vars", "harness", "provision"]
)
def test_goss_files_render_with_harness_and_provision_vars(variables: dict | None) -> None:
    for path in sorted(GOSS_DIR.glob("*.yaml")):
        _render(path, variables)


@pytest.mark.skipif(shutil.which("goss") is None, reason="needs goss")
def test_provision_self_test_skips_disk_and_desktop_checks() -> None:
    """forensic-provision passes provision=true and no disks; the harness passes provision=false."""
    checks = {
        "storage.yaml": "airlock-setro --check",
        "base.yaml": "desktop-session:",
        "smoke.yaml": "the desktop started",
    }
    for name, needle in checks.items():
        assert needle in _render(GOSS_DIR / name, HARNESS_VARS), name
        assert needle not in _render(GOSS_DIR / name, PROVISION_VARS), name
    assert "    gdm:" not in _render(GOSS_DIR / "base.yaml", PROVISION_VARS)
