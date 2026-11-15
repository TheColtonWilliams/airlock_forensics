"""Parser sandbox: command construction, seccomp program, launcher limits (tasks 3A.9, 4G.1).

The privilege-dropping methods need root and are tested for real in
tests/functional/test_sandbox.sh. Here the launcher runs without a privilege drop ("none"), so
the seccomp filter and resource limits are still exercised.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest

from forensic_analyze import sandbox as sb

X86 = sb.platform.machine() in {"x86_64", "AMD64"}


@pytest.mark.skipif(not X86, reason="seccomp program is x86_64 only")
def test_seccomp_program_shape() -> None:
    prog = sb.seccomp_program()
    assert prog is not None and len(prog) % 8 == 0
    insns = [struct.unpack("HBBI", prog[i : i + 8]) for i in range(0, len(prog), 8)]
    assert insns[0] == (sb.BPF_LD_W_ABS, 0, 0, 4)  # checks the architecture first
    assert insns[1][3] == sb.AUDIT_ARCH_X86_64
    numbers = {k for code, _jt, _jf, k in insns if code == sb.BPF_JEQ_K}
    assert set(sb.DENIED_SYSCALLS_X86_64.values()) <= numbers
    assert sb.NR_SOCKET in numbers and sb.AF_UNIX in numbers
    assert insns[-1] == (sb.BPF_RET_K, 0, 0, sb.SECCOMP_RET_ALLOW)


def test_limits_for_tools() -> None:
    fls = sb.limits_for("/usr/bin/fls")
    assert fls.memory_bytes == 2 * sb.GIB and fls.as_limit
    dotnet = sb.limits_for("/opt/eztools/MFTECmd")
    assert not dotnet.as_limit
    custom = sb.limits_for("/usr/bin/x", memory_bytes=123, timeout=7)
    assert custom.memory_bytes == 123 and custom.timeout_s == 7.0


def _box(method: str, tmp_path: Path) -> sb.Sandbox:
    return sb.Sandbox(
        method=method,
        ro_paths=[str(tmp_path / "run")],
        devices=["/dev/loop7"],
        user=sb.SandboxUser("airlock-parse", 999, 999),
    )


def test_bwrap_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sb.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sb, "systemd_is_pid1", lambda: False)
    (tmp_path / "run" / "modules" / "m").mkdir(parents=True)
    box = _box("bwrap", tmp_path)
    wd = tmp_path / "run" / "modules" / "m"
    argv = box.build(["/usr/bin/fls", "-r", "/dev/loop7"], workdir=wd, limits=sb.limits_for("fls"))
    for flag in ("--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session"):
        assert flag in argv
    assert "--unshare-user" not in argv and "--unshare-all" not in argv  # real uid drop
    joined = " ".join(argv)
    assert f"--ro-bind {tmp_path / 'run'} {tmp_path / 'run'}" in joined
    assert f"--bind {wd} {wd}" in joined
    assert "--dev-bind /dev/loop7 /dev/loop7" in joined
    assert joined.index("--ro-bind " + str(tmp_path / "run")) < joined.index("--bind " + str(wd))
    spec = argv[argv.index("--", argv.index("-c")) - 1]
    assert '"uid": 999' in spec and '"seccomp": true' in spec
    assert argv[-3:] == ["/usr/bin/fls", "-r", "/dev/loop7"]


def test_systemd_run_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sb.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sb.grp, "getgrgid", lambda gid: type("G", (), {"gr_name": "airlock-parse"}))
    box = _box("systemd-run", tmp_path)
    wd = tmp_path / "w"
    argv = box.build(["/usr/bin/exiftool", "x"], workdir=wd, limits=sb.limits_for("exiftool"))
    props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    for want in (
        "User=airlock-parse",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        f"ReadWritePaths={wd}",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "DeviceAllow=/dev/loop7 r",
    ):
        assert want in props
    assert any(p.startswith("MemoryMax=") for p in props)
    assert any(p.startswith("RuntimeMaxSec=") for p in props)


def test_unshare_and_none_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sb.os, "geteuid", lambda: 0)
    argv = _box("unshare", tmp_path).build(
        ["/bin/true"], workdir=tmp_path, limits=sb.limits_for("true")
    )
    assert argv[:3] == ["unshare", "--net", "--"]
    plain = _box("none", tmp_path).build(["/bin/true"], workdir=tmp_path, limits=sb.limits_for("x"))
    assert plain[0] == sys.executable and '"uid": null' in plain[plain.index("--") - 1]


def test_detect_method_respects_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRLOCK_SANDBOX", "unshare")
    assert sb.detect_method() == "unshare"
    monkeypatch.delenv("AIRLOCK_SANDBOX")
    monkeypatch.setattr(sb.os, "geteuid", lambda: 1000)
    assert sb.detect_method() == "none"


STANDIN = """
import socket, sys, time
what = sys.argv[1]
try:
    if what == "socket":
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("ALLOWED")
    elif what == "unix":
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print("ALLOWED")
    elif what == "memory":
        b = bytearray(1024 * 1024 * 1024)
        print("ALLOWED")
    elif what == "sleep":
        time.sleep(30)
    elif what == "cwd":
        import os
        print(os.getcwd())
except OSError as e:
    print("STOPPED", e.errno)
except MemoryError:
    print("STOPPED memory")
"""


@pytest.mark.skipif(not X86, reason="seccomp program is x86_64 only")
def test_launcher_applies_seccomp_and_limits(tmp_path: Path) -> None:
    script = tmp_path / "standin.py"
    script.write_text(STANDIN)
    box = sb.Sandbox(method="none")
    wd = tmp_path / "work"
    py = sys.executable

    def go(what: str) -> str:
        cp, rec = box.run([py, str(script), what], workdir=wd, memory_bytes=256 * 1024**2)
        assert rec.method == "none" and rec.seccomp
        return cp.stdout.strip()

    assert go("socket") == "STOPPED 13"
    assert go("unix") == "ALLOWED"
    assert go("memory") == "STOPPED memory"
    assert go("cwd") == str(wd)
    with pytest.raises(sb.LimitExceeded):
        box.run([py, str(script), "sleep"], workdir=wd, timeout=1)


def test_missing_tool(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sb.Sandbox(method="none").run(["no-such-tool-xyz"], workdir=tmp_path)


def test_open_evidence_without_root_or_for_e01(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img = tmp_path / "a.E01"
    img.write_bytes(b"x")
    h = sb.open_evidence(str(img), raw=False)
    assert h.method == "path" and "container" in h.reason
    monkeypatch.setattr(sb.os, "geteuid", lambda: 1000)
    h = sb.open_evidence(str(tmp_path / "a.dd"), raw=True)
    assert h.method == "path" and h.path.endswith("a.dd")
    h.close()


def test_launcher_usage_error() -> None:
    assert sb._launch_main(["{}"]) == 125
    assert os.path.basename(sb._pylib_dir()) == "pylib"


def test_writable_by_user(tmp_path: Path) -> None:
    box = sb.Sandbox(method="none", user=sb.SandboxUser("p", 4242, 4242))
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o755)
    assert not box.writable_by_user(d)
    d.chmod(0o777)
    assert box.writable_by_user(d)
    assert box.prepare_writable(tmp_path / "new") is True  # "none" drops no privileges
