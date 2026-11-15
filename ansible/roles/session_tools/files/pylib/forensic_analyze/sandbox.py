"""Parser sandbox (task 3A.9).

Every parser runs as the unprivileged ``airlock-parse`` user (``nobody`` when that user does not
exist, which only happens in tests), with no network, a read-only view of the system and the
evidence, one writable output folder, a seccomp filter, and memory and time limits.

Methods, best first (the chosen one is recorded in ``run.json``):

``bwrap``
    bubblewrap, started by root *without* a user namespace (so the parse user is a real,
    unprivileged user outside the sandbox), new network, PID, IPC, and UTS namespaces,
    read-only binds of the system folders, the evidence handle, and the run folder, one
    writable bind for the module's work folder, ``--die-with-parent``. When systemd is PID 1
    the sandbox also runs inside a transient scope with ``MemoryMax``.
``systemd-run``
    a transient service with ``PrivateNetwork=yes``, ``ProtectSystem=strict``,
    ``ReadWritePaths=<work folder>``, ``MemoryMax``, ``RuntimeMaxSec``, ``NoNewPrivileges``,
    ``RestrictAddressFamilies=AF_UNIX``, and ``DeviceAllow`` for the evidence handle only.
``unshare``
    fallback: ``unshare -n`` (no network) and the launcher below; file access is limited by the
    parse user's own permissions.
``none``
    not root (unit tests): launcher only, so limits and seccomp still apply.

In every method the last step before the tool is the *launcher* (``_launch_main`` in this file,
standard library only): it sets resource limits (address space, CPU time, core size, file
size), drops to the parse user (setgroups, setresgid, setresuid), sets ``no_new_privs``,
installs the seccomp filter, and then ``exec``s the tool. Wall-clock time is enforced by the
parent, which kills the whole process group.

Root opens the evidence once as a kernel read-only loop device (``losetup --read-only``),
readable by the parse user's group only, and hands that to the workers. See
``EvidenceHandle``.
"""

from __future__ import annotations

import contextlib
import ctypes
import grp
import json
import os
import platform
import pwd
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PARSE_USER = "airlock-parse"
FALLBACK_USER = "nobody"
GIB = 1024**3
DEFAULT_TIMEOUT_S = 6 * 3600
DEFAULT_MEMORY_BYTES = 4 * GIB
SYSTEM_RO_DIRS = ("/usr", "/etc", "/opt")
SYSTEM_LINKS = ("/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32")
SANDBOX_TMP = "/tmp"  # noqa: S108 - a private tmpfs inside the bwrap sandbox
SANDBOX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Tools whose runtime reserves large virtual address space up front (.NET, Go). An address
# space limit breaks them, so they get the cgroup limit only (or none, recorded).
NO_AS_LIMIT = frozenset(
    {
        "dotnet",
        "MFTECmd",
        "RBCmd",
        "LECmd",
        "JLECmd",
        "EvtxECmd",
        "RECmd",
        "SBECmd",
        "PECmd",
        "AmcacheParser",
        "AppCompatCacheParser",
        "SrumECmd",
        "SQLECmd",
        "WxTCmd",
        # llama.cpp maps whole model files; the cgroup limit still applies.
        "llama-mtmd-cli",
        "llama-server",
    }
)

# Per-tool overrides: (memory bytes, wall-clock seconds). Anything else uses the defaults.
TOOL_LIMITS: dict[str, tuple[int, int]] = {
    "fls": (2 * GIB, 4 * 3600),
    "icat": (1 * GIB, 4 * 3600),
    "mmls": (512 * 1024**2, 600),
    "fsstat": (512 * 1024**2, 600),
    "exiftool": (2 * GIB, 4 * 3600),
    "ffprobe": (2 * GIB, 3600),
    "mediainfo": (2 * GIB, 3600),
    "photorec": (2 * GIB, 24 * 3600),
    "bulk_extractor": (8 * GIB, 24 * 3600),
    "log2timeline.py": (8 * GIB, 24 * 3600),
    "psort.py": (8 * GIB, 12 * 3600),
}


class SandboxError(RuntimeError):
    """The sandbox could not be set up, or a tool broke a limit."""


class LimitExceeded(SandboxError):
    """The tool ran past its wall-clock time limit and was killed."""


# ----------------------------------------------------------------------------------------------
# Seccomp (x86_64). A small deny list: everything a parser never needs and that widens the
# kernel surface. Sockets other than AF_UNIX are refused with EACCES.
# ----------------------------------------------------------------------------------------------

AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1
EACCES = 13
AF_UNIX = 1
NR_SOCKET = 41
X32_SYSCALL_BIT = 0x40000000

DENIED_SYSCALLS_X86_64: dict[str, int] = {
    "ptrace": 101,
    "syslog": 103,
    "pivot_root": 155,
    "adjtimex": 159,
    "chroot": 161,
    "acct": 163,
    "settimeofday": 164,
    "mount": 165,
    "umount2": 166,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "sethostname": 170,
    "setdomainname": 171,
    "iopl": 172,
    "ioperm": 173,
    "init_module": 175,
    "delete_module": 176,
    "clock_settime": 227,
    "kexec_load": 246,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "unshare": 272,
    "perf_event_open": 298,
    "name_to_handle_at": 303,
    "open_by_handle_at": 304,
    "clock_adjtime": 305,
    "setns": 308,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "finit_module": 313,
    "kexec_file_load": 320,
    "bpf": 321,
    "userfaultfd": 323,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "fspick": 433,
    "mount_setattr": 442,
}


def _bpf(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_JGE_K = 0x35
BPF_RET_K = 0x06


def seccomp_program() -> bytes | None:
    """The BPF filter for this machine, or None when the architecture is not supported."""
    if platform.machine() not in {"x86_64", "AMD64"}:
        return None
    errno_eperm = SECCOMP_RET_ERRNO | EPERM
    errno_eacces = SECCOMP_RET_ERRNO | EACCES
    prog: list[bytes] = [
        _bpf(BPF_LD_W_ABS, 0, 0, 4),  # seccomp_data.arch
        _bpf(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        _bpf(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _bpf(BPF_LD_W_ABS, 0, 0, 0),  # seccomp_data.nr
        _bpf(BPF_JGE_K, 0, 1, X32_SYSCALL_BIT),
        _bpf(BPF_RET_K, 0, 0, errno_eperm),
    ]
    for nr in sorted(DENIED_SYSCALLS_X86_64.values()):
        prog.append(_bpf(BPF_JEQ_K, 0, 1, nr))
        prog.append(_bpf(BPF_RET_K, 0, 0, errno_eperm))
    # socket(): allow AF_UNIX only.
    prog += [
        _bpf(BPF_JEQ_K, 0, 4, NR_SOCKET),
        _bpf(BPF_LD_W_ABS, 0, 0, 16),  # seccomp_data.args[0] (low 32 bits)
        _bpf(BPF_JEQ_K, 0, 1, AF_UNIX),
        _bpf(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        _bpf(BPF_RET_K, 0, 0, errno_eacces),
        _bpf(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ]
    return b"".join(prog)


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2


def _install_seccomp(program: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // 8, ctypes.addressof(buf))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_SECCOMP) failed")


def _set_no_new_privs() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")


# ----------------------------------------------------------------------------------------------
# Launcher: runs as the last step inside every method, then execs the tool.
# ----------------------------------------------------------------------------------------------


def _launch_main(argv: Sequence[str] | None = None) -> int:
    """``python3 -I -S -c ... SPEC_JSON -- TOOL ARGS``: apply limits, drop privileges, exec."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3 or args[1] != "--":
        print("sandbox launcher: usage SPEC -- argv", file=sys.stderr)
        return 125
    spec: dict[str, Any] = json.loads(args[0])
    tool = args[2:]
    mem = int(spec.get("memory_bytes") or 0)
    if mem and spec.get("as_limit", True):
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    cpu = int(spec.get("cpu_seconds") or 0)
    if cpu:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
    fsize = int(spec.get("file_bytes") or 0)
    if fsize:
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    uid, gid = spec.get("uid"), spec.get("gid")
    if os.geteuid() == 0 and uid is not None and gid is not None:
        os.setgroups([])
        os.setresgid(int(gid), int(gid), int(gid))
        os.setresuid(int(uid), int(uid), int(uid))
        if os.geteuid() == 0 or os.getuid() == 0:
            print("sandbox launcher: could not drop root", file=sys.stderr)
            return 125
    if spec.get("cwd"):
        os.chdir(spec["cwd"])
    program = seccomp_program() if spec.get("seccomp", True) else None
    if program is not None:
        _install_seccomp(program)
    else:
        _set_no_new_privs()
    env = {str(k): str(v) for k, v in (spec.get("env") or {}).items()}
    try:
        os.execve(tool[0], tool, env)  # noqa: S606 - argument list, no shell
    except OSError as exc:
        print(f"sandbox launcher: cannot run {tool[0]}: {exc.strerror}", file=sys.stderr)
        return 127
    return 127  # pragma: no cover - execve does not return


# ----------------------------------------------------------------------------------------------
# Parent side
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxUser:
    name: str
    uid: int
    gid: int


def sandbox_user() -> SandboxUser:
    for name in (PARSE_USER, FALLBACK_USER):
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        return SandboxUser(name, pw.pw_uid, pw.pw_gid)
    return SandboxUser("nobody", 65534, 65534)


def systemd_is_pid1() -> bool:
    try:
        return Path("/proc/1/comm").read_text(encoding="ascii").strip() == "systemd"
    except OSError:
        return False


_PROBE_CACHE: dict[str, bool] = {}


def _bwrap_works(bwrap: str) -> bool:
    if bwrap in _PROBE_CACHE:
        return _PROBE_CACHE[bwrap]
    argv = [bwrap, "--unshare-net", "--die-with-parent", *_system_binds(), "--", "/bin/true"]
    try:
        ok = subprocess.run(argv, capture_output=True, timeout=20, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    _PROBE_CACHE[bwrap] = ok
    return ok


def _system_binds() -> list[str]:
    out: list[str] = []
    for d in SYSTEM_RO_DIRS:
        if Path(d).is_dir():
            out += ["--ro-bind", d, d]
    for link in SYSTEM_LINKS:
        p = Path(link)
        if p.is_symlink():
            out += ["--symlink", os.readlink(p), link]
        elif p.is_dir():
            out += ["--ro-bind", link, link]
    return out


def detect_method(preferred: str | None = None) -> str:
    """Pick the best method that works here. ``AIRLOCK_SANDBOX`` or ``preferred`` can force one."""
    forced = preferred or os.environ.get("AIRLOCK_SANDBOX") or ""
    if forced:
        return forced
    if os.geteuid() != 0:
        return "none"
    bwrap = shutil.which("bwrap")
    if bwrap and _bwrap_works(bwrap):
        return "bwrap"
    if shutil.which("systemd-run") and systemd_is_pid1():
        return "systemd-run"
    if shutil.which("unshare"):
        return "unshare"
    return "none"


def _pylib_dir() -> Path:
    return Path(__file__).resolve().parent.parent


@dataclass
class ToolLimits:
    memory_bytes: int
    timeout_s: float
    as_limit: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_bytes": self.memory_bytes,
            "timeout_s": self.timeout_s,
            "address_space_limit": self.as_limit,
        }


def limits_for(
    tool_path: str, *, memory_bytes: int | None = None, timeout: float | None = None
) -> ToolLimits:
    name = Path(tool_path).name
    mem, secs = TOOL_LIMITS.get(name, (DEFAULT_MEMORY_BYTES, DEFAULT_TIMEOUT_S))
    return ToolLimits(
        memory_bytes=memory_bytes or mem,
        timeout_s=float(timeout or secs),
        as_limit=name not in NO_AS_LIMIT,
    )


@dataclass
class SandboxRun:
    """What happened to one sandboxed call, for run.json."""

    method: str
    user: str
    seccomp: bool
    limits: dict[str, Any]
    returncode: int
    duration_s: float
    killed: str = ""  # "" | "timeout"
    workdir_writable: bool = True
    argv: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "user": self.user,
            "seccomp": self.seccomp,
            "limits": self.limits,
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 3),
            "killed": self.killed,
            "workdir_writable": self.workdir_writable,
        }


class Sandbox:
    """Builds and runs sandboxed command lines.

    ``ro_paths`` are bound read-only (the run folder, the evidence image file, ASSETS);
    ``devices`` are device nodes the tool may read (the read-only loop handle).
    """

    def __init__(
        self,
        *,
        method: str | None = None,
        ro_paths: Sequence[str | os.PathLike[str]] = (),
        devices: Sequence[str] = (),
        user: SandboxUser | None = None,
    ) -> None:
        self.method = detect_method(method)
        self.user = user or sandbox_user()
        self.ro_paths = [str(p) for p in ro_paths]
        self.devices = list(devices)
        self.seccomp = seccomp_program() is not None
        self.cgroup = self.method == "bwrap" and systemd_is_pid1() and shutil.which("systemd-run")

    def describe(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "user": self.user.name if self._drops_privileges() else _current_user(),
            "uid": self.user.uid if self._drops_privileges() else os.geteuid(),
            "seccomp": self.seccomp,
            "seccomp_arch": platform.machine(),
            "network": "none" if self.method in {"bwrap", "systemd-run", "unshare"} else "host",
            "memory_cgroup": bool(self.cgroup) or self.method == "systemd-run",
            "defaults": {
                "memory_bytes": DEFAULT_MEMORY_BYTES,
                "timeout_s": DEFAULT_TIMEOUT_S,
            },
        }

    def _drops_privileges(self) -> bool:
        return self.method in {"bwrap", "systemd-run", "unshare"} and os.geteuid() == 0

    def prepare_writable(self, path: Path) -> bool:
        """Make ``path`` writable by the parse user. Returns whether its mode bits now allow it.

        exFAT keeps no owners or modes (they come from the mount options), so there the answer
        depends on how OUTPUT was mounted; ``run.json`` records it per tool call.
        """
        path.mkdir(parents=True, exist_ok=True)
        if not self._drops_privileges():
            return True
        try:
            os.chown(path, self.user.uid, self.user.gid)
            os.chmod(path, 0o750)  # noqa: S103 - owner is the parse user; root reads it back
        except OSError:
            # Ownership fixed by mount options: a world-writable module folder inside the run
            # folder is the only way left for the parse user to write.
            with contextlib.suppress(OSError):
                os.chmod(path, 0o777)  # noqa: S103
        return self.writable_by_user(path)

    def writable_by_user(self, path: Path) -> bool:
        st = path.stat()
        if st.st_uid == self.user.uid:
            return bool(st.st_mode & stat.S_IWUSR)
        if st.st_gid == self.user.gid:
            return bool(st.st_mode & stat.S_IWGRP)
        return bool(st.st_mode & stat.S_IWOTH)

    def grant_device(self, dev: str) -> None:
        """Let the parse user's group read a (read-only loop) device node."""
        if os.geteuid() != 0:
            return
        os.chown(dev, 0, self.user.gid)
        os.chmod(dev, 0o440)

    # -- command construction ------------------------------------------------------------------

    def _launcher_argv(self, spec: dict[str, Any], argv: Sequence[str]) -> list[str]:
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); del sys.argv[1]; "
            "from forensic_analyze.sandbox import _launch_main; raise SystemExit(_launch_main())"
        )
        return [
            sys.executable,
            "-I",
            "-S",
            "-c",
            code,
            str(_pylib_dir()),
            json.dumps(spec, sort_keys=True),
            "--",
            *argv,
        ]

    def build(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        limits: ToolLimits,
        extra_ro: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        devices: Sequence[str] = (),
    ) -> list[str]:
        """The full command line for ``argv`` (whose argv[0] must be an absolute path).

        ``devices`` are extra device nodes for this call only (a GPU render node), opened
        read-write; the evidence handles given to the constructor stay read-only.
        """
        tool_dir = str(Path(argv[0]).parent)
        drop = self._drops_privileges()
        spec: dict[str, Any] = {
            "memory_bytes": limits.memory_bytes,
            "as_limit": limits.as_limit,
            "cpu_seconds": int(limits.timeout_s) + 60,
            "uid": self.user.uid if drop and self.method != "systemd-run" else None,
            "gid": self.user.gid if drop and self.method != "systemd-run" else None,
            "cwd": str(workdir),
            "seccomp": True,
            "env": {
                "PATH": f"{SANDBOX_PATH}:{tool_dir}",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                # Inside bwrap /tmp is a private tmpfs for this call only.
                "HOME": SANDBOX_TMP if self.method == "bwrap" else str(workdir),
                "TMPDIR": SANDBOX_TMP if self.method == "bwrap" else str(workdir),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "DOTNET_gcHeapHardLimit": hex(limits.memory_bytes),
                **(env or {}),
            },
        }
        launcher = self._launcher_argv(spec, argv)
        if self.method == "bwrap":
            return self._bwrap(launcher, workdir, limits, [tool_dir, *extra_ro], devices)
        if self.method == "systemd-run":
            return self._systemd_run(launcher, workdir, limits, devices)
        if self.method == "unshare":
            return ["unshare", "--net", "--", *launcher]
        return launcher

    def _bwrap(
        self,
        launcher: list[str],
        workdir: Path,
        limits: ToolLimits,
        extra_ro: Sequence[str],
        devices: Sequence[str] = (),
    ) -> list[str]:
        bwrap = shutil.which("bwrap") or "bwrap"
        args = [
            bwrap,
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CAP_SETUID",
            "--cap-add",
            "CAP_SETGID",
            *_system_binds(),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--perms",
            "1777",
            "--tmpfs",
            SANDBOX_TMP,
        ]
        made: set[str] = {"/", SANDBOX_TMP, "/proc", "/dev", *SYSTEM_RO_DIRS, *SYSTEM_LINKS}
        bound: list[str] = list(SYSTEM_RO_DIRS)

        def under_bound(p: str) -> bool:
            return any(p == b or p.startswith(b + "/") for b in bound)

        def parents(path: str) -> list[str]:
            out: list[str] = []
            for parent in reversed(Path(path).parents):
                p = str(parent)
                if p in made or under_bound(p):
                    continue
                made.add(p)
                out += ["--perms", "0755", "--dir", p]
            return out

        pylib = str(_pylib_dir())
        ro = []
        for p in [pylib, sys.prefix, *self.ro_paths, *extra_ro]:
            if p and Path(p).exists() and not any(p == d or p.startswith(d + "/") for d in ro):
                ro.append(p)
        for p in sorted(set(ro), key=len):
            if under_bound(p):
                continue
            args += [*parents(p), "--ro-bind", p, p]
            bound.append(p)
        for dev in [*self.devices, *devices]:
            args += [*parents(dev), "--dev-bind", dev, dev]
        wd = str(workdir)
        args += [*parents(wd), "--bind", wd, wd, "--", *launcher]
        if self.cgroup:
            return [
                "systemd-run",
                "--scope",
                "--quiet",
                "--collect",
                "-p",
                f"MemoryMax={limits.memory_bytes}",
                "-p",
                "MemorySwapMax=0",
                "-p",
                "TasksMax=512",
                "--",
                *args,
            ]
        return args

    def _systemd_run(
        self,
        launcher: list[str],
        workdir: Path,
        limits: ToolLimits,
        devices: Sequence[str] = (),
    ) -> list[str]:
        props = [
            f"User={self.user.name}",
            f"Group={grp.getgrgid(self.user.gid).gr_name}",
            "PrivateNetwork=yes",
            "PrivateTmp=yes",
            "PrivateIPC=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "NoNewPrivileges=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "CapabilityBoundingSet=",
            f"ReadWritePaths={workdir}",
            f"WorkingDirectory={workdir}",
            f"MemoryMax={limits.memory_bytes}",
            "MemorySwapMax=0",
            f"RuntimeMaxSec={int(limits.timeout_s)}",
            "DevicePolicy=closed",
        ]
        props += [f"DeviceAllow={dev} r" for dev in self.devices]
        props += [f"DeviceAllow={dev} rw" for dev in devices]
        args = ["systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--service-type=exec"]
        for p in props:
            args += ["-p", p]
        return [*args, "--", *launcher]

    # -- execution -----------------------------------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        timeout: float | None = None,
        memory_bytes: int | None = None,
        stdout_path: Path | None = None,
        extra_ro: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        devices: Sequence[str] = (),
    ) -> tuple[subprocess.CompletedProcess[str], SandboxRun]:
        """Run ``argv`` sandboxed. Raises ``LimitExceeded`` when the time limit kills it."""
        if not argv:
            raise ValueError("empty argv")
        exe = argv[0] if os.path.isabs(argv[0]) else shutil.which(argv[0])
        if not exe:
            raise FileNotFoundError(f"{argv[0]}: not installed or not on PATH")
        full = [exe, *[str(a) for a in argv[1:]]]
        limits = limits_for(exe, memory_bytes=memory_bytes, timeout=timeout)
        workdir_writable = self.prepare_writable(workdir)
        cmd = self.build(
            full, workdir=workdir, limits=limits, extra_ro=extra_ro, env=env, devices=devices
        )
        started = time.monotonic()
        out_fh = open(stdout_path, "wb") if stdout_path else None  # noqa: SIM115
        killed = ""
        try:
            child = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=out_fh if out_fh else subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                out_b, err_b = child.communicate(timeout=limits.timeout_s)
            except subprocess.TimeoutExpired:
                killed = "timeout"
                _kill_group(child)
                out_b, err_b = child.communicate()
        finally:
            if out_fh:
                out_fh.close()
        duration = time.monotonic() - started
        record = SandboxRun(
            method=self.method,
            user=self.user.name if self._drops_privileges() else _current_user(),
            seccomp=self.seccomp,
            limits=limits.to_dict(),
            returncode=child.returncode,
            duration_s=duration,
            killed=killed,
            argv=full,
            workdir_writable=workdir_writable,
        )
        stdout = "" if out_fh else (out_b or b"").decode("utf-8", "replace")
        stderr = (err_b or b"").decode("utf-8", "replace")
        cp = subprocess.CompletedProcess(full, child.returncode, stdout, stderr)
        if killed:
            raise LimitExceeded(
                f"{Path(exe).name}: stopped after the {limits.timeout_s:.0f} s limit"
            )
        return cp, record


def _kill_group(child: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        child.kill()


def _current_user() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return str(os.geteuid())


# ----------------------------------------------------------------------------------------------
# Evidence handle: root opens the target once, read-only, and hands workers a read-only node.
# ----------------------------------------------------------------------------------------------


@dataclass
class EvidenceHandle:
    """A kernel read-only loop device over the target, or the target path itself."""

    source: str
    path: str
    method: str  # "ro_loop" | "path"
    reason: str = ""
    loop_device: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "path": self.path,
            "method": self.method,
            "reason": self.reason,
            "loop_device": self.loop_device,
        }

    def close(self) -> None:
        if self.loop_device:
            subprocess.run(["losetup", "--detach", self.loop_device], check=False)
            self.loop_device = ""


def loop_readonly(dev: str) -> bool:
    name = Path(dev).name
    try:
        return Path(f"/sys/block/{name}/ro").read_text(encoding="ascii").strip() == "1"
    except OSError:
        return False


def open_evidence(source: str, *, raw: bool, sandbox: Sandbox | None = None) -> EvidenceHandle:
    """Make a read-only loop device over ``source`` when root can; else hand out the path.

    ``raw`` is False for formats a loop device cannot present (E01): those keep the file path
    and are bound read-only into the sandbox.
    """
    if not raw:
        return EvidenceHandle(source, source, "path", "container format, bound read-only")
    if os.geteuid() != 0 or not shutil.which("losetup"):
        return EvidenceHandle(source, source, "path", "not root: no loop device")
    cp = subprocess.run(
        ["losetup", "--read-only", "--find", "--show", source],
        capture_output=True,
        text=True,
        check=False,
    )
    loop = cp.stdout.strip()
    if cp.returncode != 0 or not loop:
        last = (cp.stderr.strip().splitlines() or ["losetup failed"])[-1]
        return EvidenceHandle(source, source, "path", f"no loop device: {last}")
    if not loop_readonly(loop):
        subprocess.run(["losetup", "--detach", loop], check=False)
        raise SandboxError(f"{loop} is not read-only; refusing to use it")
    if sandbox is not None:
        sandbox.grant_device(loop)
    return EvidenceHandle(source, loop, "ro_loop", "", loop)


def detach_stale(loop: str, source: str) -> bool:
    """Detach a loop device left by a killed run, if it is still ours (read-only, same file)."""
    if not loop or not Path(loop).exists() or not loop_readonly(loop):
        return False
    name = Path(loop).name
    try:
        backing = Path(f"/sys/block/{name}/loop/backing_file").read_text(encoding="utf-8").strip()
    except OSError:
        return False
    if os.path.realpath(backing) != os.path.realpath(source):
        return False
    return subprocess.run(["losetup", "--detach", loop], check=False).returncode == 0
