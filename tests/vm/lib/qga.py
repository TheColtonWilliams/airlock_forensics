#!/usr/bin/env python3
"""Minimal QEMU guest agent client for tests/run-qemu-tests.sh (host side, stdlib only).

The test VM has no network. The harness talks to the guest through the QEMU guest agent
on a virtio serial port, exposed by QEMU as a Unix socket on the host. That is enough to
copy the test payload in, run goss and tests/vm/*.sh as root, and read their output and
exit codes.

Usage:
  qga.py --socket PATH wait [--timeout SEC]
  qga.py --socket PATH exec [--timeout SEC] [--env K=V ...] -- PROGRAM [ARG ...]
  qga.py --socket PATH put LOCAL_FILE GUEST_PATH
  qga.py --socket PATH shutdown

exec prints the guest's stdout and stderr and exits with the guest's exit code
(124 when the command timed out, 125 when the agent failed).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import socket
import sys
import time
from typing import Any

EXIT_TIMEOUT = 124
EXIT_AGENT = 125
CHUNK = 1 << 20  # bytes per guest-file-write


class QGAError(Exception):
    """The agent answered with an error, or did not answer in time."""


class QGA:
    def __init__(self, path: str) -> None:
        self.path = path
        self.sock: socket.socket | None = None
        self.buf = b""
        self._decoder = json.JSONDecoder()

    # -- transport -------------------------------------------------------------------------
    def connect(self, timeout: float = 5.0) -> None:
        self.close()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(self.path)
        self.sock = sock
        self.buf = b""

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def send(self, obj: dict[str, Any]) -> None:
        if self.sock is None:
            raise QGAError("not connected")
        self.sock.sendall(json.dumps(obj).encode() + b"\n")

    def recv(self, timeout: float) -> dict[str, Any]:
        """Return the next JSON object from the agent, skipping sync bytes (0xFF)."""
        if self.sock is None:
            raise QGAError("not connected")
        deadline = time.monotonic() + timeout
        while True:
            text = self.buf.lstrip(b"\xff \t\r\n").decode("utf-8", "replace")
            if text:
                try:
                    obj, end = self._decoder.raw_decode(text)
                except json.JSONDecodeError:
                    pass
                else:
                    self.buf = text[end:].encode()
                    if isinstance(obj, dict):
                        return obj
                    continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QGAError("no answer from the guest agent")
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError as exc:
                raise QGAError("no answer from the guest agent") from exc
            if not chunk:
                raise QGAError("the guest agent closed the connection")
            self.buf += chunk

    # -- protocol --------------------------------------------------------------------------
    def sync(self, timeout: float = 5.0) -> None:
        """guest-sync with a fresh id; drops any stale replies left from earlier tries."""
        token = random.randint(1, 2**31 - 1)  # noqa: S311 - not security sensitive
        self.send({"execute": "guest-sync", "arguments": {"id": token}})
        deadline = time.monotonic() + timeout
        while True:
            reply = self.recv(max(0.1, deadline - time.monotonic()))
            if reply.get("return") == token:
                return

    def call(
        self, command: str, arguments: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> Any:
        msg: dict[str, Any] = {"execute": command}
        if arguments is not None:
            msg["arguments"] = arguments
        self.send(msg)
        reply = self.recv(timeout)
        if "error" in reply:
            err = reply["error"]
            raise QGAError(f"{command}: {err.get('class', '')} {err.get('desc', '')}".strip())
        return reply.get("return")

    def wait_ready(self, timeout: float, poll: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        last = "not tried"
        while time.monotonic() < deadline:
            try:
                self.connect()
                self.sync(timeout=poll)
                self.call("guest-ping")
                return
            except (OSError, QGAError) as exc:
                last = str(exc)
                self.close()
                time.sleep(min(poll, max(0.0, deadline - time.monotonic())))
        raise QGAError(f"the guest agent did not answer within {timeout:.0f} s ({last})")

    def exec(
        self,
        argv: list[str],
        env: list[str] | None = None,
        timeout: float = 600.0,
        poll: float = 0.5,
    ) -> tuple[int, bytes, bytes]:
        args: dict[str, Any] = {"path": argv[0], "arg": argv[1:], "capture-output": True}
        if env:
            args["env"] = env
        pid = self.call("guest-exec", args)["pid"]
        deadline = time.monotonic() + timeout
        while True:
            status = self.call("guest-exec-status", {"pid": pid})
            if status.get("exited"):
                out = base64.b64decode(status.get("out-data", ""))
                err = base64.b64decode(status.get("err-data", ""))
                code = status.get("exitcode")
                if code is None:  # killed by a signal
                    code = 128 + int(status.get("signal", 0))
                return int(code), out, err
            if time.monotonic() > deadline:
                return EXIT_TIMEOUT, b"", f"timed out after {timeout:.0f} s\n".encode()
            time.sleep(poll)
            poll = min(poll * 1.5, 5.0)

    def put(self, local: str, remote: str) -> int:
        handle = self.call("guest-file-open", {"path": remote, "mode": "wb"})
        total = 0
        try:
            with open(local, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    self.call(
                        "guest-file-write",
                        {"handle": handle, "buf-b64": base64.b64encode(chunk).decode()},
                        timeout=120,
                    )
                    total += len(chunk)
        finally:
            self.call("guest-file-close", {"handle": handle})
        return total

    def shutdown(self) -> None:
        # The agent usually dies before it can answer; do not wait for one.
        self.send({"execute": "guest-shutdown", "arguments": {"mode": "powerdown"}})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qga.py", description=__doc__.splitlines()[0])
    ap.add_argument("--socket", required=True, help="guest agent Unix socket")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("wait", help="wait until the guest agent answers")
    w.add_argument("--timeout", type=float, default=900)
    e = sub.add_parser("exec", help="run a program in the guest")
    e.add_argument("--timeout", type=float, default=600)
    e.add_argument("--env", action="append", default=[], metavar="K=V")
    e.add_argument("program", nargs=argparse.REMAINDER)
    p = sub.add_parser("put", help="copy a file into the guest")
    p.add_argument("local")
    p.add_argument("remote")
    sub.add_parser("shutdown", help="ask the guest to power off")
    args = ap.parse_args(argv)

    qga = QGA(args.socket)
    try:
        if args.cmd == "wait":
            qga.wait_ready(args.timeout)
            print("qga: guest agent is answering")
            return 0
        qga.connect()
        qga.sync()
        if args.cmd == "exec":
            program = args.program[1:] if args.program[:1] == ["--"] else args.program
            if not program:
                ap.error("exec needs a program")
            code, out, err = qga.exec(program, env=args.env, timeout=args.timeout)
            sys.stdout.buffer.write(out)
            sys.stdout.flush()
            sys.stderr.buffer.write(err)
            sys.stderr.flush()
            return code
        if args.cmd == "put":
            size = qga.put(args.local, args.remote)
            print(f"qga: copied {size} bytes to {args.remote}")
            return 0
        qga.shutdown()
        return 0
    except (OSError, QGAError) as exc:
        print(f"qga: {exc}. Check the serial log in the work folder.", file=sys.stderr)
        return EXIT_AGENT
    finally:
        qga.close()


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
