#!/usr/bin/env python3
"""Small HTTPS file server for tests/windows/Test-FetchAssets.ps1 (task 4G.2).

Serves ROOT on 127.0.0.1 at a free port over TLS, answers GET and HEAD (with Range for
resumed downloads), writes the port to PORTFILE once it listens, and appends one JSON line per
request to LOGFILE (method, path, whether an Auth-Key header was sent, and the Range header).
Test-only; standard library only; never listens on anything but loopback.

Usage: serve_https.py ROOT CERT_PEM KEY_PEM PORTFILE LOGFILE
"""

from __future__ import annotations

import http.server
import json
import os
import ssl
import sys
import threading
from pathlib import Path

LOCK = threading.Lock()


def make_handler(root: Path, logfile: Path) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _log(self) -> None:
            row = {
                "key": bool(self.headers.get("Auth-Key")),
                "method": self.command,
                "path": self.path,
                "range": self.headers.get("Range"),
            }
            with LOCK, logfile.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

        def _empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _serve(self, body: bool) -> None:
            self._log()
            rel = self.path.split("?", 1)[0].lstrip("/")
            path = (root / rel).resolve()
            if root not in path.parents or not path.is_file():
                self._empty(404)
                return
            data = path.read_bytes()
            etag = f'"{len(data):x}-{path.stat().st_mtime_ns:x}"'
            start, status = 0, 200
            rng = self.headers.get("Range") or ""
            if rng.startswith("bytes=") and self.headers.get("If-Range") in (None, etag):
                start = int(rng[6:].split("-", 1)[0] or 0)
                if start >= len(data):
                    self._empty(416)
                    return
                status = 206
            part = data[start:]
            self.send_response(status)
            self.send_header("Content-Length", str(len(part)))
            self.send_header("ETag", etag)
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
            self.end_headers()
            if body:
                self.wfile.write(part)

        def do_GET(self) -> None:
            self._serve(True)

        def do_HEAD(self) -> None:
            self._serve(False)

    return Handler


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("usage: serve_https.py ROOT CERT_PEM KEY_PEM PORTFILE LOGFILE", file=sys.stderr)
        return 2
    root, cert, key, portfile, logfile = (Path(a) for a in argv)
    root = root.resolve()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(root, logfile))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    tmp = portfile.with_name(portfile.name + ".tmp")
    tmp.write_text(str(server.server_address[1]), encoding="utf-8")
    os.replace(tmp, portfile)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
