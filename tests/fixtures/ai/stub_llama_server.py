#!/usr/bin/env python3
"""A stand-in for ``llama-server`` on 127.0.0.1, for tests (4G.10, 4G.11, 4B.12).

Serves ``/health``, ``/props`` (``model_path`` = ``--model-file``), and
``/v1/chat/completions``. Every completion request is appended to ``--log`` as one JSON line
holding the SHA-256 of any attached image, the system prompt's SHA-256, and the user text, so a
test can prove which files reached "the model" and what the model was told.

Modes: ``describe`` answers with a fixed neutral sentence; ``decline`` refuses; ``empty`` sends
an empty reply; ``echo`` returns the user text (to show where evidence text was placed).

    python3 stub_llama_server.py --port-file F --log L --model-file M [--mode describe]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPLIES = {
    "describe": "A simple synthetic picture with plain shapes and flat colours.",
    "decline": "I'm sorry, but I can't help with describing this image.",
    "empty": "",
}


def make_handler(args: argparse.Namespace, lock: threading.Lock) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:  # keep test output quiet
            return

        def _send(self, code: int, doc: dict) -> None:
            body = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send(200, {"status": "ok"})
            elif self.path == "/props":
                self._send(200, {"model_path": args.model_file})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
            if self.path != "/v1/chat/completions":
                self._send(404, {"error": "not found"})
                return
            msgs = req.get("messages", [])
            system = next((m["content"] for m in msgs if m.get("role") == "system"), "")
            user = next((m["content"] for m in msgs if m.get("role") == "user"), [])
            images, texts = [], []
            for part in user if isinstance(user, list) else [{"type": "text", "text": user}]:
                if part.get("type") == "image_url":
                    data = part["image_url"]["url"].split(",", 1)[1]
                    images.append(hashlib.sha256(base64.b64decode(data)).hexdigest())
                elif part.get("type") == "text":
                    texts.append(part.get("text", ""))
            rec = {
                "images": images,
                "system_sha256": hashlib.sha256(system.encode()).hexdigest(),
                "user_text": "\n".join(texts),
                "temperature": req.get("temperature"),
                "seed": req.get("seed"),
                "top_k": req.get("top_k"),
            }
            with lock, open(args.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            reply = rec["user_text"] if args.mode == "echo" else REPLIES[args.mode]
            self._send(
                200,
                {
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": reply},
                            "finish_reason": "stop",
                        }
                    ]
                },
            )

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--model-file", required=True)
    ap.add_argument("--mode", default="describe", choices=[*REPLIES, "echo"])
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(args, threading.Lock()))
    Path(args.port_file).write_text(str(server.server_address[1]), encoding="ascii")
    server.serve_forever()


if __name__ == "__main__":
    main()
