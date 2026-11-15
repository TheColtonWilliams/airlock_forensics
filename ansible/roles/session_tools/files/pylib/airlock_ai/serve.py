"""Launcher for ``llama-server`` under systemd (task 4B.10; unit in the ``tools_ai`` role).

``llama-server.service`` runs ``python3 -m airlock_ai.serve``. It:

* reads the tier chosen at boot (``/var/lib/airlock/ai-tier.json`` from ``ai-probe --write``),
  or probes again if there is none;
* starts ``/opt/llama/bin/llama-server`` bound to 127.0.0.1 only (any other host is refused),
  on the back-end port that ``systemd-socket-proxyd`` forwards ``127.0.0.1:8088`` to;
* waits for ``/health``. If a GPU tier's model fails to load (the server exits or never gets
  ready), it starts again on the CPU tier (tier0, no GPU layers) and records why;
* hashes the loaded model and projector files and writes them, with the tier and back end, to
  ``/run/airlock-llama/effective.json`` for the provenance columns;
* tells systemd it is ready (``sd_notify READY=1``) and passes SIGTERM on to the server.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import FrameType
from typing import Any

from airlock_ai import config as cfgmod
from airlock_ai import llm, probe
from airlock_common import jsonio, timeutil

HOST = "127.0.0.1"


def notify(message: str) -> None:
    """Send ``message`` to systemd's notify socket, if there is one (stdlib sd_notify)."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    with contextlib.suppress(OSError), socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(addr)
        s.sendall(message.encode())


def _models(doc: dict[str, Any]) -> tuple[str, str]:
    model = mmproj = ""
    for m in doc.get("models", []):
        if m.get("role") == "mmproj":
            mmproj = str(m.get("path", ""))
        else:
            model = model or str(m.get("path", ""))
    return model, mmproj


def server_argv(cfg: dict[str, Any], doc: dict[str, Any], port: int) -> list[str]:
    model, mmproj = _models(doc)
    if not model:
        raise RuntimeError(f"tier {doc.get('tier')} has no model file staged")
    llama = cfg["llama"]
    argv = [
        str(Path(llama["prefix"]) / "bin" / "llama-server"),
        "--host",
        HOST,
        "--port",
        str(port),
        "-m",
        model,
        "-ngl",
        str(int(doc.get("n_gpu_layers", 0))),
        "--ctx-size",
        str(int(llama.get("ctx_size", 8192))),
        "--seed",
        str(int(llama.get("seed", 42))),
        "--temp",
        "0",
        "--parallel",
        "1",
        "--no-webui",
    ]
    if mmproj:
        argv += ["--mmproj", mmproj]
    return argv


def _healthy(port: int) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{HOST}:{port}/health", timeout=5) as resp:
            return resp.status == 200
    except OSError:
        return False


def start(
    cfg: dict[str, Any], doc: dict[str, Any], port: int, wait_s: float
) -> subprocess.Popen[bytes] | None:
    """Start the server for ``doc``'s tier; None if it exits or never becomes ready."""
    env = dict(os.environ)
    dev = doc.get("vulkan_device_index")
    if int(doc.get("n_gpu_layers", 0)) > 0 and dev is not None:
        env["GGML_VK_VISIBLE_DEVICES"] = str(dev)
    child = subprocess.Popen(server_argv(cfg, doc, port), env=env)
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if child.poll() is not None:
            return None
        if _healthy(port):
            return child
        time.sleep(1)
    child.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        child.wait(timeout=30)
    if child.poll() is None:
        child.kill()
    return None


def cpu_fallback(cfg: dict[str, Any]) -> dict[str, Any]:
    choice = probe.choose_tier(vulkaninfo_text="", config=cfg)  # no GPU: CPU tier
    return choice.to_dict()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airlock-llama-serve")
    ap.add_argument("--port", type=int, default=None, help="back-end port on 127.0.0.1")
    ap.add_argument("--wait", type=float, default=900.0, help="seconds to wait for /health")
    args = ap.parse_args(argv)
    cfg = cfgmod.load_ai_config()
    port = args.port or int(cfg["llama"].get("backend_port", 8089))
    doc = probe.load_choice() or probe.choose_tier(config=cfg).to_dict()
    if doc.get("tier") in (None, "none"):
        print(
            "airlock-llama-serve: no model tier is staged. Restage ASSETS with AI tiers.",
            file=sys.stderr,
        )
        return 1
    fallback_reason = ""
    child = start(cfg, doc, port, args.wait)
    if child is None and int(doc.get("n_gpu_layers", 0)) > 0:
        fallback_reason = f"{doc.get('tier')} failed to load on the GPU; using the CPU tier"
        print(f"airlock-llama-serve: {fallback_reason}", file=sys.stderr)
        doc = cpu_fallback(cfg)
        if doc.get("tier") != "none":
            child = start(cfg, doc, port, args.wait)
    if child is None:
        print(
            "airlock-llama-serve: llama-server did not start. See the log above.", file=sys.stderr
        )
        return 1
    model, mmproj = _models(doc)
    run_dir = llm.run_dir()
    effective = {
        "schema": 1,
        "utc": timeutil.iso(),
        "tier": doc.get("tier"),
        "backend": "vulkan" if int(doc.get("n_gpu_layers", 0)) > 0 else "cpu",
        "n_gpu_layers": int(doc.get("n_gpu_layers", 0)),
        "model_id": doc.get("model_id") or Path(model).name,
        "model_path": model,
        "model_sha256": llm.file_sha256(model),
        "mmproj_path": mmproj,
        "mmproj_sha256": llm.file_sha256(mmproj) if mmproj else "",
        "fallback_reason": fallback_reason,
        "listen": f"{HOST}:{port}",
    }
    with contextlib.suppress(OSError):
        jsonio.dump_json(run_dir / "effective.json", effective)
    notify("READY=1")

    def _forward(signum: int, _frame: FrameType | None) -> None:
        with contextlib.suppress(ProcessLookupError):
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)
    code = child.wait()
    notify("STOPPING=1")
    return 0 if code in (0, -signal.SIGTERM) else 1


if __name__ == "__main__":
    raise SystemExit(main())
