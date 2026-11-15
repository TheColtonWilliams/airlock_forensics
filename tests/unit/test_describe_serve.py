"""llama-server launcher: 127.0.0.1 only, CPU fallback when a GPU tier fails to load.

Tasks 4B.3 and 4B.10.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from airlock_ai import config as cfgmod
from airlock_ai import serve

REPO = Path(__file__).resolve().parents[2]
PYLIB = REPO / "ansible" / "roles" / "session_tools" / "files" / "pylib"

FAKE_SERVER = r"""#!/usr/bin/env python3
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
args = sys.argv[1:]
opt = {args[i]: args[i + 1] for i in range(0, len(args) - 1) if args[i].startswith("-")}
with open(sys.argv[0] + ".calls", "a") as fh:
    fh.write(json.dumps(args) + "\n")
if int(opt.get("-ngl", "0")) > 0:
    sys.exit("simulated: model failed to load on the GPU")
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')
HTTPServer((opt["--host"], int(opt["--port"])), H).serve_forever()
"""


def _free_port() -> int:
    import socket  # noqa: PLC0415

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _setup(root: Path) -> dict:
    prefix = root / "llama"
    (prefix / "bin").mkdir(parents=True)
    exe = prefix / "bin" / "llama-server"
    exe.write_text(FAKE_SERVER, encoding="utf-8")
    exe.chmod(0o755)
    cfg = json.loads(json.dumps(cfgmod.DEFAULT_AI_CONFIG))
    cfg["llama"]["prefix"] = str(prefix)
    for t in ("tier0", "tier2"):
        cfg["tiers"][t]["models"] = [
            {"id": f"{t}", "role": "model", "target": f"models/{t}/m.gguf"},
            {"id": f"{t}-mm", "role": "mmproj", "target": f"models/{t}/mm.gguf"},
        ]
        d = root / "assets" / "files" / "models" / t
        d.mkdir(parents=True)
        (d / "m.gguf").write_bytes(t.encode())
        (d / "mm.gguf").write_bytes(b"mm" + t.encode())
    (root / "etc" / "ai-tiers.json").write_text(json.dumps(cfg), encoding="utf-8")
    state = {
        "tier": "tier2",
        "n_gpu_layers": 99,
        "vulkan_device_index": 1,
        "models": [
            {"role": "model", "path": str(root / "assets/files/models/tier2/m.gguf")},
            {"role": "mmproj", "path": str(root / "assets/files/models/tier2/mm.gguf")},
        ],
    }
    (root / "state" / "ai-tier.json").write_text(json.dumps(state), encoding="utf-8")
    return cfg


def test_gpu_failure_falls_back_to_cpu_tier(airlock_env: Path):
    _setup(airlock_env)
    port = _free_port()
    run_dir = airlock_env / "run-llama"
    env = {**os.environ, "PYTHONPATH": str(PYLIB), "AIRLOCK_LLAMA_RUN_DIR": str(run_dir)}
    child = subprocess.Popen(
        [sys.executable, "-m", "airlock_ai.serve", "--port", str(port), "--wait", "20"],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    eff = run_dir / "effective.json"
    try:
        for _ in range(200):
            if eff.exists() or child.poll() is not None:
                break
            time.sleep(0.1)
        assert eff.exists(), child.stderr.read() if child.poll() is not None else "timeout"
        doc = json.loads(eff.read_text(encoding="utf-8"))
        assert doc["tier"] == "tier0"
        assert doc["backend"] == "cpu"
        assert "failed to load on the GPU" in doc["fallback_reason"]
        assert doc["model_path"].endswith("tier0/m.gguf")
        assert len(doc["model_sha256"]) == 64
        assert doc["listen"] == f"127.0.0.1:{port}"
    finally:
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=20)
    calls = (airlock_env / "llama/bin/llama-server.calls").read_text().splitlines()
    first, second = json.loads(calls[0]), json.loads(calls[1])
    assert first[first.index("-ngl") + 1] == "99"
    assert second[second.index("-ngl") + 1] == "0"
    for argv in (first, second):
        assert argv[argv.index("--host") + 1] == "127.0.0.1"


def test_server_argv_binds_loopback_only(airlock_env: Path):
    cfg = _setup(airlock_env)
    argv = serve.server_argv(
        cfg,
        {
            "tier": "tier0",
            "n_gpu_layers": 0,
            "models": [{"role": "model", "path": "/m"}, {"role": "mmproj", "path": "/mm"}],
        },
        8089,
    )
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert "0.0.0.0" not in argv  # noqa: S104 - asserting it is absent
    assert argv[argv.index("--mmproj") + 1] == "/mm"
    assert argv[argv.index("--temp") + 1] == "0"
