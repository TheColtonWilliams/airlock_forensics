"""Client for the local ``llama-server`` on 127.0.0.1 (task 4B.8, 4B.10).

Only loopback addresses are accepted, and HTTP proxies from the environment are ignored, so a
request can never leave the machine. The server is socket-activated by systemd
(``llama-server.socket``, ``ListenStream=127.0.0.1:8088``) and stays off until a describe step
starts it; ``LlamaServer`` starts the socket and stops it again afterwards.

Every request uses greedy decoding (temperature 0, top-k 1) and a fixed seed. A reply that is
empty or a refusal is reported as ``model_declined``; the caller writes a row for it.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import config as cfgmod
from airlock_common import hashing, jsonio, proc

URL_ENV = "AIRLOCK_LLAMA_URL"
RUN_DIR_ENV = "AIRLOCK_LLAMA_RUN_DIR"
NO_START_ENV = "AIRLOCK_LLAMA_NO_START"
DEFAULT_RUN_DIR = "/run/airlock-llama"
SOCKET_UNIT = "llama-server.socket"
SERVICE_UNITS = ("llama-server-proxy.service", "llama-server.service")

_REFUSAL = re.compile(
    r"^\s*(declined\b|i\s*(?:can(?:no|')?t|cannot|won'?t|am\s+(?:not\s+able|unable)|'m\s+"
    r"(?:not\s+able|unable|sorry))|sorry\b|i\s+apologi[sz]e|as\s+an\s+ai\b)",
    re.IGNORECASE,
)

IMAGE_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".jpe": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".ppm": "image/x-portable-pixmap",
}


class LlmError(RuntimeError):
    """The model server is unreachable, not local, or answered with an error."""


@dataclass
class Reply:
    text: str
    declined: bool
    finish_reason: str = ""
    raw_excerpt: str = ""


@dataclass
class ModelInfo:
    model_id: str
    model_path: str
    model_sha256: str
    mmproj_sha256: str = ""
    tier: str = ""
    backend: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def is_refusal(text: str) -> bool:
    return not text.strip() or bool(_REFUSAL.match(text))


def check_loopback(url: str) -> str:
    """Return ``url`` if it points at a loopback address, else raise ``LlmError``."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http":
        raise LlmError(f"{url}: only plain http to 127.0.0.1 is allowed")
    host = parsed.hostname or ""
    if host == "localhost":
        return url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url
    except ValueError:
        pass
    raise LlmError(f"{url}: the model server must be on 127.0.0.1 (no network use)")


def default_url(cfg: dict[str, Any] | None = None) -> str:
    env = os.environ.get(URL_ENV)
    if env:
        return env.rstrip("/")
    listen = (cfg or cfgmod.load_ai_config())["llama"]["listen"]
    return f"http://{listen}"


class LlamaClient:
    def __init__(self, base_url: str | None = None, *, timeout: float = 900.0) -> None:
        self.base_url = check_loopback(base_url or default_url())
        self.timeout = timeout
        # No proxy handler: http_proxy and friends in the environment are never used.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, sort_keys=True).encode()
        req = urllib.request.Request(  # noqa: S310 - loopback http only, checked above
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace")
            raise LlmError(f"model server answered {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise LlmError(f"model server not reachable at {self.base_url}: {exc}") from exc
        try:
            out = json.loads(payload or b"{}")
        except ValueError as exc:
            raise LlmError("model server sent something that is not JSON") from exc
        return out if isinstance(out, dict) else {"data": out}

    def healthy(self) -> bool:
        try:
            doc = self._call("GET", "/health", timeout=10)
        except LlmError:
            return False
        return doc.get("status", "ok") == "ok"

    def props(self) -> dict[str, Any]:
        return self._call("GET", "/props", timeout=30)

    def chat(
        self,
        system_prompt: str,
        *,
        text: str | None = None,
        image: Path | None = None,
        seed: int,
        max_tokens: int,
    ) -> Reply:
        """One greedy chat completion. ``text`` must already be a data block."""
        content: list[dict[str, Any]] = []
        if image is not None:
            mime = IMAGE_MIME.get(image.suffix.lower(), "application/octet-stream")
            b64 = base64.b64encode(image.read_bytes()).decode("ascii")
            content.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}})
        if text is not None:
            content.append({"type": "text", "text": text})
        body = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
            ],
            "temperature": 0,
            "top_k": 1,
            "top_p": 1.0,
            "seed": seed,
            "max_tokens": max_tokens,
            "stream": False,
            "cache_prompt": False,
        }
        doc = self._call("POST", "/v1/chat/completions", body)
        try:
            choice = doc["choices"][0]
            reply = str(choice.get("message", {}).get("content") or "")
            finish = str(choice.get("finish_reason") or "")
        except (KeyError, IndexError, TypeError):
            return Reply("", True, "", json.dumps(doc)[:200])
        reply = reply.strip()
        return Reply(reply, is_refusal(reply), finish, reply[:200])


# ---------------------------------------------------------------------------------------------
# Server lifecycle and model provenance
# ---------------------------------------------------------------------------------------------

_HASH_CACHE: dict[tuple[str, int, int], str] = {}


def file_sha256(path: str) -> str:
    """SHA-256 of a model file, cached per process by (path, size, mtime)."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path, st.st_size, int(st.st_mtime))
    if key not in _HASH_CACHE:
        _HASH_CACHE[key] = hashing.sha256_file(path)
    return _HASH_CACHE[key]


def run_dir() -> Path:
    return Path(os.environ.get(RUN_DIR_ENV) or DEFAULT_RUN_DIR)


def model_info(client: LlamaClient) -> ModelInfo:
    """What the server has loaded. ``effective.json`` (written by ``serve``) wins over ``/props``.

    The model SHA-256 is always from the file itself, never from a server claim alone.
    """
    eff_path = run_dir() / "effective.json"
    eff: dict[str, Any] = {}
    if eff_path.exists():
        try:
            eff = jsonio.load_json(eff_path)
        except (OSError, ValueError):
            eff = {}
    model_path = str(eff.get("model_path") or "")
    if not model_path:
        props = client.props()
        model_path = str(
            props.get("model_path") or props.get("default_generation_settings", {}).get("model", "")
        )
    if not model_path:
        raise LlmError("the model server does not say which model it loaded")
    digest = str(eff.get("model_sha256") or "") or file_sha256(model_path)
    if len(digest) != 64:
        raise LlmError(f"cannot hash the loaded model file {model_path}")
    mmproj = str(eff.get("mmproj_path") or "")
    return ModelInfo(
        model_id=str(eff.get("model_id") or Path(model_path).name),
        model_path=model_path,
        model_sha256=digest,
        mmproj_sha256=str(eff.get("mmproj_sha256") or (file_sha256(mmproj) if mmproj else "")),
        tier=str(eff.get("tier") or ""),
        backend=str(eff.get("backend") or ""),
        extra={k: v for k, v in eff.items() if k in {"n_gpu_layers", "fallback_reason"}},
    )


class LlamaServer:
    """Start the socket-activated server for the length of a ``with`` block."""

    def __init__(self, client: LlamaClient, *, start: bool = True, wait_s: float = 900.0) -> None:
        self.client = client
        self.start = start and not os.environ.get(NO_START_ENV)
        self.wait_s = wait_s
        self.started = False

    def _systemctl(self, *args: str) -> None:
        argv = ["systemctl", *args]
        if os.geteuid() != 0:
            argv = ["sudo", "-n", *argv]
        res = proc.run(argv, check=False, timeout=60)
        if res.returncode != 0:
            last = (res.stderr.strip().splitlines() or [""])[-1]
            raise LlmError(f"cannot run {' '.join(args)}: {last}")

    def __enter__(self) -> LlamaClient:
        if self.client.healthy():
            return self.client
        if not self.start:
            raise LlmError(f"no model server at {self.client.base_url}")
        if proc.which("systemctl") is None:
            raise LlmError("systemctl is not available to start the model server")
        self._systemctl("start", SOCKET_UNIT)
        self.started = True
        deadline = time.monotonic() + self.wait_s
        while time.monotonic() < deadline:
            if self.client.healthy():  # the first connection also starts the service
                return self.client
            time.sleep(2)
        raise LlmError("the model server did not become ready (see journalctl -u llama-server)")

    def __exit__(self, *_exc: object) -> None:
        if self.started:
            for unit in (SOCKET_UNIT, *SERVICE_UNITS):
                try:
                    self._systemctl("stop", unit)
                except (LlmError, proc.ToolError):
                    continue
