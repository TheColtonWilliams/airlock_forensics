"""Client for the local ``llama-server`` used to draft report sections (tasks 4E.2, 4E.3).

* Loopback only: the URL must point at 127.0.0.1, ``::1``, or ``localhost``, and HTTP proxy
  settings in the environment are ignored, so no request can leave the machine (hard rule 2.3.1).
* Greedy decoding: temperature 0, top-k 1, top-p 1, a fixed seed, no prompt cache.
  ``/v1/chat/completions`` is used; a server without it gets ``/completion``.
* Provenance: the llama.cpp build (``/props`` ``build_info``), backend, model path and file
  SHA-256, quantisation, and context size are recorded for the report. A model whose file
  cannot be hashed is not used: AI output must always carry the model hash (hard rule 2.3.8).

When the AI package (``airlock_ai.llm``) is installed, its loopback check, default URL,
socket-activated server start, and ``effective.json`` provenance are reused.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing

DEFAULT_URL = "http://127.0.0.1:8088"
URL_ENV = "AIRLOCK_LLAMA_URL"
DEFAULT_SEED = 1234
DEFAULT_MAX_TOKENS = 512
QUANT_RE = re.compile(
    r"(?:^|[-_.])((?:I?Q\d(?:_[A-Z0-9]+)*)|BF16|F16|F32)(?=[-_.]|$)", re.IGNORECASE
)


class LlmError(RuntimeError):
    """The model server is unreachable, not local, or answered with an error."""


@dataclass
class ModelRecord:
    """What drafted the text. Shown in the report and in ``logs/report-provenance.json``."""

    base_url: str
    model_id: str = ""
    model_path: str = ""
    model_sha256: str = ""
    quantization: str = ""
    llama_build: str = ""
    backend: str = ""
    n_ctx: int | None = None
    seed: int = DEFAULT_SEED
    temperature: float = 0.0
    top_k: int = 1
    endpoint: str = "/v1/chat/completions"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_loopback(url: str) -> str:
    """Return ``url`` without a trailing slash if it is plain http to a loopback address."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http":
        raise LlmError(f"{url}: only plain http to 127.0.0.1 is allowed")
    host = parsed.hostname or ""
    ok = host == "localhost"
    if not ok:
        try:
            ok = ipaddress.ip_address(host).is_loopback
        except ValueError:
            ok = False
    if not ok:
        raise LlmError(f"{url}: the model server must be on 127.0.0.1 (no network use)")
    return url.rstrip("/")


def default_url() -> str:
    env = os.environ.get(URL_ENV)
    if env:
        return env.rstrip("/")
    try:
        from airlock_ai import llm as ai_llm  # noqa: PLC0415 - optional package

        return ai_llm.default_url()
    except Exception:  # the AI package or its config may be absent: use the fixed default
        return DEFAULT_URL


def quantization_of(name: str) -> str:
    """``Q4_K_M``, ``Q8_0``, ``F16`` ... from a GGUF file name, or ``""``."""
    stem = Path(name).name
    if stem.lower().endswith(".gguf"):
        stem = stem[:-5]
    found = QUANT_RE.findall(stem)
    return found[-1].upper() if found else ""


class LocalModel:
    """One loopback model server, used with greedy decoding and a fixed seed."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        seed: int = DEFAULT_SEED,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = 900.0,
    ) -> None:
        self.base_url = check_loopback(base_url or default_url())
        self.seed = seed
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self._chat = True
        self.record: ModelRecord | None = None

    # -- HTTP ----------------------------------------------------------------------------------

    def _call(
        self, method: str, path: str, body: dict[str, Any] | None = None, *, timeout: float = 0
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, sort_keys=True).encode()
        req = urllib.request.Request(  # noqa: S310 - loopback http only, checked in __init__
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace")
            raise LlmError(f"model server answered {exc.code} on {path}: {detail}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise LlmError(f"model server not reachable at {self.base_url}: {exc}") from exc
        try:
            out = json.loads(payload or b"{}")
        except ValueError as exc:
            raise LlmError(f"model server sent something that is not JSON on {path}") from exc
        return out if isinstance(out, dict) else {"data": out}

    def healthy(self) -> bool:
        try:
            doc = self._call("GET", "/health", timeout=10)
        except LlmError:
            return False
        return doc.get("status", "ok") == "ok"

    # -- provenance ----------------------------------------------------------------------------

    def probe(self) -> ModelRecord:
        """Ask the server what it runs and hash the model file. Raises ``LlmError``."""
        props: dict[str, Any] = {}
        with contextlib.suppress(LlmError):
            props = self._call("GET", "/props", timeout=30)
        models: dict[str, Any] = {}
        with contextlib.suppress(LlmError):
            models = self._call("GET", "/v1/models", timeout=30)
        entry: dict[str, Any] = {}
        data = models.get("data")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            entry = data[0]
        eff = _effective()
        settings = props.get("default_generation_settings")
        settings = settings if isinstance(settings, dict) else {}
        model_path = str(
            eff.get("model_path")
            or props.get("model_path")
            or settings.get("model")
            or entry.get("id")
            or ""
        )
        if not model_path:
            raise LlmError("the model server does not say which model it loaded")
        digest = str(eff.get("model_sha256") or "")
        if len(digest) != 64:
            digest = _hash_model(model_path)
        if len(digest) != 64:
            raise LlmError(
                f"cannot hash the loaded model file {model_path}; AI text needs the model hash"
            )
        n_ctx = settings.get("n_ctx") or props.get("n_ctx")
        meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
        rec = ModelRecord(
            base_url=self.base_url,
            model_id=str(eff.get("model_id") or Path(model_path).name),
            model_path=model_path,
            model_sha256=digest,
            quantization=quantization_of(model_path),
            llama_build=str(props.get("build_info") or eff.get("llama_build") or "unknown"),
            backend=str(eff.get("backend") or props.get("backend") or "unknown"),
            n_ctx=int(n_ctx) if isinstance(n_ctx, int | float) and n_ctx else None,
            seed=self.seed,
            extra={
                k: v
                for k, v in {
                    "tier": eff.get("tier"),
                    "n_params": meta.get("n_params"),
                    "model_size_bytes": meta.get("size"),
                    "n_ctx_train": meta.get("n_ctx_train"),
                }.items()
                if v not in (None, "")
            },
        )
        self.record = rec
        return rec

    # -- completion ----------------------------------------------------------------------------

    def complete(self, system: str, user: str) -> str:
        """One greedy completion. ``user`` must hold evidence only inside data blocks."""
        if self._chat:
            body = {
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0,
                "top_k": 1,
                "top_p": 1.0,
                "seed": self.seed,
                "max_tokens": self.max_tokens,
                "stream": False,
                "cache_prompt": False,
            }
            try:
                doc = self._call("POST", "/v1/chat/completions", body)
            except LlmError as exc:
                if " 404 " not in f" {exc} ":
                    raise
                self._chat = False
                if self.record is not None:
                    self.record.endpoint = "/completion"
            else:
                try:
                    return str(doc["choices"][0]["message"]["content"] or "").strip()
                except (KeyError, IndexError, TypeError) as exc:
                    raise LlmError("model server reply has no message content") from exc
        body = {
            "prompt": f"{system}\n\n{user}\n\n",
            "temperature": 0,
            "top_k": 1,
            "top_p": 1.0,
            "seed": self.seed,
            "n_predict": self.max_tokens,
            "stream": False,
            "cache_prompt": False,
        }
        doc = self._call("POST", "/completion", body)
        return str(doc.get("content") or "").strip()


def _effective() -> dict[str, Any]:
    """``effective.json`` written by the AI package's server launcher, when present."""
    try:
        from airlock_ai import llm as ai_llm  # noqa: PLC0415

        path = ai_llm.run_dir() / "effective.json"
    except Exception:
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _hash_model(path: str) -> str:
    try:
        if Path(path).is_file():
            return hashing.sha256_file(path)
    except OSError:
        return ""
    return ""


@contextlib.contextmanager
def server(model: LocalModel, *, start: bool = True) -> Iterator[LocalModel]:
    """Yield ``model`` once its server answers, starting the socket-activated unit if allowed.

    The start uses the AI package's ``LlamaServer`` (``systemctl start llama-server.socket``)
    and stops it again afterwards. Raises ``LlmError`` when no server becomes available.
    """
    if model.healthy():
        yield model
        return
    if not start:
        raise LlmError(f"no model server at {model.base_url}")
    try:
        from airlock_ai import llm as ai_llm  # noqa: PLC0415
    except ImportError as exc:
        raise LlmError(f"no model server at {model.base_url}") from exc
    client = ai_llm.LlamaClient(model.base_url)
    try:
        ctx = ai_llm.LlamaServer(client, start=True)
        ctx.__enter__()
    except ai_llm.LlmError as exc:
        raise LlmError(str(exc)) from exc
    try:
        deadline = time.monotonic() + 30
        while not model.healthy() and time.monotonic() < deadline:
            time.sleep(1)
        yield model
    finally:
        ctx.__exit__(None, None, None)
