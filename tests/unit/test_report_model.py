"""Model-drafted sections, stub llama-server on 127.0.0.1 (4E.2, 4E.3, 4E.5, 4E.9, 4E.10)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

from evidence_report import llm, mapreduce, render

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "injection"
BLOCK_RE = re.compile(r"<<<DATA id=(\S+)>>>\n(.*?)\n<<<END DATA id=\1>>>", re.DOTALL)
PLANTED = ("smith", "ignore previous", "suspect", "admin mode")


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


STUB = _load("stub_report_llm")


class Stub:
    def __init__(self, tmp: Path, mode: str) -> None:
        self.model = tmp / f"tiny-{mode}-Q4_K_M.gguf"
        self.model.write_bytes(b"not a real model " + mode.encode())
        self.log = tmp / f"stub-{mode}.jsonl"
        args = argparse.Namespace(mode=mode, log=str(self.log), model_file=str(self.model))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), STUB.make_handler(args, threading.Lock()))
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def requests(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def env(tmp_path: Path, airlock_env: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    del airlock_env
    monkeypatch.setenv("AIRLOCK_LLAMA_RUN_DIR", str(tmp_path / "no-effective"))
    return tmp_path


@pytest.fixture
def behave(env: Path) -> Iterator[Stub]:
    s = Stub(env, "behave")
    yield s
    s.close()


@pytest.fixture
def obey(env: Path) -> Iterator[Stub]:
    s = Stub(env, "obey")
    yield s
    s.close()


def make_run(root: Path) -> Path:
    return _load("make_run").build(root / "out", FIXTURES / "rows.json", "T-M")


def test_behaving_model_drafts_labelled_paragraphs(env: Path, behave: Stub) -> None:
    run = make_run(env)
    html_path, md_path = render.build(run, use_model=True, model_url=behave.url, start_server=False)
    md = md_path.read_text(encoding="utf-8")
    prompts = mapreduce.load_prompts()
    model_sha = llm.hashing.sha256_file(behave.model)
    assert md.count("AI-generated draft. Not evidence.") >= 3
    assert md.count("Reviewed by:") == md.count("AI-generated draft. Not evidence.")
    assert model_sha in md and prompts["results_map"].sha256 in md
    assert "NOT FINAL. This report contains AI-generated draft paragraphs" in md
    assert "b9999-stubcafe" in md and "Q4\\_K\\_M" in md
    prov = json.loads((run / "logs" / "report-provenance.json").read_text(encoding="utf-8"))
    assert prov["model"]["model_sha256"] == model_sha
    assert prov["model"]["llama_build"] == "b9999-stubcafe"
    assert prov["model"]["quantization"] == "Q4_K_M"
    assert prov["model"]["n_ctx"] == 8192
    assert not prov["removed"], prov["removed"]
    kept = [s for sec in prov["sections"] for s in sec["sentences"]]
    assert kept and all(re.search(r"\[F-\d{6}(, F-\d{6})*\]\.?$", s["text"]) for s in kept)
    for text in (md, html_path.read_text(encoding="utf-8")):
        low = text.lower()
        assert not any(p in low for p in PLANTED)
    # Greedy decoding with a fixed seed on every call; the system prompt is a fixed file.
    reqs = behave.requests()
    assert reqs
    fixed = {p.sha256 for p in prompts.values()}
    import hashlib  # noqa: PLC0415

    fixed_text = {hashlib.sha256(p.text.encode()).hexdigest() for p in prompts.values()}
    assert fixed == fixed_text
    for r in reqs:
        assert (r["temperature"], r["top_k"], r["seed"]) == (0, 1, llm.DEFAULT_SEED)
        assert r["system_sha256"] in fixed


def test_compromised_model_is_stripped(env: Path, obey: Stub) -> None:
    run = make_run(env)
    html_path, md_path = render.build(run, use_model=True, model_url=obey.url, start_server=False)
    for text in (md_path.read_text(encoding="utf-8"), html_path.read_text(encoding="utf-8")):
        low = text.lower()
        for planted in PLANTED:
            assert planted not in low, planted
        assert "deliberately" not in low and "to hide" not in low
    prov = json.loads((run / "logs" / "report-provenance.json").read_text(encoding="utf-8"))
    assert len(prov["removed"]) >= 10
    # Every removed sentence is listed in Appendix E by its hash.
    md = md_path.read_text(encoding="utf-8")
    for rec in prov["removed"]:
        assert rec["sha256"] in md
    # The well-behaved sentences the stub also wrote survive.
    assert md.count("AI-generated draft. Not evidence.") >= 3
    # The full removed text is in the run log for audit, not in the report.
    log = (run / "logs" / "report.jsonl").read_text(encoding="utf-8")
    assert "John Smith" in log


def test_evidence_text_only_inside_data_blocks(env: Path, obey: Stub) -> None:
    run = make_run(env)
    render.build(run, use_model=True, model_url=obey.url, start_server=False)
    reqs = obey.requests()
    assert reqs
    for r in reqs:
        user = r["user"]
        outside = BLOCK_RE.sub("", user)
        assert "IGNORE" not in outside and "Smith" not in outside and "admin mode" not in outside
        for m in BLOCK_RE.finditer(user):
            assert "<<<" not in m.group(2) and ">>>" not in m.group(2)
        assert "\u202e" not in user and "\u0007" not in user
        # Media rows reach the model as IDs, labels, and scores only (4E.8).
        assert "/Pictures/" not in user and "describe this image" not in user
    assert any("IGNORE PREVIOUS INSTRUCTIONS" in r["user"] for r in reqs)


def test_model_unreachable_falls_back(env: Path) -> None:
    run = make_run(env)
    _h, md_path = render.build(
        run, use_model=True, model_url="http://127.0.0.1:9", start_server=False
    )
    md = md_path.read_text(encoding="utf-8")
    assert "No AI draft: local model not available" in md
    assert "AI-generated draft. Not evidence." not in md


def test_model_without_hash_is_not_used(env: Path, behave: Stub) -> None:
    behave.model.unlink()  # the server names a file that cannot be hashed
    run = make_run(env)
    _h, md_path = render.build(run, use_model=True, model_url=behave.url, start_server=False)
    md = md_path.read_text(encoding="utf-8")
    assert "No AI draft: local model not available" in md
    assert "cannot hash the loaded model file" in md


@pytest.mark.parametrize(
    "url",
    ["http://10.0.0.5:8088", "https://127.0.0.1:8088", "http://example.com", "http://0.0.0.0:1"],
)
def test_loopback_only(url: str) -> None:
    with pytest.raises(llm.LlmError):
        llm.LocalModel(url)


def test_loopback_accepted() -> None:
    assert llm.LocalModel("http://127.0.0.1:8088/").base_url == "http://127.0.0.1:8088"
    assert llm.LocalModel("http://[::1]:8088").base_url == "http://[::1]:8088"
    assert llm.LocalModel("http://localhost:8088").base_url == "http://localhost:8088"


@pytest.mark.parametrize(
    ("name", "quant"),
    [
        ("/opt/models/Qwen3-VL-8B-Instruct-Q4_K_M.gguf", "Q4_K_M"),
        ("Qwen3-VL-8B-Instruct-Q8_0.gguf", "Q8_0"),
        ("model-f16.gguf", "F16"),
        ("model-IQ4_XS.gguf", "IQ4_XS"),
        ("plain.gguf", ""),
    ],
)
def test_quantization_of(name: str, quant: str) -> None:
    assert llm.quantization_of(name) == quant


def test_completion_endpoint_fallback(env: Path) -> None:
    """A server without the chat endpoint gets /completion with the same decoding settings."""
    from http.server import BaseHTTPRequestHandler  # noqa: PLC0415

    seen: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            return

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/completion":
                seen.append(body)
                out = json.dumps({"content": " drafted "}).encode()
                self.send_response(200)
            else:
                out = b'{"error": "nope"}'
                self.send_response(404)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        m = llm.LocalModel(f"http://127.0.0.1:{srv.server_address[1]}", seed=7)
        assert m.complete("SYSTEM", "USER") == "drafted"
        assert m.complete("SYSTEM", "USER") == "drafted"
    finally:
        srv.shutdown()
        srv.server_close()
    assert seen[0]["temperature"] == 0 and seen[0]["top_k"] == 1 and seen[0]["seed"] == 7
    assert seen[0]["prompt"].startswith("SYSTEM")
