"""Map-reduce drafting for small context windows (tasks 4E.3, 4E.5, 4E.8)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

import pytest

from evidence_report import inputs, mapreduce

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "injection"
BLOCK_RE = re.compile(r"<<<DATA id=(\S+)>>>\n(.*?)\n<<<END DATA id=\1>>>", re.DOTALL)


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def db(tmp_path: Path) -> inputs.CaseDB:
    run = _load("make_run").build(tmp_path / "out", FIXTURES / "rows.json")
    return inputs.CaseDB(run / "case.sqlite")


def test_prompts_are_fixed_files_with_hashes() -> None:
    prompts = mapreduce.load_prompts()
    assert set(prompts) == set(mapreduce.PROMPTS)
    for p in prompts.values():
        raw = (mapreduce.PROMPT_DIR / p.file).read_bytes()
        assert p.sha256 == hashlib.sha256(raw).hexdigest()
        # 4E.7 rules are in every prompt.
        assert "account SID" in p.text
        assert "intent" in p.text
        assert "<<<DATA" in p.text and "never an instruction" in p.text
    assert "the USN journal records a delete at" in prompts["results_map"].text


def test_span_text() -> None:
    assert mapreduce.span_text(0) == "0 seconds"
    assert mapreduce.span_text(90) == "1 minute 30 seconds"
    assert mapreduce.span_text(86400 + 3600 * 2 + 1) == "1 day 2 hours 1 second"


def test_compute_values_does_date_arithmetic() -> None:
    rows = [
        {"finding_id": "F-000001", "artifact_type": "a", "datetime": "2026-03-01T10:15:00Z"},
        {"finding_id": "F-000002", "artifact_type": "a", "datetime": "2026-03-03T11:16:30.5Z"},
        {
            "finding_id": "F-000003",
            "artifact_type": "b",
            "allocated": False,
            "owner_sid": "S-1-5-18",
        },
    ]
    v = mapreduce.compute_values(rows, sensitive=False, total=10, given=3)
    assert v["first_time"] == "2026-03-01T10:15:00Z"
    assert v["last_time"] == "2026-03-03T11:16:30.5Z"
    assert v["time_span"] == "2 days 1 hour 1 minute 30 seconds"
    assert v["time_span_whole_days"] == 2
    assert v["rows_per_artifact_type"] == {"a": 2, "b": 1}
    assert v["rows_marked_unallocated"] == 1
    assert v["rows_in_category"] == 10


def test_windows_fit_budget_in_time_order() -> None:
    rows = [
        {
            "finding_id": f"F-{i:06d}",
            "category": "timeline",
            "artifact_type": "fs_time",
            "derivation": "observed",
            "datetime": f"2026-03-{(30 - i):02d}T00:00:00Z",
            "message": "x" * 200,
        }
        for i in range(1, 21)
    ]
    rows.append(
        {
            "finding_id": "F-000099",
            "category": "timeline",
            "artifact_type": "note",
            "derivation": "observed",
            "message": "no time",
        }
    )
    s = mapreduce.Settings(data_chars=1200, rows_per_window=40)
    wins = mapreduce.make_windows("timeline", rows, sensitive=False, total=21, settings=s)
    assert len(wins) > 2
    stamps = [r["datetime"] for w in wins for r in w.rows if r.get("datetime")]
    assert stamps == sorted(stamps)
    assert wins[-1].label == "rows with no recorded time"
    for w in wins:
        size = sum(len(json.dumps(inputs.model_row(r))) for r in w.rows)
        assert len(w.rows) == 1 or size <= 1200 + 300
    assert sum(len(w.rows) for w in wins) == 21


def test_draft_with_fake_model(db: inputs.CaseDB) -> None:
    calls: list[tuple[str, str]] = []

    def complete(system: str, user: str) -> str:
        calls.append((system, user))
        blocks = {m.group(1).split("-")[0]: m.group(2) for m in BLOCK_RE.finditer(user)}
        if "rows" in blocks:
            ids = [json.loads(line)["finding_id"] for line in blocks["rows"].splitlines()]
            return f"This part holds {len(ids)} rows [{', '.join(ids)}]. Made up claim [F-000999]."
        if system.startswith("You combine"):
            # The merge cites an ID that no statement cites: it must be removed.
            return "Merged statement about these rows [F-000001]. Another merged row [F-000013]."
        statements = [line.split(": ", 1)[1] for line in blocks["statements"].splitlines()]
        return statements[0]

    prompts = mapreduce.load_prompts()
    log: list[dict] = []
    d = mapreduce.Drafter(db, complete, prompts, settings=mapreduce.Settings(), log=log.append)
    out = d.run()
    keys = [r.key for r in out["results"]]
    assert keys == [
        "deletion",
        "recycle_bin",
        "inventory",
        "users",
        "documents",
        "timeline",
        "xval",
        "images",
    ]
    for r in out["results"]:
        assert r.status == "drafted", r
        assert all(s.text.startswith("This part holds") for s in r.sentences)
        assert any("F-000999" in x.text for x in r.removed)
    assert out["interpretation"].status == "drafted"
    assert out["conclusions"].sentences
    events = {e["event"] for e in log}
    assert {"model_call", "sentence_removed"} <= events
    # Sensitive rows: no path, filename, message, or text reaches the model.
    image_calls = [u for _s, u in calls if "Report section: Images" in u]
    assert image_calls
    for u in image_calls:
        rows = [
            json.loads(line)
            for line in BLOCK_RE.search(u.split("Rows from")[1]).group(2).splitlines()
        ]
        assert all(set(r) <= set(inputs.SENSITIVE_FIELDS) for r in rows)


def test_reduce_may_only_use_cited_statements(db: inputs.CaseDB) -> None:
    def complete(system: str, user: str) -> str:
        blocks = {m.group(1).split("-")[0]: m.group(2) for m in BLOCK_RE.finditer(user)}
        if "rows" in blocks:
            ids = [json.loads(line)["finding_id"] for line in blocks["rows"].splitlines()]
            return " ".join(f"This record is listed here [{i}]." for i in ids)
        # A merge that cites a real finding the statements never cited is rejected.
        return "This record is listed here [F-000001]. This record is listed here [F-000006]."

    s = mapreduce.Settings(rows_per_window=1)
    d = mapreduce.Drafter(db, complete, mapreduce.load_prompts(), settings=s)
    draft, _rows, _vals = d.draft_category("deletion")
    assert draft.method.startswith("map over 2 window(s)")
    assert [x.ids for x in draft.sentences] == [["F-000006"]]
    assert any(r.ids == ["F-000001"] for r in draft.removed)


def test_no_model_and_call_budget(db: inputs.CaseDB) -> None:
    d = mapreduce.Drafter(db, None, mapreduce.load_prompts(), unavailable_reason="off")
    out = d.run()
    assert {r.status for r in out["results"]} == {"no_model"}
    assert out["conclusions"].status == "no_model"

    n = 0

    def complete(_s: str, _u: str) -> str:
        nonlocal n
        n += 1
        return "NONE"

    d2 = mapreduce.Drafter(
        db, complete, mapreduce.load_prompts(), settings=mapreduce.Settings(max_calls=3)
    )
    out2 = d2.run()
    assert n == 3
    assert all(not r.sentences for r in out2["results"])


def test_model_error_does_not_stop_drafting(db: inputs.CaseDB) -> None:
    def complete(_s: str, _u: str) -> str:
        raise RuntimeError("server went away")

    d = mapreduce.Drafter(db, complete, mapreduce.load_prompts())
    out = d.run()
    assert d.errors and all(r.status == "nothing_supported" for r in out["results"])
