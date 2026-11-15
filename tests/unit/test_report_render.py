"""The code-filled report (tasks 4E.1, 4E.2, 4E.8, 4E.9, 4E.11), rendered without a model."""

from __future__ import annotations

import html.parser
import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

import pytest

from evidence_report import cli, render

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "injection"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_run(root: Path, mode: str = "direct") -> Path:
    return _load("make_run").build(root / "out", FIXTURES / "rows.json", "T-R", mode)


@pytest.fixture
def run_dir(tmp_path: Path, airlock_env: Path) -> Path:
    del airlock_env
    return make_run(tmp_path)


def test_build_without_model(run_dir: Path) -> None:
    html_path, md_path = render.build(run_dir, use_model=False)
    assert html_path == run_dir / "report.html" and md_path == run_dir / "report.md"
    for text in (html_path.read_text(encoding="utf-8"), md_path.read_text(encoding="utf-8")):
        assert "No AI draft: local model not available" in text
        assert "AI-generated draft. Not evidence" not in text
        assert "Reviewed by" not in text
        assert "NOT FINAL" in text


def test_factual_sections_filled_by_code(run_dir: Path) -> None:
    _html, md_path = render.build(run_dir, use_model=False)
    md = md_path.read_text(encoding="utf-8")
    plain = md.replace("\\", "")
    for expected in (
        "Forensic analysis report: case T-R",
        "Triage report: drive read directly",
        "| Case ID | T-R |",
        "| Exhibit ID | EX-7 |",
        "| Examiner | Examiner One |",
        "| Authority reference | Warrant 2026/0042 |",
        "5" * 64,  # evidence SHA-256 before and after
        "6" * 32,  # MD5
        "| Hardware write blocker used | yes |",
        "| Blocker make and model | ExampleMake EB-1 |",
        "| Observed write requests to the target | 0 |",
        "It is not a write blocker.",
        "| fls | 4.12.1 |",
        "Validation reference",
        "## Appendix A. Run summary",
        "## Appendix B. Hash verification",
        "## Appendix C. Parser disagreements",
        "## Appendix F. Glossary",
        "matches run.json",
    ):
        assert expected in plain, expected
    # The software layer is never called a write blocker.
    assert "software write blocker" not in plain.lower()
    # Failures and skipped modules come first (4C.20).
    order = [
        m for m in ("| malware | failed", "| carve | skipped", "| inventory | ok") if m in plain
    ]
    assert order == ["| malware | failed", "| carve | skipped", "| inventory | ok"]
    idx = [plain.index(m) for m in order]
    assert idx == sorted(idx)


def test_nist_limitations_verbatim_and_direct_statement(run_dir: Path) -> None:
    html_path, md_path = render.build(run_dir, use_model=False)
    for path in (html_path, md_path):
        text = path.read_text(encoding="utf-8").replace("\\", "")
        for lead in (
            "Not all evidence may be found.",
            "Recovered deleted files may include extraneous material.",
            "Artifact meaning changes between OS versions.",
        ):
            assert lead in text
        assert "docs/known-limitations.md" in text
        assert render.DIRECT_MODE_STATEMENT in html_unescape(text)


def test_image_mode_has_no_direct_statement(tmp_path: Path, airlock_env: Path) -> None:
    del airlock_env
    run = make_run(tmp_path, mode="image")
    _h, md_path = render.build(run, use_model=False)
    text = md_path.read_text(encoding="utf-8")
    assert render.DIRECT_MODE_STATEMENT not in text
    assert "Examination report: analysis of a verified copy" in text


def html_unescape(text: str) -> str:
    import html as _html  # noqa: PLC0415

    return _html.unescape(text)


class _Collector(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend(attrs)


def test_html_is_self_contained_and_escaped(run_dir: Path) -> None:
    html_path, _md = render.build(run_dir, use_model=False)
    text = html_path.read_text(encoding="utf-8")
    p = _Collector()
    p.feed(text)
    assert not {"script", "img", "iframe", "object", "embed", "link", "video", "audio", "a"} & set(
        p.tags
    )
    assert not [a for a in p.attrs if a[0] in {"src", "href"}]
    assert "Content-Security-Policy" in text and "default-src 'none'" in text
    assert not re.search(r"https?://", text)
    # Evidence text with a planted delimiter is escaped in the disagreement-free tables; the
    # hostile document name holds a bidi override, shown as an escape, never raw.
    assert "\u202e" not in text and "\u0007" not in text


def test_media_counts_only(run_dir: Path) -> None:
    html_path, md_path = render.build(run_dir, use_model=False)
    for path in (html_path, md_path):
        text = path.read_text(encoding="utf-8")
        assert "/Pictures/" not in text  # media paths never appear (4B.17, 4E.8)
        assert "describe this image" not in text
    md = md_path.read_text(encoding="utf-8")
    assert "| images | violence | 1 | 1 | 0.81 |" in md


def test_disagreement_table(run_dir: Path) -> None:
    _h, md_path = render.build(run_dir, use_model=False)
    md = md_path.read_text(encoding="utf-8")
    section = md.split("## Appendix C")[1].split("## Appendix D")[0]
    assert "F-000015" in section and "xval\\_entry" in section


def test_provenance_and_logs(run_dir: Path) -> None:
    render.build(run_dir, use_model=False)
    prov = json.loads((run_dir / "logs" / "report-provenance.json").read_text(encoding="utf-8"))
    assert prov["model"] is None
    assert set(prov["prompts"]) == {
        "results_map.txt",
        "results_reduce.txt",
        "interpretation.txt",
        "conclusions.txt",
    }
    assert all(len(v) == 64 for v in prov["prompts"].values())
    assert set(prov["outputs"]) == {"report.html", "report.md"}
    events = [json.loads(line)["event"] for line in (run_dir / "logs" / "report.jsonl").open()]
    assert events[0] == "report_start" and events[-1] == "report_written"


def test_markdown_escapes_markup(tmp_path: Path, airlock_env: Path) -> None:
    del airlock_env
    run = make_run(tmp_path)
    doc = json.loads((run / "run.json").read_text(encoding="utf-8"))
    doc["case"]["notes"] = "<script>alert(1)</script> | *bold* [x](y)"
    (run / "run.json").write_text(json.dumps(doc), encoding="utf-8")
    html_path, md_path = render.build(run, use_model=False)
    assert "<script>" not in html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html_path.read_text(encoding="utf-8")
    md = md_path.read_text(encoding="utf-8")
    assert "\\<script\\>" in md and "\\| \\*bold\\* \\[x\\]" in md


def test_missing_run_json(tmp_path: Path) -> None:
    with pytest.raises(render.ReportError, match=r"no run\.json"):
        render.build(tmp_path, use_model=False)


def test_cli_errors_one_line(
    tmp_path: Path, airlock_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del airlock_env
    assert cli.main([str(tmp_path / "nope")]) == 2
    (tmp_path / "empty").mkdir()
    assert cli.main([str(tmp_path / "empty"), "--no-model"]) == 1
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 2 and all(line.startswith("evidence-report:") for line in err)


def test_cli_resigns_finished_run(tmp_path: Path, airlock_env: Path) -> None:
    del airlock_env
    pytest.importorskip("forensic_analyze.signing")
    import shutil  # noqa: PLC0415

    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    from forensic_analyze import signing  # noqa: PLC0415

    run = make_run(tmp_path)
    out_root = run.parents[2]
    signing.hash_and_sign(run, out_root)
    assert cli.main([str(run), "--no-model"]) == 0
    assert "report.html" in (run / "outputs.sha256").read_text(encoding="utf-8")
    assert signing.verify(run) == []


def test_report_records_image_age(tmp_path: Path, airlock_env: Path) -> None:
    """Task 4F.6, report half: the report records the image build date and age."""
    etc = airlock_env / "etc"
    (etc / "build-info.json").write_text(
        json.dumps(
            {"build_date": "2026-01-01T00:00:00Z", "version": "0.2.0", "git_commit": "abc1234"}
        ),
        encoding="utf-8",
    )
    run = make_run(tmp_path)
    _h, md_path = render.build(run, use_model=False)
    md = md_path.read_text(encoding="utf-8")
    line = next(x for x in md.splitlines() if x.startswith("| AIRLOCK image |"))
    assert "version 0.2.0, commit abc1234; built 2026-01-01T00:00:00Z" in line
    assert "days old" in line and "older than the limit" in line
