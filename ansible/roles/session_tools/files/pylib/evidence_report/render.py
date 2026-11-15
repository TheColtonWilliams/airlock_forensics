"""Render ``report.html`` and ``report.md`` for a run folder (4E.1, 4E.2, 4E.8, 4E.9, 4E.11).

``build(run_dir, *, use_model)`` is the contract entry point (docs/dev/contract.md 8a).

Code fills every factual section from ``run.json`` and ``case.sqlite``: title and report type,
case and exhibit IDs, examiner, request and authority, items received with identifiers and
hashes, methodology (hashes, hardware write blocker record, the software read-only policy,
observed write requests, mode with its limits, tools and versions, validation reference),
module counts with failures and skipped modules first, media screening counts (scores and
counts only), the three NIST IR 8354 limitations (fixed text), and the appendices.

The model drafts three kinds of section, through ``mapreduce.Drafter``: results by category,
interpretation, and conclusions. Every drafted paragraph is labelled "AI-generated draft",
carries the model and prompt SHA-256, and has a "Reviewed by" line. Without a model those
sections say "No AI draft: local model not available".

Both files are self-contained: no scripts, no images, no external resources (a
Content-Security-Policy forbids loading any), and every value is escaped. The runner calls
``evidence-report`` before it writes ``outputs.sha256`` and its signature, so the report is
hashed and signed with the rest of the run. Re-rendering a finished run re-hashes and re-signs
it (``cli.main``).
"""

from __future__ import annotations

import contextlib
import html
import os
import re
import shlex
import string
import tempfile
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing, jsonio, paths, sessionlog, timeutil
from evidence_report import TOOL_NAME, __version__, inputs, llm, mapreduce, verify

TEMPLATE_DIR = Path(__file__).with_name("templates")
HTML_NAME = "report.html"
MD_NAME = "report.md"
LOG_NAME = "logs/report.jsonl"
PROVENANCE_NAME = "logs/report-provenance.json"
KNOWN_LIMITATIONS_DOC = "docs/known-limitations.md"
MAX_TABLE_ROWS = 200

# Task 4E.2: the NIST IR 8354 limitations, inserted verbatim by code (research basis item 6).
NIST_LIMITATIONS: tuple[tuple[str, str], ...] = (
    (
        "Not all evidence may be found.",
        "Tools find only what their parsers understand and what the run was set to look for. "
        "Data that is encrypted, overwritten, in an unsupported format, or outside the "
        "modules chosen for this run is not reported.",
    ),
    (
        "Recovered deleted files may include extraneous material.",
        "Space freed by a deletion can be reused, so a recovered or carved file can hold data "
        "from other files. Its content is not proof of what the original file held.",
    ),
    (
        "Artifact meaning changes between OS versions.",
        "The same record can mean different things on different versions of an operating "
        "system or application. Each artifact must be read against the version that wrote it.",
    ),
)
NIST_SOURCE = (
    "NIST IR 8354, Digital Investigation Techniques: A NIST Scientific Foundation Review (2022)."
)

DIRECT_MODE_STATEMENT = (
    "This run read the drive directly and kept no forensic copy. It is documented triage "
    "(SWGDE 17-F-002-2.1), not an examination of a verified copy (SWGDE 18-F-001-2.0). The "
    "results cannot be re-examined from a copy, and a second tool cannot be run later on the "
    "same data. The before and after hashes show whether the drive changed during the run."
)
SOFTWARE_POLICY_NOTE = (
    "The software read-only policy is a policy and a second line of defence. It is not a "
    "write blocker."
)
NOT_FINAL_AI = (
    "NOT FINAL. This report contains AI-generated draft paragraphs. It is not final until every "
    "'Reviewed by' line is filled in and the examiner signs the declaration in section 8. "
    "AI-generated text is triage to help the examiner write the report; it is never evidence."
)
NOT_FINAL_PLAIN = (
    "NOT FINAL. This report is not final until the examiner signs the declaration in section 8."
)
REVIEW_LINE = "Reviewed by: ______________________________   Date: ________________"
NO_DRAFT = mapreduce.NO_MODEL_TEXT


class ReportError(RuntimeError):
    """The report could not be written. The message says what failed and what to do next."""


# --------------------------------------------------------------------------------------------
# Text safety
# --------------------------------------------------------------------------------------------

_ESCAPE_CATS = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp", "Co", "Cn"})
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|&~#])")


def safe(value: Any) -> str:
    """Display text: control, bidi, invisible, and unassigned characters shown as escapes."""
    text = fmt(value)
    if not any(unicodedata.category(c) in _ESCAPE_CATS for c in text):
        return text
    out = []
    for ch in text:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif unicodedata.category(ch) in _ESCAPE_CATS:
            cp = ord(ch)
            out.append(f"\\U{cp:08x}" if cp > 0xFFFF else f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def h(value: Any) -> str:
    return html.escape(safe(value), quote=True)


def md(value: Any) -> str:
    return _MD_SPECIAL.sub(r"\\\1", safe(value))


def fmt(value: Any) -> str:
    if value is None or value == "":
        return "not recorded"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return ", ".join(fmt(v) for v in value) if value else "none"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {fmt(v)}" for k, v in sorted(value.items())) or "none"
    return str(value)


# --------------------------------------------------------------------------------------------
# Document model: one structure, two renderers
# --------------------------------------------------------------------------------------------


@dataclass
class Para:
    text: str
    css: str = ""

    def html(self) -> str:
        cls = f' class="{self.css}"' if self.css else ""
        return f"<p{cls}>{h(self.text)}</p>"

    def md(self) -> str:
        return md(self.text)


@dataclass
class Heading:
    text: str
    level: int = 3

    def html(self) -> str:
        return f"<h{self.level}>{h(self.text)}</h{self.level}>"

    def md(self) -> str:
        return f"{'#' * self.level} {md(self.text)}"


@dataclass
class Notice:
    text: str

    def html(self) -> str:
        return f'<div class="notice"><p>{h(self.text)}</p></div>'

    def md(self) -> str:
        return f"> **{md(self.text)}**"


@dataclass
class Bullets:
    items: list[str]
    ordered: bool = False
    css: str = ""

    def html(self) -> str:
        tag = "ol" if self.ordered else "ul"
        cls = f' class="{self.css}"' if self.css else ""
        body = "".join(f"<li>{h(i)}</li>" for i in self.items)
        return f"<{tag}{cls}>{body}</{tag}>"

    def md(self) -> str:
        if not self.items:
            return ""
        return "\n".join(
            f"{n + 1}. {md(i)}" if self.ordered else f"* {md(i)}" for n, i in enumerate(self.items)
        )


@dataclass
class Table:
    headers: list[str]
    rows: list[list[Any]]
    note: str = ""

    def html(self) -> str:
        head = "".join(f"<th>{h(x)}</th>" for x in self.headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{h(c)}</td>" for c in row) + "</tr>" for row in self.rows
        )
        out = f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        if self.note:
            out += f'<p class="muted">{h(self.note)}</p>'
        return out

    def md(self) -> str:
        def cell(v: Any) -> str:
            return md(v).replace("\n", " ")

        lines = [
            "| " + " | ".join(cell(x) for x in self.headers) + " |",
            "|" + "|".join("---" for _ in self.headers) + "|",
        ]
        lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in self.rows]
        if self.note:
            lines += ["", md(self.note)]
        return "\n".join(lines)


@dataclass
class KeyValue:
    rows: list[tuple[str, Any]]

    def html(self) -> str:
        body = "".join(f"<tr><th>{h(k)}</th><td>{h(v)}</td></tr>" for k, v in self.rows)
        return f"<table><tbody>{body}</tbody></table>"

    def md(self) -> str:
        return Table(["Item", "Value"], [[k, v] for k, v in self.rows]).md()


@dataclass
class AiBlock:
    """One drafted paragraph with its label, provenance, and review line (task 4E.9)."""

    draft: mapreduce.Draft
    provenance: str
    removed_count: int = 0

    @property
    def has_text(self) -> bool:
        return bool(self.draft.sentences)

    def _empty_text(self) -> str:
        d = self.draft
        if d.status == "no_model":
            return f"{NO_DRAFT}."
        if d.status == "no_rows":
            return f"No AI draft: {d.note or 'no rows to draft from.'}"
        return (
            "No AI draft: none of the model's sentences for this section passed the code "
            f"verifier ({self.removed_count} removed; see Appendix E)."
        )

    def html(self) -> str:
        if not self.has_text:
            return f'<p class="muted">{h(self._empty_text())}</p>'
        text = " ".join(s.text for s in self.draft.sentences)
        return (
            '<div class="ai">'
            '<p class="label">AI-generated draft. Not evidence. Check every sentence against '
            "the cited findings.</p>"
            f"<p>{h(text)}</p>"
            f'<p class="prov">{h(self.provenance)}</p>'
            f'<p class="review">{h(REVIEW_LINE)}</p>'
            "</div>"
        )

    def md(self) -> str:
        if not self.has_text:
            return f"*{md(self._empty_text())}*"
        text = " ".join(s.text for s in self.draft.sentences)
        return "\n".join(
            [
                "> **AI-generated draft. Not evidence. Check every sentence against the cited "
                "findings.**",
                ">",
                f"> {md(text)}",
                ">",
                f"> {md(self.provenance)}",
                ">",
                f"> **{md(REVIEW_LINE)}**",
            ]
        )


Block = Para | Heading | Notice | Bullets | Table | KeyValue | AiBlock


@dataclass
class Section:
    title: str
    anchor: str
    blocks: list[Block] = field(default_factory=list)
    level: int = 2

    def html(self) -> str:
        head = f'<h{self.level} id="{h(self.anchor)}">{h(self.title)}</h{self.level}>'
        return "\n".join([head, *(b.html() for b in self.blocks)])

    def md(self) -> str:
        head = f"{'#' * self.level} {md(self.title)}"
        parts = [head, *(b.md() for b in self.blocks)]
        return "\n\n".join(p for p in parts if p)


# --------------------------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------------------------


@dataclass
class ModelOutcome:
    drafts: dict[str, Any]
    record: llm.ModelRecord | None
    reason: str
    calls: int
    errors: list[str]


def build(
    run_dir: str | os.PathLike[str],
    *,
    use_model: bool,
    model_url: str | None = None,
    start_server: bool = True,
    seed: int = llm.DEFAULT_SEED,
    settings: mapreduce.Settings | None = None,
) -> tuple[Path, Path]:
    """Write ``report.html`` and ``report.md`` into ``run_dir``; return their paths."""
    run = Path(run_dir)
    doc = _load_run(run)
    db_path, db_origin = inputs.ensure_database(run)
    log_path = run / LOG_NAME
    generated = timeutil.iso(micro=False)

    def log(rec: dict[str, Any]) -> None:
        with contextlib.suppress(OSError):
            jsonio.append_line(log_path, {"ts": timeutil.iso(), "run_id": doc.get("run_id"), **rec})

    log({"event": "report_start", "use_model": use_model, "version": __version__})
    prompts = mapreduce.load_prompts()
    with inputs.CaseDB(db_path) as db:
        outcome = _draft(
            db,
            prompts,
            use_model=use_model,
            model_url=model_url,
            start_server=start_server,
            seed=seed,
            settings=settings,
            log=log,
        )
        sections, ai_blocks, removed = _document(
            run,
            doc,
            db,
            db_origin=db_origin,
            outcome=outcome,
            prompts=prompts,
            generated=generated,
        )
    title = f"Forensic analysis report: case {doc.get('case', {}).get('case_id') or 'unknown'}"
    html_text = _render_html(title, sections)
    md_text = _render_md(title, sections)
    html_path = _write(run / HTML_NAME, html_text)
    md_path = _write(run / MD_NAME, md_text)
    prov = _provenance(
        doc,
        outcome,
        prompts=prompts,
        ai_blocks=ai_blocks,
        removed=removed,
        db_path=db_path,
        db_origin=db_origin,
        generated=generated,
    )
    prov["outputs"] = {
        HTML_NAME: hashing.sha256_file(html_path),
        MD_NAME: hashing.sha256_file(md_path),
    }
    jsonio.dump_json(run / PROVENANCE_NAME, prov)
    log({"event": "report_written", **prov["outputs"], "ai_paragraphs": prov["ai_paragraphs"]})
    with contextlib.suppress(OSError):
        sessionlog.log_event(
            TOOL_NAME,
            "report_written",
            run_id=doc.get("run_id"),
            run_dir=str(run),
            model_used=outcome.record is not None,
            model_sha256=outcome.record.model_sha256 if outcome.record else "",
            sentences_removed=len(removed),
            **prov["outputs"],
        )
    return html_path, md_path


def _load_run(run: Path) -> dict[str, Any]:
    path = run / "run.json"
    if not path.is_file():
        raise ReportError(
            f"{run} has no run.json. Point evidence-report at a forensic-analyze run folder."
        )
    try:
        doc = jsonio.load_json(path)
    except (OSError, ValueError) as exc:
        raise ReportError(
            f"run.json in {run} cannot be read ({exc}). Check the output drive."
        ) from exc
    if not isinstance(doc, dict):
        raise ReportError(f"run.json in {run} is not a JSON object. Check the output drive.")
    return doc


def _settings_for(
    record: llm.ModelRecord | None, given: mapreduce.Settings | None
) -> mapreduce.Settings:
    if given is not None:
        return given
    out = mapreduce.Settings()
    if record is not None and record.n_ctx:
        # About three characters per token; leave room for the prompt and the reply.
        budget = (record.n_ctx - llm.DEFAULT_MAX_TOKENS - 900) * 3
        out.data_chars = max(1500, min(24000, budget))
    return out


def _draft(
    db: inputs.CaseDB,
    prompts: dict[str, mapreduce.Prompt],
    *,
    use_model: bool,
    model_url: str | None,
    start_server: bool,
    seed: int,
    settings: mapreduce.Settings | None,
    log: Any,
) -> ModelOutcome:
    reason = "model use was turned off for this report (--no-model)"
    if use_model:
        try:
            model = llm.LocalModel(model_url, seed=seed)
            with llm.server(model, start=start_server):
                record = model.probe()
                log({"event": "model_probe", **record.to_dict()})
                drafter = mapreduce.Drafter(
                    db, model.complete, prompts, settings=_settings_for(record, settings), log=log
                )
                drafts = drafter.run()
                return ModelOutcome(drafts, record, "", drafter.calls, drafter.errors)
        except llm.LlmError as exc:
            reason = f"no local model server could be used ({exc})"
            log({"event": "model_unavailable", "reason": reason})
    drafter = mapreduce.Drafter(
        db,
        None,
        prompts,
        settings=_settings_for(None, settings),
        log=log,
        unavailable_reason=reason,
    )
    return ModelOutcome(drafter.run(), None, reason, 0, [])


# --------------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------------


def _document(
    run: Path,
    doc: dict[str, Any],
    db: inputs.CaseDB,
    *,
    db_origin: str,
    outcome: ModelOutcome,
    prompts: dict[str, mapreduce.Prompt],
    generated: str,
) -> tuple[list[Section], list[AiBlock], list[tuple[str, verify.Rejected]]]:
    prov_line = _prov_line(outcome, prompts)
    ai_blocks: list[AiBlock] = []
    removed: list[tuple[str, verify.Rejected]] = []

    def ai(draft: mapreduce.Draft) -> AiBlock:
        names = draft.prompts or ["results_map"]
        line = prov_line(names)
        if draft.removed:
            line += (
                f" {len(draft.removed)} sentence(s) failed the check and were removed (Appendix E)."
            )
        block = AiBlock(draft, line, len(draft.removed))
        ai_blocks.append(block)
        removed.extend((draft.title, r) for r in draft.removed)
        return block

    results: list[mapreduce.Draft] = outcome.drafts["results"]
    result_blocks = [(d, ai(d)) for d in results]
    interp_block = ai(outcome.drafts["interpretation"])
    concl_block = ai(outcome.drafts["conclusions"])
    has_ai = any(b.has_text for b in ai_blocks)

    sections = [
        _header(doc, generated, has_ai),
        _authority(doc),
        _items(doc),
        _methodology(doc),
        _summary(doc, db),
        _results(db, result_blocks, outcome.reason if outcome.record is None else ""),
        _interpretation(doc, interp_block),
        Section("7. Conclusions", "conclusions", [concl_block]),
        _declaration(has_ai),
        _appendix_run(run, doc, db, db_origin),
        _appendix_hashes(run, doc),
        _appendix_disagreements(db),
        _appendix_ai(outcome, prompts),
        _appendix_removed(removed),
        _appendix_glossary(),
    ]
    return sections, ai_blocks, removed


def _prov_line(outcome: ModelOutcome, prompts: dict[str, mapreduce.Prompt]) -> Any:
    rec = outcome.record

    def line(names: Iterable[str]) -> str:
        if rec is None:
            return ""
        used = "; ".join(
            f"{prompts[n].file} SHA-256 {prompts[n].sha256}" for n in dict.fromkeys(names)
        )
        quant = f", {rec.quantization}" if rec.quantization else ""
        return (
            f"Model: {rec.model_id}{quant}, SHA-256 {rec.model_sha256}. llama.cpp build "
            f"{rec.llama_build}, backend {rec.backend}, seed {rec.seed}, temperature 0. "
            f"Prompts: {used}. Every sentence was checked by code against the finding rows "
            "it cites."
        )

    return line


def _header(doc: dict[str, Any], generated: str, has_ai: bool) -> Section:
    case = doc.get("case", {})
    mode = doc.get("mode_record", {}).get("mode") or doc.get("config", {}).get("mode")
    if mode == "image":
        rtype = "Examination report: analysis of a verified copy (SWGDE 18-F-001-2.0)"
    else:
        rtype = "Triage report: drive read directly (SWGDE 17-F-002-2.1)"
    title = f"Forensic analysis report: case {case.get('case_id') or 'unknown'}"
    return Section(
        title,
        "top",
        [
            Para(f"Report type: {rtype}. Draft produced by AIRLOCK evidence-report {__version__}."),
            Notice(NOT_FINAL_AI if has_ai else NOT_FINAL_PLAIN),
            KeyValue(
                [
                    ("Case ID", case.get("case_id")),
                    ("Exhibit ID", case.get("exhibit_id")),
                    ("Evidence ID", doc.get("target", {}).get("evidence_id")),
                    ("Examiner", case.get("examiner")),
                    ("Agency", case.get("agency")),
                    ("Run ID", doc.get("run_id")),
                    ("Run status", doc.get("status")),
                    ("Report generated (UTC)", generated),
                ]
            ),
        ],
        level=1,
    )


def _authority(doc: dict[str, Any]) -> Section:
    case = doc.get("case", {})
    ack = doc.get("authority_ack", {})
    return Section(
        "1. Request and authority",
        "authority",
        [
            KeyValue(
                [
                    ("Authority reference", case.get("authority_ref")),
                    ("Authority acknowledged", ack.get("acknowledged")),
                    ("Acknowledged at (UTC)", ack.get("ts")),
                    (
                        "Acknowledged by",
                        "command-line flag" if ack.get("via") == "flag" else ack.get("via"),
                    ),
                    ("Text acknowledged", ack.get("text")),
                    ("Text SHA-256", ack.get("text_sha256")),
                    ("Case notes", case.get("notes")),
                ]
            )
        ],
    )


def _items(doc: dict[str, Any]) -> Section:
    tgt = doc.get("target", {})
    before = doc.get("hashes", {}).get("before", {})
    blocks: list[Block] = [
        KeyValue(
            [
                ("Exhibit ID", doc.get("case", {}).get("exhibit_id")),
                ("Evidence ID", tgt.get("evidence_id")),
                ("Kind", tgt.get("kind")),
                ("Path at time of run", tgt.get("path")),
                ("Model", tgt.get("model")),
                ("Serial number", tgt.get("serial")),
                ("Size (bytes)", tgt.get("size_bytes")),
                ("Transport", tgt.get("transport")),
                ("Removable", tgt.get("removable")),
                ("SHA-256 before the run", before.get("sha256")),
                ("MD5 before the run", before.get("md5")),
            ]
        )
    ]
    img = doc.get("image")
    if isinstance(img, dict) and img:
        blocks.append(Para("Forensic copy made for this run:"))
        blocks.append(
            KeyValue(
                [
                    ("Copy", img.get("image_path")),
                    ("Imager", img.get("imager")),
                    ("Verified against the drive hash", img.get("verified")),
                    ("Files", img.get("files")),
                ]
            )
        )
    vols = doc.get("volumes") or []
    if vols:
        blocks.append(Para("Volumes found:"))
        blocks.append(
            Table(
                ["Index", "File system", "Label", "Offset (bytes)", "Size (bytes)", "BitLocker"],
                [
                    [
                        v.get("index"),
                        v.get("fs_type"),
                        v.get("label"),
                        v.get("offset_bytes"),
                        v.get("size_bytes"),
                        v.get("bitlocker"),
                    ]
                    for v in vols
                ],
            )
        )
    return Section("2. Items received", "items", blocks)


def _image_age() -> dict[str, Any]:
    try:
        from airlock_session import system  # noqa: PLC0415 - optional package
    except Exception:
        return {"status": "unknown"}
    try:
        return system.image_age()
    except Exception as exc:
        return {"status": "unreadable", "error": str(exc)}


def _build_info() -> dict[str, Any]:
    try:
        info = jsonio.load_json(paths.build_info())
    except (OSError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}


def _methodology(doc: dict[str, Any]) -> Section:
    cfg = doc.get("config", {})
    mrec = doc.get("mode_record", {})
    mode = mrec.get("mode") or cfg.get("mode")
    hashes = doc.get("hashes", {})
    before, after = hashes.get("before", {}), hashes.get("after", {})
    wb = doc.get("write_blocker", {})
    handle = doc.get("handle", {})
    wr = doc.get("write_requests", {})
    tracer = "; ".join(
        f"{k}: {v.get('write_requests')} write requests ({v.get('method') or 'unknown method'})"
        for k, v in sorted(wr.items())
        if isinstance(v, dict)
    )
    clock = doc.get("clock", {})
    age = _image_age()
    info = _build_info()
    age_text = (
        f"built {age.get('build_date') or 'unknown'}, {age.get('age_days')} days old"
        f"{' (older than the limit; tools may be out of date)' if age.get('too_old') else ''}"
        if age.get("age_days") is not None
        else f"unknown ({age.get('status', 'unknown')})"
    )
    sandbox = doc.get("sandbox", {})
    plan = doc.get("plan", {})
    method = handle.get("method")
    handle_text = "read-only loop device" if method == "ro_loop" else method or "read-only handle"
    rows: list[tuple[str, Any]] = [
        (
            "Analysis mode",
            "Read directly (documented triage, SWGDE 17-F-002-2.1)"
            if mode == "direct"
            else f"Copy first with {mrec.get('imager') or cfg.get('imager')} (SWGDE 18-F-001-2.0)",
        ),
        ("Preset", cfg.get("preset")),
        ("Modules planned", plan.get("planned")),
        ("Modules not installed", plan.get("not_available")),
        ("Evidence (image) hash before, SHA-256", before.get("sha256")),
        ("Evidence (image) hash after, SHA-256", after.get("sha256")),
        ("Hashes match", hashes.get("match")),
        ("Hardware write blocker used", wb.get("in_use")),
        ("Blocker make and model", " ".join(x for x in (wb.get("make"), wb.get("model")) if x)),
        ("Blocker firmware", wb.get("firmware")),
        ("Blocker test report (NIST CFTT)", wb.get("report_url")),
        (
            "Software read-only policy",
            f"target opened through a {handle_text}; "
            f"read-only flag on the target: {fmt(doc.get('target', {}).get('readonly_flag'))}. "
            + SOFTWARE_POLICY_NOTE,
        ),
        ("Observed write requests to the target", doc.get("write_requests_total")),
        ("Write tracer detail", tracer),
        (
            "Integrity check",
            "passed"
            if doc.get("integrity", {}).get("ok")
            else doc.get("integrity", {}).get("problems"),
        ),
        (
            "Parser sandbox",
            f"{sandbox.get('method')}, network {sandbox.get('network')}, "
            f"user {sandbox.get('user')}",
        ),
        ("System clock at start (UTC)", clock.get("system_utc_at_entry")),
        (
            "Reference time and source",
            f"{fmt(clock.get('reference_time'))} ({fmt(clock.get('reference_source'))})",
        ),
        ("Clock offset (seconds; the clock is never changed)", clock.get("clock_offset_seconds")),
        (
            "AIRLOCK image",
            f"version {fmt(info.get('version'))}, commit {fmt(info.get('git_commit'))}; {age_text}",
        ),
        (
            "Validation reference",
            "docs/validation-guide.md and the validation report published with this AIRLOCK "
            f"release (version {fmt(info.get('version'))})",
        ),
    ]
    blocks: list[Block] = [KeyValue(rows)]
    if mrec.get("limits"):
        blocks += [Para("Limits of this analysis mode:"), Bullets(list(mrec["limits"]))]
    if mode == "direct":
        blocks.insert(0, Notice(DIRECT_MODE_STATEMENT))
    tv = doc.get("tool_versions") or {}
    if tv:
        blocks.append(Para("Tools and versions used in this run:"))
        blocks.append(
            Table(
                ["Tool", "Version", "Binary SHA-256"],
                [[name, v.get("version"), v.get("sha256")] for name, v in sorted(tv.items())],
            )
        )
    for key, title in (
        ("deviations", "Deviations"),
        ("warnings", "Warnings"),
        ("errors", "Errors"),
    ):
        items = doc.get(key) or []
        if items:
            blocks.append(Para(f"{title} recorded during the run:"))
            blocks.append(
                Bullets(
                    [
                        f"{e.get('where')}: {e.get('error')}" if isinstance(e, dict) else str(e)
                        for e in items
                    ]
                )
            )
    return Section("3. Methodology", "methodology", blocks)


def _module_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    mods = doc.get("summary", {}).get("modules")
    if isinstance(mods, list) and mods:
        return mods
    raw = doc.get("modules") or []
    rank = {"failed": 0, "skipped": 1, "not_available": 1}
    return sorted(raw, key=lambda m: rank.get(m.get("status"), 2))


def _summary(doc: dict[str, Any], db: inputs.CaseDB) -> Section:
    mods = _module_rows(doc)
    blocks: list[Block] = [
        Para("Modules that failed or were skipped are listed first."),
        Table(
            ["Module", "Status", "Reason", "Findings", "Counts"],
            [
                [
                    m.get("name"),
                    m.get("status"),
                    m.get("reason") or "-",
                    m.get("findings", 0),
                    fmt(m.get("counts") or {}),
                ]
                for m in mods
            ],
        ),
    ]
    counts = db.category_counts()
    blocks.append(Para(f"Findings in this run: {db.total()}, by category and derivation:"))
    blocks.append(
        Table(
            ["Category", "Derivation", "Findings"],
            [[c["category"], c["derivation"], c["count"]] for c in counts],
        )
    )
    blocks.append(
        Table(
            ["View in case.sqlite", "Rows"],
            [[v, db.view_count(v)] for v in inputs.VIEWS],
        )
    )
    return Section("4. Summary of the run", "summary", blocks)


def _results(
    db: inputs.CaseDB, result_blocks: list[tuple[mapreduce.Draft, AiBlock]], reason: str
) -> Section:
    blocks: list[Block] = [
        Para(
            "Each part below starts with counts made by code. The paragraph that follows is an "
            "AI-generated draft from the rows of the named view; every sentence cites the "
            "findings it relies on and was checked by code against them."
        )
    ]
    if reason:
        blocks.append(Para(f"{NO_DRAFT}: {reason}. Appendix D has the details.", css="muted"))
    if not result_blocks:
        blocks.append(Para("This run produced no findings to report by category."))
    for draft, block in result_blocks:
        view = mapreduce.CATEGORY_PLAN[draft.key][0]
        blocks.append(
            Heading(f"5.{len([b for b in blocks if isinstance(b, Heading)]) + 1} {draft.title}")
        )
        count = (
            f"Category '{draft.key}': {draft.rows_total} row(s) in {view}; "
            f"{draft.rows_given} read for the model."
        )
        if draft.sensitive:
            count += (
                " Media screening rows are given to the model as IDs, labels, scores, and "
                "flags only."
            )
        blocks.append(Para(count, css="muted"))
        if draft.note and draft.status != "no_model":
            blocks.append(Para(draft.note, css="muted"))
        blocks.append(block)
    flags = db.flag_summary()
    blocks.append(Heading("Media screening: counts and scores only"))
    blocks.append(
        Para("No media is shown in this report, and no description of media content.", css="muted")
    )
    if flags:
        blocks.append(
            Table(
                ["Category", "Label", "Rows", "Flagged", "Highest score"],
                [
                    [f["category"], f["label"] or "(none)", f["rows"], f["flagged"], f["max_score"]]
                    for f in flags
                ],
                note="Scores are triage. A flag means a classifier score passed the examiner's "
                "threshold; it does not prove what a file shows.",
            )
        )
    else:
        blocks.append(Para("No classifier results in this run.", css="muted"))
    return Section("5. Results by category", "results", blocks)


def _known_limitations() -> str:
    path = paths.repo_dir() / KNOWN_LIMITATIONS_DOC
    base = (
        f"Known limitations of this AIRLOCK build: see {KNOWN_LIMITATIONS_DOC} in the AIRLOCK "
        f"release (on the drive: {path})."
    )
    if path.is_file():
        try:
            return base + f" SHA-256 of that file at report time: {hashing.sha256_file(path)}."
        except OSError:
            return base
    return base


def _interpretation(doc: dict[str, Any], block: AiBlock) -> Section:
    mode = doc.get("mode_record", {}).get("mode") or doc.get("config", {}).get("mode")
    blocks: list[Block] = [
        Heading("Standard limitations (NIST IR 8354)"),
        Para("Stated in every AIRLOCK report:"),
        Bullets(
            [f"{lead} {detail}" for lead, detail in NIST_LIMITATIONS], ordered=True, css="limits"
        ),
        Para(NIST_SOURCE, css="muted"),
    ]
    if mode == "direct":
        blocks.append(Para(DIRECT_MODE_STATEMENT))
    blocks.append(
        Para(
            "Findings say what records show about an account SID, never about a person. File "
            "ownership and timestamps show which account a file belongs to, not who used it."
        )
    )
    blocks.append(Para(_known_limitations()))
    blocks.append(Heading("Interpretation"))
    blocks.append(block)
    return Section("6. Interpretation and limitations", "interpretation", blocks)


def _declaration(has_ai: bool) -> Section:
    text = (
        "I have checked every AI-generated draft paragraph in this report against the cited "
        "findings, filled in each 'Reviewed by' line, and I take responsibility for the content."
        if has_ai
        else "I have checked this report against the findings and take responsibility for it."
    )
    return Section(
        "8. Examiner declaration",
        "declaration",
        [
            Para(text),
            Para("Examiner name: ______________________________"),
            Para("Signature: ______________________________   Date: ________________"),
        ],
    )


def _appendix_run(run: Path, doc: dict[str, Any], db: inputs.CaseDB, db_origin: str) -> Section:
    findings = doc.get("findings", {})
    clock = doc.get("clock", {})
    exports = doc.get("exports", {})
    info = db.export_info()
    return Section(
        "Appendix A. Run summary",
        "appendix-run",
        [
            KeyValue(
                [
                    ("Run folder", run.name),
                    ("Status", doc.get("status")),
                    ("Started (UTC)", clock.get("started_utc")),
                    ("Finished (UTC)", doc.get("finished_utc") or clock.get("finished_utc")),
                    ("Duration (seconds)", clock.get("duration_s")),
                    ("Command line", shlex.join(str(a) for a in doc.get("argv") or [])),
                    ("Resumed", len(doc.get("resumes") or [])),
                    ("findings.jsonl rows", findings.get("rows")),
                    ("findings.jsonl SHA-256 (run.json)", findings.get("sha256")),
                    ("case.sqlite", f"{db_origin}; rows {info.get('row_count', 'unknown')}"),
                    (
                        "Exports",
                        {k: v.get("status") for k, v in exports.items() if isinstance(v, dict)},
                    ),
                    ("Errors", len(doc.get("errors") or [])),
                ]
            )
        ],
    )


def _appendix_hashes(run: Path, doc: dict[str, Any]) -> Section:
    hashes = doc.get("hashes", {})
    rows = []
    for key in ("before", "after"):
        h_ = hashes.get(key, {})
        if h_:
            rows.append(
                [
                    f"Target, {key} the run",
                    h_.get("sha256"),
                    h_.get("md5"),
                    h_.get("error") or "complete",
                ]
            )
    img = doc.get("image") or {}
    for name, digest in sorted((img.get("files_sha256") or {}).items()):
        after = (img.get("files_sha256_after") or {}).get(name)
        rows.append(
            [
                f"Copy file {name}",
                digest,
                "",
                "unchanged" if after in (None, digest) else f"changed to {after}",
            ]
        )
    findings = doc.get("findings", {})
    fpath = run / inputs.FINDINGS_NAME
    now = hashing.sha256_file(fpath) if fpath.is_file() else ""
    if findings.get("sha256") or now:
        state = "matches run.json" if now == findings.get("sha256") else "DIFFERS from run.json"
        rows.append(["findings.jsonl", now or "missing", "", state])
    return Section(
        "Appendix B. Hash verification",
        "appendix-hashes",
        [
            Table(["Item", "SHA-256", "MD5", "State"], rows),
            Para(
                f"Before and after hashes match: {fmt(hashes.get('match'))}. This report is "
                "listed in outputs.sha256 and covered by outputs.sha256.sig, which are written "
                "after it; check them with sha256sum -c outputs.sha256."
            ),
        ],
    )


def _appendix_disagreements(db: inputs.CaseDB) -> Section:
    total = db.view_count("v_disagreements")
    rows = db.view("v_disagreements", limit=MAX_TABLE_ROWS)
    if not rows:
        return Section(
            "Appendix C. Parser disagreements",
            "appendix-disagreements",
            [Para("No cross-check disagreements were recorded (view v_disagreements is empty).")],
        )
    note = (
        f"Showing {len(rows)} of {total}; the rest are in case.sqlite." if total > len(rows) else ""
    )
    return Section(
        "Appendix C. Parser disagreements",
        "appendix-disagreements",
        [
            Para(
                "Rows of v_disagreements: two parsers reported different values for the "
                "same record."
            ),
            Table(
                ["Finding", "Artifact", "Parser", "Path", "Message"],
                [
                    [
                        r.get("finding_id"),
                        r.get("artifact_type"),
                        r.get("parser"),
                        inputs.truncate(safe(r.get("path") or ""), 200),
                        inputs.truncate(safe(r.get("message") or ""), 300),
                    ]
                    for r in rows
                ],
                note=note,
            ),
        ],
    )


def _appendix_ai(outcome: ModelOutcome, prompts: dict[str, mapreduce.Prompt]) -> Section:
    blocks: list[Block] = []
    rec = outcome.record
    if rec is None:
        blocks.append(Para(f"{NO_DRAFT}: {outcome.reason}."))
    else:
        blocks.append(
            KeyValue(
                [
                    ("Model", rec.model_id),
                    ("Model file SHA-256", rec.model_sha256),
                    ("Quantization", rec.quantization),
                    ("llama.cpp build", rec.llama_build),
                    ("Backend", rec.backend),
                    ("Context size (tokens)", rec.n_ctx),
                    (
                        "Decoding",
                        f"temperature {rec.temperature}, top-k {rec.top_k}, seed {rec.seed}",
                    ),
                    ("Endpoint", f"{rec.base_url}{rec.endpoint} (loopback only)"),
                    ("Model calls", outcome.calls),
                    ("Call errors", outcome.errors),
                    ("Other", rec.extra),
                ]
            )
        )
    blocks.append(Para("Fixed prompt files (recorded for every run):"))
    blocks.append(Table(["Prompt file", "SHA-256"], [[p.file, p.sha256] for p in prompts.values()]))
    blocks.append(
        Para(
            "Model input came only from rows of the case.sqlite views, with evidence text inside "
            "delimited data blocks; every model call and reply is in logs/report.jsonl."
        )
    )
    return Section("Appendix D. AI provenance", "appendix-ai", blocks)


def _appendix_removed(removed: list[tuple[str, verify.Rejected]]) -> Section:
    if not removed:
        return Section(
            "Appendix E. Sentences removed by the verifier",
            "appendix-removed",
            [Para("No drafted sentence was removed.")],
        )
    return Section(
        "Appendix E. Sentences removed by the verifier",
        "appendix-removed",
        [
            Para(
                "These drafted sentences failed the code check and are not in the report. Their "
                "text is not repeated here; it is in logs/report.jsonl (event sentence_removed), "
                "found by its SHA-256."
            ),
            Table(
                ["Section", "Cited IDs", "Why it was removed", "Sentence SHA-256"],
                [
                    [
                        section,
                        ", ".join(r.ids) or "none",
                        "; ".join(r.reasons),
                        mapreduce.sentence_sha256(r.text),
                    ]
                    for section, r in removed
                ],
            ),
        ],
    )


def _appendix_glossary() -> Section:
    data = jsonio.load_json(TEMPLATE_DIR / "glossary.json")
    return Section(
        "Appendix F. Glossary",
        "appendix-glossary",
        [Table(["Term", "Meaning"], [[t, d] for t, d in data["entries"]])],
    )


# --------------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------------


def _render_html(title: str, sections: list[Section]) -> str:
    tmpl = string.Template((TEMPLATE_DIR / "report.html").read_text(encoding="utf-8"))
    body = "\n".join(s.html() for s in sections)
    return tmpl.substitute(title=h(title), body=body, version=h(__version__))


def _render_md(title: str, sections: list[Section]) -> str:
    tmpl = string.Template((TEMPLATE_DIR / "report.md").read_text(encoding="utf-8"))
    del title  # the first section carries the title
    body = "\n\n".join(s.md() for s in sections)
    return tmpl.substitute(body=body, version=__version__).rstrip("\n") + "\n"


def _write(target: Path, text: str) -> Path:
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def _provenance(
    doc: dict[str, Any],
    outcome: ModelOutcome,
    *,
    prompts: dict[str, mapreduce.Prompt],
    ai_blocks: list[AiBlock],
    removed: list[tuple[str, verify.Rejected]],
    db_path: Path,
    db_origin: str,
    generated: str,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_utc": generated,
        "run_id": doc.get("run_id"),
        "model": outcome.record.to_dict() if outcome.record else None,
        "model_unavailable_reason": outcome.reason,
        "model_calls": outcome.calls,
        "prompts": {p.file: p.sha256 for p in prompts.values()},
        "database": {"path": db_path.name, "origin": db_origin},
        "ai_paragraphs": sum(1 for b in ai_blocks if b.has_text),
        "sections": [
            {
                "key": b.draft.key,
                "status": b.draft.status,
                "method": b.draft.method,
                "rows_total": b.draft.rows_total,
                "rows_given": b.draft.rows_given,
                "sentences": [{"text": s.text, "ids": s.ids} for s in b.draft.sentences],
                "removed": len(b.draft.removed),
            }
            for b in ai_blocks
        ],
        "removed": [
            {
                "section": sec,
                "ids": r.ids,
                "reasons": r.reasons,
                "sha256": mapreduce.sentence_sha256(r.text),
            }
            for sec, r in removed
        ],
    }
