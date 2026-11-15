"""Model drafting by map and reduce, for small context windows (tasks 4E.2, 4E.3, 4E.5, 4E.8).

Map: for each category, the rows from its SQLite view are cut into time windows that fit the
model's context. Each window goes to the model with the fixed ``results_map`` prompt, the rows
in one data block, and values code computed from them (counts, first and last times, time
spans) in another. The reply is checked by ``verify.Verifier``; only sentences that cite rows
of that window and match them survive.

Reduce: the surviving sentences of a category are given back as numbered statements with the
fixed ``results_reduce`` prompt. The merged text may cite only IDs those statements cite, and it
is checked against the rows again. When the merge keeps nothing, the checked statements are
used as they are. Interpretation and conclusions are drafted the same way from the checked
results statements.

Sensitive categories (images, video, audio; classifier flags) go to the model as IDs, labels,
scores, thresholds, and flags only (``inputs.SENSITIVE_FIELDS``).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import jsonio
from evidence_report import inputs, verify

PROMPT_DIR = Path(__file__).with_name("prompts")
PROMPTS = ("results_map", "results_reduce", "interpretation", "conclusions")

# Category -> (view, title, sensitive). Rows come from these views only (task 4E.4).
CATEGORY_PLAN: dict[str, tuple[str, str, bool]] = {
    "deletion": ("v_deleted", "Deletion history", False),
    "recycle_bin": ("v_recycle_bin", "Recycle bin", False),
    "inventory": ("v_deleted", "Deleted entries in the file inventory", False),
    "carve": (inputs.REPORT_VIEW, "Carved files", False),
    "malware": ("v_hash_hits", "Malware signature matches", False),
    "hash": ("v_hash_hits", "Hash set matches", False),
    "users": (inputs.REPORT_VIEW, "Accounts", False),
    "documents": (inputs.REPORT_VIEW, "Documents", False),
    "timeline": ("v_timeline", "Timeline", False),
    "system": (inputs.REPORT_VIEW, "System records", False),
    "xval": (inputs.REPORT_VIEW, "Parser cross-checks", False),
    "images": ("v_media", "Images", True),
    "video": ("v_media", "Video", True),
    "audio": ("v_media", "Audio", True),
}
CATEGORY_ORDER = tuple(CATEGORY_PLAN)

NO_MODEL_TEXT = "No AI draft: local model not available"


@dataclass
class Settings:
    data_chars: int = 6000  # characters of row data per model call
    rows_per_window: int = 40
    rows_per_category: int = 400  # rows read from a view per category
    max_calls: int = 120
    max_statements: int = 60


@dataclass(frozen=True)
class Prompt:
    name: str
    text: str
    sha256: str
    file: str


def load_prompts(folder: Path = PROMPT_DIR) -> dict[str, Prompt]:
    """The fixed prompt files and their SHA-256 (task 4E.3)."""
    out: dict[str, Prompt] = {}
    for name in PROMPTS:
        path = folder / f"{name}.txt"
        raw = path.read_bytes()
        out[name] = Prompt(name, raw.decode("utf-8"), hashlib.sha256(raw).hexdigest(), path.name)
    return out


@dataclass
class Window:
    category: str
    label: str
    rows: list[dict[str, Any]]
    values: dict[str, Any]

    @property
    def ids(self) -> list[str]:
        return [str(r["finding_id"]) for r in self.rows]


@dataclass
class Draft:
    """One drafted section: kept sentences, removed sentences, and how it was made."""

    key: str
    title: str
    status: str  # drafted | no_model | no_rows | nothing_supported | error | skipped
    sentences: list[verify.Sentence] = field(default_factory=list)
    removed: list[verify.Rejected] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    note: str = ""
    rows_total: int = 0
    rows_given: int = 0
    sensitive: bool = False
    method: str = ""

    @property
    def ids(self) -> set[str]:
        return {i for s in self.sentences for i in s.ids}


# --------------------------------------------------------------------------------------------
# Values computed by code (date arithmetic is never left to the model)
# --------------------------------------------------------------------------------------------


def _parse(stamp: str) -> _dt.datetime | None:
    try:
        head, _, frac = stamp.rstrip("Z").partition(".")
        base = _dt.datetime.fromisoformat(head).replace(tzinfo=_dt.UTC)
    except ValueError:
        return None
    if frac:
        base += _dt.timedelta(microseconds=int(frac[:6].ljust(6, "0")))
    return base


def _sort_key(stamp: str) -> tuple[str, str]:
    head, _, frac = stamp.rstrip("Z").partition(".")
    return head, frac.rstrip("0")


def span_text(seconds: int) -> str:
    """``3 days 4 hours 5 minutes``-style text for a span in whole seconds."""
    days, rest = divmod(max(0, seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    parts = []
    for n, unit in ((days, "day"), (hours, "hour"), (minutes, "minute"), (secs, "second")):
        if n:
            parts.append(f"{n} {unit}{'' if n == 1 else 's'}")
    return " ".join(parts) or "0 seconds"


def compute_values(
    rows: list[Mapping[str, Any]], *, sensitive: bool, total: int, given: int
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "rows_in_this_part": len(rows),
        "rows_in_category": total,
        "rows_given_to_the_model_for_category": given,
        "rows_per_artifact_type": dict(
            sorted(Counter(str(r["artifact_type"]) for r in rows).items())
        ),
    }
    stamps = sorted((str(r["datetime"]) for r in rows if r.get("datetime")), key=_sort_key)
    if stamps:
        values["first_time"] = stamps[0]
        values["last_time"] = stamps[-1]
        a, b = _parse(stamps[0]), _parse(stamps[-1])
        if a is not None and b is not None:
            secs = int((b - a).total_seconds())
            values["time_span"] = span_text(secs)
            values["time_span_seconds"] = secs
            values["time_span_whole_days"] = secs // 86400
            values["time_span_whole_hours"] = secs // 3600
        values["rows_with_a_time"] = len(stamps)
    if sensitive:
        labels = Counter(str(r.get("label")) for r in rows if r.get("label"))
        values["rows_per_label"] = dict(sorted(labels.items()))
        values["flagged_rows"] = sum(1 for r in rows if r.get("sensitive_flag"))
        best: dict[str, float] = {}
        for r in rows:
            if r.get("label") and isinstance(r.get("score"), int | float):
                key = str(r["label"])
                best[key] = max(best.get(key, float("-inf")), float(r["score"]))
        values["highest_score_per_label"] = dict(sorted(best.items()))
    else:
        deleted = sum(1 for r in rows if r.get("allocated") is False)
        if deleted:
            values["rows_marked_unallocated"] = deleted
        sids = {r["owner_sid"] for r in rows if r.get("owner_sid")}
        if sids:
            values["distinct_account_sids"] = len(sids)
    return values


def flatten_values(values: Any) -> list[Any]:
    """Every scalar inside ``values`` (for the verifier's allowed values)."""
    if isinstance(values, Mapping):
        out: list[Any] = []
        for v in values.values():
            out.extend(flatten_values(v))
        return out
    if isinstance(values, list | tuple):
        out = []
        for v in values:
            out.extend(flatten_values(v))
        return out
    return [values]


def make_windows(
    category: str,
    rows: list[dict[str, Any]],
    *,
    sensitive: bool,
    total: int,
    settings: Settings,
) -> list[Window]:
    """Cut rows into time windows that fit the data budget, timed rows first, in time order."""
    timed = sorted((r for r in rows if r.get("datetime")), key=lambda r: _sort_key(r["datetime"]))
    untimed = [r for r in rows if not r.get("datetime")]
    windows: list[Window] = []
    for group, timed_group in ((timed, True), (untimed, False)):
        chunk: list[dict[str, Any]] = []
        size = 0
        for row in group:
            line = len(jsonio.dumps_line(inputs.model_row(row, sensitive=sensitive)))
            if chunk and (
                size + line > settings.data_chars or len(chunk) >= settings.rows_per_window
            ):
                windows.append(
                    _window(
                        category,
                        chunk,
                        timed=timed_group,
                        sensitive=sensitive,
                        total=total,
                        given=len(rows),
                    )
                )
                chunk, size = [], 0
            chunk.append(row)
            size += line
        if chunk:
            windows.append(
                _window(
                    category,
                    chunk,
                    timed=timed_group,
                    sensitive=sensitive,
                    total=total,
                    given=len(rows),
                )
            )
    return windows


def _window(
    category: str,
    rows: list[dict[str, Any]],
    *,
    timed: bool,
    sensitive: bool,
    total: int,
    given: int,
) -> Window:
    values = compute_values(rows, sensitive=sensitive, total=total, given=given)
    if timed:
        label = f"{values.get('first_time')} to {values.get('last_time')}"
    else:
        label = "rows with no recorded time"
    return Window(category, label, rows, values)


# --------------------------------------------------------------------------------------------
# Drafting
# --------------------------------------------------------------------------------------------

Complete = Callable[[str, str], str]


class Drafter:
    """Runs the map and reduce steps for every section and keeps the call log."""

    def __init__(
        self,
        db: inputs.CaseDB,
        complete: Complete | None,
        prompts: Mapping[str, Prompt],
        *,
        settings: Settings | None = None,
        log: Callable[[dict[str, Any]], None] | None = None,
        unavailable_reason: str = "",
    ) -> None:
        self.db = db
        self.complete = complete
        self.prompts = prompts
        self.settings = settings or Settings()
        self.log = log or (lambda _rec: None)
        self.unavailable_reason = unavailable_reason
        self.calls = 0
        self.errors: list[str] = []

    # -- model calls ---------------------------------------------------------------------------

    def _ask(self, prompt: str, user: str, *, stage: str, section: str) -> str | None:
        if self.complete is None:
            return None
        if self.calls >= self.settings.max_calls:
            self.log({"event": "call_budget_reached", "stage": stage, "section": section})
            return None
        self.calls += 1
        p = self.prompts[prompt]
        t0 = time.monotonic()
        try:
            reply = self.complete(p.text, user)
        except Exception as exc:  # a failing server must not stop the report
            self.errors.append(f"{stage} {section}: {exc}")
            self.log(
                {"event": "model_error", "stage": stage, "section": section, "error": str(exc)}
            )
            return None
        self.log(
            {
                "event": "model_call",
                "stage": stage,
                "section": section,
                "prompt": p.file,
                "prompt_sha256": p.sha256,
                "request_sha256": hashlib.sha256(user.encode("utf-8")).hexdigest(),
                "reply": reply,
                "seconds": round(time.monotonic() - t0, 3),
            }
        )
        return reply

    def _verify(
        self,
        reply: str | None,
        *,
        allowed: Iterable[str],
        values: Iterable[Any],
        rows: Iterable[Mapping[str, Any]],
        stage: str,
        section: str,
    ) -> verify.VerifyResult:
        if reply is None or reply.strip().strip(".").upper() == "NONE":
            return verify.VerifyResult()
        checker = verify.Verifier(
            self.db.row, allowed_ids=allowed, values=values, evidence_rows=rows
        )
        res = checker.verify_text(reply)
        for rej in res.removed:
            self.log(
                {
                    "event": "sentence_removed",
                    "stage": stage,
                    "section": section,
                    "text": rej.text,
                    "ids": rej.ids,
                    "reasons": rej.reasons,
                    "details": rej.details,
                    "sentence_sha256": sentence_sha256(rej.text),
                }
            )
        return res

    # -- results by category -------------------------------------------------------------------

    def categories(self) -> list[str]:
        present = set(self.db.categories())
        return [c for c in CATEGORY_ORDER if c in present]

    def draft_category(self, category: str) -> tuple[Draft, list[dict[str, Any]], list[Any]]:
        view, title, sensitive = CATEGORY_PLAN[category]
        total = self.db.view_count(view, category=category)
        draft = Draft(category, title, "no_rows", rows_total=total, sensitive=sensitive)
        if total == 0:
            draft.note = f"No rows of this category in {view}."
            return draft, [], []
        rows = self.db.view(view, category=category, limit=self.settings.rows_per_category)
        if sensitive:
            # Task 4E.8: model-made descriptions of media are never used to summarise it.
            rows = [r for r in rows if r.get("derivation") != "ai_generated"]
        draft.rows_given = len(rows)
        if self.complete is None:
            draft.status = "no_model"
            draft.note = self.unavailable_reason
            return draft, rows, []
        windows = make_windows(
            category, rows, sensitive=sensitive, total=total, settings=self.settings
        )
        partial = verify.VerifyResult()
        all_values: list[Any] = []
        for win in windows:
            user = _map_message(title, win, sensitive=sensitive)
            reply = self._ask("results_map", user, stage="map", section=category)
            vals = flatten_values(win.values)
            all_values.extend(vals)
            partial.extend(
                self._verify(
                    reply,
                    allowed=win.ids,
                    values=vals,
                    rows=win.rows,
                    stage="map",
                    section=category,
                )
            )
        draft.prompts.append("results_map")
        draft.removed.extend(partial.removed)
        draft.method = f"map over {len(windows)} window(s)"
        sentences = partial.kept
        if len(windows) > 1 and sentences:
            merged = self._reduce(category, title, sentences, all_values, rows)
            draft.prompts.append("results_reduce")
            draft.removed.extend(merged.removed)
            if merged.kept:
                sentences = merged.kept
                draft.method += ", then merged"
            else:
                draft.method += "; merge kept nothing, checked partials used"
        draft.sentences = sentences
        draft.status = "drafted" if sentences else "nothing_supported"
        if len(rows) < total:
            draft.note = (
                f"The model was given {len(rows)} of {total} rows of this category; "
                "the counts above cover all of them."
            )
        return draft, rows, all_values

    def _reduce(
        self,
        section: str,
        title: str,
        sentences: list[verify.Sentence],
        values: list[Any],
        rows: list[dict[str, Any]],
    ) -> verify.VerifyResult:
        statements = sentences[: self.settings.max_statements]
        allowed = {i for s in statements for i in s.ids}
        user = _statements_message(title, statements)
        reply = self._ask("results_reduce", user, stage="reduce", section=section)
        return self._verify(
            reply, allowed=allowed, values=values, rows=rows, stage="reduce", section=section
        )

    # -- interpretation and conclusions --------------------------------------------------------

    def draft_from_statements(
        self,
        key: str,
        title: str,
        prompt: str,
        *,
        statements: list[verify.Sentence],
        values: list[Any],
        rows: list[dict[str, Any]],
    ) -> Draft:
        draft = Draft(key, title, "no_rows")
        if self.complete is None:
            draft.status = "no_model"
            draft.note = self.unavailable_reason
            return draft
        if not statements:
            draft.note = "No checked results statements to draw on."
            return draft
        used = statements[: self.settings.max_statements]
        allowed = {i for s in used for i in s.ids}
        reply = self._ask(prompt, _statements_message(title, used), stage=key, section=key)
        res = self._verify(reply, allowed=allowed, values=values, rows=rows, stage=key, section=key)
        draft.prompts.append(prompt)
        draft.sentences = res.kept
        draft.removed = res.removed
        draft.status = "drafted" if res.kept else "nothing_supported"
        draft.method = f"from {len(used)} checked statement(s)"
        return draft

    def run(self) -> dict[str, Any]:
        """Draft every section: ``{"results": [...], "interpretation": d, "conclusions": d}``."""
        results: list[Draft] = []
        statements: list[verify.Sentence] = []
        values: list[Any] = []
        rows: list[dict[str, Any]] = []
        for cat in self.categories():
            draft, cat_rows, cat_values = self.draft_category(cat)
            results.append(draft)
            statements.extend(draft.sentences)
            values.extend(cat_values)
            rows.extend(cat_rows)
        interp = self.draft_from_statements(
            "interpretation",
            "Interpretation and limitations",
            "interpretation",
            statements=statements,
            values=values,
            rows=rows,
        )
        concl = self.draft_from_statements(
            "conclusions",
            "Conclusions",
            "conclusions",
            statements=statements,
            values=values,
            rows=rows,
        )
        return {"results": results, "interpretation": interp, "conclusions": concl}


def sentence_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _map_message(title: str, win: Window, *, sensitive: bool) -> str:
    parts = [
        f"Report section: {title}. Part: {win.label}.",
        inputs.DATA_NOTE,
        "Values computed by code from these rows (use them exactly as written):",
        inputs.values_block(win.values),
        "Rows from the findings database, one JSON object per line:",
        inputs.rows_block(win.rows, sensitive=sensitive),
    ]
    if sensitive:
        parts.append(
            "These rows are media screening results. Describe them only by counts, labels, "
            "scores, and finding IDs."
        )
    return "\n\n".join(parts)


def _statements_message(title: str, statements: list[verify.Sentence]) -> str:
    numbered = [(f"S{i + 1}", s.text) for i, s in enumerate(statements)]
    return "\n\n".join(
        [
            f"Report section: {title}.",
            inputs.DATA_NOTE,
            "Checked statements, one per line, each ending with its finding IDs:",
            inputs.statements_block(numbered),
        ]
    )
