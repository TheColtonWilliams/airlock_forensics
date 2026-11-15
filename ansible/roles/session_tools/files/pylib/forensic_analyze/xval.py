"""Two-parser cross-validation (task 4C.28).

Core artifacts are parsed by more than one independent parser (The Sleuth Kit or Dissect
against MFTECmd for the MFT; RBCmd against the built-in ``$I`` parser and Dissect for the
recycle bin; Dissect against the built-in USN parser for the change journal). ``join`` groups
what each parser saw by a shared key (volume, MFT entry, stream; or the ``$I`` file; or the USN)
and compares the chosen fields:

* ``agree``: two or more parsers saw the record and every compared field matches.
* ``disagree``: two or more parsers saw it and at least one field differs. Every value is
  kept and listed; nothing is resolved or picked silently.
* ``single_source``: only one parser saw it (or only one parser was available).

A parser that does not report a field is not counted for that field. ``rows`` turns the
results into findings rows in category ``xval``: one summary per artifact and volume (which
parsers ran, which were missing and why, the counts) and one row per disagreement.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

XVAL_TOOL = "forensic-analyze"
XVAL_VERSION = "xval 1"
AGREE, DISAGREE, SINGLE = "agree", "disagree", "single_source"

Equal = Callable[[Any, Any], bool]


@dataclass(frozen=True)
class Observation:
    """What one parser saw for one record."""

    parser: str
    key: tuple[Any, ...]
    values: Mapping[str, Any]
    ref: str = ""  # source_record of the raw record


@dataclass(frozen=True)
class Difference:
    field: str
    values: dict[str, Any]  # parser -> value


@dataclass
class Result:
    key: tuple[Any, ...]
    status: str
    parsers: tuple[str, ...]
    differences: list[Difference] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    duplicates: int = 0  # extra observations from a parser that saw the key more than once


def exact(a: Any, b: Any) -> bool:
    return bool(a == b)


def same_second(a: Any, b: Any) -> bool:
    """Times agree when equal to the whole second (The Sleuth Kit prints whole seconds)."""
    return str(a)[:19] == str(b)[:19]


def same_text_ci(a: Any, b: Any) -> bool:
    return str(a).casefold() == str(b).casefold()


def overlap(a: Any, b: Any) -> bool:
    """For sets of names (hard links): agree when they share at least one name."""
    sa = set(a) if isinstance(a, set | frozenset | list | tuple) else {a}
    sb = set(b) if isinstance(b, set | frozenset | list | tuple) else {b}
    return bool(sa & sb)


def _differs(values: dict[str, Any], eq: Equal) -> bool:
    items = list(values.values())
    return any(not eq(items[0], other) for other in items[1:])


def join(
    observations: Iterable[Observation],
    *,
    fields: Sequence[str],
    equal: Mapping[str, Equal] | None = None,
) -> dict[tuple[Any, ...], Result]:
    """Group observations by key and compare ``fields`` between parsers."""
    eqs = dict(equal or {})
    grouped: dict[tuple[Any, ...], dict[str, Observation]] = {}
    dups: Counter[tuple[Any, ...]] = Counter()
    for obs in observations:
        per = grouped.setdefault(obs.key, {})
        if obs.parser in per:
            dups[obs.key] += 1
            continue
        per[obs.parser] = obs
    results: dict[tuple[Any, ...], Result] = {}
    for key, per in grouped.items():
        parsers = tuple(sorted(per))
        diffs: list[Difference] = []
        if len(parsers) > 1:
            for name in fields:
                vals = {p: per[p].values.get(name) for p in parsers}
                vals = {p: v for p, v in vals.items() if v is not None}
                if len(vals) > 1 and _differs(vals, eqs.get(name, exact)):
                    diffs.append(Difference(name, vals))
        status = SINGLE if len(parsers) == 1 else (DISAGREE if diffs else AGREE)
        results[key] = Result(
            key=key,
            status=status,
            parsers=parsers,
            differences=diffs,
            observations=[per[p] for p in parsers],
            duplicates=dups[key],
        )
    return results


def status_of(results: Mapping[tuple[Any, ...], Result], key: tuple[Any, ...]) -> str:
    res = results.get(key)
    return res.status if res else SINGLE


def counts(results: Mapping[tuple[Any, ...], Result]) -> dict[str, int]:
    c = Counter(r.status for r in results.values())
    return {AGREE: c[AGREE], DISAGREE: c[DISAGREE], SINGLE: c[SINGLE]}


def _show(value: Any) -> str:
    if isinstance(value, set | frozenset | list | tuple):
        return " | ".join(sorted(str(v) for v in value))
    return str(value)


def summary_row(
    artifact: str,
    results: Mapping[tuple[Any, ...], Result],
    *,
    volume_index: int | None,
    parsers_run: Sequence[str],
    parsers_missing: Mapping[str, str],
) -> dict[str, Any]:
    """One row that says what was compared, by which parsers, and the outcome."""
    c = counts(results)
    where = f" on volume {volume_index}" if volume_index is not None else ""
    ran = ", ".join(parsers_run) or "none"
    if len(parsers_run) < 2:
        msg = (
            f"Cross-check of {artifact}{where}: only one parser was available ({ran}), so every "
            f"record is single_source ({c[SINGLE]} records)."
        )
    else:
        msg = (
            f"Cross-check of {artifact}{where} by {ran}: {c[AGREE]} agree, {c[DISAGREE]} "
            f"disagree, {c[SINGLE]} seen by one parser only."
        )
    if c[DISAGREE]:
        msg += " Disagreements are listed one per row; no value was chosen over another."
    text = ""
    if parsers_missing:
        text = "Parsers not run: " + "; ".join(
            f"{name}: {why}" for name, why in sorted(parsers_missing.items())
        )
    row: dict[str, Any] = {
        "category": "xval",
        "artifact_type": "xval_summary",
        "message": msg,
        "derivation": "observed",
        "source_tool": XVAL_TOOL,
        "tool_version": XVAL_VERSION,
        "parser": "xval",
    }
    if text:
        row["text"] = text
    return row


def disagreement_rows(
    artifact: str,
    results: Mapping[tuple[Any, ...], Result],
    *,
    describe: Callable[[Result], dict[str, Any]],
) -> list[dict[str, Any]]:
    """One row per disagreeing record. ``describe`` adds path, inode_ref and the like."""
    out: list[dict[str, Any]] = []
    for key in sorted(results, key=lambda k: tuple(str(x) for x in k)):
        res = results[key]
        if res.status != DISAGREE:
            continue
        fields = ", ".join(d.field for d in res.differences)
        detail = "; ".join(
            f"{d.field}: " + ", ".join(f"{p}={_show(v)}" for p, v in sorted(d.values.items()))
            for d in res.differences
        )
        refs = [o.ref for o in res.observations if o.ref]
        row: dict[str, Any] = {
            "category": "xval",
            "artifact_type": "xval_disagreement",
            "message": (
                f"Parsers disagree on {fields} for this {artifact} record "
                f"({', '.join(res.parsers)}). Both values are kept; neither is chosen."
            ),
            "derivation": "observed",
            "source_tool": XVAL_TOOL,
            "tool_version": XVAL_VERSION,
            "parser": "xval",
            "xval_status": DISAGREE,
            "text": detail,
        }
        if refs:
            row["source_record"] = refs[0]
        row.update({k: v for k, v in describe(res).items() if v is not None})
        out.append(row)
    return out
