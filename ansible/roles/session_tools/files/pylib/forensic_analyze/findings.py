"""The findings store: the system of record for every forensic-analyze run (Milestone 4D).

Modules write rows through ``FindingsWriter.emit`` (normally reached as ``ModuleContext.emit``)
into ``<run>/modules/<name>/findings.part.jsonl``. When every module has finished, the runner
calls ``merge_parts`` which writes ``<run>/findings.jsonl`` in module order, assigns
``finding_id`` F-000001 onwards, and is byte-deterministic. Exports (SQLite, CSV, bodyfile)
are generated from ``findings.jsonl`` only.

Rows are checked against ``schema.json`` by the small standard-library validator below, which
implements exactly the JSON Schema keywords that file uses. Field meanings: docs/schema.md.

Command line (used by tests and for checking a run by hand)::

    python3 -m forensic_analyze.findings validate FILE [--part]
    python3 -m forensic_analyze.findings merge RUN_DIR MODULE [MODULE ...]
    python3 -m forensic_analyze.findings compare FINDINGS_A FINDINGS_B
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, TextIO

from airlock_common import jsonio
from forensic_analyze.csvsafe import display_escape, is_safe_display

SCHEMA_PATH = Path(__file__).with_name("schema.json")
FINDINGS_NAME = "findings.jsonl"
PART_NAME = "findings.part.jsonl"
SCHEMA_VERSION = 1

REQUIRED_FIELDS: tuple[str, ...] = (
    "finding_id",
    "run_id",
    "evidence_id",
    "evidence_sha256",
    "category",
    "artifact_type",
    "message",
    "derivation",
    "source_tool",
    "tool_version",
    "parser",
)
OPTIONAL_FIELDS: tuple[str, ...] = (
    "datetime",
    "timestamp_desc",
    "tz_basis",
    "path",
    "filename",
    "path_b64",
    "inode_ref",
    "size_bytes",
    "allocated",
    "sha256",
    "md5",
    "owner_sid",
    "hashset_name",
    "hashset_version",
    "match_algorithm",
    "score",
    "label",
    "threshold",
    "text",
    "confidence",
    "xval_status",
    "source_record",
    "model_id",
    "model_sha256",
    "prompt_sha256",
    "sensitive_flag",
)
# Every schema field in documentation order. SQLite and CSV column order derive from this.
FIELDS: tuple[str, ...] = REQUIRED_FIELDS + OPTIONAL_FIELDS
# Fields filled by the writer, never by a module.
WRITER_FIELDS: tuple[str, ...] = ("run_id", "evidence_id", "evidence_sha256")
# Fields a model or classifier produces; excluded from the byte-determinism guarantee (4D.9).
AI_FIELDS: tuple[str, ...] = ("confidence", "label", "message", "score", "sensitive_flag", "text")

# Fields that name the run itself. A replay is a new run, so these always differ and are not
# compared by compare_findings(); they are reported as run_id_a/run_id_b instead.
RUN_IDENTITY_FIELDS: tuple[str, ...] = ("run_id",)

FINDING_ID_RE = re.compile(r"^F-[0-9]{6,}$")


class SchemaError(ValueError):
    """A row does not match schema.json. ``errors`` lists every problem found."""

    def __init__(self, errors: Sequence[str], *, where: str = "") -> None:
        self.errors = list(errors)
        prefix = f"{where}: " if where else ""
        first = self.errors[0] if self.errors else "invalid row"
        more = f" (and {len(self.errors) - 1} more)" if len(self.errors) > 1 else ""
        super().__init__(f"{prefix}{first}{more}")


# --------------------------------------------------------------------------------------------
# Minimal JSON Schema (draft 2020-12 subset) validator
# --------------------------------------------------------------------------------------------

ANNOTATION_KEYWORDS = frozenset({"$id", "$schema", "title", "description"})
SUPPORTED_KEYWORDS = frozenset(
    {
        "type",
        "enum",
        "const",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "format",
        "required",
        "properties",
        "additionalProperties",
        "allOf",
        "if",
        "then",
        "else",
    }
)
SUPPORTED_FORMATS = frozenset({"date-time", "x-display-safe"})
_DATETIME_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$"
)


def _short(value: Any) -> str:
    """A short, display-safe rendering of a value for error messages (evidence text is data)."""
    text = repr(value)
    if len(text) > 80:
        text = text[:77] + "..."
    return display_escape(text)


@cache
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def check_schema_keywords(schema: Mapping[str, Any], where: str = "#") -> list[str]:
    """List keywords in ``schema`` that this validator does not implement (should be none)."""
    problems: list[str] = []
    for key, value in schema.items():
        if key in ANNOTATION_KEYWORDS:
            continue
        if key not in SUPPORTED_KEYWORDS:
            problems.append(f"{where}: unsupported keyword {key!r}")
            continue
        if key == "format" and value not in SUPPORTED_FORMATS:
            problems.append(f"{where}: unsupported format {value!r}")
        if key == "properties":
            for name, sub in value.items():
                problems += check_schema_keywords(sub, f"{where}/properties/{name}")
        elif key in {"if", "then", "else"} or (
            key == "additionalProperties" and isinstance(value, dict)
        ):
            problems += check_schema_keywords(value, f"{where}/{key}")
        elif key == "allOf":
            for i, sub in enumerate(value):
                problems += check_schema_keywords(sub, f"{where}/allOf/{i}")
    return problems


_TYPE_CHECKS: dict[str, Any] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
}


def _type_ok(value: Any, wanted: str) -> bool:
    check = _TYPE_CHECKS.get(wanted)
    if check is None:
        raise ValueError(f"unsupported type {wanted!r}")
    return bool(check(value))


def _datetime_ok(value: str) -> bool:
    m = _DATETIME_RE.match(value)
    if not m:
        return False
    try:
        _dt.datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=_dt.UTC)
    except ValueError:
        return False
    return True


def _format_ok(value: str, fmt: str) -> bool:
    if fmt == "date-time":
        return _datetime_ok(value)
    if fmt == "x-display-safe":
        return is_safe_display(value)
    raise ValueError(f"unsupported format {fmt!r}")


def _check_basic(value: Any, schema: Mapping[str, Any], label: str) -> list[str] | None:
    """Type, finiteness, and UTF-8 checks. A non-None result stops further checks."""
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            return [f"{label}: expected {' or '.join(types)}, got {type(value).__name__}"]
    if isinstance(value, float) and not math.isfinite(value):
        return [f"{label}: number must be finite"]
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return [f"{label}: not valid UTF-8 text (lone surrogate); use findings.safe_path()"]
    return None


def _check_string(value: str, schema: Mapping[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    min_len = schema.get("minLength")
    if min_len is not None and len(value) < min_len:
        errors.append(
            f"{label}: must not be empty"
            if min_len == 1
            else f"{label}: shorter than {min_len} characters"
        )
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        errors.append(f"{label}: longer than {schema['maxLength']} characters")
    if "pattern" in schema and not _regex(schema["pattern"]).search(value):
        errors.append(f"{label}: {_short(value)} does not match {schema['pattern']}")
    if "format" in schema and not _format_ok(value, schema["format"]):
        if schema["format"] == "date-time":
            errors.append(f"{label}: {_short(value)} is not an ISO 8601 UTC time ending in Z")
        else:
            errors.append(f"{label}: holds control or bidi characters; use findings.safe_path()")
    return errors


def _check_number(value: float, schema: Mapping[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{label}: {value!r} is below {schema['minimum']}")
    if "maximum" in schema and value > schema["maximum"]:
        errors.append(f"{label}: {value!r} is above {schema['maximum']}")
    return errors


def _check_conditional(value: Any, schema: Mapping[str, Any], where: str) -> list[str]:
    branch = "then" if not validate_instance(value, schema["if"], where) else "else"
    if branch not in schema:
        return []
    errors = validate_instance(value, schema[branch], where)
    if errors and branch == "then":
        cond = _describe_if(schema["if"])
        errors = [f"{e} (required when {cond})" for e in errors]
    return errors


def validate_instance(value: Any, schema: Mapping[str, Any], where: str = "") -> list[str]:
    """Validate ``value`` against ``schema`` (the keyword subset above). Returns error strings."""
    label = where or "row"
    stop = _check_basic(value, schema, label)
    if stop is not None:
        return stop
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{label}: must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{label}: {_short(value)} is not one of {', '.join(schema['enum'])}")
    if isinstance(value, str):
        errors += _check_string(value, schema, label)
    elif isinstance(value, int | float) and not isinstance(value, bool):
        errors += _check_number(value, schema, label)
    elif isinstance(value, dict):
        errors += _validate_object(value, schema, where)
    for sub in schema.get("allOf", []):
        errors += validate_instance(value, sub, where)
    if "if" in schema:
        errors += _check_conditional(value, schema, where)
    return errors


def _describe_if(schema: Mapping[str, Any]) -> str:
    parts = []
    for name, sub in schema.get("properties", {}).items():
        if "const" in sub:
            parts.append(f"{name} is {sub['const']}")
    return " and ".join(parts) or "a condition holds"


def _validate_object(value: dict[str, Any], schema: Mapping[str, Any], where: str) -> list[str]:
    errors: list[str] = []
    props: Mapping[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in value:
            errors.append(f"missing required field {name!r}")
    for name in sorted(value, key=str):
        if not isinstance(name, str):
            errors.append(f"field name {_short(name)} is not a string")
            continue
        sub_where = f"{where}.{name}" if where else name
        if name in props:
            errors += validate_instance(value[name], props[name], sub_where)
            continue
        extra = schema.get("additionalProperties", True)
        if extra is False:
            errors.append(f"unknown field {_short(name)}")
        elif isinstance(extra, dict):
            errors += validate_instance(value[name], extra, sub_where)
    return errors


@cache
def load_schema() -> dict[str, Any]:
    """schema.json, checked once for keywords this validator does not implement."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    problems = check_schema_keywords(schema)
    if problems:
        raise RuntimeError(f"schema.json uses keywords the validator lacks: {problems[0]}")
    return schema


@cache
def _part_schema() -> dict[str, Any]:
    """The schema for part-file rows: identical, except ``finding_id`` is not yet assigned."""
    schema = dict(load_schema())
    schema["required"] = [f for f in schema["required"] if f != "finding_id"]
    return schema


def validate_row(row: Any, *, part: bool = False) -> list[str]:
    """Check one finding row against schema.json. Returns a list of error strings (empty = ok).

    ``part=True`` checks a row as it is written to a module's part file: ``finding_id`` must be
    absent, because IDs are assigned only at merge.
    """
    if not isinstance(row, dict):
        return [f"row: expected an object, got {type(row).__name__}"]
    if part:
        errors = validate_instance(row, _part_schema())
        if "finding_id" in row:
            errors.insert(0, "finding_id: assigned at merge; modules must not set it")
        return errors
    return validate_instance(row, load_schema())


def is_ai_row(row: Mapping[str, Any]) -> bool:
    """A row whose content depends on a model or classifier (outside the determinism promise)."""
    return row.get("derivation") == "ai_generated" or "model_sha256" in row


# --------------------------------------------------------------------------------------------
# Hostile file names
# --------------------------------------------------------------------------------------------


def _str_to_raw(text: str) -> bytes:
    """Bytes behind a str path. Surrogate escapes (U+DC80..U+DCFF, as made by os.fsdecode)
    become the original bytes; other lone surrogates (invalid UTF-16 from NTFS) are kept as
    their 3-byte generalised UTF-8 form so nothing is lost."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        pass
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xDC80 <= cp <= 0xDCFF:
            out.append(cp - 0xDC00)
        else:
            out += ch.encode("utf-8", "surrogatepass")
    return bytes(out)


def _display(text: str) -> str:
    """Display form: surrogate escapes become ``\\xNN``, other unsafe characters ``\\uXXXX``."""
    parts: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xDC80 <= cp <= 0xDCFF:
            parts.append(f"\\x{cp - 0xDC00:02x}")
        else:
            parts.append(display_escape(ch))
    return "".join(parts)


def escape_surrogates(text: str) -> str:
    """``text`` with only its lone surrogates escaped (``\\xNN`` or ``\\udXXX``)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return "".join(_display(c) if 0xD800 <= ord(c) <= 0xDFFF else c for c in text)
    return text


def safe_path(raw: bytes | str) -> tuple[str, str]:
    """Return ``(display, b64)`` for a path from evidence.

    ``display`` is safe to show and to store in ``path``: bytes that are not valid UTF-8 appear
    as ``\\xNN``, control, bidi, invisible, and lone-surrogate characters as ``\\uXXXX`` (newline
    as ``\\n``). ``b64`` is standard base64 of the raw bytes, for ``path_b64``.
    """
    if isinstance(raw, bytes | bytearray | memoryview):
        data = bytes(raw)
        text = data.decode("utf-8", "surrogateescape")
    else:
        text = raw
        data = _str_to_raw(text)
    return _display(text), base64.b64encode(data).decode("ascii")


def decode_path_b64(value: str) -> bytes:
    """The raw bytes of a ``path_b64`` value (a leading ``'`` from a CSV cell is ignored)."""
    return base64.b64decode(value.lstrip("'"), validate=True)


def _needs_raw_copy(text: str) -> bool:
    if "\\" in text or not is_safe_display(text):
        return True
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def normalise_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Prepare a module's row for validation. Returns a new dict.

    * ``path`` / ``filename`` given as bytes are decoded as UTF-8 when they can be. Bytes that
      are not valid UTF-8, or text holding control, bidi, or lone surrogate characters, are
      replaced by their display form; for ``path`` the raw bytes go to
      ``path_b64`` (unless the module already set it). A path holding a backslash also gets
      ``path_b64``, so a literal ``\\x41`` in a name is never confused with an escape.
    * Lone surrogates in any other text field (a name pasted into ``message``, say) become
      ``\\xNN`` / ``\\udXXX`` escapes, so the row can be stored as UTF-8. Other characters in
      those fields are kept; exports escape them for display.
    * ``datetime`` given as an aware ``datetime.datetime`` becomes ISO 8601 UTC with ``Z``.
    * Keys whose value is ``None`` are dropped (absent and null mean the same: unknown).
    """
    out: dict[str, Any] = {k: v for k, v in row.items() if v is not None}
    for key in ("path", "filename"):
        value = out.get(key)
        if isinstance(value, bytes | bytearray | memoryview):
            try:
                value = out[key] = bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                value = bytes(value)
        if isinstance(value, bytes) or (isinstance(value, str) and _needs_raw_copy(value)):
            display, b64 = safe_path(value)
            out[key] = display
            if key == "path":
                out.setdefault("path_b64", b64)
    for key, value in out.items():
        if key not in {"path", "filename"} and isinstance(value, str):
            out[key] = escape_surrogates(value)
    stamp = out.get("datetime")
    if isinstance(stamp, _dt.datetime):
        if stamp.tzinfo is None:
            raise SchemaError(["datetime: naive datetime; give a timezone-aware value"])
        out["datetime"] = stamp.astimezone(_dt.UTC).isoformat().replace("+00:00", "Z")
    return out


# --------------------------------------------------------------------------------------------
# Writing part files
# --------------------------------------------------------------------------------------------


class FindingsWriter:
    """Writes one module's rows to its part file, validating each row first.

    ``run_id``, ``evidence_id`` and ``evidence_sha256`` are filled in by the writer. A row that
    sets one of them to a different value, sets ``finding_id``, or fails the schema raises
    ``SchemaError`` and nothing is written for it.
    """

    def __init__(
        self,
        part_path: str | os.PathLike[str],
        *,
        run_id: str,
        evidence_id: str,
        evidence_sha256: str,
        module: str,
    ) -> None:
        self.part_path = Path(part_path)
        self.module = module
        self.count = 0
        self._fixed = {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "evidence_sha256": evidence_sha256,
        }
        errors: list[str] = []
        props = load_schema()["properties"]
        for name, value in self._fixed.items():
            errors += validate_instance(value, props[name], name)
        if errors:
            raise SchemaError(errors, where=f"{module}: writer")
        self.part_path.parent.mkdir(parents=True, exist_ok=True)
        # A module that re-runs (no .done marker) starts its part file again.
        self._fh: TextIO | None = open(  # noqa: SIM115 - closed in close()
            self.part_path, "w", encoding="utf-8", newline="\n"
        )

    def __enter__(self) -> FindingsWriter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._fh is None

    def emit(self, row: Mapping[str, Any]) -> None:
        """Validate ``row`` and append it to the part file."""
        if self._fh is None:
            raise RuntimeError(f"{self.module}: findings writer is closed")
        if not isinstance(row, Mapping):
            raise SchemaError(
                [f"row: expected a dict, got {type(row).__name__}"], where=self.module
            )
        out = normalise_row(row)
        errors: list[str] = []
        for name, value in self._fixed.items():
            if name in out and out[name] != value:
                errors.append(f"{name}: set by the writer; the row gave a different value")
            out[name] = value
        errors += validate_row(out, part=True)
        if errors:
            raise SchemaError(errors, where=self.module)
        self._fh.write(jsonio.dumps_line(out))
        self._fh.write("\n")
        self.count += 1

    def close(self) -> None:
        if self._fh is None:
            return
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        self._fh = None


# --------------------------------------------------------------------------------------------
# Reading and merging
# --------------------------------------------------------------------------------------------


def _iter_lines(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (line number, row) from a JSON-lines file, strictly: UTF-8, ``\\n`` ends."""
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.endswith(b"\n"):
                raise SchemaError(
                    ["last line has no line end (file cut short?)"], where=f"{path}:{lineno}"
                )
            body = raw[:-1]
            if not body or body.endswith(b"\r"):
                raise SchemaError(["empty line or CRLF line end"], where=f"{path}:{lineno}")
            try:
                row = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise SchemaError([f"not valid JSON: {exc}"], where=f"{path}:{lineno}") from exc
            if not isinstance(row, dict):
                raise SchemaError(["line is not a JSON object"], where=f"{path}:{lineno}")
            yield lineno, row


def iter_findings(source: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
    """Rows of ``findings.jsonl`` in finding order. ``source`` is the file or its run folder."""
    path = Path(source)
    if path.is_dir():
        path = path / FINDINGS_NAME
    for _, row in _iter_lines(path):
        yield row


def part_path(run_dir: str | os.PathLike[str], module: str) -> Path:
    """``<run>/modules/<module>/findings.part.jsonl``."""
    return Path(run_dir) / "modules" / module / PART_NAME


@dataclass
class MergeResult:
    path: Path
    sha256: str
    count: int
    per_module: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path.name,
            "sha256": self.sha256,
            "count": self.count,
            "per_module": dict(self.per_module),
        }


def _module_names(module_order: Iterable[Any]) -> list[str]:
    names = [m if isinstance(m, str) else str(m.name) for m in module_order]
    seen: set[str] = set()
    for n in names:
        if n in seen:
            raise ValueError(f"module {n!r} listed twice in the merge order")
        seen.add(n)
    return names


def merge(run_dir: str | os.PathLike[str], module_order: Iterable[Any]) -> MergeResult:
    """Merge part files into ``findings.jsonl`` and return its path, SHA-256, and counts.

    Parts are read in ``module_order`` (names or ``Module`` objects); a module with no part file
    contributes nothing. Rows keep their emit order. Every row is re-validated; one bad row
    stops the merge with ``SchemaError`` naming the file and line. The output is written to a
    temporary file and renamed, so a reader never sees a half-written file.
    """
    run = Path(run_dir)
    names = _module_names(module_order)
    target = run / FINDINGS_NAME
    run.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    per_module: dict[str, int] = {}
    n = 0
    fd, tmp = tempfile.mkstemp(prefix=f".{FINDINGS_NAME}.", dir=run)
    try:
        with os.fdopen(fd, "wb") as out:
            for name in names:
                part = part_path(run, name)
                if not part.is_file():
                    continue
                per_module[name] = 0
                for lineno, row in _iter_lines(part):
                    errors = validate_row(row, part=True)
                    if errors:
                        raise SchemaError(errors, where=f"{part}:{lineno}")
                    n += 1
                    row["finding_id"] = f"F-{n:06d}"
                    line = (jsonio.dumps_line(row) + "\n").encode("utf-8")
                    digest.update(line)
                    out.write(line)
                    per_module[name] += 1
            out.flush()
            os.fsync(out.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return MergeResult(path=target, sha256=digest.hexdigest(), count=n, per_module=per_module)


def merge_parts(run_dir: str | os.PathLike[str], module_order: Iterable[Any]) -> Path:
    """Contract entry point (docs/dev/contract.md 8a): merge and return the path written."""
    return merge(run_dir, module_order).path


def file_sha256(path: str | os.PathLike[str]) -> str:
    """SHA-256 of ``findings.jsonl`` (or any file), for ``run.json``."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------------------
# Determinism check (4D.9)
# --------------------------------------------------------------------------------------------


def _split_ai(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not is_ai_row(row):
        return row, {}
    base = {k: v for k, v in row.items() if k not in AI_FIELDS}
    ai = {k: row[k] for k in AI_FIELDS if k in row}
    return base, ai


def compare_findings(
    a: str | os.PathLike[str], b: str | os.PathLike[str], *, limit: int = 50
) -> dict[str, Any]:
    """Compare two findings files (or run folders) for the replay determinism test.

    Returns ``identical`` (byte-identical files), ``non_ai_identical`` (identical once the AI
    fields of AI rows are set aside), ``ai_drift`` (finding ID, field, both values) and
    ``differences`` (non-AI differences), each list capped at ``limit`` entries. ``run_id`` is
    not compared: a replay is a new run.
    """
    pa = Path(a) / FINDINGS_NAME if Path(a).is_dir() else Path(a)
    pb = Path(b) / FINDINGS_NAME if Path(b).is_dir() else Path(b)
    rows_a = list(iter_findings(pa))
    rows_b = list(iter_findings(pb))
    differences: list[dict[str, Any]] = []
    ai_drift: list[dict[str, Any]] = []
    n_diff = n_drift = 0
    for i in range(max(len(rows_a), len(rows_b))):
        ra = rows_a[i] if i < len(rows_a) else None
        rb = rows_b[i] if i < len(rows_b) else None
        fid = (ra or rb or {}).get("finding_id", f"line {i + 1}")
        if ra is None or rb is None:
            n_diff += 1
            if len(differences) < limit:
                side = "a" if rb is None else "b"
                differences.append({"finding_id": fid, "field": "*", "only_in": side})
            continue
        base_a, ai_a = _split_ai(ra)
        base_b, ai_b = _split_ai(rb)
        for key in sorted(set(base_a) | set(base_b)):
            if key in RUN_IDENTITY_FIELDS:
                continue
            if base_a.get(key) != base_b.get(key):
                n_diff += 1
                if len(differences) < limit:
                    differences.append(
                        {
                            "finding_id": fid,
                            "field": key,
                            "a": base_a.get(key),
                            "b": base_b.get(key),
                        }
                    )
        for key in sorted(set(ai_a) | set(ai_b)):
            if ai_a.get(key) != ai_b.get(key):
                n_drift += 1
                if len(ai_drift) < limit:
                    ai_drift.append(
                        {"finding_id": fid, "field": key, "a": ai_a.get(key), "b": ai_b.get(key)}
                    )
    return {
        "identical": pa.read_bytes() == pb.read_bytes(),
        "non_ai_identical": n_diff == 0,
        "rows_a": len(rows_a),
        "rows_b": len(rows_b),
        "run_id_a": rows_a[0].get("run_id") if rows_a else None,
        "run_id_b": rows_b[0].get("run_id") if rows_b else None,
        "sha256_a": file_sha256(pa),
        "sha256_b": file_sha256(pb),
        "difference_count": n_diff,
        "differences": differences,
        "ai_drift_count": n_drift,
        "ai_drift": ai_drift,
    }


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------

USAGE = """usage:
  python3 -m forensic_analyze.findings validate FILE [--part]
  python3 -m forensic_analyze.findings merge RUN_DIR MODULE [MODULE ...]
  python3 -m forensic_analyze.findings compare FINDINGS_A FINDINGS_B"""


def _cmd_validate(args: list[str]) -> int:
    part = "--part" in args
    files = [a for a in args if a != "--part"]
    if len(files) != 1:
        print(USAGE, file=sys.stderr)
        return 2
    count = 0
    for lineno, row in _iter_lines(Path(files[0])):
        errors = validate_row(row, part=part)
        if errors:
            print(
                f"{files[0]}:{lineno}: {errors[0]}. Fix the module that wrote it.", file=sys.stderr
            )
            return 1
        count += 1
    print(f"ok: {count} rows match the schema")
    return 0


def _cmd_compare(args: list[str]) -> int:
    report = compare_findings(args[0], args[1])
    print(jsonio.dumps(report))
    if not report["non_ai_identical"]:
        print(
            "findings differ outside AI fields; the run is not reproducible. "
            "Check the differences listed above.",
            file=sys.stderr,
        )
        return 1
    if report["ai_drift_count"]:
        print(
            f"note: {report['ai_drift_count']} AI field(s) drifted; listed above.", file=sys.stderr
        )
    return 0


def _cmd_merge(args: list[str]) -> int:
    print(jsonio.dumps(merge(args[0], args[1:]).to_dict()))
    return 0


_COMMANDS = {
    "validate": (_cmd_validate, 1),
    "merge": (_cmd_merge, 2),
    "compare": (_cmd_compare, 2),
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    spec = _COMMANDS.get(args[0]) if args else None
    if spec is None or len(args) - 1 < spec[1] or (args[0] == "compare" and len(args) != 3):
        print(USAGE, file=sys.stderr)
        return 2
    try:
        return spec[0](args[1:])
    except SchemaError as exc:
        print(f"findings: {exc}. Fix the part file or the module that wrote it.", file=sys.stderr)
    except OSError as exc:
        print(
            f"findings: cannot read or write {exc.filename}: {exc.strerror}. "
            "Check the path and free space.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
