"""Code verifier for model-drafted report text (tasks 4E.6, 4E.7, 4E.10, 4G.14).

The verifier is code, not a model. It splits a draft into sentences and keeps a sentence only
when every check passes:

1. It ends with finding IDs in square brackets, ``[F-000123, F-000124]``.
2. Every cited ID exists, and (when the caller gives the set) was among the rows the model was
   given for that section. An ID written inside the sentence must also be cited at its end.
3. Every date or time, number, path or file name, hash, SID, and quoted value in the sentence
   appears in at least one cited row, or in the values code computed and passed in (counts,
   first and last times, time spans: date arithmetic is done in code, never by the model).
   Dates are normalised before comparison (``2026-03-01T10:15:00Z``, ``2026-03-01 10:15 UTC``,
   ``1 March 2026``, ``March 1, 2026`` all name the same day), at the precision written.
4. Wording rules (4E.7): no person (suspect, he, she, the user ...), no intent (deliberately,
   in order to, tried to ...), and an account is only ever an "account SID".
5. No capitalised word that could be a personal name, unless it is a known technical term or
   appears in a code-made field of a cited row (artifact type, tool, parser, label ...).
   Text written by whoever made the evidence (paths, file names, document text) does not count
   here: a name inside a file name never makes that name usable in a sentence.
6. No run of four or more words copied from evidence text outside a quoted path, and nothing
   that reads like an instruction to a model (ignore previous instructions, system prompt ...).

A sentence that fails is removed and returned with its reasons, so the report can list it.
The verifier is deliberately strict: a false rejection only costs a draft sentence.
"""

from __future__ import annotations

import datetime as _dt
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from evidence_report import inputs

Lookup = Callable[[str], Mapping[str, Any] | None]

ID_RE = re.compile(r"F-[0-9]{6,}")
CITATION_RE = re.compile(r"\[\s*(F-[0-9]{6,}(?:\s*[,;]\s*F-[0-9]{6,})*)\s*\]")
END_CITATION_RE = re.compile(
    r"\[\s*(F-[0-9]{6,}(?:\s*[,;]\s*F-[0-9]{6,})*)\s*\]\s*[.!?]?\s*$", re.DOTALL
)
MAX_SENTENCE_CHARS = 600

# Fields of a row that code (not the evidence) writes. Words found here may be capitalised.
CODE_FIELDS: tuple[str, ...] = (
    "category",
    "artifact_type",
    "derivation",
    "timestamp_desc",
    "tz_basis",
    "source_tool",
    "tool_version",
    "parser",
    "hashset_name",
    "hashset_version",
    "match_algorithm",
    "label",
    "model_id",
    "xval_status",
)
# Fields holding text written by whoever made the evidence (used for the echo check).
ECHO_FIELDS: tuple[str, ...] = ("path", "filename", "text")

_MONTHS = {
    m: i + 1
    for i, names in enumerate(
        [
            ("january", "jan"),
            ("february", "feb"),
            ("march", "mar"),
            ("april", "apr"),
            ("may",),
            ("june", "jun"),
            ("july", "jul"),
            ("august", "aug"),
            ("september", "sep", "sept"),
            ("october", "oct"),
            ("november", "nov"),
            ("december", "dec"),
        ]
    )
    for m in names
}
_MONTH_ALT = "|".join(sorted(_MONTHS, key=len, reverse=True))
_TZ = r"(?:\s*(?P<tz>Z|UTC|GMT|[+-]\d{2}:?\d{2})(?![\w]))?"
_TIME = r"(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2})(?:[.,](?P<f>\d{1,9}))?)?"

ISO_DATE_RE = re.compile(
    r"(?<![\w-])(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})"
    r"(?:(?:T|\s+(?:at\s+)?)" + _TIME + r")?" + _TZ,
    re.IGNORECASE,
)
DMY_DATE_RE = re.compile(
    r"(?<![\w])(?P<d>\d{1,2})(?:st|nd|rd|th)?\s+(?P<mon>" + _MONTH_ALT + r")\.?,?\s+(?P<y>\d{4})"
    r"(?:,?\s+(?:at\s+)?" + _TIME + r")?" + _TZ,
    re.IGNORECASE,
)
MDY_DATE_RE = re.compile(
    r"(?<![\w])(?P<mon>" + _MONTH_ALT + r")\.?\s+(?P<d>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<y>\d{4})"
    r"(?:,?\s+(?:at\s+)?" + _TIME + r")?" + _TZ,
    re.IGNORECASE,
)
MONTH_YEAR_RE = re.compile(r"(?<![\w])(?P<mon>" + _MONTH_ALT + r")\s+(?P<y>\d{4})(?![\w])", re.I)
TIME_ONLY_RE = re.compile(r"(?<![\w:.])" + _TIME + _TZ + r"(?![\w:])", re.IGNORECASE)

SID_RE = re.compile(r"(?<![\w-])S-1-\d+(?:-\d+)+(?![\w-])")
HASH_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![\w])")
INODE_RE = re.compile(r"(?<![\w])v\d+:\d+(?:-\d+)?(?![\w])")
_PATH_STOP = r"\s\"'`<>|,;\[\]()"
WIN_PATH_RE = re.compile(r"(?<![\w])[A-Za-z]:[\\/][^" + _PATH_STOP + r"]*")
BACKSLASH_PATH_RE = re.compile(r"(?<![\w\\])\\[^" + _PATH_STOP + r"]+")
POSIX_PATH_RE = re.compile(r"(?<![\w/:.])/[^" + _PATH_STOP + r"/]+(?:/[^" + _PATH_STOP + r"/]*)*")
SYSFILE_RE = re.compile(r"(?<![\w$])\$[A-Za-z][\w.$:]*")
FILENAME_RE = re.compile(
    r"(?<![\w$.~-])[\w$~-]+(?:\.[\w-]+)*\.[A-Za-z][A-Za-z0-9]{0,7}(?![\w])", re.UNICODE
)
NUMBER_RE = re.compile(
    r"(?<![\w.])(?P<num>\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"
    r"(?:\s*(?P<unit>%|percent|bytes?|KB|MB|GB|TB|KiB|MiB|GiB|TiB))?(?![\w])",
    re.IGNORECASE,
)
QUOTE_RE = re.compile(r"`([^`]+)`|\"([^\"]+)\"|“([^”]+)”")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z'\u2019-]*")

# Abbreviations and technical names that look like file names but are not.
NOT_FILENAMES = frozenset(
    {
        "e.g",
        "i.e",
        "etc",
        "vs",
        "a.m",
        "p.m",
        "llama.cpp",
        "findings.jsonl",
        "findings.csv",
        "case.sqlite",
        "run.json",
        "report.html",
        "report.md",
    }
)
# Technical names that contain digits; blanked before the number check.
DIGIT_TERMS_RE = re.compile(
    r"(?<![\w-])(?:SHA-?(?:1|224|256|384|512)|MD5|UTF-?(?:8|16)|ISO\s*8601|NIST\s+IR\s*8354|"
    r"IR\s*8354|x86[-_]64|ext[234]|FAT(?:12|16|32)|I30|Ed25519)(?![\w])",
    re.IGNORECASE,
)
# NTFS and Windows names that are vocabulary, not evidence paths.
SYSTEM_NAMES = frozenset(
    {
        "$mft",
        "$mftmirr",
        "$logfile",
        "$usnjrnl",
        "$usnjrnl:$j",
        "$j",
        "$recycle.bin",
        "$i",
        "$r",
        "$secure",
        "$secure:$sds",
        "$sds",
        "$i30",
        "$bitmap",
        "$boot",
        "$extend",
        "$standard_information",
        "$file_name",
        "$si",
        "$fn",
        "$data",
    }
)

_UNITS = {
    "kb": (1000, 1024),
    "mb": (1000**2, 1024**2),
    "gb": (1000**3, 1024**3),
    "tb": (1000**4, 1024**4),
    "kib": (1024,),
    "mib": (1024**2,),
    "gib": (1024**3,),
    "tib": (1024**4,),
}

# --- 4E.7 wording rules ------------------------------------------------------------------------

PERSON_RE = re.compile(
    r"\b(suspects?|victims?|offenders?|perpetrators?|culprits?|accused|defendants?|"
    r"persons?|people|individuals?|someone|somebody|anyone|employees?|"
    r"he|she|him|her|his|hers|himself|herself|man|woman|men|women|"
    r"mr|mrs|ms|miss|sir|madam)\b",
    re.IGNORECASE,
)
USER_RE = re.compile(
    r"\busers?\b(?!\s+(?:account|profile|folder|director(?:y|ies)|sids?)\b)", re.IGNORECASE
)
OWNER_RE = re.compile(r"\bowners?\b(?!\s+account\s+sids?\b)", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\baccounts?\b(?!\s+sids?\b)", re.IGNORECASE)
INTENT_RE = re.compile(
    r"\b(intend(?:s|ed|ing)?|intent(?:ion(?:al(?:ly)?)?|ions)?|deliberate(?:ly)?|"
    r"purpose(?:ly|ful(?:ly)?)?|on\s+purpose|in\s+order\s+to|so\s+as\s+to|"
    r"tr(?:y|ied|ying)\s+to|attempt(?:s|ed|ing)?\s+to|want(?:s|ed)?\s+to|wish(?:es|ed)?\s+to|"
    r"sought\s+to|motive|motivat\w*|to\s+hide|to\s+conceal|conceal\w*|cover(?:ed)?\s+up|"
    r"cover\w*\s+(?:their|his|her)\s+tracks|guilt\w*|innocen\w*|knowingly|wilful(?:ly)?|"
    r"willful(?:ly)?|clearly\s+shows?\s+that)\b",
    re.IGNORECASE,
)
INSTRUCTION_RE = re.compile(
    r"\b(ignore|disregard|previous\s+instructions?|prior\s+instructions?|instructions?|"
    r"system\s+prompt|prompt|you\s+must|as\s+an\s+ai|jailbreak|override)\b",
    re.IGNORECASE,
)

# Capitalised words that are technical vocabulary, not names (compared case-sensitively).
TERMS: frozenset[str] = frozenset(
    [
        "AI",
        "AI-generated",
        "API",
        "ASCII",
        "ATA",
        "Account",
        "Accounts",
        "AIRLOCK",
        "BitLocker",
        "Bin",
        "CASE",
        "CFTT",
        "CPU",
        "CSV",
        "ClamAV",
        "Dissect",
        "DOS",
        "EICAR",
        "EXIF",
        "EZ",
        "FAT",
        "FAT32",
        "GPT",
        "GUID",
        "HFS",
        "HTML",
        "I30",
        "ID",
        "IDs",
        "IR",
        "ISO",
        "JPEG",
        "JSON",
        "Journal",
        "Kit",
        "LBA",
        "LogFile",
        "MAC",
        "MACB",
        "MBR",
        "MD5",
        "MFT",
        "MFTECmd",
        "Master",
        "NIST",
        "NSRL",
        "NTFS",
        "NudeNet",
        "OS",
        "PDF",
        "PNG",
        "PE",
        "RBCmd",
        "Recycle",
        "SHA",
        "SHA-1",
        "SHA-256",
        "SID",
        "SIDs",
        "SQLite",
        "SSD",
        "SigLIP",
        "Sleuth",
        "Table",
        "The",
        "TSK",
        "UCO",
        "URL",
        "USB",
        "USN",
        "UTC",
        "UTF-8",
        "Unicode",
        "VSS",
        "Windows",
        "YARA",
        "ZIP",
        "exFAT",
        "ext4",
        "llama.cpp",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
        "Creation",
        "Modification",
        "Access",
        "Deletion",
        "Time",
        "Times",
        "Entry",
        "Record",
        "Records",
        "File",
        "Name",
        "Standard",
        "Information",
        "Data",
        "Change",
        "Metadata",
        "Content",
        "Last",
        "Birth",
        "Recycled",
        "Deleted",
    ]
)
# Words that may start a sentence with a capital letter (compared in lower case).
STARTERS: frozenset[str] = frozenset(
    [
        "a",
        "an",
        "the",
        "this",
        "that",
        "these",
        "those",
        "there",
        "here",
        "it",
        "its",
        "no",
        "none",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "each",
        "every",
        "all",
        "some",
        "several",
        "many",
        "most",
        "both",
        "either",
        "neither",
        "only",
        "on",
        "at",
        "in",
        "into",
        "from",
        "between",
        "during",
        "after",
        "before",
        "since",
        "until",
        "by",
        "for",
        "of",
        "to",
        "with",
        "without",
        "within",
        "across",
        "among",
        "about",
        "above",
        "below",
        "over",
        "under",
        "around",
        "near",
        "overall",
        "together",
        "also",
        "however",
        "additionally",
        "further",
        "furthermore",
        "finally",
        "then",
        "thus",
        "therefore",
        "taken",
        "according",
        "based",
        "deleted",
        "file",
        "files",
        "record",
        "records",
        "entry",
        "entries",
        "recycle",
        "timeline",
        "analysis",
        "results",
        "result",
        "documents",
        "document",
        "images",
        "image",
        "video",
        "videos",
        "audio",
        "media",
        "hash",
        "hashes",
        "signature",
        "signatures",
        "malware",
        "carving",
        "carved",
        "users",
        "account",
        "accounts",
        "sid",
        "sids",
        "timestamps",
        "timestamp",
        "activity",
        "events",
        "event",
        "creation",
        "modification",
        "access",
        "deletion",
        "observed",
        "inferred",
        "cross-check",
        "cross-checks",
        "parsers",
        "parser",
        "earliest",
        "latest",
        "first",
        "last",
        "total",
        "zero",
        "count",
        "counts",
        "rows",
        "row",
        "findings",
        "finding",
        "usn",
        "mft",
        "ntfs",
        "the",
        "windows",
        "two-parser",
        "classifier",
        "classifiers",
        "scores",
        "score",
        "labels",
        "label",
        "flagged",
        "flags",
        "flag",
        "none",
        "nothing",
        "other",
        "others",
        "another",
        "more",
        "fewer",
        "less",
        "where",
        "when",
        "which",
        "what",
        "while",
        "whereas",
        "although",
        "though",
        "because",
        "as",
        "if",
        "unless",
        "not",
        "neither",
        "nor",
        "yes",
    ]
)


@dataclass
class Sentence:
    text: str
    ids: list[str]


Issue = tuple[str, str]  # (fixed reason, detail with the offending token)

# Fixed reasons. They never quote the sentence, so a report can list them safely.
R_LONG = "too long"
R_NO_CITATION = "does not end with finding IDs in square brackets"
R_UNKNOWN_ID = "cites a finding ID that does not exist"
R_NOT_GIVEN = "cites a finding that was not among the rows given for this part"
R_EMPTY = "has no statement before its citation"
R_QUOTE = "quoted value not found in the cited rows"
R_QUOTE_INSTRUCTION = "quotes evidence text that reads like an instruction or names a person"
R_UNCITED_ID = "names a finding ID it does not cite"
R_IDENTIFIER = "SID, hash, or record address not found in the cited rows"
R_DATE = "date or time not found in the cited rows"
R_PATH = "path or file name not found in the cited rows"
R_NUMBER = "number not found in the cited rows or the computed values"
R_PERSON = "refers to a person"
R_USER = "says 'user' where an account SID is meant"
R_OWNER = "says 'owner' without 'account SID'"
R_ACCOUNT = "names an account without 'account SID'"
R_INTENT = "states or suggests intent"
R_NAME = "capitalised word that could be a name and is not a known term"
R_INSTRUCTION = "reads like an instruction to a model"
R_ECHO = "repeats evidence text outside a quoted path"
R_CLAIM = "makes a claim the cited rows do not record"


@dataclass
class Rejected:
    text: str
    ids: list[str]
    reasons: list[str]
    details: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    kept: list[Sentence] = field(default_factory=list)
    removed: list[Rejected] = field(default_factory=list)

    def extend(self, other: VerifyResult) -> None:
        self.kept.extend(other.kept)
        self.removed.extend(other.removed)


# --------------------------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------------------------

_SPLIT_AFTER_CITATION = re.compile(
    r"(\[\s*F-[0-9]{6,}(?:\s*[,;]\s*F-[0-9]{6,})*\s*\]\s*[.!?]?)(?=\s|$)"
)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[\"'“`(\[]?[A-Z0-9$])")
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)]|#+)\s+")


def clean_output(text: str) -> str:
    """Model output with control and bidi characters removed (line breaks kept)."""
    out = []
    for ch in text.replace("\r\n", "\n").replace("\r", "\n"):
        if ch == "\n":
            out.append(ch)
        elif unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            continue
        else:
            out.append(ch)
    return "".join(out)


def _mask_quotes(text: str) -> str:
    """Replace quoted spans with same-length filler so splitting never breaks inside them."""
    return QUOTE_RE.sub(lambda m: "q" * len(m.group(0)), text)


def split_sentences(text: str) -> list[str]:
    """Split a draft into sentences. Every sentence that ends in a citation is cut after it."""
    text = clean_output(text)
    lines = [_BULLET.sub("", line) for line in text.split("\n")]
    flat = " ".join(line.strip() for line in lines if line.strip())
    if not flat:
        return []
    out: list[str] = []
    pos = 0
    chunks: list[str] = []
    for m in _SPLIT_AFTER_CITATION.finditer(flat):
        chunks.append(flat[pos : m.end()])
        pos = m.end()
    chunks.append(flat[pos:])
    for chunk in chunks:
        masked = _mask_quotes(chunk)
        start = 0
        for m in _SENTENCE_END.finditer(masked):
            piece = chunk[start : m.start()].strip()
            if piece:
                out.append(piece)
            start = m.end()
        piece = chunk[start:].strip()
        if piece:
            out.append(piece)
    return out


# --------------------------------------------------------------------------------------------
# Value pools built from the cited rows
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Stamp:
    """A date or time as written, with its precision."""

    year: int | None
    month: int | None
    day: int | None
    hour: int | None = None
    minute: int | None = None
    second: int | None = None
    fraction: str | None = None  # digits as written


def _stamp_from_match(m: re.Match[str]) -> Stamp | None:
    g = m.groupdict()
    try:
        year = int(g["y"]) if g.get("y") else None
        if g.get("mon"):
            month: int | None = _MONTHS[g["mon"].lower().rstrip(".")]
        else:
            month = int(g["mo"]) if g.get("mo") else None
        day = int(g["d"]) if g.get("d") else None
        hour = int(g["h"]) if g.get("h") else None
        minute = int(g["mi"]) if g.get("mi") else None
        second = int(g["s"]) if g.get("s") else None
    except (KeyError, ValueError):
        return None
    frac = g.get("f")
    stamp = Stamp(year, month, day, hour, minute, second, frac)
    tz = (g.get("tz") or "").upper()
    if tz and tz not in {"Z", "UTC", "GMT"} and None not in (year, month, day, hour, minute):
        sign = -1 if tz.startswith("-") else 1
        digits = tz[1:].replace(":", "")
        offset = _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)) * sign
        try:
            local = _dt.datetime(year, month, day, hour, minute, second or 0)  # type: ignore[arg-type]
        except ValueError:
            return None
        utc = local - offset
        stamp = Stamp(utc.year, utc.month, utc.day, utc.hour, utc.minute, second, frac)
    if stamp.month is not None and not 1 <= stamp.month <= 12:
        return None
    if stamp.day is not None and not 1 <= stamp.day <= 31:
        return None
    return stamp


def _stamp_matches(said: Stamp, known: Stamp) -> bool:
    for attr in ("year", "month", "day", "hour", "minute", "second"):
        want = getattr(said, attr)
        if want is None:
            continue
        if getattr(known, attr) != want:
            return False
    if said.fraction:
        have = (known.fraction or "").ljust(len(said.fraction), "0")
        if have[: len(said.fraction)] != said.fraction:
            return False
    return True


def find_stamps(text: str) -> list[tuple[int, int, Stamp]]:
    """Every date or time in ``text`` as ``(start, end, Stamp)``, longest forms first."""
    found: list[tuple[int, int, Stamp]] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for rx in (ISO_DATE_RE, DMY_DATE_RE, MDY_DATE_RE, MONTH_YEAR_RE, TIME_ONLY_RE):
        for m in rx.finditer(text):
            if not free(m.start(), m.end()):
                continue
            stamp = _stamp_from_match(m)
            if stamp is None:
                continue
            found.append((m.start(), m.end(), stamp))
            taken.append((m.start(), m.end()))
    found.sort(key=lambda t: t[0])
    return found


def _norm_path(text: str) -> str:
    out = text.replace("\\", "/")
    while "//" in out:
        out = out.replace("//", "/")
    return out


def _decimal(text: str) -> Decimal | None:
    try:
        return Decimal(text.replace(",", ""))
    except InvalidOperation:
        return None


@dataclass
class Pool:
    """Everything the cited rows (and code-computed values) let a sentence say."""

    strings: list[str] = field(default_factory=list)
    stamps: list[Stamp] = field(default_factory=list)
    numbers: set[Decimal] = field(default_factory=set)
    code_words: set[str] = field(default_factory=set)
    echo_grams: set[tuple[str, ...]] = field(default_factory=set)

    def add_value(self, value: Any, *, field_name: str = "") -> None:
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, int | float):
            dec = _decimal(repr(value)) if isinstance(value, float) else Decimal(value)
            if dec is not None:
                self.numbers.add(dec)
            self.strings.append(str(value))
            return
        text = str(value)
        self.strings.append(text)
        rest = text
        for start, end, stamp in find_stamps(text):
            self.stamps.append(stamp)
            rest = rest[:start] + " " * (end - start) + rest[end:]
        for rx in (HASH_RE, SID_RE, INODE_RE, ID_RE):
            rest = rx.sub(" ", rest)
        for m in re.finditer(r"\d+(?:\.\d+)?", rest):
            dec = _decimal(m.group(0))
            if dec is not None:
                self.numbers.add(dec)
        if field_name in CODE_FIELDS:
            for w in WORD_RE.findall(text.replace("_", " ")):
                self.code_words.add(w.lower())

    def add_row(self, row: Mapping[str, Any]) -> None:
        for key, value in row.items():
            self.add_value(value, field_name=key)

    def has_text(self, token: str) -> bool:
        """``token`` appears in a pooled string (paths compared with ``/`` for ``\\``)."""
        want = _norm_path(token.strip())
        if not want:
            return True
        low = want.lower()
        for s in self.strings:
            have = _norm_path(s)
            if want in have:
                return True
            # NTFS names are case-insensitive; accept a case difference in a path or name.
            if ("/" in want or "." in want) and low in have.lower():
                return True
        return False

    def has_stamp(self, said: Stamp) -> bool:
        return any(_stamp_matches(said, known) for known in self.stamps)

    def has_number(self, text: str, unit: str | None, extra: set[Decimal]) -> bool:
        value = _decimal(text)
        if value is None:
            return False
        places = -value.as_tuple().exponent if "." in text else 0  # type: ignore[operator]
        unit_l = (unit or "").lower()
        if unit_l in {"%", "percent"}:
            return value in extra
        candidates = self.numbers | extra
        if unit_l in _UNITS:
            for base in _UNITS[unit_l]:
                for n in candidates:
                    exact = n / base
                    # Whole units must be exact; with decimals, rounding to the digits given.
                    if exact == value or (places > 0 and round(exact, places) == value):
                        return True
            return False
        if value in candidates:
            return True
        return any(
            n != n.to_integral_value() and round(n, places) == value and places > 0
            for n in candidates
        )


def _grams(text: str, n: int = 4) -> set[tuple[str, ...]]:
    words = re.findall(r"[a-z0-9']+", text.lower())
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


# --------------------------------------------------------------------------------------------
# The verifier
# --------------------------------------------------------------------------------------------


class Verifier:
    """Checks drafted sentences against the finding rows they cite.

    ``lookup(finding_id)`` returns the row or ``None``. ``allowed_ids`` (optional) is the set of
    IDs the model was given; ``values`` are values computed by code and passed to the model
    (counts, first and last times, spans); ``evidence_rows`` are every row the model saw, for
    the echo check.
    """

    def __init__(
        self,
        lookup: Lookup,
        *,
        allowed_ids: Iterable[str] | None = None,
        values: Iterable[Any] = (),
        evidence_rows: Iterable[Mapping[str, Any]] = (),
    ) -> None:
        self.lookup = lookup
        self.allowed_ids = set(allowed_ids) if allowed_ids is not None else None
        self.value_pool = Pool()
        for v in values:
            self.value_pool.add_value(v)
        self.echo: set[tuple[str, ...]] = set()
        for row in evidence_rows:
            self._add_echo(row)

    def _add_echo(self, row: Mapping[str, Any]) -> None:
        for name in ECHO_FIELDS:
            value = row.get(name)
            if isinstance(value, str):
                self.echo |= _grams(value.replace("\\", " ").replace("/", " "))

    # -- public --------------------------------------------------------------------------------

    def verify_text(self, text: str) -> VerifyResult:
        result = VerifyResult()
        for sentence in split_sentences(text):
            ids, issues = self.check_detailed(sentence)
            if issues:
                reasons = list(dict.fromkeys(r for r, _ in issues))
                details = list(dict.fromkeys(d for _, d in issues))
                result.removed.append(Rejected(sentence, ids, reasons, details))
            else:
                result.kept.append(Sentence(sentence, ids))
        return result

    def check(self, sentence: str) -> tuple[list[str], list[str]]:
        """``(cited ids, reasons)``; an empty reason list means the sentence is kept.

        Reasons are fixed phrases that never quote the sentence (so a report can list them
        without repeating evidence text); ``check_detailed`` also gives the offending token.
        """
        ids, issues = self.check_detailed(sentence)
        return ids, list(dict.fromkeys(r for r, _ in issues))

    def check_detailed(self, sentence: str) -> tuple[list[str], list[Issue]]:
        issues: list[Issue] = []
        if len(sentence) > MAX_SENTENCE_CHARS:
            issues.append((R_LONG, f"{len(sentence)} characters"))
        m = END_CITATION_RE.search(sentence)
        if not m:
            ids = sorted(set(ID_RE.findall(sentence)))
            return ids, [*issues, (R_NO_CITATION, "")]
        ids = [i.strip() for i in re.split(r"[,;]", m.group(1))]
        body = sentence[: m.start()].strip()
        rows: list[Mapping[str, Any]] = []
        for fid in dict.fromkeys(ids):
            row = self.lookup(fid)
            if row is None:
                issues.append((R_UNKNOWN_ID, fid))
                continue
            if self.allowed_ids is not None and fid not in self.allowed_ids:
                issues.append((R_NOT_GIVEN, fid))
            rows.append(row)
        if len(re.findall(r"[A-Za-z]{2,}", body)) < 3:
            issues.append((R_EMPTY, ""))
        if issues:
            return ids, issues
        pool = Pool(stamps=list(self.value_pool.stamps), numbers=set(self.value_pool.numbers))
        pool.strings.extend(self.value_pool.strings)
        echo = set(self.echo)
        for row in rows:
            pool.add_row(row)
            for name in ECHO_FIELDS:
                value = row.get(name)
                if isinstance(value, str):
                    echo |= _grams(value.replace("\\", " ").replace("/", " "))
        issues.extend(self._check_body(body, ids, pool, echo))
        issues.extend(_claims(body, rows))
        return ids, issues

    # -- the checks ----------------------------------------------------------------------------

    def _check_body(  # noqa: PLR0912 - one pass over each kind of token
        self, body: str, ids: list[str], pool: Pool, echo: set[tuple[str, ...]]
    ) -> list[Issue]:
        issues: list[Issue] = []
        work = body
        # Values computed by code (and the count of cited findings); percentages must be one.
        extra = {Decimal(len(set(ids)))} | self.value_pool.numbers

        def blank(text: str, a: int, b: int) -> str:
            return text[:a] + " " * (b - a) + text[b:]

        # Quoted values: each must appear in a cited row, and must not read like an instruction.
        for m in list(QUOTE_RE.finditer(work)):
            value = next(g for g in m.groups() if g is not None)
            if not pool.has_text(value):
                issues.append((R_QUOTE, _show(value)))
            if INSTRUCTION_RE.search(value) or PERSON_RE.search(value):
                issues.append((R_QUOTE_INSTRUCTION, _show(value)))
            work = blank(work, m.start(), m.end())
        # IDs written inside the sentence must be cited at its end.
        for m in ID_RE.finditer(work):
            if m.group(0) not in ids:
                issues.append((R_UNCITED_ID, m.group(0)))
            work = blank(work, m.start(), m.end())
        for rx in (SID_RE, HASH_RE, INODE_RE):
            for m in rx.finditer(work):
                token = m.group(0)
                if not pool.has_text(token) and not pool.has_text(token.lower()):
                    issues.append((R_IDENTIFIER, token))
                work = blank(work, m.start(), m.end())
        for start, end, stamp in find_stamps(work):
            if not pool.has_stamp(stamp):
                issues.append((R_DATE, _show(work[start:end].strip())))
            work = blank(work, start, end)
        for rx in (WIN_PATH_RE, BACKSLASH_PATH_RE, POSIX_PATH_RE, SYSFILE_RE, FILENAME_RE):
            for m in rx.finditer(work):
                token = m.group(0).rstrip(".,;:!?)")
                low = token.lower()
                if (
                    low in NOT_FILENAMES
                    or low in SYSTEM_NAMES
                    or (rx is SYSFILE_RE and low.split(":")[0] in SYSTEM_NAMES)
                ):
                    work = blank(work, m.start(), m.end())
                    continue
                if not pool.has_text(token):
                    issues.append((R_PATH, _show(token)))
                work = blank(work, m.start(), m.end())
        for m in DIGIT_TERMS_RE.finditer(work):
            work = blank(work, m.start(), m.end())
        for m in NUMBER_RE.finditer(work):
            if not pool.has_number(m.group("num"), m.group("unit"), extra):
                issues.append((R_NUMBER, _show(m.group(0).strip())))
            work = blank(work, m.start(), m.end())
        issues.extend(_wording(work))
        issues.extend(_names(work, pool))
        if INSTRUCTION_RE.search(work):
            issues.append((R_INSTRUCTION, ""))
        copied = _grams(work) & echo
        if copied:
            issues.append((R_ECHO, _show(" ".join(sorted(copied)[0]))))
        return issues


def _show(text: str, limit: int = 60) -> str:
    text = inputs.clean_text(text)
    return repr(text if len(text) <= limit else text[:limit] + "...")


def _wording(text: str) -> list[Issue]:
    issues: list[Issue] = []
    for rx, why in (
        (PERSON_RE, R_PERSON),
        (USER_RE, R_USER),
        (OWNER_RE, R_OWNER),
        (ACCOUNT_RE, R_ACCOUNT),
        (INTENT_RE, R_INTENT),
    ):
        m = rx.search(text)
        if m:
            issues.append((why, repr(m.group(0))))
    return issues


def _names(text: str, pool: Pool) -> list[Issue]:
    """Capitalised words that are neither technical terms nor code-made row values."""
    issues: list[Issue] = []
    first = True
    for m in WORD_RE.finditer(text):
        word = m.group(0).strip("'\u2019-")
        if not word:
            continue
        is_first, first = first, False
        if not word[0].isupper():
            continue
        if word in TERMS or word.lower() in pool.code_words:
            continue
        if is_first and word.lower() in STARTERS:
            continue
        issues.append((R_NAME, repr(word)))
    return issues


def _code_text(row: Mapping[str, Any]) -> str:
    return " ".join(str(row.get(k, "")) for k in CODE_FIELDS).lower().replace("_", " ")


def _claims(body: str, rows: list[Mapping[str, Any]]) -> list[Issue]:
    """Claim words that need support from code-made fields of a cited row (not its message)."""
    issues: list[Issue] = []
    for rx, test, what in CLAIMS:
        m = rx.search(body)
        if m and not any(test(r) for r in rows):
            issues.append((R_CLAIM, f"{what} ({m.group(0)!r})"))
    return issues


def _is_deleted(row: Mapping[str, Any]) -> bool:
    return (
        row.get("allocated") is False
        or row.get("category") in {"deletion", "recycle_bin"}
        or "delet" in _code_text(row)
    )


CLAIMS: tuple[tuple[re.Pattern[str], Callable[[Mapping[str, Any]], bool], str], ...] = (
    (re.compile(r"\bdelet\w*|\bremov\w*|\berase\w*", re.I), _is_deleted, "deletion"),
    (
        re.compile(r"\brecycle\s*bin\b|\brecycled\b", re.I),
        lambda r: r.get("category") == "recycle_bin" or "recycle" in _code_text(r),
        "recycle bin",
    ),
    (
        re.compile(r"\bflag(?:ged|s)?\b", re.I),
        lambda r: r.get("sensitive_flag") is True,
        "classifier flag",
    ),
    (
        re.compile(r"\bmalware\b|\bmalicious\b|\bvirus\w*|\btrojan\w*", re.I),
        lambda r: r.get("category") in {"malware", "hash"} or bool(r.get("hashset_name")),
        "malware match",
    ),
    (
        re.compile(r"\bdisagree\w*|\bconflict\w*", re.I),
        lambda r: r.get("xval_status") == "disagree" or "disagree" in _code_text(r),
        "parser disagreement",
    ),
    (
        re.compile(r"\bcreat\w*", re.I),
        lambda r: "creat" in _code_text(r) or "birth" in _code_text(r),
        "creation",
    ),
    (
        re.compile(r"\bmodif\w*", re.I),
        lambda r: "modif" in _code_text(r),
        "modification",
    ),
    (
        re.compile(r"\baccess(?:ed)?\b", re.I),
        lambda r: "access" in _code_text(r),
        "access",
    ),
)
