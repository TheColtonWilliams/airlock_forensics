"""Helpers shared by the findings and export tests (no tests here).

Named test_findings_support.py so it sits in the findings package's test-file namespace;
pytest collects it and finds nothing to run.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from forensic_analyze import findings

RUN_ID = "R-20261115T101500Z-0a1b2c"
EVIDENCE_ID = "EXHIBIT-01"
EVIDENCE_SHA256 = "5" * 64
MODEL_SHA = "a" * 64
PROMPT_SHA = "b" * 64

# Hostile file names (4G.13). Generated text only, no media.
HOSTILE_NAMES: list[str | bytes] = [
    "=cmd|' /C calc'!A0.txt",
    "+1+1.txt",
    "-2+3.txt",
    "@SUM(1,2).txt",
    "\t=tab-start.txt",
    "\r=cr-start.txt",
    "   =space-then-equals.txt",
    "line one\nline two.txt",
    "carriage\r\nreturn.txt",
    "invoice\u202etxt.exe",
    "isolate\u2066abc\u2069.doc",
    "zero\u200bwidth.txt",
    "bad\ud800surrogate.txt",
    "low\udfffsurrogate.txt",
    "\uff1d1+1 full-width.txt",
    'quote " and , comma.txt',
    "nul\x00byte.txt",
    b"raw-\xff\xfe-bytes=.txt",
    b"=raw-start\xc3.txt",
]


def base_row(**extra: Any) -> dict[str, Any]:
    """A minimal valid part row (no run fields, no finding_id)."""
    row: dict[str, Any] = {
        "category": "inventory",
        "artifact_type": "file_entry",
        "message": "File entry",
        "derivation": "observed",
        "source_tool": "sleuthkit",
        "tool_version": "4.12.1",
        "parser": "fls",
    }
    row.update(extra)
    return row


def full_row(**extra: Any) -> dict[str, Any]:
    """A complete merged row (with run fields and a finding_id)."""
    row = base_row(
        run_id=RUN_ID,
        evidence_id=EVIDENCE_ID,
        evidence_sha256=EVIDENCE_SHA256,
        finding_id="F-000001",
    )
    row.update(extra)
    return row


def writer(run_dir: Path, module: str) -> findings.FindingsWriter:
    return findings.FindingsWriter(
        findings.part_path(run_dir, module),
        run_id=RUN_ID,
        evidence_id=EVIDENCE_ID,
        evidence_sha256=EVIDENCE_SHA256,
        module=module,
    )


def write_parts(run_dir: Path, parts: dict[str, Iterable[dict[str, Any]]]) -> dict[str, int]:
    counts = {}
    for module, rows in parts.items():
        with writer(run_dir, module) as w:
            for row in rows:
                w.emit(row)
            counts[module] = w.count
    return counts


def sample_parts() -> dict[str, list[dict[str, Any]]]:
    """A varied set of rows touching every view, export, and hostile name."""
    inventory = []
    for i, name in enumerate(HOSTILE_NAMES):
        path = (b"/Users/u/" + name) if isinstance(name, bytes) else "/Users/u/" + name
        inventory.append(
            base_row(
                path=path,
                filename=name,
                message=name if isinstance(name, str) else "File entry",
                inode_ref=f"v0:{100 + i}-1",
                size_bytes=i * 10,
                allocated=i % 3 != 0,
                datetime=f"2024-03-0{1 + i % 9}T12:00:0{i % 10}.{i}Z",
                timestamp_desc="Content Modification Time",
                tz_basis="utc",
                source_record=f"modules/inventory/fls.body#L{i + 1}",
            )
        )
    recycle = [
        base_row(
            category="recycle_bin",
            artifact_type="recycle_bin_entry",
            message="Recycle bin entry for /Users/u/report.txt",
            path="/Users/u/report.txt",
            owner_sid="S-1-5-21-1000-2000-3000-1001",
            datetime="2024-03-02T08:00:00Z",
            timestamp_desc="Deletion Time",
            source_tool="RBCmd",
            parser="rbcmd",
            xval_status="disagree",
        )
    ]
    deletion = [
        base_row(
            category="deletion",
            artifact_type="usn_delete",
            message="The USN journal records a delete",
            path="/Users/u/gone.txt",
            datetime="2024-03-02T07:59:59.5Z",
            timestamp_desc="Deletion Time",
            source_tool="dissect",
            parser="dissect.ntfs.usnjrnl",
            xval_status="agree",
        )
    ]
    malware = [
        base_row(
            category="malware",
            artifact_type="hash_match",
            message="SHA-256 matches a known-bad hash set entry",
            path="/Users/u/tool.exe",
            sha256="c" * 64,
            md5="d" * 32,
            hashset_name="test-set",
            hashset_version="2026-11-01",
            match_algorithm="sha256",
            source_tool="airlock_hashsets",
            parser="triage",
        )
    ]
    images = [
        base_row(
            category="images",
            artifact_type="classifier_score",
            message="Classifier score above threshold",
            path="/Users/u/shape-01.png",
            derivation="inferred",
            score=0.91,
            threshold=0.8,
            label="flagged",
            sensitive_flag=True,
            model_id="stub-classifier",
            model_sha256="e" * 64,
            source_tool="stub-classifier",
            parser="screen",
        ),
        base_row(
            category="images",
            artifact_type="ai_description",
            message="A blue square on a white background",
            path="/Users/u/shape-02.png",
            derivation="ai_generated",
            text="A blue square on a white background.",
            confidence=0.5,
            model_id="stub-vlm-q4",
            model_sha256=MODEL_SHA,
            prompt_sha256=PROMPT_SHA,
            source_tool="llama-server",
            parser="describe",
        ),
    ]
    return {
        "inventory": inventory,
        "recycle_bin": recycle,
        "deletion_history": deletion,
        "malware": malware,
        "images": images,
    }


MODULE_ORDER = ["inventory", "recycle_bin", "deletion_history", "users", "malware", "images"]


def build_run(run_dir: Path) -> findings.MergeResult:
    write_parts(run_dir, sample_parts())
    return findings.merge(run_dir, MODULE_ORDER)
