"""``evidence-report RUN_DIR``: write the run report (Milestone 4E; docs/workflows/report.md).

The runner (``forensic-analyze``) calls this before it writes ``outputs.sha256`` and its
signature, so the report is hashed and signed with the run. Run by hand on a finished run
folder, it re-hashes and re-signs the folder afterwards (unless ``--no-resign``), so the
signed list never goes stale. Before writing anything it checks the run as ``forensic-analyze
--verify`` does: if any file other than the ones the report replaces (report.html, report.md,
logs/report-provenance.json) has changed, is missing or is unlisted, or the signature does not
verify, it refuses, so a changed file is never given a fresh signature. ``--force`` re-signs
anyway; that is recorded in the run log and the session log, and the previous list and
signature are kept as ``outputs.sha256.prev-<n>`` either way.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from airlock_common import sessionlog
from evidence_report import TOOL_NAME, inputs, llm, mapreduce, render


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Write report.html and report.md for one forensic-analyze run folder.",
    )
    p.add_argument("run_dir", help="the run folder (<output>/cases/<case>/<run_id>)")
    p.add_argument(
        "--no-model",
        action="store_true",
        help="do not use the local model; the AI sections say 'No AI draft'",
    )
    p.add_argument(
        "--model-url",
        default=None,
        help=f"llama-server address on 127.0.0.1 (default: ${llm.URL_ENV} or the AI config)",
    )
    p.add_argument(
        "--no-start",
        action="store_true",
        help="use the model server only if it is already running; never start it",
    )
    p.add_argument("--seed", type=int, default=llm.DEFAULT_SEED, help="fixed decoding seed")
    p.add_argument(
        "--data-chars",
        type=int,
        default=None,
        help="characters of row data per model call (default: from the model's context size)",
    )
    p.add_argument("--max-calls", type=int, default=None, help="limit on model calls")
    p.add_argument(
        "--no-resign",
        action="store_true",
        help="do not re-hash and re-sign a run folder that already has outputs.sha256",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="re-sign even if the run folder already fails verification (recorded in the logs)",
    )
    return p.parse_args(argv)


# Files build() replaces outright: an earlier edit to them is overwritten, not signed.
REPLACED_BEFORE = frozenset({"report.html", "report.md", "logs/report-provenance.json"})
# After build(): the same, plus the report log it appends to.
REPLACED_AFTER = REPLACED_BEFORE | {"logs/report.jsonl"}


class _NoResign(Exception):
    """The run is signed but cannot be re-signed here; the message says why."""


def _output_root(run_dir: Path) -> Path:
    real = run_dir.resolve()
    if len(real.parents) < 3 or real.parents[1].name != "cases":
        raise _NoResign(
            "the run folder is not under <output>/cases/, so it cannot be re-signed; "
            "use --no-resign to write the report without re-signing"
        )
    return real.parents[2]


def _precheck(run_dir: Path, force: bool) -> None:
    """Refuse before writing anything when the signed run has changed (or cannot be signed)."""
    try:
        from forensic_analyze import signing  # noqa: PLC0415
    except ImportError as exc:
        raise _NoResign(
            "forensic_analyze is not installed to check and re-sign the run; "
            "use --no-resign to write the report without re-signing"
        ) from exc
    try:
        signing.check_before_resign(
            run_dir,
            _output_root(run_dir),
            REPLACED_BEFORE.__contains__,
            force=force,
            tool=TOOL_NAME,
        )
    except signing.ResignRefused as exc:
        raise _NoResign(f"{exc}. Explain the change first, or use --force (logged)") from exc
    except (signing.SigningError, OSError) as exc:
        raise _NoResign(
            f"the run cannot be re-signed ({exc}); run it with sudo, "
            "or use --no-resign to write the report without re-signing"
        ) from exc


def _resign(run_dir: Path, force: bool) -> tuple[bool, str]:
    """Re-hash and re-sign a finished run after the report changed. Returns (ok, status)."""
    from forensic_analyze import signing  # noqa: PLC0415

    try:
        res = signing.resign(
            run_dir,
            _output_root(run_dir),
            REPLACED_AFTER.__contains__,
            force=force,
            tool=TOOL_NAME,
            reason="report re-rendered",
        )
    except (signing.SigningError, OSError, _NoResign) as exc:
        return False, f"outputs.sha256 was not rewritten: {exc}"
    if res.error:
        return False, f"outputs.sha256 was rewritten but not signed: {res.error}"
    status = "outputs.sha256 and its signature were rewritten to include the new report"
    if force:
        status += " (--force given; recorded in logs/run.jsonl and the session log)"
    return True, status


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(
            f"{TOOL_NAME}: {run_dir} is not a folder. Give the run folder that holds run.json.",
            file=sys.stderr,
        )
        return 2
    settings = None
    if args.data_chars or args.max_calls:
        settings = mapreduce.Settings()
        if args.data_chars:
            settings.data_chars = max(500, args.data_chars)
        if args.max_calls:
            settings.max_calls = max(0, args.max_calls)
    resign = (run_dir / "outputs.sha256").exists() and not args.no_resign
    if resign:
        try:
            _precheck(run_dir, args.force)
        except _NoResign as exc:
            with contextlib.suppress(OSError):
                sessionlog.log_event(
                    TOOL_NAME, "report_refused", run_dir=str(run_dir), reason=str(exc)
                )
            print(f"{TOOL_NAME}: the report was not written: {exc}.", file=sys.stderr)
            return 1
    try:
        html_path, md_path = render.build(
            run_dir,
            use_model=not args.no_model,
            model_url=args.model_url,
            start_server=not args.no_start,
            seed=args.seed,
            settings=settings,
        )
    except (render.ReportError, inputs.InputError, llm.LlmError) as exc:
        with contextlib.suppress(OSError):
            sessionlog.log_event(TOOL_NAME, "report_failed", run_dir=str(run_dir), error=str(exc))
        print(f"{TOOL_NAME}: the report was not written: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        with contextlib.suppress(OSError):
            sessionlog.log_event(TOOL_NAME, "report_failed", run_dir=str(run_dir), error=str(exc))
        print(
            f"{TOOL_NAME}: the report was not written ({exc.strerror or exc}). "
            "Check that the output drive is writable and has free space, then run it again.",
            file=sys.stderr,
        )
        return 1
    print(html_path)
    print(md_path)
    if resign:
        ok, status = _resign(run_dir, args.force)
        with contextlib.suppress(OSError):
            sessionlog.log_event(
                TOOL_NAME, "report_resigned", run_dir=str(run_dir), status=status, ok=ok
            )
        print(status, file=sys.stderr)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
