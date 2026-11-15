"""``evidence-report RUN_DIR``: write the run report (Milestone 4E; docs/workflows/report.md).

The runner (``forensic-analyze``) calls this before it writes ``outputs.sha256`` and its
signature, so the report is hashed and signed with the run. Run by hand on a finished run
folder, it re-hashes and re-signs the folder afterwards (unless ``--no-resign``), so the
signed list never goes stale.
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
    return p.parse_args(argv)


def _resign(run_dir: Path) -> str:
    """Re-hash and re-sign a finished run after the report changed. Returns a status line."""
    try:
        from forensic_analyze import signing  # noqa: PLC0415
    except ImportError:
        return "outputs.sha256 is now out of date and forensic_analyze is not installed to redo it"
    real = run_dir.resolve()
    if len(real.parents) < 3 or real.parents[1].name != "cases":
        return (
            "outputs.sha256 is now out of date: the run folder is not under <output>/cases/, "
            "so it was not re-signed"
        )
    output_root = real.parents[2]
    res = signing.hash_and_sign(run_dir, output_root)
    if res.error:
        return f"outputs.sha256 was rewritten but not signed: {res.error}"
    return "outputs.sha256 and its signature were rewritten to include the new report"


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
    signed_before = (run_dir / "outputs.sha256").exists()
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
    if signed_before and not args.no_resign:
        status = _resign(run_dir)
        with contextlib.suppress(OSError):
            sessionlog.log_event(TOOL_NAME, "report_resigned", run_dir=str(run_dir), status=status)
        print(status, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
