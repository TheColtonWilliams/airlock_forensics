"""``evidence-describe``: descriptions of cleared files by the local model (task 4B.8).

Only files that ``evidence-screen`` cleared are sent, matched by SHA-256 (the file is hashed
again here, so a file changed after screening is refused). Flagged files and files that could
not be screened are never sent; they get a ``not_cleared`` row. Requests go to ``llama-server``
on 127.0.0.1 with a fixed prompt file, temperature 0, and a fixed seed. A refusal or an empty
reply is written as ``model_declined``; no file is ever dropped from the output.

Output columns: path, sha256, kind, status, description, model_id, model_sha256,
mmproj_sha256, prompt_id, prompt_sha256, tier, seed, label, detail. Every description is
labelled "AI-generated" and is triage, never evidence.

Documents (text summary, OCR of scanned pages), audio (transcript summary), and video (native
video input through ``llama-mtmd-cli``) use the same provenance columns; see
``airlock_ai.documents``, ``airlock_ai.audio``, and ``airlock_ai.video``.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import os
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from airlock_ai import AI_LABEL, datablock, llm
from airlock_ai import config as cfgmod
from airlock_common import hashing, proc, sessionlog

TOOL = "evidence-describe"
CSV_COLUMNS: tuple[str, ...] = (
    "path",
    "sha256",
    "kind",
    "status",
    "description",
    "model_id",
    "model_sha256",
    "mmproj_sha256",
    "prompt_id",
    "prompt_sha256",
    "tier",
    "seed",
    "label",
    "detail",
)
# described: model text present; model_declined: refusal or empty reply; not_cleared: not sent
# because screening did not clear it; error: could not be processed.
STATUSES = ("described", "model_declined", "not_cleared", "error")


class DescribeError(RuntimeError):
    """Describing could not start (no screening results, no model server)."""


@dataclass
class DescribeResult:
    path: str
    sha256: str
    kind: str  # image | video | document | audio | page
    status: str
    description: str = ""
    model_id: str = ""
    model_sha256: str = ""
    mmproj_sha256: str = ""
    prompt_id: str = ""
    prompt_sha256: str = ""
    tier: str = ""
    seed: int = 0
    detail: str = ""

    @property
    def ai_row(self) -> bool:
        return self.status in {"described", "model_declined"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessOutput:
    """Results of one document or audio file, plus what the module needs for its rows."""

    results: list[DescribeResult]
    extra: dict[str, Any]


class Describer:
    """One model session: fixed prompts, greedy decoding, provenance on every answer."""

    def __init__(
        self,
        client: llm.LlamaClient,
        *,
        info: llm.ModelInfo | None = None,
        ai_config: dict[str, Any] | None = None,
        tier: str = "",
    ) -> None:
        self.client = client
        self.cfg = ai_config or cfgmod.load_ai_config()
        self.info = info or llm.model_info(client)
        self.seed = int(self.cfg["llama"].get("seed", 42))
        self.max_tokens = int(self.cfg["llama"].get("max_tokens", 384))
        self.tier = tier or self.info.tier
        self._prompts: dict[str, cfgmod.Prompt] = {}

    def prompt(self, prompt_id: str) -> cfgmod.Prompt:
        if prompt_id not in self._prompts:
            self._prompts[prompt_id] = cfgmod.load_prompt(prompt_id)
        return self._prompts[prompt_id]

    def _result(  # noqa: PLR0917
        self, path: str, sha: str, kind: str, prompt_id: str, reply: llm.Reply, detail: str = ""
    ) -> DescribeResult:
        p = self.prompt(prompt_id)
        status = "model_declined" if reply.declined else "described"
        if reply.declined and not detail:
            detail = f"model reply: {reply.raw_excerpt!r}" if reply.raw_excerpt else "empty reply"
        return DescribeResult(
            path=path,
            sha256=sha,
            kind=kind,
            status=status,
            description="" if reply.declined else reply.text,
            model_id=self.info.model_id,
            model_sha256=self.info.model_sha256,
            mmproj_sha256=self.info.mmproj_sha256,
            prompt_id=p.prompt_id,
            prompt_sha256=p.sha256,
            tier=self.tier,
            seed=self.seed,
            detail=detail,
        )

    def image(
        self, path: Path, sha: str, *, kind: str = "image", prompt_id: str = "describe_image"
    ) -> DescribeResult:
        reply = self.client.chat(
            self.prompt(prompt_id).text, image=path, seed=self.seed, max_tokens=self.max_tokens
        )
        return self._result(str(path), sha, kind, prompt_id, reply)

    def text(
        self, evidence_text: str, path: str, sha: str, *, kind: str, prompt_id: str, data_kind: str
    ) -> DescribeResult:
        """Summarise evidence text. The text goes only inside a delimited data block."""
        block = datablock.wrap(evidence_text, kind=data_kind)
        reply = self.client.chat(
            self.prompt(prompt_id).text, text=block, seed=self.seed, max_tokens=self.max_tokens
        )
        return self._result(path, sha, kind, prompt_id, reply)


def _verdicts_from(screen: Any) -> dict[str, str]:
    if screen is None:
        return {}
    if isinstance(screen, str | os.PathLike):
        from airlock_ai.screen import read_verdicts  # noqa: PLC0415

        return read_verdicts(screen)
    if isinstance(screen, Mapping):
        return {str(k): str(v) for k, v in screen.items()}
    out: dict[str, str] = {}
    for r in screen:  # ScreenResult objects
        if out.get(r.sha256) in {"flagged", "error"}:
            continue
        out[r.sha256] = r.verdict
    return out


def describe_paths(
    paths_in: Iterable[str | os.PathLike[str]],
    out_csv: str | os.PathLike[str] | None,
    tier: str | None = None,
    *,
    screen: Any = None,
    describer: Describer | None = None,
    client: llm.LlamaClient | None = None,
    start_server: bool = True,
) -> list[DescribeResult]:
    """Describe cleared images. ``screen`` is a screen.csv path, a ``{sha256: verdict}`` map,
    or ``ScreenResult`` objects; without it nothing is sent and every file is ``not_cleared``.
    """
    verdicts = _verdicts_from(screen)
    items: list[tuple[Path, str]] = []
    results: dict[str, DescribeResult] = {}
    order: list[str] = []
    for raw in paths_in:
        p = Path(os.path.abspath(raw))
        order.append(str(p))
        try:
            digest = hashing.sha256_file(p)
        except OSError as exc:
            results[str(p)] = DescribeResult(
                str(p), "", "image", "error", detail=f"cannot read: {exc.strerror}"
            )
            continue
        verdict = verdicts.get(digest, "")
        if verdict != "cleared":
            why = f"screening verdict: {verdict}" if verdict else "not screened"
            results[str(p)] = DescribeResult(
                str(p), digest, "image", "not_cleared", tier=tier or "", detail=why
            )
            continue
        items.append((p, digest))
    if items:
        if describer is None:
            cl = client or llm.LlamaClient()
            with llm.LlamaServer(cl, start=start_server) as live:
                d = Describer(live, tier=tier or "")
                for p, digest in items:
                    results[str(p)] = _safe(d, p, digest)
        else:
            for p, digest in items:
                results[str(p)] = _safe(describer, p, digest)
    ordered = [results[k] for k in order]
    if out_csv is not None:
        write_csv(Path(out_csv), ordered)
    return ordered


def _safe(d: Describer, p: Path, digest: str) -> DescribeResult:
    try:
        return d.image(p, digest)
    except llm.LlmError as exc:
        return DescribeResult(str(p), digest, "image", "error", tier=d.tier, detail=str(exc))


def write_csv(path: Path, results: Sequence[DescribeResult]) -> None:
    from forensic_analyze.csvsafe import csv_cell  # noqa: PLC0415 - shared CSV safety rules

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator="\r\n")
        w.writerow(CSV_COLUMNS)
        for r in results:
            row = r.to_dict()
            row["label"] = f"{AI_LABEL} draft for triage, not evidence" if r.ai_row else ""
            row["seed"] = r.seed if r.ai_row else ""
            w.writerow([csv_cell(row.get(c, "")) for c in CSV_COLUMNS])
    tmp.replace(path)


def summarise(results: Sequence[DescribeResult]) -> dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    counts["total"] = len(results)
    return counts


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def _kind(path: Path) -> str:
    from airlock_ai import audio, documents, video  # noqa: PLC0415
    from airlock_ai.screen import IMAGE_EXTENSIONS  # noqa: PLC0415

    ext = path.suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in video.VIDEO_EXTENSIONS:
        return "video"
    if ext in audio.AUDIO_EXTENSIONS:
        return "audio"
    if ext in documents.DOCUMENT_EXTENSIONS:
        return "document"
    return ""


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0915 - one flat CLI flow
    from airlock_ai import audio, documents, video  # noqa: PLC0415
    from airlock_ai.tools import gpu_render_nodes, sandbox_runner  # noqa: PLC0415

    ap = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Describe files with the local model. Images and videos must have been cleared by "
            "evidence-screen first. Output is AI-generated triage, never evidence."
        ),
    )
    ap.add_argument("inputs", nargs="+", help="files to describe")
    ap.add_argument("-o", "--output", required=True, help="where to write describe.csv")
    ap.add_argument(
        "--screen-csv", help="screen.csv from evidence-screen (needed for images and videos)"
    )
    ap.add_argument(
        "--no-start",
        action="store_true",
        help="do not start the model server; fail if it is not running",
    )
    args = ap.parse_args(argv)
    files = [Path(os.path.abspath(p)) for p in args.inputs]
    missing = [str(p) for p in files if not p.is_file()]
    if missing:
        print(f"evidence-describe: not a file: {missing[0]}. Check the path.", file=sys.stderr)
        return 2
    visual = [p for p in files if _kind(p) in {"image", "video"}]
    if visual and not args.screen_csv:
        print(
            "evidence-describe: images and videos need --screen-csv from evidence-screen. "
            "Run evidence-screen first.",
            file=sys.stderr,
        )
        return 2
    try:
        verdicts = _verdicts_from(args.screen_csv) if args.screen_csv else {}
    except OSError as exc:
        print(
            f"evidence-describe: cannot read {args.screen_csv} ({exc.strerror}).", file=sys.stderr
        )
        return 2
    results: list[DescribeResult] = []
    try:
        cfg = cfgmod.load_ai_config()
        client = llm.LlamaClient()
        with (
            tempfile.TemporaryDirectory(prefix="airlock-describe-") as tmp,
            llm.LlamaServer(client, start=not args.no_start) as live,
        ):
            work = Path(tmp)
            run_tool = sandbox_runner(work)
            d = Describer(live, ai_config=cfg)
            for p in files:
                kind = _kind(p)
                digest = hashing.sha256_file(p)
                if kind in {"image", "video"} and verdicts.get(digest) != "cleared":
                    v = verdicts.get(digest, "")
                    results.append(
                        DescribeResult(
                            str(p),
                            digest,
                            kind,
                            "not_cleared",
                            tier=d.tier,
                            detail=f"screening verdict: {v or 'none'}",
                        )
                    )
                    continue
                try:
                    if kind == "image":
                        results.append(d.image(p, digest))
                    elif kind == "video":
                        gpu_tool = sandbox_runner(work, devices=gpu_render_nodes())
                        results.append(video.describe_video(p, digest, gpu_tool, d, work))
                    elif kind == "document":
                        results += documents.process(p, digest, run_tool, d, work).results
                    elif kind == "audio":
                        results += audio.process(p, digest, run_tool, d, work).results
                    else:
                        results.append(
                            DescribeResult(
                                str(p),
                                digest,
                                "",
                                "error",
                                detail="not an image, video, audio, or document file",
                            )
                        )
                except (llm.LlmError, proc.ToolError, OSError) as exc:
                    results.append(
                        DescribeResult(str(p), digest, kind, "error", tier=d.tier, detail=str(exc))
                    )
    except (llm.LlmError, cfgmod.ConfigError, proc.ToolError) as exc:
        print(
            f"evidence-describe: {exc}. Check that a model tier is staged (ai-probe).",
            file=sys.stderr,
        )
        return 1
    out = Path(args.output)
    write_csv(out, results)
    counts = summarise(results)
    with contextlib.suppress(OSError):
        sessionlog.log_event(TOOL, "describe_done", csv=str(out), **counts)
    print(
        f"{counts['described']} described, {counts['model_declined']} declined by the model, "
        f"{counts['not_cleared']} not sent (not cleared), {counts['error']} errors. "
        f"Results ({AI_LABEL}, triage only): {out}"
    )
    return 0 if counts["error"] == 0 else 4


if __name__ == "__main__":
    raise SystemExit(main())
