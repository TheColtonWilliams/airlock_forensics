"""Run control (tasks 4C.17, 4C.20, 2B.17, 3A.5, 3A.6, 3A.9).

One run, in order:

1. checks: the target is read-only and not mounted; HPA and DCO queries; SSD warning; SMART
   warning before a Full direct run;
2. write tracer starts; SHA-256 and MD5 of the target in one read pass;
3. copy-first mode: make and verify the copy, hash the drive again, then analyse the copy;
4. root opens the target once as a read-only loop device for the sandboxed parsers;
5. filesystem detection, BitLocker unlock if needed;
6. each module in order: skipped when it does not apply (with the reason), a ``.done`` marker
   when it finished, failures shown at once while the run continues;
7. tracer stops; SHA-256 and MD5 again;
8. findings merged, exports built, ``run.json`` finished, ``evidence-report`` called;
9. optional purge of exported copies; ``outputs.sha256`` and its signature written last.

``run.json`` is written after every step, so a killed run can be resumed with ``--resume``.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing, jsonio, paths, proc, sessionlog, timeutil
from forensic_analyze import case as case_mod
from forensic_analyze import cleanup, fsdetect, mode, presets, signing, tracer
from forensic_analyze import sandbox as sb
from forensic_analyze import target as target_mod
from forensic_analyze.api import ModuleResult, Target, Volume
from forensic_analyze.context import TOOL_NAME, ToolRecorder, build_context, findings_backend
from forensic_analyze.modules import all_modules, load_errors

SCHEMA = 1
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
EXIT_INTEGRITY = 3
DONE = ".done"
CONFIG_KEYS = (
    "target",
    "mode",
    "imager",
    "output",
    "preset",
    "modules",
    "case_id",
    "exhibit_id",
    "examiner",
    "authority_ref",
    "notes",
    "agency",
    "write_blocker",
    "blocker_make",
    "blocker_model",
    "blocker_firmware",
    "blocker_report_url",
    "bitlocker_key_file",
    "purge_exports",
    "images_dir",
    "sandbox",
)

Notify = Callable[[str], None]
Confirm = Callable[[str, str], bool]


class RunAborted(RuntimeError):
    """The run stopped. ``message`` says what failed and what to do next."""

    def __init__(self, message: str, *, run_dir: Path | None = None) -> None:
        super().__init__(message)
        self.run_dir = run_dir


class OutputFull(RunAborted):
    """The output drive filled up."""


class Escalated(RunAborted):
    """forensic-escalate stopped this run (``<run>/ESCALATED`` exists). Nothing more is written."""


# Written by forensic-escalate (airlock_ai.escalate); read here.
ESCALATED_MARKER = "ESCALATED"
PID_FILE = "forensic-analyze.pid"


@dataclass
class RunConfig:
    """Everything that decides what a run does. Saved in ``run.json`` and replayed by --config."""

    target: str
    mode: str = "direct"
    imager: str = "ewf"
    output: str = ""
    preset: str = "quick"
    modules: list[str] = field(default_factory=list)
    case_id: str = ""
    exhibit_id: str = ""
    examiner: str = ""
    authority_ref: str = ""
    notes: str = ""
    agency: str = ""
    write_blocker: str = "unknown"
    blocker_make: str = ""
    blocker_model: str = ""
    blocker_firmware: str = ""
    blocker_report_url: str = ""
    bitlocker_key_file: str = ""
    purge_exports: bool = False
    images_dir: str = ""
    sandbox: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunConfig:
        known = {k: data[k] for k in CONFIG_KEYS if k in data}
        if "modules" in known and not isinstance(known["modules"], list):
            known["modules"] = [m for m in str(known["modules"]).split(",") if m]
        return cls(**known)


@dataclass
class RunInputs:
    """Per-run answers that are recorded but not replayed (who, when, under what authority)."""

    authority: case_mod.AuthorityAck
    clock: case_mod.ClockRecord
    blocker: target_mod.BlockerRecord
    argv: list[str]
    accept_smart_warning: bool = False
    deviations: list[str] = field(default_factory=list)


@dataclass
class Outcome:
    exit_code: int
    run_dir: Path
    message: str
    doc: dict[str, Any]


def new_run_id() -> str:
    return f"R-{timeutil.compact()}-{secrets.token_hex(3)}"


def _is_full_disk(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT)


class Run:
    """One analysis run. Create with ``Run.start`` or ``Run.resume``, then call ``execute``."""

    def __init__(
        self,
        cfg: RunConfig,
        inputs: RunInputs,
        run_dir: Path,
        doc: dict[str, Any],
        *,
        notify: Notify,
        confirm: Confirm,
        resumed: bool,
    ) -> None:
        self.cfg = cfg
        self.inputs = inputs
        self.run_dir = run_dir
        self.doc = doc
        self.notify = notify
        self.confirm = confirm
        self.resumed = resumed
        self.run_id: str = doc["run_id"]
        self.logs = run_dir / "logs"
        self.log_path = self.logs / "run.jsonl"
        self.output_root = Path(cfg.output)
        self._lock_fh: Any = None
        self.handles: list[sb.EvidenceHandle] = []

    # -- construction --------------------------------------------------------------------------

    @classmethod
    def start(cls, cfg: RunConfig, inputs: RunInputs, *, notify: Notify, confirm: Confirm) -> Run:
        run_id = new_run_id()
        case_id = case_mod.safe_id(cfg.case_id or "CASE")
        run_dir = Path(cfg.output) / "cases" / case_id / run_id
        try:
            (run_dir / "logs").mkdir(parents=True, exist_ok=False)
            (run_dir / "modules").mkdir()
        except OSError as exc:
            if _is_full_disk(exc):
                raise OutputFull(
                    "The output drive is full. Free some space and try again."
                ) from exc
            raise RunAborted(f"Cannot create the run folder {run_dir}: {exc.strerror}.") from exc
        doc: dict[str, Any] = {
            "schema": SCHEMA,
            "tool": TOOL_NAME,
            "run_id": run_id,
            "status": "running",
            "config": cfg.to_dict(),
            "argv": inputs.argv,
            "case": {
                "case_id": case_id,
                "exhibit_id": cfg.exhibit_id,
                "examiner": cfg.examiner,
                "authority_ref": cfg.authority_ref,
                "notes": cfg.notes,
                "agency": cfg.agency,
            },
            "authority_ack": inputs.authority.to_dict(),
            "clock": inputs.clock.to_dict(),
            "write_blocker": inputs.blocker.to_dict(),
            "errors": [],
            "deviations": list(inputs.deviations),
            "warnings": [],
            "resumes": [],
            "modules": [],
            "tools": [],
            "tool_versions": {},
            "models": [],
        }
        return cls(cfg, inputs, run_dir, doc, notify=notify, confirm=confirm, resumed=False)

    @classmethod
    def resume(
        cls, run_dir: Path, inputs: RunInputs | None, *, notify: Notify, confirm: Confirm
    ) -> Run:
        path = run_dir / "run.json"
        if not path.exists():
            raise RunAborted(f"{run_dir} has no run.json. Check the folder name and try again.")
        doc = jsonio.load_json(path)
        if doc.get("status") == "complete":
            raise RunAborted(f"Run {doc.get('run_id')} is already complete. Nothing to resume.")
        if doc.get("status") == "escalated" or (run_dir / ESCALATED_MARKER).exists():
            raise RunAborted(
                f"Run {doc.get('run_id')} was stopped by forensic-escalate and cannot be resumed. "
                "Follow your escalation procedure.",
                run_dir=run_dir,
            )
        cfg = RunConfig.from_dict(doc.get("config", {}))
        cfg.output = str(run_dir.parents[2])
        clock = case_mod.ClockRecord(**_clock_fields(doc.get("clock", {})))
        clock.monotonic_start = round(time.monotonic(), 6)
        clock.mark("resumed")
        ack = case_mod.AuthorityAck(**doc.get("authority_ack", {}))
        blocker = target_mod.BlockerRecord(**doc.get("write_blocker", {}))
        merged = RunInputs(
            authority=ack,
            clock=clock,
            blocker=blocker,
            argv=inputs.argv if inputs else [],
            accept_smart_warning=bool(inputs and inputs.accept_smart_warning),
        )
        doc.setdefault("resumes", []).append(
            {"utc": timeutil.iso(), "argv": merged.argv, "previous_status": doc.get("status")}
        )
        doc["status"] = "running"
        return cls(cfg, merged, run_dir, doc, notify=notify, confirm=confirm, resumed=True)

    # -- persistence ---------------------------------------------------------------------------

    def save(self) -> None:
        self.doc["clock"] = self.inputs.clock.to_dict()
        if (self.run_dir / ESCALATED_MARKER).exists():
            # Never overwrite what forensic-escalate recorded.
            self.doc["status"] = "escalated"
            with contextlib.suppress(OSError, ValueError):
                on_disk = jsonio.load_json(self.run_dir / "run.json")
                if "escalation" in on_disk:
                    self.doc["escalation"] = on_disk["escalation"]
        try:
            jsonio.dump_json(self.run_dir / "run.json", self.doc)
        except OSError as exc:
            if _is_full_disk(exc):
                raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
            raise

    def _full_message(self) -> str:
        return (
            "The output drive is full. Free space (or use a larger drive), then continue with "
            f"forensic-analyze --resume {self.run_dir}"
        )

    def event(self, event: str, **fields: Any) -> None:
        rec = {"ts": timeutil.iso(), "event": event, "run_id": self.run_id, **fields}
        try:
            jsonio.append_line(self.log_path, rec)
        except OSError as exc:
            if _is_full_disk(exc):
                raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
            raise
        # The session log is on the root filesystem; the run log above is the record.
        with contextlib.suppress(OSError):
            sessionlog.log_event(TOOL_NAME, event, run_id=self.run_id, **fields)

    def session_event(self, event: str, **fields: Any) -> None:
        with contextlib.suppress(OSError):
            sessionlog.log_event(TOOL_NAME, event, run_id=self.run_id, **fields)

    def deviation(self, text: str) -> None:
        self.doc["deviations"].append(text)
        self.event("deviation", text=text)

    def warn(self, text: str) -> None:
        self.doc["warnings"].append(text)
        self.notify(text)
        self.event("warning", text=text)

    def error(self, where: str, text: str) -> None:
        self.doc["errors"].append({"where": where, "error": text, "utc": timeutil.iso()})
        self.event("error", where=where, error=text)

    def _lock(self) -> None:
        self.logs.mkdir(parents=True, exist_ok=True)
        # The lock lives beside the run folder so it never appears in outputs.sha256.
        fh = open(self.run_dir.parent / f".{self.run_id}.lock", "w")  # noqa: SIM115
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.close()
            raise RunAborted(
                f"Run {self.run_id} is already running in another window. Wait for it to finish."
            ) from exc
        self._lock_fh = fh

    # -- main ----------------------------------------------------------------------------------

    def execute(self) -> Outcome:
        self._lock()
        pid_file = self.run_dir / PID_FILE
        pid_file.write_text(f"{os.getpid()}\n", encoding="ascii")
        try:
            return self._execute()
        except Escalated:
            self._release_handles()
            self.doc["status"] = "escalated"
            self.save()
            raise
        except OutputFull:
            self._release_handles()
            self.doc["status"] = "incomplete"
            with contextlib.suppress(OutputFull):
                self.save()
            raise
        except RunAborted:
            self._release_handles()
            self.doc["status"] = "stopped"
            self.save()
            raise
        finally:
            self._release_handles()
            pid_file.unlink(missing_ok=True)
            if self._lock_fh is not None:
                self._lock_fh.close()
                Path(self._lock_fh.name).unlink(missing_ok=True)

    def _execute(self) -> Outcome:
        cand, recorder = self._begin()
        trace = self._start_tracer(cand)
        before = self._hash_before(cand)
        self.save()
        analysis_path, analysis_kind = cand.path, cand.kind
        if self.cfg.mode == "image":
            analysis_path = self._make_image(cand, before)
            analysis_kind = "image"
            if trace is not None:
                self._finish_trace(trace, "target")
                trace = None
            self._hash_after(cand, key="after")
            self.save()
        handle, copy_trace = self._prepare_handle(analysis_path, analysis_kind, recorder)
        tgt = self._build_target(handle, recorder, cand, before, analysis_kind)
        self._run_modules(tgt, recorder)
        self._check_escalated()
        self._after_modules(cand, trace, copy_trace, recorder)
        self._check_escalated()
        return self._finish()

    def _check_escalated(self) -> None:
        """Stop at once if forensic-escalate ran: no more modules, merge, export or signing."""
        if (self.run_dir / ESCALATED_MARKER).exists():
            self.event("escalated_stop")
            raise Escalated(
                "Run stopped: forensic-escalate was used. Nothing more was written. "
                "Follow your escalation procedure.",
                run_dir=self.run_dir,
            )

    def _begin(self) -> tuple[target_mod.Candidate, ToolRecorder]:
        cfg = self.cfg
        self.event("run_resume" if self.resumed else "run_start", target=cfg.target, mode=cfg.mode)
        if cfg.mode == "direct":
            self.notify(mode.DIRECT_WARNING)
        try:
            cand = target_mod.resolve(cfg.target)
            target_mod.require_readonly(cand)
        except target_mod.TargetError as exc:
            raise RunAborted(str(exc), run_dir=self.run_dir) from exc
        self._record_target(cand)
        self.save()
        recorder = ToolRecorder(
            sb.Sandbox(method=cfg.sandbox or None, ro_paths=self._ro_paths()), self.log_path
        )
        self.doc["sandbox"] = recorder.sandbox.describe()
        recorder.records = list(self.doc.get("tools", []))  # keep records from before a resume
        return cand, recorder

    def _prepare_handle(
        self, path: str, kind: str, recorder: ToolRecorder
    ) -> tuple[sb.EvidenceHandle, tracer.WriteTracer | None]:
        handle = self._open_handle(path, recorder)
        self._hand_to_sandbox(handle, recorder)
        copy_trace = None
        if kind == "image":
            copy_trace = tracer.WriteTracer(
                handle.loop_device or None,
                reason_if_none="image file without a loop device, checked by hash",
            )
            copy_trace.start()
        return handle, copy_trace

    @staticmethod
    def _hand_to_sandbox(handle: sb.EvidenceHandle, recorder: ToolRecorder) -> None:
        recorder.sandbox.devices = [handle.path] if handle.method == "ro_loop" else []
        if handle.method == "path":
            recorder.sandbox.ro_paths.append(str(Path(handle.path).parent))

    def _build_target(
        self,
        handle: sb.EvidenceHandle,
        recorder: ToolRecorder,
        cand: target_mod.Candidate,
        before: dict[str, Any],
        kind: str,
    ) -> Target:
        volumes = self._detect(handle, recorder, cand)
        if any(v.bitlocker for v in volumes):
            handle, volumes = self._unlock(handle, recorder, cand)
        self.doc["volumes"] = [asdict(v) for v in volumes]
        tgt = Target(
            path=Path(handle.path),
            kind="device" if kind == "device" else "image",
            evidence_id=target_mod.evidence_id(cand, self.cfg.exhibit_id),
            sha256=before.get("sha256", ""),
            md5=before.get("md5", ""),
            size_bytes=cand.size_bytes,
            model=cand.model,
            serial=cand.serial,
            volumes=tuple(volumes),
        )
        self.doc["target"]["evidence_id"] = tgt.evidence_id
        self.save()
        return tgt

    def _after_modules(
        self,
        cand: target_mod.Candidate,
        trace: tracer.WriteTracer | None,
        copy_trace: tracer.WriteTracer | None,
        recorder: ToolRecorder,
    ) -> None:
        self._release_handles()
        if copy_trace is not None:
            self.doc.setdefault("write_requests", {})["analysis_copy"] = copy_trace.stop().to_dict()
        if trace is not None:
            self._finish_trace(trace, "target")
        if self.cfg.mode == "direct":
            self._hash_after(cand, key="after")
        else:
            img = self.doc.get("image", {})
            if img.get("image_path"):
                self.doc["image"]["files_sha256_after"] = _files_sha256(
                    Path(img["image_path"]).parent, img.get("files", [])
                )
        self._integrity()
        self.doc["tools"] = recorder.records
        self.doc["tool_versions"] = recorder.versions()
        self.save()

    def _finish(self) -> Outcome:
        self._merge_and_export()
        self._summary()
        case_mod.finish_clock(self.inputs.clock)
        self.doc["status"] = "complete"
        self.doc["finished_utc"] = timeutil.iso()
        self.save()
        self._report()
        if self.cfg.purge_exports:
            res = cleanup.purge_exports(self.run_dir)
            self.doc["purge"] = res.to_dict()
            self.event("purged_exports", **res.to_dict())
        self.doc["signing"] = self._signing_plan()
        self.save()
        code = EXIT_OK if self.doc["integrity"]["ok"] else EXIT_INTEGRITY
        self.event("run_complete", exit_code=code)
        # Nothing in the run folder changes after this point; later events go to the session log.
        sign = signing.hash_and_sign(self.run_dir, self.output_root)
        self.session_event("outputs_signed", **sign.to_dict())
        if sign.error:
            self.notify(f"Outputs were hashed but not signed: {sign.error}")
        msg = (
            f"Run {self.run_id} complete. Results: {self.run_dir}"
            if code == EXIT_OK
            else f"Run {self.run_id} finished with integrity warnings; read run.json in "
            f"{self.run_dir} before relying on it."
        )
        return Outcome(code, self.run_dir, msg, self.doc)

    # -- steps ---------------------------------------------------------------------------------

    def _ro_paths(self) -> list[str]:
        out = [str(self.run_dir)]
        assets = paths.assets_dir()
        if assets.is_dir():
            out.append(str(assets))
        return out

    def _record_target(self, cand: target_mod.Candidate) -> None:
        info: dict[str, Any] = {**cand.to_dict(), "readonly_flag": cand.readonly}
        prev = self.doc.get("target")
        if prev and self.resumed:
            same = prev.get("size_bytes") == cand.size_bytes and prev.get("serial") == cand.serial
            if not same:
                raise RunAborted(
                    "The target attached now is not the one this run started on "
                    "(size or serial differ). Attach the original drive and resume again."
                )
            return
        if cand.kind == "device":
            rot = target_mod.rotational(cand.path)
            info["rotational"] = rot
            if rot is False:
                info["ssd_warning"] = target_mod.SSD_WARNING
                self.warn(target_mod.SSD_WARNING)
            info["hpa_dco"] = target_mod.hpa_dco(cand)
            hpa = info["hpa_dco"].get("hpa", {})
            if hpa.get("hpa_enabled"):
                self.warn(
                    f"The drive has a Host Protected Area of {hpa.get('hidden_sectors')} "
                    "sectors. It was logged, not removed; data there is not analysed."
                )
            if info["hpa_dco"].get("dco_hidden"):
                self.warn("The drive reports a Device Configuration Overlay. It was logged only.")
            if self.cfg.preset == "full" and self.cfg.mode == "direct":
                smart = target_mod.smart_check(cand)
                info["smart"] = smart
                if smart.get("available") and smart.get("warning"):
                    text = target_mod.smart_warning_text(smart)
                    self.warn(text)
                    if not (self.inputs.accept_smart_warning or self.confirm("Drive health", text)):
                        raise RunAborted(
                            "Stopped before a Full run on a drive with SMART warnings. Use "
                            "--mode image --imager ddrescue, or pass --yes to go ahead anyway."
                        )
                    self.deviation("Full direct run on a drive with SMART warnings")
        self.doc["target"] = info

    def _start_tracer(self, cand: target_mod.Candidate) -> tracer.WriteTracer | None:
        if cand.kind != "device":
            return None
        tr = tracer.WriteTracer(cand.path, blktrace_dir=self.logs / "blktrace")
        stored = self.doc.get("write_requests", {}).get("target", {}).get("before")
        tr.start()
        if self.resumed and stored and tr.stat is not None:
            if all(tr.result.before.get(k, 0) >= v for k, v in stored.items()):
                tr.result.before = stored  # counters survived: the whole run is covered
            else:
                self.deviation(
                    "write counters were reset between the interruption and the resume "
                    "(drive replugged?); requests in that gap were not counted"
                )
        self.doc.setdefault("write_requests", {})["target"] = tr.result.to_dict()
        return tr

    def _finish_trace(self, tr: tracer.WriteTracer, key: str) -> None:
        res = tr.stop()
        self.doc.setdefault("write_requests", {})[key] = res.to_dict()
        if res.write_requests:
            self.warn(
                f"The tracer counted {res.write_requests} write requests to the target. "
                "Expected 0. Treat the target as changed and record why."
            )

    def _hash_before(self, cand: target_mod.Candidate) -> dict[str, str]:
        hashes = self.doc.setdefault("hashes", {})
        if hashes.get("before", {}).get("sha256"):
            return hashes["before"]
        self.notify(f"Hashing {cand.path} (SHA-256 and MD5, one read pass). This can take a while.")
        hashes["before"] = _hash_or_error(Path(cand.path))
        b = hashes["before"]
        if not b.get("sha256") or (
            cand.size_bytes > 0 and b.get("bad_bytes", 0) >= cand.size_bytes
        ):
            raise RunAborted(
                f"The target could not be read at all ({hashes['before'].get('error')}). "
                "Check the cable and the write blocker, then try again.",
                run_dir=self.run_dir,
            )
        if hashes["before"].get("error"):
            self.error("hash_before", hashes["before"]["error"])
            self.deviation(
                "the target could not be read completely; its hash is incomplete. Copy it with "
                "--mode image --imager ddrescue to keep what can be read"
            )
            self.notify(
                "The target has read errors. The run continues, but its hash is incomplete."
            )
        self.event("hashed", which="before", **hashes["before"])
        return hashes["before"]

    def _hash_after(self, cand: target_mod.Candidate, *, key: str) -> None:
        hashes = self.doc.setdefault("hashes", {})
        hashes[key] = _hash_or_error(Path(cand.path))
        self.event("hashed", which=key, **hashes[key])

    def _make_image(self, cand: target_mod.Candidate, before: dict[str, str]) -> str:
        existing = self.doc.get("image", {})
        if existing.get("verified") or (existing.get("image_path") and existing.get("done")):
            return str(existing["image_path"])
        chk = shutil.disk_usage(self.output_root)
        if chk.free < cand.size_bytes:
            raise OutputFull(
                "Copy-first mode needs room for the whole drive and the output drive is too "
                "small. Use a larger output drive or --mode direct.",
                run_dir=self.run_dir,
            )
        self.notify(f"Copying {cand.path} with {self.cfg.imager}. This can take hours.")
        try:
            res = mode.acquire(
                self.cfg.imager,
                cand.path,
                self.run_dir / "image",
                expected=before,
                case_id=self.doc["case"]["case_id"],
                exhibit_id=self.cfg.exhibit_id or cand.name,
                examiner=self.cfg.examiner,
                notes=self.cfg.notes,
            )
        except mode.ModeError as exc:
            raise RunAborted(f"Making the copy failed: {exc}", run_dir=self.run_dir) from exc
        except OSError as exc:
            if _is_full_disk(exc):
                raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
            raise
        self.doc["image"] = {
            **res.to_dict(),
            "done": True,
            "files_sha256": _files_sha256(Path(res.image_path).parent, res.files),
        }
        for note in res.notes:
            self.deviation(note)
        self.event("imaged", **res.to_dict())
        return res.image_path

    def _open_handle(self, path: str, recorder: ToolRecorder) -> sb.EvidenceHandle:
        old = self.doc.get("handle", {})
        if self.resumed and old.get("loop_device"):
            sb.detach_stale(old["loop_device"], old.get("source", ""))
        raw = fsdetect.image_type(path) == "raw"
        try:
            h = sb.open_evidence(path, raw=raw, sandbox=recorder.sandbox)
        except sb.SandboxError as exc:
            raise RunAborted(f"{exc}. The target was not touched.", run_dir=self.run_dir) from exc
        self.handles.append(h)
        self.doc["handle"] = h.to_dict()
        self.save()
        return h

    def _release_handles(self) -> None:
        while self.handles:
            self.handles.pop().close()

    def _detect(
        self, handle: sb.EvidenceHandle, recorder: ToolRecorder, cand: target_mod.Candidate
    ) -> list[Volume]:
        work = self.run_dir / "modules" / "_fsdetect"

        def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            return recorder.run("fsdetect", argv, workdir=work, **kw)

        size = cand.size_bytes
        if handle.path != cand.path and Path(handle.path).is_file():
            size = Path(handle.path).stat().st_size
        try:
            return fsdetect.detect(handle.path, tool=tool, workdir=work, size_bytes=size)
        except proc.ToolError as exc:
            self.error("fsdetect", str(exc))
            self.deviation("filesystem detection failed; modules that need a filesystem skip")
            return []

    def _unlock(
        self, handle: sb.EvidenceHandle, recorder: ToolRecorder, cand: target_mod.Candidate
    ) -> tuple[sb.EvidenceHandle, list[Volume]]:
        key = Path(self.cfg.bitlocker_key_file) if self.cfg.bitlocker_key_file else None
        out_dir = self.run_dir / "decrypted"
        existing = out_dir / "decrypted.raw"
        if self.resumed and existing.exists() and self.doc.get("bitlocker", {}).get("unlocked"):
            image = existing
        else:
            staged = _stage_key(key, out_dir, recorder.sandbox) if key is not None else None
            self.notify("BitLocker found. Unlocking into a read-only working copy.")

            def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
                return recorder.run("bitlocker", argv, workdir=out_dir, timeout=24 * 3600, **kw)

            try:
                res = fsdetect.unlock(handle.path, staged, out_dir, tool=tool)
            except fsdetect.BitLockerLocked as exc:
                if staged is not None and staged.name == ".startup-key.bek":
                    staged.unlink(missing_ok=True)
                self.doc["bitlocker"] = {"found": True, "unlocked": False, "reason": str(exc)}
                raise RunAborted(str(exc), run_dir=self.run_dir) from exc
            if staged is not None and staged.name == ".startup-key.bek":
                staged.unlink(missing_ok=True)
            image = res.image
            self.doc["bitlocker"] = {
                "found": True,
                "unlocked": True,
                "method": "dissect fve-dd",
                "argv": res.tool_argv,
                "working_copy": image.relative_to(self.run_dir).as_posix(),
                "working_copy_sha256": hashing.sha256_file(image),
            }
            self.deviation("BitLocker: modules analysed a decrypted working copy in decrypted/")
        new = self._open_handle(str(image), recorder)
        self._hand_to_sandbox(new, recorder)
        vols = self._detect(new, recorder, cand)
        return new, vols

    def _module_options(self) -> dict[str, Any]:
        thresholds: dict[str, Any] = {}
        tpath = paths.etc_dir() / "screen-thresholds.json"
        if tpath.exists():
            try:
                thresholds = jsonio.load_json(tpath)
            except (OSError, ValueError) as exc:
                self.error("thresholds", str(exc))
        self.doc["thresholds"] = {
            "path": str(tpath),
            "sha256": hashing.sha256_file(tpath) if tpath.exists() else "",
            "values": thresholds,
        }
        return {
            "preset": self.cfg.preset,
            "mode": self.cfg.mode,
            "full": self.cfg.preset == "full",
            "thresholds": thresholds,
            "output_root": str(self.output_root),
            "purge_exports": self.cfg.purge_exports,
            "case_id": self.doc["case"]["case_id"],
        }

    def _run_modules(self, tgt: Target, recorder: ToolRecorder) -> None:
        registry = all_modules()
        names = [m.name for m in registry]
        try:
            planned, missing = presets.modules_for(self.cfg.preset, names, self.cfg.modules)
        except presets.PresetError as exc:
            raise RunAborted(f"{exc}.", run_dir=self.run_dir) from exc
        self.doc["plan"] = {
            "preset": self.cfg.preset,
            "planned": planned,
            "not_available": missing,
            "registry": names,
            "load_errors": load_errors(),
            "findings_backend": findings_backend(),
        }
        options = self._module_options()
        shared: dict[str, Any] = {}
        results: dict[str, dict[str, Any]] = {}
        for name in missing:
            results[name] = {
                "name": name,
                "status": "not_available",
                "reason": "this module is not installed on this build",
            }
        by_name = {m.name: m for m in registry}
        for name in planned:
            self._check_escalated()
            mod = by_name[name]
            marker = self.run_dir / "modules" / name / DONE
            if marker.exists():
                rec = jsonio.load_json(marker)
                rec["resumed_from_marker"] = True
                results[name] = rec
                self.event("module_skipped_done", module=name)
                continue
            ok, why = mod.applicable(tgt)
            if not ok:
                rec = self._module_record(mod, ModuleResult("skipped", why), 0, 0.0, "")
                self._write_marker(marker, rec)
                results[name] = rec
                self.event("module_skipped", module=name, reason=why)
                continue
            results[name] = self._run_one(mod, tgt, recorder, options, shared, marker)
            self.doc["modules"] = _ordered(results, planned, missing)
            self.doc["tools"] = recorder.records
            self.save()
        self.doc["modules"] = _ordered(results, planned, missing)
        self._collect_models()

    def _run_one(  # noqa: PLR0917 - private helper of _run_modules
        self,
        mod: Any,
        tgt: Target,
        recorder: ToolRecorder,
        options: dict[str, Any],
        shared: dict[str, Any],
        marker: Path,
    ) -> dict[str, Any]:
        name = mod.name
        part = self.run_dir / "modules" / name / "findings.part.jsonl"
        self.notify(f"Running {mod.title or name} ...")
        started_utc = timeutil.iso()
        t0 = time.monotonic()
        handles = None
        try:
            handles = build_context(
                run_id=self.run_id,
                module=name,
                target=tgt,
                run_dir=self.run_dir,
                options=options,
                recorder=recorder,
                shared=shared,
                evidence_sha256=tgt.sha256,
                run_log=self.log_path,
            )
            result = mod.run(handles.ctx)
            if not isinstance(result, ModuleResult):
                result = ModuleResult("failed", "module returned no result")
            handles.writer.close()
            count = int(getattr(handles.writer, "count", 0))
        except Exception as exc:
            if handles is not None:
                # Already failing; the original error is the one reported.
                with contextlib.suppress(Exception):
                    handles.writer.close()
            if _is_full_disk(exc):
                part.unlink(missing_ok=True)
                self.error(name, "output drive full")
                raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
            result = ModuleResult("failed", f"{type(exc).__name__}: {exc}")
            count = int(getattr(handles.writer, "count", 0)) if handles else 0
        duration = time.monotonic() - t0
        if handles is not None:
            self.doc.setdefault("module_events", {})[name] = handles.log_events
        rec = self._module_record(mod, result, count, duration, started_utc)
        if result.status == "failed":
            self.notify(f"Module {name} failed: {result.reason}. The run continues.")
            self.error(name, result.reason)
            part.unlink(missing_ok=True)
            rec["findings"] = 0
        else:
            self._write_marker(marker, rec)
        self.event("module_finished", module=name, status=result.status, findings=rec["findings"])
        return rec

    def _module_record(
        self, mod: Any, result: ModuleResult, count: int, duration: float, started: str
    ) -> dict[str, Any]:
        return {
            "name": mod.name,
            "title": mod.title,
            "order": mod.order,
            "status": result.status,
            "reason": result.reason,
            "counts": dict(result.counts),
            "findings": count,
            "started_utc": started,
            "duration_s": round(duration, 3),
        }

    def _write_marker(self, marker: Path, rec: dict[str, Any]) -> None:
        try:
            jsonio.dump_json(marker, rec)
        except OSError as exc:
            if _is_full_disk(exc):
                raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
            raise

    def _collect_models(self) -> None:
        models: list[dict[str, Any]] = []
        for name, events in sorted(self.doc.get("module_events", {}).items()):
            for ev in events:
                if ev.get("event") == "model_used":
                    models.append({k: v for k, v in ev.items() if k != "ts"} | {"module": name})
        self.doc["models"] = models

    def _integrity(self) -> None:
        h = self.doc.get("hashes", {})
        before, after = h.get("before", {}), h.get("after", {})
        problems: list[str] = []
        if before.get("error") or after.get("error"):
            problems.append("a target hash is incomplete (read errors)")
        elif before.get("sha256") != after.get("sha256") or before.get("md5") != after.get("md5"):
            problems.append("the target's hash changed between before and after")
        wr = self.doc.get("write_requests", {})
        total = 0
        measured = False
        for part in wr.values():
            if isinstance(part, dict) and part.get("write_requests") is not None:
                measured = True
                total += int(part["write_requests"])
        if total:
            problems.append(f"{total} write requests reached the target")
        img = self.doc.get("image")
        if img is not None:
            if not img.get("verified"):
                problems.append("the copy could not be verified against the target's hash")
            after_files = img.get("files_sha256_after")
            if after_files is not None and after_files != img.get("files_sha256"):
                problems.append("the copy's hash changed during analysis")
        self.doc["write_requests_total"] = total if measured else None
        self.doc["hashes"]["match"] = (
            not before.get("error")
            and not after.get("error")
            and before.get("sha256") == after.get("sha256")
            and before.get("md5") == after.get("md5")
        )
        self.doc["integrity"] = {"ok": not problems, "problems": problems}
        self.doc["mode_record"] = {
            "mode": self.cfg.mode,
            "imager": self.cfg.imager if self.cfg.mode == "image" else "",
            "warning": mode.DIRECT_WARNING if self.cfg.mode == "direct" else "",
            "limits": mode.DIRECT_LIMITS if self.cfg.mode == "direct" else mode.IMAGE_LIMITS,
        }
        for p in problems:
            self.warn(f"Integrity: {p}.")

    def _merge_and_export(self) -> None:
        order = [m["name"] for m in self.doc["modules"] if m.get("status") in ("ok", "skipped")]
        order = sorted(order, key=lambda n: _order_of(self.doc["modules"], n))
        try:
            from forensic_analyze import findings  # noqa: PLC0415

            path = findings.merge_parts(self.run_dir, order)
            backend = "forensic_analyze.findings.merge_parts"
        except ImportError:
            path = _fallback_merge(self.run_dir, order)
            backend = "internal-fallback"
            self.deviation("findings package missing: merged with the internal fallback")
        except Exception as exc:
            self.error("merge", f"{type(exc).__name__}: {exc}")
            path = _fallback_merge(self.run_dir, order)
            backend = "internal-fallback after error"
        self.doc["findings"] = {
            "path": Path(path).name,
            "sha256": hashing.sha256_file(path),
            "rows": _count_lines(Path(path)),
            "merge": backend,
        }
        exports: dict[str, Any] = {}
        for name in ("export_csv", "export_sqlite", "export_bodyfile"):
            try:
                mod = __import__(f"forensic_analyze.{name}", fromlist=["build"])
            except ImportError:
                exports[name] = {"status": "not installed"}
                continue
            try:
                out = mod.build(self.run_dir)
                exports[name] = {"status": "ok", "path": Path(out).name}
            except Exception as exc:
                if _is_full_disk(exc):
                    raise OutputFull(self._full_message(), run_dir=self.run_dir) from exc
                exports[name] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
                self.error(name, exports[name]["error"])
        self.doc["exports"] = exports

    def _summary(self) -> None:
        mods = self.doc["modules"]
        failed = [m for m in mods if m["status"] == "failed"]
        skipped = [m for m in mods if m["status"] in ("skipped", "not_available")]
        ok = [m for m in mods if m["status"] == "ok"]
        self.doc["summary"] = {
            "first": "failures and skipped modules are listed before results",
            "modules": [
                {
                    "name": m["name"],
                    "status": m["status"],
                    "reason": m.get("reason", ""),
                    "findings": m.get("findings", 0),
                    "counts": m.get("counts", {}),
                }
                for m in [*failed, *skipped, *ok]
            ],
            "failed": [m["name"] for m in failed],
            "skipped": [m["name"] for m in skipped],
            "findings_per_module": {m["name"]: m.get("findings", 0) for m in mods},
            "findings_total": self.doc.get("findings", {}).get("rows", 0),
            "integrity_ok": self.doc["integrity"]["ok"],
            "write_requests_total": self.doc.get("write_requests_total"),
        }

    def _report(self) -> None:
        exe = shutil.which("evidence-report")
        if not exe:
            self.doc["report"] = {"status": "not installed"}
            self.save()
            return
        self.notify("Writing the report ...")
        res = proc.run([exe, str(self.run_dir)], check=False, timeout=6 * 3600)
        self.doc["report"] = {
            "status": "ok" if res.returncode == 0 else "failed",
            "command_line": res.command_line,
            "returncode": res.returncode,
            "error": "" if res.returncode == 0 else res.stderr.strip()[-300:],
        }
        if res.returncode != 0:
            self.error("report", self.doc["report"]["error"])
            self.notify("The report could not be written; findings and CSV are complete.")
        self.save()

    def _signing_plan(self) -> dict[str, Any]:
        try:
            _key, pub = signing.ensure_key(self.output_root)
            fp = hashing.sha256_file(pub)
        except (proc.ToolError, OSError) as exc:
            return {"status": "unavailable", "error": str(exc)}
        return {
            "status": "signed after this file was written",
            "key": str(signing.key_dir(self.output_root) / "key.pem"),
            "public_key_sha256": fp,
            "algorithm": "Ed25519 (openssl pkeyutl -rawin)",
            "list": signing.LIST_NAME,
            "signature": signing.SIG_NAME,
        }


def _stage_key(key: Path, out_dir: Path, box: sb.Sandbox) -> Path:
    """Recovery passwords are read here; a .BEK file is copied where the parser can read it."""
    if not key.is_file():
        return key
    try:
        text = key.read_text(encoding="ascii").strip()
    except (UnicodeDecodeError, OSError):
        text = ""
    if fsdetect.RECOVERY_RE.match(text):
        return key
    box.prepare_writable(out_dir)
    staged = out_dir / ".startup-key.bek"
    shutil.copyfile(key, staged)
    os.chmod(staged, 0o444)
    return staged


def _files_sha256(folder: Path, names: list[str]) -> dict[str, str]:
    """SHA-256 of each copy file (E01 segments, or the raw copy and its map)."""
    out: dict[str, str] = {}
    for name in sorted(names):
        p = folder / name
        out[name] = hashing.sha256_file(p) if p.exists() else "missing"
    return out


def _clock_fields(data: dict[str, Any]) -> dict[str, Any]:
    allowed = case_mod.ClockRecord.__dataclass_fields__
    return {k: v for k, v in data.items() if k in allowed}


Reader = Callable[[int, int], bytes]
SECTOR = 512
SECTOR_RETRY_LIMIT = 64 * 1024 * 1024


def hash_tolerant(
    path: Path, *, reader: Reader | None = None, size: int | None = None
) -> dict[str, Any]:
    """SHA-256 and MD5 that keep going past read errors.

    Unreadable 512-byte sectors are hashed as zeros (the same bytes a ddrescue copy holds) and
    listed in ``bad_ranges``; ``complete`` is False when any were found. Opened read-only.
    """
    fd = -1
    if reader is None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        size = os.lseek(fd, 0, os.SEEK_END)

        def reader(offset: int, length: int) -> bytes:
            return os.pread(fd, length, offset)

    total = int(size or 0)
    sha, md5 = hashlib.sha256(), hashlib.md5()  # noqa: S324 - MD5 is a forensic convention here
    bad: list[list[int]] = []
    offset = 0
    try:
        while offset < total:
            want = min(hashing.BLOCK, total - offset)
            try:
                chunk = reader(offset, want)
            except OSError:
                if sum(b - a for a, b in bad) < SECTOR_RETRY_LIMIT:
                    chunk = _read_sectors(reader, offset, want, bad)
                else:  # a dying drive: stop retrying sector by sector (ddrescue does it better)
                    chunk = b"\0" * want
                    _add_bad(bad, offset, want)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
            offset += len(chunk)
    finally:
        if fd >= 0:
            os.close(fd)
    return {
        "sha256": sha.hexdigest(),
        "md5": md5.hexdigest(),
        "complete": not bad,
        "bad_ranges": bad,
        "bad_bytes": sum(b - a for a, b in bad),
        "bytes_read": offset,
        "unreadable_as": "zeros",
    }


def _add_bad(bad: list[list[int]], pos: int, n: int) -> None:
    if bad and bad[-1][1] == pos:
        bad[-1][1] = pos + n
    else:
        bad.append([pos, pos + n])


def _read_sectors(reader: Reader, offset: int, length: int, bad: list[list[int]]) -> bytes:
    out = bytearray()
    pos = offset
    while pos < offset + length:
        n = min(SECTOR, offset + length - pos)
        try:
            data = reader(pos, n)
        except OSError:
            data = b"\0" * n
            _add_bad(bad, pos, n)
        if not data:
            break
        out += data
        pos += len(data)
    return bytes(out)


def _hash_or_error(path: Path) -> dict[str, Any]:
    started = timeutil.iso()
    t0 = time.monotonic()
    try:
        digests: dict[str, Any] = dict(hashing.hash_file(path))
        digests["complete"] = True
    except OSError as exc:
        first = f"{exc.strerror or exc} (errno {exc.errno})"
        try:
            digests = hash_tolerant(path)
        except OSError as exc2:
            return {
                "error": f"{exc2.strerror or exc2} (errno {exc2.errno})",
                "started_utc": started,
                "duration_s": round(time.monotonic() - t0, 3),
            }
        digests["error"] = f"read errors: {first}; {digests['bad_bytes']} bytes unreadable"
    return {
        **digests,
        "started_utc": started,
        "finished_utc": timeutil.iso(),
        "duration_s": round(time.monotonic() - t0, 3),
    }


def _ordered(
    results: dict[str, dict[str, Any]], planned: list[str], missing: list[str]
) -> list[dict[str, Any]]:
    out = [results[n] for n in planned if n in results]
    out += [results[n] for n in missing if n in results]
    return out


def _order_of(mods: list[dict[str, Any]], name: str) -> int:
    for m in mods:
        if m["name"] == name:
            return int(m.get("order", 1000))
    return 1000


def _count_lines(path: Path) -> int:
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def _fallback_merge(run_dir: Path, order: list[str]) -> Path:
    """Concatenate parts in module order and number them F-000001.. (sorted keys)."""
    out = run_dir / "findings.jsonl"
    n = 0
    tmp = run_dir / ".findings.jsonl.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for name in order:
            part = run_dir / "modules" / name / "findings.part.jsonl"
            if not part.exists():
                continue
            with open(part, encoding="utf-8") as src:
                for line in src:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    n += 1
                    row["finding_id"] = f"F-{n:06d}"
                    fh.write(jsonio.dumps_line(row) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(out)
    return out
