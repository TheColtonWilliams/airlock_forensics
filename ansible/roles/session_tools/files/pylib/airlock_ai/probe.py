"""``ai-probe``: pick the model tier from measured GPU memory (task 4B.3).

Input is ``vulkaninfo`` output. The tier depends on capacities only, never on a vendor or
device name (decision log 2026-11-10, "Model tier chosen at boot from VRAM").

Formats understood (auto-detected; recorded samples in ``tests/fixtures/vulkaninfo/``):

* the plain text report (``vulkaninfo`` with no options). This is what the probe runs on the
  image: it lists every device with its memory heaps. Current ``vulkaninfo --json`` writes a
  Vulkan Profiles file per device instead, and that file has no memory heaps (decision log
  2026-11-15);
* the legacy JSON report (``vulkaninfo --json`` before Vulkan SDK 1.3.2xx), which carries
  ``VkPhysicalDeviceProperties`` and ``VkPhysicalDeviceMemoryProperties`` at the top level;
* the Vulkan Profiles JSON (``VP_VULKANINFO_*.json``); device type only, heaps when present;
* a JSON array of any of the JSON forms (one entry per device);
* the ``--summary`` text (device types only, no heaps).

Rules:

* per device, the largest heap with the device-local flag is its memory;
* integrated (and virtual) GPUs take that heap from system RAM, so their usable memory is
  capped at ``MemTotal`` minus ``integrated_ram_margin_gib``;
* CPU devices (llvmpipe and other software rasterisers) are not GPUs;
* the device with the most usable memory wins; the tier is the highest one whose
  ``min_vram_gib`` it meets, that ships on the image, and whose model files are staged;
* no usable device gives the CPU tier (tier0, no layers on a GPU). If a GPU tier's model then
  fails to load, ``airlock_ai.serve`` falls back to the CPU tier.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import config as cfgmod
from airlock_common import jsonio, proc, sessionlog

TOOL = "ai-probe"
GIB = 1024**3
# A card sold as "8 GB" can report a little under 8 GiB; this much slack still counts.
TOLERANCE_GIB = 0.125
CPU_TIER = "tier0"
TIER_ORDER = ("tier0", "tier1", "tier2", "tier3", "tier4")

_TYPE_NAMES = {
    0: "other",
    1: "integrated",
    2: "discrete",
    3: "virtual",
    4: "cpu",
    "OTHER": "other",
    "INTEGRATED_GPU": "integrated",
    "DISCRETE_GPU": "discrete",
    "VIRTUAL_GPU": "virtual",
    "CPU": "cpu",
}
HEAP_DEVICE_LOCAL = 0x1


class ProbeError(RuntimeError):
    """vulkaninfo output could not be read."""


@dataclass
class Heap:
    size_bytes: int
    device_local: bool


@dataclass
class Device:
    index: int
    device_type: str  # discrete | integrated | virtual | cpu | other | unknown
    name: str = ""  # informational only; never used to decide anything
    heaps: list[Heap] = field(default_factory=list)
    usable_bytes: int = 0
    note: str = ""

    @property
    def device_local_bytes(self) -> int:
        return max((h.size_bytes for h in self.heaps if h.device_local), default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "type": self.device_type,
            "name": self.name,
            "device_local_gib": round(self.device_local_bytes / GIB, 3),
            "usable_gib": round(self.usable_bytes / GIB, 3),
            "heaps": [asdict(h) for h in self.heaps],
            "note": self.note,
        }


@dataclass
class TierChoice:
    tier: str
    n_gpu_layers: int
    reason: str
    device: Device | None
    devices: list[Device]
    memtotal_bytes: int
    margin_gib: float
    source_format: str
    models: list[dict[str, Any]] = field(default_factory=list)
    model_id: str = ""
    steps: list[str] = field(default_factory=list)

    @property
    def backend(self) -> str:
        return "vulkan" if self.n_gpu_layers > 0 else "cpu"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "tier": self.tier,
            "backend": self.backend,
            "n_gpu_layers": self.n_gpu_layers,
            "vulkan_device_index": self.device.index if self.device else None,
            "reason": self.reason,
            "device": self.device.to_dict() if self.device else None,
            "devices": [d.to_dict() for d in self.devices],
            "memtotal_gib": round(self.memtotal_bytes / GIB, 3),
            "integrated_ram_margin_gib": self.margin_gib,
            "source_format": self.source_format,
            "model_id": self.model_id,
            "models": self.models,
            "steps": self.steps,
        }


# ---------------------------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------------------------


def _norm_type(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return _TYPE_NAMES.get(value, "unknown")
    text = str(value or "").strip().upper()
    text = re.sub(r"^(VK_)?PHYSICAL_DEVICE_TYPE_", "", text)
    return _TYPE_NAMES.get(text, "unknown")


def _flags_device_local(flags: Any) -> bool:
    if isinstance(flags, int) and not isinstance(flags, bool):
        return bool(flags & HEAP_DEVICE_LOCAL)
    if isinstance(flags, list):
        return any("DEVICE_LOCAL" in str(f) for f in flags)
    return "DEVICE_LOCAL" in str(flags or "")


def _device_from_json(obj: dict[str, Any], index: int) -> Device:
    props: dict[str, Any] = obj
    caps = obj.get("capabilities")
    if isinstance(caps, dict):  # Vulkan Profiles export
        dev = caps.get("device", {}) if isinstance(caps.get("device"), dict) else {}
        props = dev.get("properties", {}) if isinstance(dev.get("properties"), dict) else {}
    pdp = props.get("VkPhysicalDeviceProperties") or {}
    mem = props.get("VkPhysicalDeviceMemoryProperties") or {}
    heaps: list[Heap] = []
    for h in mem.get("memoryHeaps", []) or []:
        if not isinstance(h, dict):
            continue
        try:
            size = int(h.get("size", 0))
        except (TypeError, ValueError):
            continue
        heaps.append(Heap(size, _flags_device_local(h.get("flags", 0))))
    note = "" if heaps else "no memory heaps in this report"
    return Device(
        index, _norm_type(pdp.get("deviceType")), str(pdp.get("deviceName", "")), heaps, note=note
    )


_GPU_HEADER = re.compile(r"^GPU(\d+):\s*$")
_KV = re.compile(r"^\s*(deviceType|deviceName)\s*=\s*(.*?)\s*$")
_HEAP_START = re.compile(r"^\s*memoryHeaps\[(\d+)\]:\s*$")
_HEAP_SIZE = re.compile(r"^\s*size\s*=\s*(\d+)")
_SECTION_END = re.compile(r"^\s*memoryTypes\b|^\S")


def _parse_text(text: str) -> list[Device]:  # noqa: PLR0912 - one line-by-line scanner
    devices: dict[int, Device] = {}
    current: Device | None = None
    heap: Heap | None = None
    for line in text.splitlines():
        m = _GPU_HEADER.match(line)
        if m:
            idx = int(m.group(1))
            current = devices.setdefault(idx, Device(idx, "unknown"))
            heap = None
            continue
        if current is None:
            continue
        kv = _KV.match(line)
        if kv:
            if kv.group(1) == "deviceType":
                current.device_type = _norm_type(kv.group(2))
            elif not current.name:
                current.name = kv.group(2)
            continue
        hm = _HEAP_START.match(line)
        if hm:
            heap = Heap(0, False)
            current.heaps.append(heap)
            continue
        if heap is not None:
            sm = _HEAP_SIZE.match(line)
            if sm:
                heap.size_bytes = int(sm.group(1))
            elif "MEMORY_HEAP_DEVICE_LOCAL_BIT" in line:
                heap.device_local = True
            elif _SECTION_END.match(line) and line.strip():
                heap = None
    out = [devices[i] for i in sorted(devices)]
    for d in out:
        if not d.heaps:
            d.note = "no memory heaps in this report"
    return out


def parse_vulkaninfo(text: str) -> tuple[list[Device], str]:
    """Parse any supported vulkaninfo output. Returns (devices, format name)."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(stripped)
        except ValueError as exc:
            raise ProbeError(f"vulkaninfo JSON does not parse: {exc}") from exc
        items = data if isinstance(data, list) else [data]
        devices = [
            _device_from_json(item, i) for i, item in enumerate(items) if isinstance(item, dict)
        ]
        kind = "profiles-json" if any("capabilities" in i for i in items) else "legacy-json"
        return devices, kind if not isinstance(data, list) else f"{kind}-list"
    if "GPU" not in text:
        return [], "text"
    devices = _parse_text(text)
    kind = "text" if any(d.heaps for d in devices) else "summary-text"
    return devices, kind


def parse_memtotal(meminfo_text: str) -> int:
    """``MemTotal`` from /proc/meminfo, in bytes (0 if absent)."""
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", meminfo_text, re.MULTILINE)
    return int(m.group(1)) * 1024 if m else 0


# ---------------------------------------------------------------------------------------------
# Choosing
# ---------------------------------------------------------------------------------------------


def usable_bytes(dev: Device, memtotal: int, margin_gib: float) -> tuple[int, str]:
    if dev.device_type in {"cpu", "other", "unknown"}:
        return 0, f"{dev.device_type} device, not a GPU"
    heap = dev.device_local_bytes
    if heap <= 0:
        return 0, "no device-local memory reported"
    if dev.device_type in {"integrated", "virtual"}:
        cap = max(0, memtotal - int(margin_gib * GIB)) if memtotal else 0
        if cap < heap:
            return cap, f"shares system RAM: capped at RAM minus {margin_gib:g} GiB"
    return heap, ""


def _models_for(cfg: dict[str, Any], tier: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in cfg["tiers"].get(tier, {}).get("models", []) or []:
        path = cfgmod.asset_file(m.get("target"))
        out.append({**m, "path": str(path) if path else ""})
    return out


def _missing(models: list[dict[str, Any]]) -> list[str]:
    if not models:
        return ["no model listed for this tier"]
    return [m.get("id") or m.get("target", "?") for m in models if not Path(m["path"]).is_file()]


def choose_tier(  # noqa: PLR0912, PLR0915 - the tier rules read best as one sequence
    *,
    vulkaninfo_text: str | None = None,
    meminfo_text: str | None = None,
    config: dict[str, Any] | None = None,
    check_models: bool = True,
) -> TierChoice:
    """Pick the tier. With no arguments, runs ``vulkaninfo`` and reads ``/proc/meminfo``."""
    cfg = config or cfgmod.load_ai_config()
    if vulkaninfo_text is None:
        vulkaninfo_text = run_vulkaninfo()
    if meminfo_text is None:
        try:
            meminfo_text = Path("/proc/meminfo").read_text(encoding="ascii")
        except OSError:
            meminfo_text = ""
    margin = float(cfg.get("integrated_ram_margin_gib", 8))
    memtotal = parse_memtotal(meminfo_text)
    steps: list[str] = []
    try:
        devices, fmt = parse_vulkaninfo(vulkaninfo_text)
    except ProbeError as exc:
        devices, fmt = [], "unreadable"
        steps.append(str(exc))
    for d in devices:
        d.usable_bytes, why = usable_bytes(d, memtotal, margin)
        if why and not d.note:
            d.note = why
        elif why:
            d.note = f"{d.note}; {why}"
    gpus = [d for d in devices if d.usable_bytes > 0]
    # Most usable memory wins; ties go to the lower Vulkan index (stable).
    best = max(gpus, key=lambda d: (d.usable_bytes, -d.index), default=None)
    on_image = [t for t in TIER_ORDER if t in set(cfg.get("tiers_on_image", TIER_ORDER))]
    tiers = cfg["tiers"]

    candidates: list[str] = []
    if best is not None:
        gib = best.usable_bytes / GIB + TOLERANCE_GIB
        for t in on_image:
            low = float(tiers.get(t, {}).get("min_vram_gib", 0) or 0)
            if gib >= low:
                candidates.append(t)
        candidates.reverse()  # highest first
        steps.append(
            f"GPU {best.index} ({best.device_type}): {best.usable_bytes / GIB:.2f} GiB usable"
        )
    else:
        steps.append("no usable Vulkan GPU: CPU tier")

    for t in candidates:
        models = _models_for(cfg, t)
        missing = _missing(models) if check_models else []
        if missing:
            steps.append(f"{t} skipped: model files not staged ({', '.join(missing)})")
            continue
        if best is None:  # candidates exist only when a GPU was found
            break
        reason = (
            f"GPU {best.index} ({best.device_type}) has {best.usable_bytes / GIB:.2f} GiB "
            f"usable memory; {t} needs {tiers[t].get('min_vram_gib', 0)} GiB"
        )
        return TierChoice(
            t,
            99,
            reason,
            best,
            devices,
            memtotal,
            margin,
            fmt,
            models,
            str(tiers[t].get("model_id", "")),
            steps,
        )

    models = _models_for(cfg, CPU_TIER)
    missing = _missing(models) if check_models else []
    if CPU_TIER not in on_image:
        steps.append(f"{CPU_TIER} is not on this image")
        return TierChoice(
            "none",
            0,
            "no AI tier available on this image",
            None,
            devices,
            memtotal,
            margin,
            fmt,
            [],
            "",
            steps,
        )
    if missing:
        steps.append(f"{CPU_TIER} model files not staged ({', '.join(missing)})")
        return TierChoice(
            "none",
            0,
            "no model files staged for any tier",
            None,
            devices,
            memtotal,
            margin,
            fmt,
            [],
            "",
            steps,
        )
    reason = "no usable GPU: runs on the CPU" if best is None else "GPU tiers not staged: CPU"
    return TierChoice(
        CPU_TIER,
        0,
        reason,
        None,
        devices,
        memtotal,
        margin,
        fmt,
        models,
        str(tiers[CPU_TIER].get("model_id", "")),
        steps,
    )


def run_vulkaninfo() -> str:
    """Run ``vulkaninfo`` (text report). An absent tool or failure means "no GPU"."""
    if proc.which("vulkaninfo") is None:
        return ""
    try:
        res = proc.run(["vulkaninfo"], check=False, timeout=60)
    except proc.ToolError:
        return ""
    return res.stdout if res.returncode == 0 else ""


def load_choice() -> dict[str, Any] | None:
    """The tier written by ``ai-probe --write`` at boot, or None."""
    p = cfgmod.tier_state_path()
    try:
        return jsonio.load_json(p)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def _read(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"ai-probe: cannot read {path} ({exc.strerror}). Check the path.") from exc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="Pick the local AI model tier from measured GPU memory (never the vendor).",
    )
    ap.add_argument("--vulkaninfo", metavar="FILE", help="read vulkaninfo output from FILE")
    ap.add_argument("--meminfo", metavar="FILE", help="read /proc/meminfo from FILE")
    ap.add_argument(
        "--config", metavar="FILE", help="AI config (default /etc/airlock/ai-tiers.json)"
    )
    ap.add_argument(
        "--no-model-check",
        action="store_true",
        help="choose by memory only; do not require staged model files",
    )
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    ap.add_argument(
        "--write",
        action="store_true",
        help="save the result to /var/lib/airlock/ai-tier.json (needs root)",
    )
    args = ap.parse_args(argv)
    try:
        cfg = cfgmod.load_ai_config(args.config)
        choice = choose_tier(
            vulkaninfo_text=_read(args.vulkaninfo),
            meminfo_text=_read(args.meminfo),
            config=cfg,
            check_models=not args.no_model_check,
        )
    except cfgmod.ConfigError as exc:
        print(f"ai-probe: {exc}. Fix the file or reinstall the image.", file=sys.stderr)
        return 2
    doc = choice.to_dict()
    if args.write:
        try:
            jsonio.dump_json(cfgmod.tier_state_path(), doc)
            cfgmod.tier_state_path().chmod(0o644)  # read by the llama-server service user
        except OSError as exc:
            print(
                f"ai-probe: cannot save the tier ({exc.strerror}). Run it with sudo.",
                file=sys.stderr,
            )
            return 1
    with contextlib.suppress(OSError):  # the session log is advisory for a read-only probe
        sessionlog.log_event(
            TOOL,
            "ai_tier_chosen",
            tier=choice.tier,
            backend=choice.backend,
            reason=choice.reason,
            source_format=choice.source_format,
        )
    if args.json:
        print(jsonio.dumps(doc))
    else:
        print(f"AI tier: {choice.tier} ({choice.backend}). {choice.reason}.")
        for step in choice.steps:
            print(f"  - {step}")
    return 0 if choice.tier != "none" else 3


if __name__ == "__main__":
    raise SystemExit(main())
