#!/usr/bin/env python3
"""Write the synthesised vulkaninfo fixtures in this folder (task 4G.9).

The layout copies the recorded report (recorded-llvmpipe-no-gpu.txt, vulkaninfo 1.3.275 with
Mesa llvmpipe) section by section; only the device type, name, and memory heaps change. Device
names are neutral on purpose: the probe must decide from capacities alone. Run it again after
changing a profile here; the output is deterministic.

    python3 tests/fixtures/vulkaninfo/make-synthetic.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
GIB = 1024**3
MIB = 1024**2

HEADER = """==========
VULKANINFO
==========

Vulkan Instance Version: 1.3.275


Device Properties and Extensions:
=================================
"""


def _size(n: int) -> str:
    return f"{n} (0x{n:x}) ({n / GIB:.2f} GiB)"


def gpu_block(index: int, dev_type: str, name: str, heaps: list[tuple[int, bool]]) -> str:
    lines = [
        f"GPU{index}:",
        "VkPhysicalDeviceProperties:",
        "---------------------------",
        "\tapiVersion        = 1.3.289 (4206881)",
        "\tdriverVersion     = 24.2.8 (100671496)",
        "\tvendorID          = 0x0000",
        "\tdeviceID          = 0x0000",
        f"\tdeviceType        = PHYSICAL_DEVICE_TYPE_{dev_type}",
        f"\tdeviceName        = {name}",
        "\tpipelineCacheUUID = 00000000-0000-0000-0000-000000000000",
        "",
        "VkPhysicalDeviceMemoryProperties:",
        "=================================",
        f"memoryHeaps: count = {len(heaps)}",
    ]
    for i, (size, local) in enumerate(heaps):
        lines += [
            f"\tmemoryHeaps[{i}]:",
            f"\t\tsize   = {_size(size)}",
            f"\t\tbudget = {_size(size)}",
            "\t\tusage  = 0 (0x00000000) (0.00 B)",
        ]
        if local:
            lines += ["\t\tflags: count = 1", "\t\t\tMEMORY_HEAP_DEVICE_LOCAL_BIT"]
        else:
            lines += ["\t\tflags:", "\t\t\tNone"]
    lines += [
        "memoryTypes: count = 1",
        "\tmemoryTypes[0]:",
        "\t\theapIndex     = 0",
        "\t\tpropertyFlags = 0x0001: count = 1",
        "\t\t\tMEMORY_PROPERTY_DEVICE_LOCAL_BIT",
        "",
        "VkPhysicalDeviceFeatures:",
        "=========================",
        "\trobustBufferAccess = true",
        "",
    ]
    return "\n".join(lines) + "\n"


def legacy_json(dev_type: int, name: str, heaps: list[tuple[int, bool]]) -> dict:
    return {
        "$schema": "https://schema.khronos.org/vulkan/devsim_1_0_0.json#",
        "comments": {"desc": "Synthesised legacy vulkaninfo --json report (AIRLOCK test)"},
        "VkPhysicalDeviceProperties": {
            "apiVersion": 4206881,
            "deviceID": 0,
            "deviceName": name,
            "deviceType": dev_type,
            "driverVersion": 100671496,
            "vendorID": 0,
        },
        "VkPhysicalDeviceMemoryProperties": {
            "memoryHeapCount": len(heaps),
            "memoryHeaps": [{"flags": 1 if local else 0, "size": size} for size, local in heaps],
        },
    }


def meminfo(total_kb: int) -> str:
    return (
        f"MemTotal:       {total_kb} kB\n"
        f"MemFree:        {total_kb // 2} kB\n"
        f"MemAvailable:   {total_kb * 3 // 4} kB\n"
    )


def main() -> None:
    files: dict[str, str] = {}
    system_16 = 16 * GIB - 512 * MIB
    files["discrete-8gb.txt"] = HEADER + gpu_block(
        0, "DISCRETE_GPU", "Synthetic discrete GPU", [(8176 * MIB, True), (system_16, False)]
    )
    files["integrated-shared.txt"] = HEADER + gpu_block(
        0, "INTEGRATED_GPU", "Synthetic integrated GPU", [(12 * GIB, True)]
    )
    files["multi-gpu.txt"] = (
        HEADER
        + gpu_block(0, "INTEGRATED_GPU", "Synthetic integrated GPU", [(2 * GIB, True)])
        + gpu_block(
            1, "DISCRETE_GPU", "Synthetic discrete GPU A", [(12 * GIB, True), (system_16, False)]
        )
        + gpu_block(
            2, "DISCRETE_GPU", "Synthetic discrete GPU B", [(4 * GIB, True), (system_16, False)]
        )
        + gpu_block(3, "CPU", "Synthetic software rasteriser", [(system_16, True)])
    )
    files["discrete-4gb.legacy.json"] = (
        json.dumps(
            legacy_json(2, "Synthetic discrete GPU", [(4 * GIB, True), (system_16, False)]),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    files["two-discrete-24gb.list.json"] = (
        json.dumps(
            [
                legacy_json(2, "Synthetic discrete GPU A", [(6 * GIB, True)]),
                legacy_json(2, "Synthetic discrete GPU B", [(24 * GIB, True)]),
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    files["meminfo-16gb.txt"] = meminfo(16 * 1024 * 1024 - 300 * 1024)
    files["meminfo-8gb.txt"] = meminfo(8 * 1024 * 1024 - 300 * 1024)
    files["meminfo-64gb.txt"] = meminfo(64 * 1024 * 1024 - 900 * 1024)
    for name, text in files.items():
        (HERE / name).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
