# vulkaninfo fixtures (task 4G.9)

Inputs for `ai-probe` in `tests/unit/test_probe.py`. Every file holds capacities only; the probe
must reach the same tier whatever the device name or vendor says.

| File | Kind | What it is |
|---|---|---|
| `recorded-llvmpipe-no-gpu.txt` | recorded | `vulkaninfo` 1.3.275 text report, Mesa 25.2.8 llvmpipe only (no GPU, as in QEMU) |
| `recorded-llvmpipe-summary.txt` | recorded | `vulkaninfo --summary` on the same machine (no heaps) |
| `recorded-llvmpipe-profile.json` | recorded, trimmed | the Vulkan Profiles file `vulkaninfo --json` writes, cut to `VkPhysicalDeviceProperties` (it has no memory heaps) |
| `discrete-8gb.txt` | synthesised | one discrete GPU, 8176 MiB device-local heap |
| `discrete-4gb.legacy.json` | synthesised | legacy `vulkaninfo --json` report, discrete 4 GiB |
| `integrated-shared.txt` | synthesised | one integrated GPU reporting a 12 GiB device-local heap (shared RAM) |
| `multi-gpu.txt` | synthesised | integrated 2 GiB, discrete 12 GiB, discrete 4 GiB, and a CPU device |
| `two-discrete-24gb.list.json` | synthesised | JSON list of two legacy reports: 6 GiB and 24 GiB |
| `meminfo-*.txt` | synthesised | `/proc/meminfo` heads for 8, 16, and 64 GB machines |

Regenerate the synthesised files with `python3 make-synthetic.py`. Add real recordings from the
hardware matrix (`docs/hardware-matrix.md`, task 4B.13) as `recorded-<type>-<GiB>.txt`.
