"""airlock-check-boot-chain (task 1.13): SBAT levels and signers of EFI binaries.

Builds small synthetic PE32+ files with a .sbat section and an Authenticode-style
certificate table holding a CMS signature made here with openssl, so no real shim is
needed. (A real shimx64.efi.signed from shim-signed 1.58 reports shim,4 and the
Microsoft UEFI CA 2011.)
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "ansible" / "roles" / "base" / "files" / "airlock_check_boot_chain.py"

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("airlock_check_boot_chain", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up here
    spec.loader.exec_module(mod)
    return mod


chain = load()


def make_pe(sbat: bytes | None, signature: bytes | None) -> bytes:
    """Minimal PE32+ image: one optional .sbat section and an optional certificate table."""
    e_lfanew = 0x80
    opt_size = 112 + 16 * 8
    n_sections = 1 if sbat is not None else 0
    raw_ptr = 0x200
    body = bytearray(raw_ptr)
    body[0:2] = b"MZ"
    struct.pack_into("<I", body, 0x3C, e_lfanew)
    body[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", body, e_lfanew + 4, 0x8664, n_sections, 0, 0, 0, opt_size, 0x22)
    opt = e_lfanew + 24
    struct.pack_into("<H", body, opt, 0x20B)
    struct.pack_into("<I", body, opt + 108, 16)  # NumberOfRvaAndSizes
    if sbat is not None:
        sec = opt + opt_size
        raw_size = (len(sbat) + 0x1FF) // 0x200 * 0x200
        body[sec : sec + 8] = b".sbat\0\0\0"
        struct.pack_into("<IIII", body, sec + 8, len(sbat), 0x1000, raw_size, raw_ptr)
        body += sbat.ljust(raw_size, b"\0")
    if signature is not None:
        cert_off = len(body)
        entry = struct.pack("<IHH", 8 + len(signature), 0x0200, 0x0002) + signature
        entry = entry.ljust((len(entry) + 7) // 8 * 8, b"\0")
        struct.pack_into("<II", body, opt + 112 + 8 * 4, cert_off, len(entry))
        body += entry
    return bytes(body)


@pytest.fixture(scope="module")
def signature(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    d = tmp_path_factory.mktemp("sig")
    key, cert, data, out = d / "k.pem", d / "c.pem", d / "data", d / "sig.der"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/O=Test/CN=Test Microsoft UEFI CA 2023 stand-in",
        ],
        check=True,
        capture_output=True,
    )
    data.write_bytes(b"not a real image hash")
    subprocess.run(
        [
            "openssl",
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-in",
            str(data),
            "-signer",
            str(cert),
            "-inkey",
            str(key),
            "-outform",
            "DER",
            "-out",
            str(out),
        ],
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


SHIM_SBAT = (
    b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
    b"shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim\n"
    b"shim.ubuntu,1,Ubuntu,shim,15.8-0ubuntu1,https://www.ubuntu.com/\n\0"
)
GRUB_SBAT = (
    b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
    b"grub,5,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/\n\0"
)


def run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict]:
    rc = chain.main(args)
    out = capsys.readouterr().out
    return rc, json.loads(out) if out.strip() else {}


def test_sbat_levels_met(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], signature: bytes
) -> None:
    shim = tmp_path / "BOOTX64.EFI"
    grub = tmp_path / "grubx64.efi"
    shim.write_bytes(make_pe(SHIM_SBAT, signature))
    grub.write_bytes(make_pe(GRUB_SBAT, None))
    rc, rep = run(["--min-sbat=shim=4", "--min-sbat=grub=5", str(shim), str(grub)], capsys)
    assert rc == 0
    assert rep["sbat_ok"] is True
    assert rep["problems"] == []
    comps = {e["component"]: e["generation"] for f in rep["files"] for e in f["sbat"]}
    assert comps["shim"] == 4 and comps["grub"] == 5


def test_sbat_below_minimum_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    shim = tmp_path / "BOOTX64.EFI"
    shim.write_bytes(make_pe(SHIM_SBAT, None))
    rc, rep = run(["--min-sbat", "shim=5", str(shim)], capsys)
    assert rc == 1
    assert rep["sbat_ok"] is False
    assert rep["problems"] == ["SBAT shim generation 4 is below 5"]


def test_missing_component_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "x.efi"
    f.write_bytes(make_pe(None, None))
    rc, rep = run(["--min-sbat", "grub=1", str(f)], capsys)
    assert rc == 1
    assert rep["problems"] == ["no SBAT entry for grub"]


def test_signer_names_and_2023_ca(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], signature: bytes
) -> None:
    f = tmp_path / "BOOTX64.EFI"
    f.write_bytes(make_pe(SHIM_SBAT, signature))
    rc, rep = run([str(f)], capsys)
    assert rc == 0
    info = rep["files"][0]
    assert info["signature_count"] == 1
    assert "Test Microsoft UEFI CA 2023 stand-in" in info["signer_names"]
    assert info["ms_uefi_ca_2023"] is True
    assert info["ms_uefi_ca_2011"] is False
    assert rep["ms_uefi_ca_2023_any"] is True


def test_unsigned_binary_reports_no_signers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "grubx64.efi"
    f.write_bytes(make_pe(GRUB_SBAT, None))
    rc, rep = run([str(f)], capsys)
    assert rc == 0
    assert rep["files"][0]["signer_names"] == []
    assert rep["files"][0]["ms_uefi_ca_2023"] is False


def test_not_a_pe_file_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "junk.efi"
    f.write_bytes(b"this is not an EFI binary")
    rc, rep = run([str(f)], capsys)
    assert rc == 1
    assert "no MZ header" in rep["problems"][0]


def test_bad_minimum_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "x.efi"
    f.write_bytes(make_pe(SHIM_SBAT, None))
    assert chain.main(["--min-sbat", "shim", str(f)]) == 2


def test_parse_sbat_skips_malformed_lines() -> None:
    entries = chain.parse_sbat(b"shim,4,a,b,c,d\ngarbage\nshim.x,notanumber,a\n\0trailing")
    assert [(e.component, e.generation) for e in entries] == [("shim", 4)]
