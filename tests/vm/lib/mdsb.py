#!/usr/bin/env python3
"""Write Linux mdraid v1.2 superblocks without the md kernel driver (test fixture helper).

tests/run-qemu-tests.sh builds a disk carrying LVM, mdraid, and swap signatures (task
3A.10): the booted AIRLOCK image must leave it untouched and must not assemble it. When
the build host can run 'mdadm --create' the harness uses that; containers and some CI hosts
have no md driver, so this writes the same on-disk superblock (format from the kernel's
include/uapi/linux/raid/md_p.h) so that blkid reports linux_raid_member and
'mdadm --examine' and 'mdadm --incremental' accept the members.

Usage: mdsb.py [--name NAME] [--level 1] MEMBER [MEMBER ...]
Each MEMBER is a block device or file; member i gets role i in the array.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import uuid

MD_SB_MAGIC = 0xA92B4EFC
SB_OFFSET_BYTES = 4096  # v1.2: 4 KiB from the start of the member
DATA_OFFSET_SECTORS = 2048  # 1 MiB, as mdadm uses for small members
MAX_DEV = 128
SB_SIZE = 256 + 2 * MAX_DEV
MAX_SECTOR = 0xFFFFFFFFFFFFFFFF


def checksum(sb: bytes) -> int:
    """calc_sb_1_csum() from drivers/md/md.c, with sb_csum taken as zero."""
    buf = bytearray(sb)
    buf[216:220] = b"\0\0\0\0"
    size = 256 + 2 * struct.unpack_from("<I", buf, 220)[0]
    total = 0
    pos = 0
    while size >= 4:
        total += struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        size -= 4
    if size == 2:
        total += struct.unpack_from("<H", buf, pos)[0]
    return ((total & 0xFFFFFFFF) + (total >> 32)) & 0xFFFFFFFF


def superblock(
    *,
    set_uuid: bytes,
    name: str,
    level: int,
    raid_disks: int,
    dev_number: int,
    dev_sectors: int,
    when: int,
) -> bytes:
    data_size = dev_sectors - DATA_OFFSET_SECTORS
    if data_size <= 0:
        raise ValueError("member is too small for an mdraid superblock")
    sb = bytearray(SB_SIZE)
    struct.pack_into("<IIII", sb, 0, MD_SB_MAGIC, 1, 0, 0)
    sb[16:32] = set_uuid
    sb[32:64] = name.encode()[:32].ljust(32, b"\0")
    struct.pack_into("<QIIQ", sb, 64, when, level, 0, data_size)
    struct.pack_into("<II", sb, 88, 0, raid_disks)  # chunksize, raid_disks
    struct.pack_into("<QQQQ", sb, 128, DATA_OFFSET_SECTORS, data_size, SB_OFFSET_BYTES // 512, 0)
    struct.pack_into("<II", sb, 160, dev_number, 0)
    sb[168:184] = uuid.uuid5(uuid.UUID(bytes=set_uuid), str(dev_number)).bytes
    struct.pack_into("<QQQ", sb, 192, when, 1, MAX_SECTOR)  # utime, events, resync_offset
    struct.pack_into("<I", sb, 220, MAX_DEV)
    roles = [0xFFFF] * MAX_DEV
    for i in range(raid_disks):
        roles[i] = i
    struct.pack_into(f"<{MAX_DEV}H", sb, 256, *roles)
    struct.pack_into("<I", sb, 216, checksum(bytes(sb)))
    return bytes(sb)


def member_sectors(path: str) -> int:
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END) // 512
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mdsb.py", description=__doc__.splitlines()[0])
    ap.add_argument("--name", default="airlock:test")
    ap.add_argument("--level", type=int, default=1)
    ap.add_argument("--uuid", help="array UUID (default: random)")
    ap.add_argument("members", nargs="+")
    args = ap.parse_args(argv)
    set_uuid = uuid.UUID(args.uuid).bytes if args.uuid else uuid.uuid4().bytes
    when = int(time.time())
    for i, path in enumerate(args.members):
        sb = superblock(
            set_uuid=set_uuid,
            name=args.name,
            level=args.level,
            raid_disks=len(args.members),
            dev_number=i,
            dev_sectors=member_sectors(path),
            when=when,
        )
        fd = os.open(path, os.O_WRONLY)
        try:
            os.pwrite(fd, sb, SB_OFFSET_BYTES)
            os.fsync(fd)
        finally:
            os.close(fd)
    print(f"mdsb: wrote mdraid v1.2 superblocks (array {uuid.UUID(bytes=set_uuid)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
