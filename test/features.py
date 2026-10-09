#!/usr/bin/env python3
"""Preflight fixtures: real filesystems and field mutations, never real disks."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

mke2fs = os.environ.get("MKE2FS") or shutil.which("mke2fs")
if not mke2fs:
    raise SystemExit("e2fsprogs sbin must be in PATH, or set MKE2FS")
count = 0

def check(image, expected=None, cli=False):
    global count
    before = hashlib.sha256(image.read_bytes()).digest()
    argv = ["./ext4fuse", str(image), str(image.parent / "not-a-mountpoint")] if cli else ["./test/feature-probe", str(image)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    assert result.returncode == (1 if expected else 0), (argv, result.returncode, result.stderr)
    if expected:
        assert expected in result.stderr, (expected, result.stderr)
        assert "ASSERT" not in result.stderr
        assert "AddressSanitizer" not in result.stderr
    assert before == hashlib.sha256(image.read_bytes()).digest(), "reader changed image"
    count += 1

with tempfile.TemporaryDirectory(prefix="ext4fuse-features-") as temp:
    root = Path(temp)
    def make_image(name, options=()):
        image = root / name
        with image.open("wb") as file:
            file.truncate(32 * 1024 * 1024)
        subprocess.run([mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096", *options, str(image)], check=True, capture_output=True)
        return image

    base = make_image("default.img", ["-O", "^metadata_csum,^uninit_bg"])
    check(base)
    check(make_image("32bit.img", ["-O", "^64bit"]))
    check(make_image("inline.img", ["-O", "inline_data"]))
    check(make_image("largedir.img", ["-O", "large_dir"]))
    check(make_image("meta.img", ["-O", "meta_bg,^resize_inode"]))
    original_header = base.read_bytes()[:8192]
    def mutate(offset, fmt, value, expected=None):
        with base.open("r+b") as file:
            file.seek(offset)
            file.write(struct.pack("<" + fmt, value))
        try:
            check(base, expected)
            if expected:
                check(base, expected, cli=True)
        finally:
            with base.open("r+b") as file:
                file.write(original_header)

    incompat = struct.unpack_from("<I", original_header, 1024 + 0x60)[0]
    ro_compat = struct.unpack_from("<I", original_header, 1024 + 0x64)[0]
    for bit, name in [(1,"compression"),(4,"needs_recovery"),(8,"journal_dev"),
                      (0x100,"mmp"),(0x1000,"dirdata"),
                      (0x10000,"encrypt"),(0x20000,"casefold"),
                      (0x80000000,"unknown=0x80000000")]:
        mutate(1024 + 0x60, "I", incompat | bit, name)
    for bit, name in [(0x200,"bigalloc"),(0x4000,"shared_blocks"),(0x8000,"verity"),
                      (0x10000,"orphan_present"),(0x80000000,"unknown=0x80000000")]:
        mutate(1024 + 0x64, "I", ro_compat | bit, name)

    mutate(1024 + 0x60, "I", incompat | 0x400)

    with base.open("r+b") as file:
        file.seek(1024 + 0x60); file.write(struct.pack("<I", incompat | 0x400))
    mutate(1024 + 0x54, "I", 0, "first non-reserved inode")
    with base.open("r+b") as file:
        file.seek(1024 + 0x60); file.write(struct.pack("<I", incompat | 0x400))
    mutate(1024 + 0x48, "I", 1, "ea_inode requires Linux")

    # Compatible features may be ignored by a reader; do not confuse the masks.
    compat = struct.unpack_from("<I", original_header, 1024 + 0x5c)[0]
    mutate(1024 + 0x5c, "I", compat | 0x80000000)
    for offset, fmt, value, reason in [
        (0x38,"H",0,"bad magic"), (0x4c,"I",2,"revision"),
        (0x3a,"H",0,"not clean"), (0x3a,"H",3,"not clean"), (0xe8,"I",12,"not clean"),
        (0x18,"I",32,"block size"), (0x1c,"I",0,"cluster/block size"), (0x14,"I",1,"first data block"),
        (0x20,"I",0,"per group"), (0x28,"I",0,"per group"),
        (0x28,"I",65536,"per group"),
        (0x150,"I",0xffffffff,"signed 64-bit offsets"),
        (0x150,"I",0x10000,"group count exceeds"), (0x150,"I",1,"declared filesystem size"),
        (0x04,"I",0,"block/inode counts"), (0x00,"I",1,"block/inode counts"),
        (0x58,"H",0,"inode size"), (0x58,"H",192,"inode size"),
        (0xfe,"H",32,"descriptor size"), (0xfe,"H",128,"descriptor size"),
        (0x00,"I",0xffffffff,"inode count exceeds")]:
        mutate(1024 + offset, fmt, value, reason)
    mutate(1024 + 4, "I", 1, "group descriptor table exceeds")
    mutate(4096 + 8, "I", 0xffffffff, "inode table exceeds")
    mutate(4096 + 40, "I", 1, "inode table exceeds")

    for size, reason in [(0,"complete superblock"),(1100,"complete superblock"),(4096,"declared filesystem size")]:
        image = root / ("truncated-%d.img" % size)
        with image.open("wb") as file:
            file.write(original_header[:size])
        check(image, reason)
        check(image, reason, cli=True)

    # Real mkfs layouts independently exercise rejection of supported tool options.
    for name, options, reason in [

        ("encrypt.img", ["-O","encrypt"], "encrypt"),
        ("casefold.img", ["-O","casefold","-E","encoding=utf8"], "casefold"),

        ("bigalloc.img", ["-O","bigalloc","-C","8192"], "bigalloc")]:
        image = make_image(name, options)
        check(image, reason)
        check(image, reason, cli=True)

print("PASS: %d accepted/rejected preflight checks; images unchanged" % count)
