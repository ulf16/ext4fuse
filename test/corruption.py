#!/usr/bin/env python3
"""Compare normal reads with debugfs; malformed records must return errors."""
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

mkfs = os.environ.get("MKE2FS") or shutil.which("mke2fs")
debugfs = os.environ.get("DEBUGFS") or shutil.which("debugfs")
if not mkfs or not debugfs:
    raise SystemExit("Add e2fsprogs sbin to PATH or set MKE2FS/DEBUGFS")
checks = 0
with tempfile.TemporaryDirectory(prefix="ext4fuse-corruption-") as temp:
    root = Path(temp)
    block = 4096
    data = bytes((i % 251) + 1 for i in range(block * 16 + 13))
    host = root / "payload"
    host.write_bytes(data)
    sparse = root / "sparse"
    sparse_data = bytes(block) + data[:block] + bytes(block) + b"tail"
    sparse.write_bytes(sparse_data)
    image = root / "ext4.img"
    def debug(command, target=image):
        return subprocess.run([debugfs, "-w", "-R", command, str(target)], check=True, capture_output=True, text=True).stdout
    def create(target, kind):
        with target.open("wb") as f: f.truncate(32 * 1024 * 1024)
        subprocess.run([mkfs, "-q", "-F", "-t", kind, "-b", str(block), "-O", "^metadata_csum,^uninit_bg", str(target)], check=True, capture_output=True)
        debug("write %s /payload" % host, target)
    create(image, "ext4")
    debug("write %s /sparse" % sparse)
    debug("mkdir /nested")
    debug("write %s /nested/payload" % host)
    debug("symlink /short payload")
    long_target = "n" * 100
    debug("symlink /long " + long_target)
    baseline = image.read_bytes()
    def check(operation, path, expected, offset=0, content=None, target=image):
        global checks
        before = hashlib.sha256(target.read_bytes()).digest()
        result = subprocess.run(["./test/corruption-probe", str(target), operation, path, str(offset)], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, (result.returncode, result.stderr)
        assert not result.stderr, result.stderr
        lines = result.stdout.splitlines()
        assert int(lines[0]) == expected, (operation, path, offset, result.stdout)
        if content is not None:
            got = bytes.fromhex(lines[1]) if operation == "read" and expected > 0 else lines[1].encode() if len(lines) > 1 else b""
            assert got == content, (operation, path, offset, got, content)
        if not operation.startswith("truncate-"):
            assert before == hashlib.sha256(target.read_bytes()).digest()
        else:
            assert target.stat().st_size < len(baseline)
        checks += 1
    for operation, path in [("truncate-read", "/payload"), ("truncate-list", "/")]:
        try:
            check(operation,path,-errno.EIO)
        finally:
            image.write_bytes(baseline)
    # debugfs is an independent Linux userspace ext reader; compare its dump.
    dump = root / "dump"
    debug("dump /payload %s" % dump)
    assert dump.read_bytes() == data
    sparse_dump = root / "sparse-dump"
    debug("dump /sparse %s" % sparse_dump)
    assert sparse_dump.read_bytes() == sparse_data
    for path, contents in [("/payload",data),("/nested/payload",data),("/sparse",sparse_data)]:
        for offset in [0, 5, block-8, block+5, len(contents)-8, len(contents), len(contents)+1]:
            expected = contents[offset:offset+64]
            check("read",path,len(expected),offset,expected)
    check("lookup", "/payload/child", -errno.ENOTDIR)
    check("lookup", "/payload/", -errno.ENOTDIR)
    check("read", "/missing", -errno.ENOENT)
    check("read", "/payload", -errno.EINVAL, -1)
    check("list", "/payload", -errno.ENOTDIR)
    check("list", "/", 0)
    check("list", "/", -errno.EINVAL, 2)
    check("list", "/", -errno.EINVAL, -1)
    check("list", "/", -errno.EIO, block-4)
    check("link", "/short", 0, 4, b"pay")
    check("link", "/long", 0, 5, b"nnnn")
    check("link", "/missing", -errno.ENOENT, 4)
    check("link", "/short", -errno.ERANGE, 0)
    def number(path):
        return int(re.search(r"Inode:\s*(\d+)", debug("stat " + path)).group(1))
    inode_size = struct.unpack_from("<H", baseline, 1024+0x58)[0]
    table_block = struct.unpack_from("<I", baseline, block+8)[0]
    def inode_offset(n): return table_block * block + (n-1)*inode_size
    payload = inode_offset(number("/payload"))
    root_inode = inode_offset(2)
    root_block = struct.unpack_from("<I",baseline,root_inode+60)[0]*block
    def mutation(patches, operation="read", path="/payload", expected=-errno.EIO, offset=0, content=None):
        try:
            with image.open("r+b") as f:
                for position, raw in patches: f.seek(position); f.write(raw)
            check(operation,path,expected,offset,content)
        finally:
            with image.open("r+b") as f:
                for position, raw in patches: f.seek(position); f.write(baseline[position:position+len(raw)])
    def field(position, fmt, value): return (position,struct.pack("<"+fmt,value))
    for rel,fmt,value in [(4,"H",0),(4,"H",4),(4,"H",10),(4,"H",65532),
                          (6,"B",5),(6,"B",0),(7,"B",9),(0,"I",0xffffffff),(8,"B",0),(8,"B",47)]:
        mutation([field(root_block+rel,fmt,value)],"list","/")
    mutation([field(root_inode+4,"I",0)],"list","/")
    mutation([field(root_inode+4,"I",block-1)],"list","/")
    mutation([field(root_inode+40,"H",0)],"list","/")
    tree = payload+40
    for rel,fmt,value in [(0,"H",0),(2,"H",5),(4,"H",5),(6,"H",6),
                          (16,"H",0),(18,"H",1),(20,"I",0),(20,"I",8192),(12,"I",0xffffffff)]:
        mutation([field(tree+rel,fmt,value)])
    # Overlapping leaf entries and corrupt/missing interior nodes.
    first = baseline[tree+12:tree+24]
    mutation([field(tree+2,"H",2),(tree+24,first)])
    def header(entries,depth,maximum=4): return struct.pack("<HHHHI",0xf30a,entries,maximum,depth,0)
    def index(key,pointer,high=0): return struct.pack("<IIHH",key,pointer,high,0)
    for node in [header(0,1)+bytes(48), header(1,1)+index(0,0)+bytes(36),
                 header(1,1)+index(0,8192)+bytes(36),header(1,1)+index(0,8000,1)+bytes(36),
                 header(2,1)+index(5,8000)+index(3,8001)+bytes(24)]:
        mutation([(tree,node)])
    child = 8000*block
    parent = header(1,1)+index(0,8000)+bytes(36)
    mutation([(tree,parent),(child,bytes(block))])
    mutation([(tree,parent),(child,header(1,1)+index(0,8000)+bytes(block-24))])
    # A valid external leaf remains readable; parent/child key and depth checks are exercised.
    leaf = header(1,0,(block-12)//12)+first+bytes(block-24)
    mutation([(tree,parent),(child,leaf)],expected=64,content=data[:64])
    shifted_leaf = bytearray(leaf)
    struct.pack_into("<I", shifted_leaf, 12, 1)
    mutation([(tree,parent),(child,shifted_leaf)])
    mutation([(tree,header(1,2)+index(0,8000)+bytes(36)),
              (child,header(1,1,(block-12)//12)+index(0,8000)+bytes(block-24))])
    # A gap before an extent and unwritten extents return zeroes even at unaligned offsets.
    mutation([field(tree+12,"I",1)],expected=64,offset=5,content=bytes(64))
    mutation([field(tree+16,"H",32768+17)],expected=64,offset=5,content=bytes(64))
    # Force a real depth-one extent tree using debugfs hole punching.
    fragmented = root / "fragmented.img"
    create(fragmented,"ext4")
    expected_fragmented = bytearray(data)
    for logical in range(1,16,2):
        debug("punch /payload %d %d" % (logical,logical),fragmented)
        expected_fragmented[logical*block:(logical+1)*block] = bytes(block)
    fragment_dump = root / "fragment-dump"
    debug("dump /payload %s" % fragment_dump,fragmented)
    assert fragment_dump.read_bytes() == expected_fragmented
    raw_fragment = fragmented.read_bytes()
    fragment_number = int(re.search(r"Inode:\s*(\d+)",debug("stat /payload",fragmented)).group(1))
    fragment_table = struct.unpack_from("<I",raw_fragment,block+8)[0]*block
    fragment_inode = fragment_table+(fragment_number-1)*inode_size
    assert struct.unpack_from("<H",raw_fragment,fragment_inode+46)[0] > 0
    for offset in [0,block+3,2*block-8,8*block+3,len(data)-8]:
        chunk = expected_fragmented[offset:offset+64]
        check("read","/payload",len(chunk),offset,chunk,fragmented)
    legacy = root / "ext2.img"
    create(legacy,"ext2")
    for offset in [5,15*block+3]:
        check("read","/payload",64,offset,data[offset:offset+64],legacy)
print("PASS: %d directory/extent/read checks, including debugfs comparison" % checks)
