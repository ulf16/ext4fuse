#!/usr/bin/env python3
"""Classic block-map runs against debugfs, including holes and corrupt pointers."""
import errno
import hashlib
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import tempfile

mkfs = shutil.which('mke2fs'); debugfs = shutil.which('debugfs'); fsck = shutil.which('e2fsck')
assert mkfs and debugfs and fsck, 'e2fsprogs sbin must be in PATH'
checks = 0

def command(image, text, writable=False):
    result = subprocess.run([debugfs, *(['-w'] if writable else []), '-R', text, str(image)],
                            capture_output=True, text=True, check=True)
    assert not any(s in result.stderr for s in ['Could not', 'not found', 'Usage:', 'allocating block']), result.stderr
    return result.stdout

def probe(image, op, offset=0, size=0):
    global checks
    args = ['./test/corruption-probe', str(image), op, '/payload', str(offset)]
    if op == 'bulk': args.append(str(size))
    result = subprocess.run(args, capture_output=True, check=True, timeout=20)
    assert not result.stderr, result.stderr
    status, _, output = result.stdout.partition(b'\n')
    checks += 1
    return int(status), output

def verify(image, expected, block):
    before = hashlib.sha256(image.read_bytes()).digest()
    mapping = {}
    text = command(image, 'stat /payload')
    for match in re.finditer(r'\((\d+)(?:-(\d+))?\):(\d+)(?:-(\d+))?', text):
        first, last, physical, end = match.groups()
        first, last, physical = int(first), int(last or first), int(physical)
        assert int(end or physical) - physical == last - first, match.group()
        mapping.update((logical, physical + logical - first) for logical in range(first, last + 1))
    per = block // 4
    boundaries = [0, 1, 10, 11, 12, 13, 14, 15, 12 + per - 1, 12 + per,
                  12 + per + 1, 12 + per + per - 1, 12 + per + per]
    for logical in boundaries:
        if logical * block >= len(expected): continue
        result, output = probe(image, 'map', logical)
        assert result == 0, (logical, result)
        physical, run = map(int, output.split())
        assert physical == mapping.get(logical, 0), (logical, physical, mapping)
        limit = 12 - logical if logical < 12 else per - ((logical - 12) % per)
        length = 1
        while length < limit:
            next_block = mapping.get(logical + length, 0)
            if (physical == 0 and next_block != 0) or (physical and next_block != physical + length): break
            length += 1
        assert run == length, (logical, run, length)
    offsets = {0, 7, block - 9, 12 * block - 11, (12 + per) * block - 17,
               (12 + 2 * per) * block - 19, len(expected) - 9, len(expected), len(expected) + 1}
    for offset in sorted(offsets):
        for size in [64, block, 65536, 1048576]:
            result, output = probe(image, 'bulk', offset, size)
            want = expected[offset:offset + size]
            assert result == len(want) and output == want, (block, offset, size, result, len(want))
    result, output = probe(image, 'bulk', 0, len(expected))
    assert result == len(expected) and output == expected
    assert before == hashlib.sha256(image.read_bytes()).digest(), 'reader changed image'

with tempfile.TemporaryDirectory(prefix='ext4fuse-indirect-runs-') as temp:
    root = Path(temp); host = root / 'host'; extracted = root / 'extracted'
    rng = random.Random(0x8f2f)
    payload = rng.randbytes(8 * 1024**2 + 17); host.write_bytes(payload)
    for block in [1024, 2048, 4096]:
        image = root / 'image'
        with image.open('wb') as file: file.truncate(64 * 1024**2)
        subprocess.run([mkfs, '-q', '-F', '-t', 'ext2', '-b', str(block), str(image)], capture_output=True, check=True)
        command(image, f'write {host} /payload', True)
        subprocess.run([fsck, '-f', '-n', str(image)], capture_output=True, check=True)
        verify(image, payload, block)
        per = block // 4
        # Holes in direct, single and double indirect arrays.
        expected = bytearray(payload)
        for logical in [1, 2, 14, 15, 12 + per - 1, 12 + per + 1]:
            command(image, f'punch /payload {logical} {logical}', True)
            expected[logical * block:(logical + 1) * block] = bytes(block)
        verify(image, expected, block)
        # A second file consumes freed blocks before reallocation, introducing
        # discontinuities. debugfs is the independent content/mapping oracle.
        command(image, f'write {host} /other', True)
        for logical in [2, 15, 12 + per + 1]:
            physical = int(command(image, f'bmap -a /payload {logical}', True))
            marker = bytes([logical % 251 + 1]) * block
            with image.open('r+b') as file:
                file.seek(physical * block); file.write(marker)
            expected[logical * block:(logical + 1) * block] = marker
        subprocess.run([fsck, '-f', '-n', str(image)], capture_output=True, check=True)
        command(image, f'dump /payload {extracted}')
        assert extracted.read_bytes() == expected
        verify(image, expected, block)
        # Triple-indirect runs and absent intermediate subtrees in a sparse
        # logical file. The backing image stays small; no multi-GB buffer.
        triple = 12 + per + per * per
        tail_size = (triple + 4) * block + 3
        command(image, f'set_inode_field /payload size {tail_size}', True)
        high_markers = {}
        for logical in range(triple, triple + 4):
            physical = int(command(image, f'bmap -a /payload {logical}', True))
            marker = bytes([logical % 251 + 1]) * block
            with image.open('r+b') as file:
                file.seek(physical * block); file.write(marker)
            high_markers[logical] = marker
        subprocess.run([fsck, '-f', '-n', str(image)], capture_output=True, check=True)
        before_high = hashlib.sha256(image.read_bytes()).digest()
        for logical in range(triple, triple + 4):
            physical = int(command(image, f'bmap /payload {logical}'))
            status, output = probe(image, 'map', logical)
            got, run = map(int, output.split())
            assert status == 0 and got == physical and 1 <= run <= per - (logical - triple)
            # Every promised block must match the independent mapping oracle.
            for delta in range(min(run, 4 - (logical - triple))):
                assert int(command(image, f'bmap /payload {logical + delta}')) == physical + delta
        for offset in [(triple - 3) * block + 7, triple * block - 9,
                       triple * block + 5, (triple + 3) * block - 11,
                       tail_size - 3, tail_size]:
            for length in [64, block, 65536]:
                want = bytearray(min(length, max(0, tail_size - offset)))
                for logical, marker in high_markers.items():
                    first = max(offset, logical * block)
                    last = min(offset + len(want), (logical + 1) * block)
                    if last > first: want[first - offset:last - offset] = marker[first - logical * block:last - logical * block]
                status, output = probe(image, 'bulk', offset, length)
                assert status == len(want) and output == want, (block, offset, length, status)
        assert before_high == hashlib.sha256(image.read_bytes()).digest()
        # An invalid next pointer must not be hidden by coalescing, and must not
        # poison a read that requests only the preceding valid block.
        text = command(image, 'stat /payload')
        leaf = int(re.search(r'\(IND\):(\d+)', text)[1])
        location = leaf * block + 4  # logical block 13
        with image.open('r+b') as file:
            file.seek(location); saved = file.read(4)
            file.seek(location); file.write(struct.pack('<I', 0xffffffff))
        try:
            status, output = probe(image, 'bulk', 12 * block, block)
            assert status == block and output == expected[12 * block:13 * block]
            status, output = probe(image, 'bulk', 12 * block, block + 1)
            assert status == -errno.EIO and not output
            status, _ = probe(image, 'map', 13)
            assert status == -errno.EIO
        finally:
            with image.open('r+b') as file: file.seek(location); file.write(saved)
print(f'PASS: {checks} indirect-run mapping/content/error checks; images unchanged')
