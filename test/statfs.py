#!/usr/bin/env python3
"""Compare callback counts with e2fsprogs; mutate only disposable images."""
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

mke2fs = os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs = os.environ.get('DEBUGFS') or shutil.which('debugfs')
dumpe2fs = os.environ.get('DUMPE2FS') or shutil.which('dumpe2fs')
assert mke2fs and debugfs and dumpe2fs, 'e2fsprogs sbin must be in PATH'
count = 0

def check(image, error=0):
    global count
    before = hashlib.sha256(image.read_bytes()).digest()
    env = dict(os.environ, LC_ALL='C')
    header = subprocess.run([dumpe2fs, '-h', str(image)], env=env, text=True,
                            capture_output=True, check=True).stdout
    def field(name):
        return int(re.search(r'^' + re.escape(name) + r':\s+(\d+)', header, re.M)[1])
    bsize = field('Block size')
    free = field('Free blocks')
    expected = [bsize, bsize, field('Block count'), free,
                max(0, free - field('Reserved block count')), field('Inode count'),
                field('Free inodes'), field('Free inodes'), 255, 1]
    for path in ['/', '/payload', '/missing']:
        result = subprocess.run(['./test/corruption-probe', str(image), 'statfs', path],
                                text=True, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        assert int(lines[0]) == error, (lines, result.stderr)
        if not error:
            assert list(map(int, lines[1].split())) == expected, (lines, expected)
        else:
            assert len(lines) == 1, lines
        count += 1
    assert before == hashlib.sha256(image.read_bytes()).digest(), 'reader changed image'

with tempfile.TemporaryDirectory(prefix='ext4fuse-statfs-') as temp:
    root = Path(temp)
    payload = root / 'payload'
    payload.write_bytes(b'filesystem statistics\n' * 1000)
    for kind in ['ext2', 'ext3', 'ext4']:
        for block in [1024, 2048, 4096]:
            for reserve in [0, 5]:
                image = root / 'image'
                with image.open('wb') as file:
                    file.truncate(32 * 1024**2)
                subprocess.run([mke2fs, '-q', '-F', '-t', kind, '-b', str(block),
                                '-m', str(reserve), str(image)], check=True, capture_output=True)
                check(image)
                subprocess.run([debugfs, '-w', '-R', f'write {payload} /payload', str(image)],
                               check=True, capture_output=True)
                check(image)
    # Non-checksummed fixture permits isolated statistics mutations.
    subprocess.run([mke2fs, '-q', '-F', '-t', 'ext4', '-b', '4096', '-O',
                    '^metadata_csum,^uninit_bg', str(image)], check=True, capture_output=True)
    original = image.read_bytes()
    total = struct.unpack_from('<I', original, 1024 + 4)[0]
    inodes = struct.unpack_from('<I', original, 1024)[0]
    free = struct.unpack_from('<I', original, 1024 + 12)[0]
    for updates, error in [
        ({8: free + 1}, 0),  # reserved allowance may exceed current free space
        ({12: 0, 16: 0}, 0),
        ({12: total + 1}, -errno.EIO),
        ({8: total + 1}, -errno.EIO),
        ({16: inodes + 1}, -errno.EIO),
        ({0x158: 1}, -errno.EIO),
        ({0x154: 1}, -errno.EIO),
    ]:
        data = bytearray(original)
        for offset, value in updates.items():
            struct.pack_into('<I', data, 1024 + offset, value)
        image.write_bytes(data)
        check(image, error)
    # Restore before removing the fixture.
    image.write_bytes(original)
print(f'PASS: {count} statfs/reference/error checks; images unchanged')
