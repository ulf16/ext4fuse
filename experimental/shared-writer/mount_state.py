# SPDX-License-Identifier: GPL-2.0-only
"""Nonblocking kernel mount inventory, including disconnected FUSE mounts."""
import ctypes
import os
from pathlib import Path
import re
import sys


def mounts():
    if sys.platform == 'darwin':
        class Statfs(ctypes.Structure):
            _fields_ = [('bsize', ctypes.c_uint32), ('iosize', ctypes.c_int32),
                        ('counts', ctypes.c_uint64 * 5), ('fsid', ctypes.c_int32 * 2),
                        ('owner', ctypes.c_uint32), ('type', ctypes.c_uint32),
                        ('flags', ctypes.c_uint32), ('subtype', ctypes.c_uint32),
                        ('fstype', ctypes.c_char * 16), ('target', ctypes.c_char * 1024),
                        ('source', ctypes.c_char * 1024), ('reserved', ctypes.c_uint32 * 8)]
        libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        getmntinfo = getattr(libc, "getmntinfo$INODE64", libc.getmntinfo)
        getmntinfo.argtypes = [ctypes.POINTER(ctypes.POINTER(Statfs)), ctypes.c_int]
        getmntinfo.restype = ctypes.c_int
        entries = ctypes.POINTER(Statfs)()
        count = getmntinfo(ctypes.byref(entries), 2)  # MNT_NOWAIT: do not contact a dead filesystem.
        if count <= 0:
            raise OSError(ctypes.get_errno(), 'cannot read kernel mount inventory')
        return {os.fsdecode(entries[i].target): (os.fsdecode(entries[i].fstype), os.fsdecode(entries[i].source))
                for i in range(count)}
    if sys.platform == 'linux':
        def unescape(value):
            return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
        result = {}
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            fields = left.split(); details = right.split()
            result[unescape(fields[4])] = (details[0], unescape(details[1]))
        return result
    raise ValueError('writer mount inventory supports macOS and Linux only')


def attached(path):
    # Callers pass canonical mount intent, avoiding stat/realpath through a dead mount.
    return str(path) in mounts()
