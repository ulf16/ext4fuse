# SPDX-License-Identifier: GPL-2.0-only
"""Trusted numeric caller context, supplied by a future authenticated frontend."""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class Credentials:
    uid: int
    gid: int
    groups: tuple = ()
    umask: int = 0o022

    def __post_init__(self):
        for value in (self.uid, self.gid, *self.groups):
            if type(value) is not int or not 0 <= value < 2**32 - 1:
                raise ValueError('invalid caller identity')
        if type(self.umask) is not int or not 0 <= self.umask <= 0o777:
            raise ValueError('invalid caller umask')
        if len(self.groups) > 64:
            raise ValueError('caller group limit')
        object.__setattr__(self, 'groups', tuple(sorted(set(self.groups))))

    def encode(self):
        return struct.pack('<IIII', self.uid, self.gid, self.umask, len(self.groups)) + struct.pack('<' + 'I' * len(self.groups), *self.groups)
