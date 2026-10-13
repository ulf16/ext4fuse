# SPDX-License-Identifier: GPL-2.0-only
"""Test-only one-shot failure after an actual partial managed-image replay."""
from contextlib import contextmanager
import errno
from pathlib import Path
import inplace

@contextmanager
def torn_replay(marker=None):
    original = inplace.boundary
    observed = {'hit': False}
    def boundary(name):
        if name == 'half:0:0' and not observed['hit']:
            observed['hit'] = True
            if marker is not None:
                Path(marker).write_text(name + '\n')
            raise OSError(errno.EIO, 'injected failure after half-page replay')
        original(name)
    inplace.boundary = boundary
    try:
        yield observed
    finally:
        inplace.boundary = original
