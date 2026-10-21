# SPDX-License-Identifier: GPL-2.0-only
"""Disposable persistent leaf snapshot, authenticated by the durable chain root.

Only clean heads are eligible. Rebuild every internal node from the leaf stream;
a stored root or checksum supplied by the index itself never grants trust.
Publication is atomic and optional: redo and chain-state remain authoritative.
"""
import json
import os
import tempfile

import merkle
import progress
from durable import regular, sync, directory, boundary

NAME = 'integrity-index'
HEADER = 4096


def load(root, state):
    """Return a fully authenticated tree, or None for a cache miss.

    Callers own chain-lock and exclusive media admission. Fingerprints detect
    ordinary external edits; verified reads detect otherwise invisible changes.
    Pending transactions always take the existing full-scan recovery path.
    """
    if state['version'] != 2 or state['pending'] is not None:
        return None
    tree = None
    try:
        with regular(root / 'image.img') as image, regular(root / NAME) as saved:
            stamp = merkle.fingerprint(merkle.identity(image, state))
            info = merkle.owned(saved)
            if info.st_mode & 0o077:
                return None
            raw = saved.read(HEADER)
            if len(raw) != HEADER:
                return None
            meta = json.loads(raw.rstrip(b'\0'))
            if meta != dict(format=1, state=state, stamp=list(stamp)):
                return None
            count = (state['size'] + merkle.CHUNK - 1) // merkle.CHUNK
            if info.st_size != HEADER + count * 32:
                return None
            progress.stage('Loading authenticated integrity index; verifying stored chunk hashes...')
            tree = merkle.Tree(state['size'])
            for start in range(0, count, 2048):
                amount = min(2048, count - start)
                data = saved.read(amount * 32)
                if len(data) != amount * 32:
                    raise ValueError('short integrity index')
                for i in range(amount):
                    tree.set(tree.width + start + i, data[i*32:(i+1)*32])
            tree.finish()
            if tree.root() != state['sha256'] or merkle.fingerprint(merkle.identity(image, state)) != stamp:
                raise ValueError('integrity index authentication failed')
            tree.stamp = stamp
            return tree
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        if tree is not None:
            tree.close()
        return None


def save(root, state, tree):
    """Publish a complete snapshot after durable head publication, under lock.

    Cache write failures cost performance only; they never acknowledge a write
    or retire redo. A previous snapshot can remain and will miss by head/root.
    """
    if state['version'] != 2 or state['pending'] is not None:
        return False
    temporary = None
    try:
        with regular(root / 'image.img') as image:
            tree.check(image, state)
            encoded = json.dumps(dict(format=1, state=state, stamp=list(tree.stamp)),
                                 sort_keys=True, separators=(',', ':')).encode()
            if len(encoded) > HEADER:
                raise ValueError('oversized integrity index header')
            fd, temporary = tempfile.mkstemp(prefix='.integrity-index-', dir=root)
            with os.fdopen(fd, 'wb') as output:
                output.write(encoded.ljust(HEADER, b'\0'))
                for start in range(0, tree.count, 2048):
                    output.write(b''.join(tree.get(tree.width + i)
                        for i in range(start, min(tree.count, start + 2048))))
                output.flush()
                boundary('index:written')
                sync(output.fileno())
                boundary('index:synced')
            tree.check(image, state)
            os.replace(temporary, root / NAME)
            temporary = None
            boundary('index:renamed')
            directory(root)
            boundary('index:published')
            return True
    except OSError:
        return False
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
