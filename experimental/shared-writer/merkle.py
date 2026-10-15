#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Session-local authenticated chunk tree; cold recovery always scans clean bytes.

Only roots are persisted, alongside complete page preimages/redo. No mutable
on-disk hash index needs its own crash protocol. The cache is trusted only while
chain-lock is held and the image's identity/mtime/ctime fingerprint is unchanged.
"""
import image_io
import fcntl
import hashlib
import json
import os
import stat
import struct
import subprocess

from durable import directory, regular, sync, digest

CHUNK = 1024 * 1024
PAGE = 4096
ALGORITHM = 'sha256-merkle-1m-v1'
RECORD = struct.Struct('<Q4096s4096s')
MAX_RECORDS = 1_048_576
MAX_CACHE = 256 * 1024 * 1024


def boundary(name):
    # Keep the established replay fault-injection hook for both log formats.
    import inplace
    inplace.boundary(name)


def sha(data):
    return hashlib.sha256(data).digest()


def leaf(index, data):
    return sha(b'E4LEAF01' + struct.pack('<QQ', index, len(data)) + data)


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_nlink, info.st_mode)


def owned(stream):
    info = os.fstat(stream.fileno())
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError("Merkle log and markers must be owned single-link files")
    return info


def identity(image, state):
    info = os.fstat(image.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_nlink != 1 or (info.st_dev, info.st_ino, info.st_size) !=
            (state['device'], state['inode'], state['size'])):
        raise ValueError('chain image identity changed')
    return info


class Tree:
    def __init__(self, size):
        if size <= 0 or size % PAGE:
            raise ValueError('invalid Merkle image size')
        self.size = size
        self.count = (size + CHUNK - 1) // CHUNK
        self.width = 1 << (self.count - 1).bit_length()
        if self.width * 64 > MAX_CACHE:
            raise ValueError('Merkle cache exceeds 256 MiB budget')
        self.nodes = bytearray(self.width * 64)
        self.stamp = None
        for i in range(self.count, self.width):
            self.set(self.width + i, leaf(i, b''))

    def get(self, node):
        return bytes(self.nodes[node * 32:(node + 1) * 32])

    def set(self, node, value):
        self.nodes[node * 32:(node + 1) * 32] = value

    def finish(self):
        for node in range(self.width - 1, 0, -1):
            self.set(node, sha(b'E4NODE01' + self.get(node * 2) + self.get(node * 2 + 1)))

    def root(self, changes=None):
        node = (changes or {}).get(1, self.get(1))
        return sha(b'E4ROOT01' + struct.pack('<QQ', self.size, CHUNK) + node).hex()

    def updates(self, leaves):
        changes = {self.width + i: value for i, value in leaves.items()}
        level = set(changes)
        while level and level != {1}:
            parents = {i // 2 for i in level}
            for i in parents:
                left = changes.get(i * 2, self.get(i * 2))
                right = changes.get(i * 2 + 1, self.get(i * 2 + 1))
                changes[i] = sha(b'E4NODE01' + left + right)
            level = parents
        return changes

    def commit(self, changes):
        for node, value in changes.items():
            self.set(node, value)

    def check(self, image, state):
        info = identity(image, state)
        if fingerprint(info) != self.stamp or self.root() != state['sha256']:
            raise ValueError('image changed outside the live authenticated session')
        return info


def scan(image, state):
    before = fingerprint(identity(image, state))
    tree = Tree(state['size'])
    image.seek(0)
    for index in range(tree.count):
        data = image.read(min(CHUNK, tree.size - index * CHUNK))
        if len(data) != min(CHUNK, tree.size - index * CHUNK):
            raise ValueError('short image during Merkle scan')
        tree.set(tree.width + index, leaf(index, data))
    tree.finish()
    tree.stamp = fingerprint(identity(image, state))
    if tree.stamp != before:
        raise ValueError('image changed during Merkle scan')
    return tree


def activate(root, state):
    import inplace
    with regular(root / 'image.img') as image:
        tree = scan(image, state)
    if state['version'] == 2:
        if tree.root() != state['sha256']:
            raise ValueError('chain Merkle root mismatch')
    else:
        # Caller has already verified the legacy whole-image digest. Check it
        # again across migration so neither format trusts an unchecked image.
        with regular(root / 'image.img') as image:
            tree.check(image, dict(state, sha256=tree.root()))
            if digest(image) != state['sha256']:
                raise ValueError('legacy image changed during hash migration')
            tree.check(image, dict(state, sha256=tree.root()))
        state = dict(state, version=2, algorithm=ALGORITHM, sha256=tree.root())
        inplace.seal(root, 'chain-state', state)
    return state, tree


def capture(image_path, generation, producer, tree, expected_base):
    import inplace
    with regular(image_path) as image:
        info = os.fstat(image.fileno())
        state = dict(device=info.st_dev, inode=info.st_ino, size=tree.size, sha256=expected_base)
        tree.check(image, state)
        process = subprocess.Popen([str(producer), str(image_path), '--stream'], stdout=subprocess.PIPE, **image_io.child(image_path))
        try:
            read = inplace.block.read_exact
            magic, size, staged = struct.unpack('<8sQQ', read(process.stdout, 24))
            if magic == b'E4ER0001':
                if not 0 < size < 4096 or staged or process.stdout.read(1) or process.wait(timeout=60) == 0:
                    raise ValueError('invalid overlay producer error frame')
                raise OSError(size, os.strerror(size))
            if magic != b'E4OVL001' or size != tree.size or staged > min(MAX_RECORDS, size // PAGE):
                raise ValueError('invalid overlay stream header')
            count, previous = 0, -1
            with (generation / 'pages').open('xb') as log:
                for _ in range(staged):
                    record = read(process.stdout, RECORD.size)
                    index, old, new = RECORD.unpack(record)
                    if not previous < index < size // PAGE:
                        raise ValueError('invalid overlay stream page order or bounds')
                    image.seek(index * PAGE)
                    if image.read(PAGE) != old:
                        raise ValueError('overlay stream preimage mismatch')
                    if old != new:
                        log.write(record)
                        count += 1
                    previous = index
                    boundary('record')
                if process.stdout.read(1) or process.wait(timeout=60) != 0:
                    raise ValueError('overlay producer failed or emitted trailing data')
                log.flush()
                sync(log.fileno())
            boundary('snapshot')
            tree.check(image, state)
            with regular(generation / 'pages') as log:
                changes = plan(image, log, count, tree, 'base')
                log_hash = digest(log)
            tree.check(image, state)
            boundary('undo-log')
            saved = dict(version=3, algorithm=ALGORITHM, device=info.st_dev,
                         inode=info.st_ino, size=size, count=count,
                         base_sha256=expected_base, image_sha256=tree.root(changes), log_sha256=log_hash)
            inplace.seal(generation, 'transaction', saved)
            boundary('prepared')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
            process.wait()


def records(log, count, size):
    log.seek(0)
    previous = -1
    for _ in range(count):
        raw = log.read(RECORD.size)
        if len(raw) != RECORD.size:
            raise ValueError('short Merkle redo log')
        index, old, new = RECORD.unpack(raw)
        if not previous < index < size // PAGE or old == new:
            raise ValueError('invalid Merkle redo page order or bounds')
        previous = index
        yield index, old, new


def plan(image, log, count, tree, actual, cold=False):
    """Authenticate old chunks, substituting undo pages during crash recovery.

    Cold replay reads ALL chunks, including clean ones. Warm replay verifies only
    touched chunks against the tree built by a full scan while holding chain-lock.
    """
    iterator = iter(records(log, count, tree.size))
    record = next(iterator, None)
    leaves = {}
    index = 0
    while index < tree.count:
        if not cold and record is None:
            break
        if not cold:
            index = record[0] * PAGE // CHUNK
        length = min(CHUNK, tree.size - index * CHUNK)
        image.seek(index * CHUNK)
        current = image.read(length)
        if len(current) != length:
            raise ValueError('short authenticated chunk')
        original, result = bytearray(current), bytearray(current)
        touched = False
        while record is not None and record[0] * PAGE // CHUNK == index:
            page, old, new = record
            offset = page * PAGE - index * CHUNK
            if actual == 'base' and current[offset:offset + PAGE] != old:
                raise ValueError('image changed before commit started')
            if actual == 'result' and current[offset:offset + PAGE] != new:
                raise ValueError('completed image changed')
            original[offset:offset + PAGE] = old
            result[offset:offset + PAGE] = new
            touched = True
            record = next(iterator, None)
        old_hash = leaf(index, original)
        if cold:
            tree.set(tree.width + index, old_hash)
        elif tree.get(tree.width + index) != old_hash:
            raise ValueError('clean bytes or logged preimages changed in authenticated chunk')
        if touched:
            leaves[index] = leaf(index, result)
        index += 1
    if cold:
        tree.finish()
    return tree.updates(leaves)


def recover(root, state, tree=None):
    import inplace
    if state['pending'] is None:
        with regular(root / 'image.img') as image:
            if tree is None:
                tree = scan(image, state)
                if tree.root() != state['sha256']:
                    raise ValueError('chain image edited outside a transaction')
            else:
                tree.check(image, state)
        return state
    generation = root / f"g-{state['pending']:08d}"
    if not (generation / 'transaction').exists():
        # Let the common chain recovery abort the unsealed generation, with a
        # full scan: a failed producer never grants a new trusted fingerprint.
        return None
    info = os.lstat(generation)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('invalid generation directory')
    with regular(generation / 'transaction') as transaction:
        owned(transaction)
        fcntl.flock(transaction, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.fstat(transaction.fileno()).st_size > 4096:
            raise ValueError('oversized transaction')
        meta = json.load(transaction)
        if (set(meta) != inplace.FIELDS | {'algorithm'} or type(meta['version']) is not int or
                meta['version'] != 3 or meta['algorithm'] != ALGORITHM):
            raise ValueError('invalid Merkle transaction schema')
        for key in ('device', 'inode', 'size', 'count'):
            if type(meta[key]) is not int or meta[key] < 0:
                raise ValueError('invalid Merkle numeric field')
        if meta['size'] != state['size'] or not 0 <= meta['count'] <= min(MAX_RECORDS, state['size'] // PAGE):
            raise ValueError('invalid Merkle transaction bounds')
        for key in ('base_sha256', 'image_sha256', 'log_sha256'):
            value = meta[key]
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('invalid Merkle hash')
        if meta['base_sha256'] != state['sha256']:
            raise ValueError('generation does not extend current Merkle head')
        marker = dict(log_sha256=meta['log_sha256'], inode=meta['inode'])
        for name in ('started', 'complete'):
            if (generation / name).exists() or (generation / name).is_symlink():
                with regular(generation / name) as saved:
                    owned(saved)
                    if os.fstat(saved.fileno()).st_size > 4096 or json.load(saved) != marker:
                        raise ValueError('invalid commit marker')
        started = (generation / 'started').exists()
        complete = (generation / 'complete').exists()
        if complete and not started:
            raise ValueError('completion without start marker')
        with image_io.opened(root / 'image.img', True) as image, regular(generation / 'pages') as log:
            owned(log)
            fcntl.flock(image, fcntl.LOCK_EX | fcntl.LOCK_NB)
            identity(image, meta)
            identity(image, state)
            before = fingerprint(os.fstat(image.fileno()))
            cold = tree is None
            if cold:
                tree = Tree(state['size'])
            else:
                tree.check(image, state)
            if os.fstat(log.fileno()).st_size != meta['count'] * RECORD.size or digest(log) != meta['log_sha256']:
                raise ValueError('Merkle log integrity mismatch')
            changes = plan(image, log, meta['count'], tree,
                           'result' if complete else 'partial' if started else 'base', cold)
            if tree.root() != meta['base_sha256'] or tree.root(changes) != meta['image_sha256']:
                raise ValueError('clean image bytes or logged contents changed')
            if fingerprint(os.fstat(image.fileno())) != before:
                raise ValueError('image changed during Merkle replay validation')
            boundary('validated')
            if fingerprint(os.fstat(image.fileno())) != before:
                raise ValueError('image changed before Merkle replay')
            if not complete:
                if not started:
                    inplace.seal(generation, 'started', marker)
                boundary('started')
                for number, (index, old, new) in enumerate(records(log, meta['count'], tree.size)):
                    for half in range(2):
                        offset = index * PAGE + half * 2048
                        data = memoryview(new)[half * 2048:(half + 1) * 2048]
                        while data:
                            written = image_io.write_at(image, data, offset)
                            if written <= 0:
                                raise OSError('short page write')
                            data = data[written:]
                            offset += written
                        boundary(f'half:{number}:{half}')
                    boundary(f'page:{number}')
                boundary('applied')
                image_io.flush(image)
                boundary('synced')
                # Read back every touched chunk, including its clean bytes.
                plan(image, log, meta['count'], tree, 'result')
                inplace.seal(generation, 'complete', marker)
                boundary('complete')
            directory(generation)
            tree.commit(changes)
            tree.stamp = fingerprint(os.fstat(image.fileno()))
    result = dict(state, head=state['pending'], pending=None, sha256=meta['image_sha256'])
    boundary('head-ready')
    inplace.seal(root, 'chain-state', result)
    boundary('head-published')
    return result
