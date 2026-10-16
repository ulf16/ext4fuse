#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Serialized generations on one managed disposable image with checkpoints."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import uuid
import inplace
import merkle
from durable import regular, digest, directory, boundary


@contextmanager
def locked(root):
    root = inplace.block.canonical(root)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('managed chain must be private and owned')
    fd = os.open(root / 'chain-lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('invalid chain lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield root


def read_state(root, name='chain-state'):
    with regular(root / name) as state:
        if os.fstat(state.fileno()).st_size > 4096:
            raise ValueError('oversized chain state')
        value = json.load(state)
    if name == 'checkpoint':
        if not isinstance(value, dict) or set(value) != {'state', 'sha256'}:
            raise ValueError('invalid checkpoint envelope')
        expected = hashlib.sha256(json.dumps(value['state'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if value['sha256'] != expected:
            raise ValueError('checkpoint checksum mismatch')
        value = value['state']
    fields = {'version', 'head', 'pending', 'sha256', 'device', 'inode', 'size'}
    if (not isinstance(value, dict) or type(value.get('version')) is not int or
        value['version'] not in (1, 2) or set(value) != fields | ({'algorithm'} if value['version'] == 2 else set()) or
        (value['version'] == 2 and value['algorithm'] != merkle.ALGORITHM)):
        raise ValueError('invalid chain state')
    if type(value['head']) is not int or not 0 <= value['head'] < 99_999_999:
        raise ValueError('invalid generation')
    if value['pending'] is not None and (type(value['pending']) is not int or value['pending'] != value['head'] + 1):
        raise ValueError('invalid pending generation')
    for name in ('device', 'inode', 'size'):
        if type(value[name]) is not int or value[name] < 0:
            raise ValueError('invalid chain identity')
    if not isinstance(value['sha256'], str) or len(value['sha256']) != 64 or any(c not in '0123456789abcdef' for c in value['sha256']):
        raise ValueError('invalid chain hash')
    return value


def check_image(root, state, check_hash=True, cache=None, cache_out=None):
    with regular(root / 'image.img') as image:
        info = os.fstat(image.fileno())
        if info.st_uid != os.getuid() or info.st_nlink != 1 or (info.st_dev, info.st_ino, info.st_size) != (state['device'], state['inode'], state['size']):
            raise ValueError('chain image identity changed')
        actual = None
        if check_hash:
            if state['version'] == 2:
                tree = cache if cache is not None else merkle.scan(image, state)
                if cache is not None: tree.check(image, state)
                actual = tree.root()
                if cache_out is not None: cache_out.append(tree)
            else: actual = digest(image)
        if check_hash and actual != state['sha256']:
            raise ValueError('chain image edited outside a transaction')


def recover_locked(root, cache=None, *, cache_out=None):
    if not (root / 'chain-state').exists() and (root / 'checkpoint').exists():
        saved = read_state(root, 'checkpoint')
        if saved['pending'] is not None:
            raise ValueError('checkpoint contains a pending transaction')
        check_image(root, saved)
        if any(re.fullmatch(r'g-(\d{8})', p.name) and int(p.name[2:]) > saved['head'] for p in root.iterdir()):
            raise ValueError('checkpoint is stale; successor history needs explicit repair')
        inplace.seal(root, 'chain-state', saved)
    if not (root / 'chain-state').exists():
        inplace.recover(root)
        with regular(root / 'image.img') as image:
            info = os.fstat(image.fileno())
            state = dict(version=1, head=0, pending=None, sha256=digest(image),
                         device=info.st_dev, inode=info.st_ino, size=info.st_size)
        inplace.seal(root, 'chain-state', state)
    state = read_state(root)
    if state['version'] == 2:
        result = merkle.recover(root, state, cache, cache_out=cache_out)
        if result is not None:
            return result
    check_image(root, state, check_hash=state['pending'] is None)
    pending = state['pending'] is not None
    if pending:
        generation = root / f"g-{state['pending']:08d}"
        if generation.exists() or generation.is_symlink():
            info = os.lstat(generation)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('invalid generation directory')
        if (generation / 'transaction').exists():
            with regular(generation / 'transaction') as transaction:
                metadata = json.load(transaction)
            if metadata['base_sha256'] != state['sha256']:
                raise ValueError('generation does not extend the current head')
            inplace.recover_image(generation, root / 'image.img')
            state['head'] = state['pending']
            state['sha256'] = metadata['image_sha256']
        else:
            check_image(root, state, cache_out=cache_out)
            if generation.exists() or generation.is_symlink():
                if not stat.S_ISDIR(os.lstat(generation).st_mode):
                    raise ValueError('invalid incomplete generation')
                os.rename(generation, root / ('aborted-' + uuid.uuid4().hex))
                directory(root)
        state['pending'] = None
        boundary('head-ready')
        inplace.seal(root, 'chain-state', state)
        boundary('head-published')
    if pending:
        verified = cache_out[-1] if cache_out else None
        check_image(root, state, cache=verified)
    return state


def recover_integrity_locked(root, cache=None):
    """Recover and retain the actual verified tree under the caller's chain lock."""
    if (root/'chain-state').exists():
        saved = read_state(root)
        if saved['version'] == 1 and saved['pending'] is None:
            return merkle.activate(root, saved)
    trees = []
    state = recover_locked(root, cache, cache_out=trees)
    return (state, trees[-1]) if trees else merkle.activate(root, state)


def clone(source, root):
    """Pristine private clone, unlike init's demonstration mutation producer."""
    source=Path(source).absolute();root=inplace.block.canonical(root)
    root.mkdir(mode=0o700);directory(root.parent)
    image=root/'image.img'
    with regular(source) as base, image.open('xb') as copied:
        fcntl.flock(base,fcntl.LOCK_SH|fcntl.LOCK_NB)
        before=digest(base);base.seek(0)
        while chunk:=base.read(1024*1024):copied.write(chunk)
        copied.flush();inplace.sync(copied.fileno())
        if digest(base)!=before:raise ValueError('source changed during clone')
    directory(root)
    with regular(image) as cloned:
        info=os.fstat(cloned.fileno())
        if info.st_size<=0 or info.st_size%4096 or digest(cloned)!=before:raise ValueError('invalid clone')
        state=dict(version=1,head=0,pending=None,sha256=before,device=info.st_dev,inode=info.st_ino,size=info.st_size)
    inplace.seal(root,'chain-state',state);return state


def init(source, root, producer):
    inplace.prepare(source, root, producer)
    return recover(root)


def recover(root):
    with locked(root) as root:
        return recover_locked(root)


def append(root, producer):
    with locked(root) as root:
        return append_locked(root, producer)


def prepare_locked(root, producer, cache=None):
    """Seal a producer generation without replay; return its state and cache.

    Caller holds chain-lock. Direct journal import must authenticate this sealed
    generation before installing the physical guard and granting write access.
    """
    state = recover_locked(root, cache)
    cache = cache if cache is not None else merkle.activate(root, state)[1] if state['version'] == 2 else None
    if state['head'] >= 99_999_998:
        raise ValueError('generation limit')
    proposed = root / f"g-{state['head'] + 1:08d}"
    if proposed.exists() or proposed.is_symlink():
        raise ValueError('generation already exists')
    state['pending'] = state['head'] + 1
    inplace.seal(root, 'chain-state', state)
    boundary('chain-intent')
    generation = root / f"g-{state['pending']:08d}"
    generation.mkdir(mode=0o700)
    directory(root)
    inplace.capture_overlay(root / 'image.img', generation, producer, expected_base=state['sha256'], integrity=cache)
    boundary('chain-prepared')
    return state, cache


def append_locked(root, producer, cache=None):
    state, cache = prepare_locked(root, producer, cache)
    return recover_locked(root, cache)


GEN_FILES = {'operations', 'operations.result', 'request-producer', 'transaction', 'transaction.pending', 'pages', 'started',
             'started.pending', 'complete', 'complete.pending', 'journal-candidate', 'journal-replay.log', 'journal-daemon.log'}
CAPTURE_FILES = {'blocks', 'manifest', 'manifest.pending'}


def inspect_tree(path, device, capture=False):
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
        info.st_dev != device or info.st_mode & 0o077):
        raise ValueError('unsafe retirement directory')
    for entry in path.iterdir():
        if not capture and entry.name == 'capture':
            inspect_tree(entry, device, True)
        else:
            allowed = CAPTURE_FILES if capture else GEN_FILES
            info = os.lstat(entry)
            if (entry.name not in allowed or not stat.S_ISREG(info.st_mode) or
                info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_dev != device):
                raise ValueError('unexpected retirement entry')


def remove_tree(path):
    # All candidates are inspected before checkpoint publication/deletion. The
    # chain lock protects cooperating actors; the private directory is trusted.
    for entry in sorted(path.iterdir()):
        if entry.name == 'capture' and stat.S_ISDIR(os.lstat(entry).st_mode):
            remove_tree(entry)
        else:
            entry.unlink()
            directory(path)
            boundary('retire-entry')
    path.rmdir()
    directory(path.parent)
    boundary('retire-directory')


def checkpoint(root):
    with locked(root) as root:
        return checkpoint_locked(root)


def checkpoint_locked(root, cache=None):
    # Caller owns chain-lock; preserve durable validation/retirement protocol.
    # Do not implicitly commit a pending transaction as part of cleanup.
    state = read_state(root)
    if state['pending'] is not None:
        raise ValueError('recover pending generation before checkpointing')
    check_image(root, state, cache=cache)
    if (root / 'checkpoint').exists() or (root / 'checkpoint').is_symlink():
        previous = read_state(root, 'checkpoint')
        if previous['pending'] is not None or previous['head'] > state['head']:
            raise ValueError('invalid checkpoint ancestry')
        check_image(root, previous, check_hash=False)
    candidates = []
    root_files = []
    device = os.lstat(root).st_dev
    for entry in sorted(root.iterdir()):
        generation = re.fullmatch(r'g-(\d{8})', entry.name)
        aborted = re.fullmatch(r'aborted-[0-9a-f]{32}', entry.name)
        if generation and int(generation.group(1)) > state['head']:
            raise ValueError('untracked successor generation')
        if generation or aborted:
            inspect_tree(entry, device)
            candidates.append(entry)
        elif entry.name == 'capture':
            inspect_tree(entry, device, True)
            candidates.append(entry)
        elif entry.name in GEN_FILES:
            info = os.lstat(entry)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_dev != device:
                raise ValueError('unsafe initial transaction file')
            root_files.append(entry)
    boundary('checkpoint-validated')
    encoded = json.dumps(state, sort_keys=True, separators=(',', ':')).encode()
    inplace.seal(root, 'checkpoint', {'state': state, 'sha256': hashlib.sha256(encoded).hexdigest()})
    boundary('checkpoint-published')
    for entry in candidates:
        remove_tree(entry)
    for entry in root_files:
        entry.unlink()
        directory(root)
        boundary('retire-entry')
    boundary('retirement-complete')
    return state


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    p=commands.add_parser('clone');p.add_argument('source');p.add_argument('root')
    p = commands.add_parser('init')
    for name in ('source', 'root', 'producer'):
        p.add_argument(name)
    p = commands.add_parser('append')
    p.add_argument('root'); p.add_argument('producer')
    commands.add_parser('recover').add_argument('root')
    commands.add_parser('checkpoint').add_argument('root')
    args = vars(parser.parse_args()); action = args.pop('action')
    print(json.dumps(globals()[action](**args), sort_keys=True))
