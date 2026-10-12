#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""In-place recovery exclusively on private disposable copies created here."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import importlib.util
from durable import boundary, sync, directory, regular, digest

spec = importlib.util.spec_from_file_location('block_log', Path(__file__).with_name('block-log.py'))
block = importlib.util.module_from_spec(spec)
spec.loader.exec_module(block)
RECORD = struct.Struct('<Q4096s4096s')
FIELDS = {'version', 'device', 'inode', 'size', 'count', 'base_sha256', 'image_sha256', 'log_sha256'}


def seal(session, name, data):
    pending = session / (name + '.pending')
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        info = os.fstat(output.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError('unsafe pending marker')
        output.truncate(0)
        json.dump(data, output, sort_keys=True)
        output.flush()
        sync(output.fileno())
    boundary(name + ':pending')
    os.replace(pending, session / name)
    boundary(name + ':renamed')
    directory(session)


def prepare(source, session, producer):
    session = block.canonical(session)
    session.mkdir(mode=0o700)
    directory(session.parent)
    image = session / 'image.img'
    with regular(source) as base, image.open('xb') as output:
        fcntl.flock(base, fcntl.LOCK_SH | fcntl.LOCK_NB)
        before = digest(base)
        base.seek(0)
        while chunk := base.read(1024 * 1024):
            output.write(chunk)
        output.flush()
        sync(output.fileno())
        if digest(base) != before:
            raise ValueError('source changed during copy')
    directory(session)
    boundary('cloned')
    with regular(image) as copied:
        if digest(copied) != before:
            raise ValueError('copy differs from source snapshot')
    return capture_overlay(image, session, producer)


def capture_overlay(image, session, producer):
    with regular(image) as current:
        before = digest(current)
    capture = session / 'capture'
    block.prepare_overlay(image, session / 'unused-export', capture, producer)
    with regular(capture / 'manifest') as manifest:
        metadata = json.load(manifest)
    with regular(image) as base, regular(capture / 'blocks') as log:
        block.validate(metadata, capture, base, log)
        log.seek(0)
        with (session / 'pages').open('xb') as pages:
            for _ in range(metadata['count']):
                index, _, _, new = block.RECORD.unpack(log.read(block.RECORD.size))
                base.seek(index * 4096)
                pages.write(RECORD.pack(index, base.read(4096), new))
            pages.flush()
            sync(pages.fileno())
        info = os.fstat(base.fileno())
        if digest(base) != before:
            raise ValueError('disposable base changed')
    boundary('undo-log')
    with regular(session / 'pages') as pages:
        saved = dict(version=2, device=info.st_dev, inode=info.st_ino,
                     size=info.st_size, count=metadata['count'], base_sha256=before,
                     image_sha256=metadata['image_sha256'], log_sha256=digest(pages))
    seal(session, 'transaction', saved)
    boundary('prepared')
    return image


def verify(metadata, image, log):
    if set(metadata) != FIELDS or type(metadata['version']) is not int or metadata['version'] != 2:
        raise ValueError('invalid transaction schema')
    for name in ('device', 'inode', 'size', 'count'):
        if type(metadata[name]) is not int or metadata[name] < 0:
            raise ValueError('invalid numeric field')
    size, count = metadata['size'], metadata['count']
    if size <= 0 or size % 4096 or count > min(block.MAX_RECORDS, size // 4096):
        raise ValueError('invalid bounds')
    for name in ('base_sha256', 'image_sha256', 'log_sha256'):
        value = metadata[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('invalid hash')
    info = os.fstat(image.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
        (info.st_dev, info.st_ino, info.st_size) != (metadata['device'], metadata['inode'], size)):
        raise ValueError('disposable image identity mismatch')
    if os.fstat(log.fileno()).st_size != count * RECORD.size or digest(log) != metadata['log_sha256']:
        raise ValueError('log integrity mismatch')
    # Substitute saved preimages/new pages when hashing. This binds every clean
    # byte even when logged pages have partially reached storage.
    original, result = hashlib.sha256(), hashlib.sha256()
    cursor, previous = 0, -1
    log.seek(0)
    for _ in range(count):
        index, old, new = RECORD.unpack(log.read(RECORD.size))
        if not previous < index < size // 4096:
            raise ValueError('invalid page order or offset')
        image.seek(cursor)
        end = index * 4096
        while cursor < end:
            data = image.read(min(1024 * 1024, end - cursor))
            if not data:
                raise ValueError('short image')
            original.update(data)
            result.update(data)
            cursor += len(data)
        original.update(old)
        result.update(new)
        cursor += 4096
        previous = index
    image.seek(cursor)
    while cursor < size:
        data = image.read(min(1024 * 1024, size - cursor))
        if not data:
            raise ValueError('short image')
        original.update(data)
        result.update(data)
        cursor += len(data)
    if original.hexdigest() != metadata['base_sha256'] or result.hexdigest() != metadata['image_sha256']:
        raise ValueError('clean image bytes or logged page contents changed')


def recover(session):
    session = block.canonical(session)
    return recover_image(session, session / 'image.img')


def recover_image(session, image_path):
    # Internal helper for managed chain generations; no CLI accepts a write path.
    session = block.canonical(session)
    info = os.lstat(session)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('session must be a private owned directory')
    with regular(session / 'transaction') as transaction:
        fcntl.flock(transaction, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.fstat(transaction.fileno()).st_size > 4096:
            raise ValueError('oversized transaction')
        metadata = json.load(transaction)
        image_info = os.lstat(image_path)
        if not stat.S_ISREG(image_info.st_mode):
            raise ValueError('only a regular disposable image may be opened for writing')
        fd = os.open(image_path, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r+b', buffering=0) as image, regular(session / 'pages') as log:
            fcntl.flock(image, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(log, fcntl.LOCK_SH | fcntl.LOCK_NB)
            verify(metadata, image, log)
            boundary('validated')
            marker = {'log_sha256': metadata['log_sha256'], 'inode': metadata['inode']}
            for name in ('started', 'complete'):
                if (session / name).exists() or (session / name).is_symlink():
                    with regular(session / name) as state:
                        if os.fstat(state.fileno()).st_size > 4096 or json.load(state) != marker:
                            raise ValueError('invalid commit marker')
            if (session / 'complete').exists():
                if not (session / 'started').exists():
                    raise ValueError('completion without start marker')
                if digest(image) != metadata['image_sha256']:
                    raise ValueError('completed image changed')
                directory(session)
                return image_path
            if not (session / 'started').exists():
                if digest(image) != metadata['base_sha256']:
                    raise ValueError('image changed before commit started')
                seal(session, 'started', marker)
            boundary('started')
            log.seek(0)
            for number in range(metadata['count']):
                index, _, new = RECORD.unpack(log.read(RECORD.size))
                # Split to exercise torn-page recovery, not a 4K atomicity claim.
                for half in range(2):
                    offset = index * 4096 + half * 2048
                    data = memoryview(new)[half * 2048:(half + 1) * 2048]
                    while data:
                        written = os.pwrite(image.fileno(), data, offset)
                        if written <= 0:
                            raise OSError('short page write')
                        data = data[written:]
                        offset += written
                    boundary(f'half:{number}:{half}')
                boundary(f'page:{number}')
            boundary('applied')
            sync(image.fileno())
            boundary('synced')
            if digest(image) != metadata['image_sha256']:
                raise ValueError('committed image mismatch')
            seal(session, 'complete', marker)
            boundary('complete')
    return image_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    p = commands.add_parser('prepare')
    for name in ('source', 'session', 'producer'):
        p.add_argument(name)
    commands.add_parser('recover').add_argument('session')
    args = vars(parser.parse_args())
    action = args.pop('action')
    print(prepare(**args) if action == 'prepare' else recover(**args))
