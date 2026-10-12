#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline incremental redo log; recovery publishes a new regular-file image."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
from durable import boundary, sync, directory, regular, digest

PAGE = 4096
RECORD = struct.Struct('<Q32s32s4096s')
MAX_RECORDS = 1_048_576
FIELDS = {'version', 'source', 'target', 'size', 'count', 'base_sha256',
          'image_sha256', 'log_sha256'}


def canonical(path):
    path = Path(path).absolute()
    return path.parent.resolve() / path.name


def sha(data):
    return hashlib.sha256(data).digest()


def prepare(source, candidate, target, journal):
    source, candidate, target, journal = [canonical(p) for p in
                                         (source, candidate, target, journal)]
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    if journal.parent != target.parent or target == source:
        raise ValueError('invalid transaction paths')
    journal.mkdir(mode=0o700)
    directory(journal.parent)
    boundary('created')
    with regular(source) as base, regular(candidate) as image:
        fcntl.flock(base, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(image, fcntl.LOCK_SH | fcntl.LOCK_NB)
        size = os.fstat(base.fileno()).st_size
        if size <= 0 or size % PAGE or os.fstat(image.fileno()).st_size != size:
            raise ValueError('image sizes must match and be page aligned')
        original, expected = hashlib.sha256(), hashlib.sha256()
        count = 0
        with (journal / 'blocks').open('xb') as log:
            for index in range(size // PAGE):
                old, new = base.read(PAGE), image.read(PAGE)
                if len(old) != PAGE or len(new) != PAGE:
                    raise ValueError('short input image')
                original.update(old)
                expected.update(new)
                if old != new:
                    count += 1
                    if count > MAX_RECORDS:
                        raise ValueError('transaction exceeds record limit')
                    log.write(RECORD.pack(index, sha(old), sha(new), new))
                    boundary('record')
            log.flush()
            sync(log.fileno())
        boundary('snapshot')
        if digest(base) != original.hexdigest() or digest(image) != expected.hexdigest():
            raise ValueError('input changed during preparation')
        with regular(journal / 'blocks') as log:
            metadata = dict(version=1, source=str(source), target=str(target),
                            size=size, count=count, base_sha256=original.hexdigest(),
                            image_sha256=expected.hexdigest(), log_sha256=digest(log))
        with (journal / 'manifest.pending').open('x') as manifest:
            json.dump(metadata, manifest, sort_keys=True)
            manifest.flush()
            sync(manifest.fileno())
        boundary('manifest')
        os.rename(journal / 'manifest.pending', journal / 'manifest')
        directory(journal)
        boundary('sealed')


def validate(metadata, journal, base, log):
    if set(metadata) != FIELDS or type(metadata['version']) is not int or metadata['version'] != 1:
        raise ValueError('unsupported manifest')
    size, count = metadata['size'], metadata['count']
    if (type(size) is not int or size <= 0 or size % PAGE or
        type(count) is not int or not 0 <= count <= min(MAX_RECORDS, size // PAGE)):
        raise ValueError('invalid transaction bounds')
    for name in ('base_sha256', 'image_sha256', 'log_sha256'):
        value = metadata[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('invalid digest')
    source, target = Path(metadata['source']), Path(metadata['target'])
    if (not source.is_absolute() or not target.is_absolute() or
        target.parent != journal.parent or target in (source, journal)):
        raise ValueError('invalid transaction paths')
    if (os.fstat(base.fileno()).st_size != size or
        os.fstat(log.fileno()).st_size != count * RECORD.size or
        digest(base) != metadata['base_sha256'] or digest(log) != metadata['log_sha256']):
        raise ValueError('transaction integrity or source mismatch')
    log.seek(0)
    previous = -1
    for _ in range(count):
        index, old_hash, new_hash, data = RECORD.unpack(log.read(RECORD.size))
        if not previous < index < size // PAGE:
            raise ValueError('duplicate, unsorted or out-of-range block')
        base.seek(index * PAGE)
        if sha(base.read(PAGE)) != old_hash or sha(data) != new_hash:
            raise ValueError('block preimage or payload mismatch')
        previous = index
    return target


def recover(journal):
    journal = Path(journal).resolve()
    with regular(journal / 'manifest') as manifest:
        fcntl.flock(manifest, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.fstat(manifest.fileno()).st_size > 4096:
            raise ValueError('oversized manifest')
        metadata = json.load(manifest)
        # Open only regular files. The entire log is validated before output writes.
        with regular(metadata['source']) as base, regular(journal / 'blocks') as log:
            fcntl.flock(base, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(log, fcntl.LOCK_SH | fcntl.LOCK_NB)
            target = validate(metadata, journal, base, log)
            boundary('verified')
            stage = journal / 'recovered.img'
            if target.exists() or target.is_symlink():
                with regular(stage) as completed:
                    if (os.lstat(target).st_dev, os.lstat(target).st_ino) != (os.fstat(completed.fileno()).st_dev, os.fstat(completed.fileno()).st_ino):
                        raise FileExistsError(target)
                    if digest(completed) != metadata['image_sha256']:
                        raise ValueError('published image changed')
                directory(target.parent)
                return target
            # A previous interrupted replay is rebuilt from the immutable base.
            fd = os.open(stage, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w+b') as output:
                if not stat_regular_single(output):
                    raise ValueError('replay staging file is not private')
                output.truncate(0)
                base.seek(0)
                while chunk := base.read(1024 * 1024):
                    output.write(chunk)
                    boundary('copy')
                boundary('copied')
                log.seek(0)
                for _ in range(metadata['count']):
                    index, _, _, data = RECORD.unpack(log.read(RECORD.size))
                    output.seek(index * PAGE)
                    output.write(data)
                    output.flush()
                    boundary('patch')
                output.flush()
                if digest(output) != metadata['image_sha256']:
                    raise ValueError('reconstructed image mismatch')
                sync(output.fileno())
            directory(journal)
            boundary('replayed')
            os.link(stage, target, follow_symlinks=False)
            boundary('linked')
            directory(target.parent)
            boundary('published')
    return target


def stat_regular_single(stream):
    import stat
    info = os.fstat(stream.fileno())
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    p = commands.add_parser('prepare')
    for name in ('source', 'candidate', 'target', 'journal'):
        p.add_argument(name)
    commands.add_parser('recover').add_argument('journal')
    args = vars(parser.parse_args())
    action = args.pop('action')
    if action == 'prepare':
        prepare(**args)
    else:
        print(recover(**args))
