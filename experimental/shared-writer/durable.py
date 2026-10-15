#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Experimental full-image redo transactions. Private, offline regular files only."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat


def boundary(name):
    if os.environ.get('EXT4_TEST_CRASH') == name:
        os._exit(77)


def sync(fd):
    os.fsync(fd)
    if hasattr(fcntl, 'F_FULLFSYNC'):
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)


def directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def regular(path):
    from image_io import lookup
    view = lookup(path)
    if view is not None:
        return view.open(False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('only regular files are supported')
    return os.fdopen(fd, 'rb')


def digest(stream):
    stream.seek(0)
    return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(source, candidate, target, journal):
    source, candidate, target, journal = map(lambda p: Path(p).absolute(),
                                            (source, candidate, target, journal))
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    # Same parent/filesystem makes final publication an atomic hard link.
    if journal.parent != target.parent:
        raise ValueError('journal and target must have the same parent')
    journal.mkdir(mode=0o700)
    directory(journal.parent)
    boundary('created')
    with regular(source) as base, regular(candidate) as image:
        fcntl.flock(base, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(image, fcntl.LOCK_SH | fcntl.LOCK_NB)
        size = os.fstat(base.fileno()).st_size
        if size <= 0 or size % 4096 or os.fstat(image.fileno()).st_size != size:
            raise ValueError('image sizes must match and be page aligned')
        before = digest(base)
        expected = digest(image)
        image.seek(0)
        with (journal / 'image').open('xb') as output:
            while chunk := image.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            sync(output.fileno())
        boundary('snapshot')
        with regular(journal / 'image') as snapshot:
            if digest(snapshot) != expected or digest(base) != before or digest(image) != expected:
                raise ValueError('input changed during preparation')
        metadata = dict(version=1, source=str(source), target=str(target),
                        size=size, base_sha256=before, image_sha256=expected)
        with (journal / 'manifest.pending').open('x') as manifest:
            json.dump(metadata, manifest, sort_keys=True)
            manifest.flush()
            sync(manifest.fileno())
        boundary('manifest')
        os.rename(journal / 'manifest.pending', journal / 'manifest')
        directory(journal)
        boundary('sealed')


def recover(journal):
    journal = Path(journal).absolute()
    # Lock a stable inode for concurrent cooperating recovery processes.
    with regular(journal / 'manifest') as manifest:
        fcntl.flock(manifest, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.fstat(manifest.fileno()).st_size > 4096:
            raise ValueError('oversized manifest')
        metadata = json.load(manifest)
        if set(metadata) != {'version', 'source', 'target', 'size', 'base_sha256', 'image_sha256'} or metadata['version'] != 1:
            raise ValueError('unsupported manifest')
        target = Path(metadata['target'])
        source = Path(metadata['source'])
        if not target.is_absolute() or target.parent != journal.parent or not source.is_absolute():
            raise ValueError('invalid transaction paths')
        if target == source or target == journal:
            raise ValueError('invalid target')
        with regular(source) as base, regular(journal / 'image') as image:
            fcntl.flock(base, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(image, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if (os.fstat(base.fileno()).st_size != metadata['size'] or
                os.fstat(image.fileno()).st_size != metadata['size'] or
                digest(base) != metadata['base_sha256'] or
                digest(image) != metadata['image_sha256']):
                raise ValueError('transaction integrity or source mismatch')
            boundary('verified')
            try:
                os.link(journal / 'image', target, follow_symlinks=False)
            except FileExistsError:
                # Only our already-published inode counts as idempotent success.
                if os.lstat(target).st_ino != os.fstat(image.fileno()).st_ino or os.lstat(target).st_dev != os.fstat(image.fileno()).st_dev:
                    raise
            boundary('linked')
            directory(target.parent)
            boundary('published')
    # Retain the sealed log: deletion/space reclamation is explicit, never recovery.
    return target


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
