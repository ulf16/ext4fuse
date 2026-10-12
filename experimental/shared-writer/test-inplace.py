#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Interrupt in-place commits on disposable ext4 copies and verify independently."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--fixtures', type=Path)
parser.add_argument('--prepare-only', action='store_true')
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows = 0, []
RECORD = struct.Struct('<Q4096s4096s')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(arguments, crash=None, ok=True):
    global checks
    env = dict(os.environ)
    if crash:
        env['EXT4_TEST_CRASH'] = crash
    result = subprocess.run(['python3', str(here / 'inplace.py'), *map(str, arguments)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert (result.returncode == (77 if crash else 0)) if ok else result.returncode != 0, result.stderr
    checks += 1


def clone(template, target):
    # Clone prepared test state and rebind identity; no production API accepts
    # an arbitrary caller image for writing. Each case gets its own fresh copy.
    target.mkdir(mode=0o700)
    for name in ('image.img', 'pages'):
        shutil.copyfile(template / name, target / name)
    metadata = json.loads((template / 'transaction').read_text())
    info = (target / 'image.img').stat()
    metadata.update(device=info.st_dev, inode=info.st_ino)
    (target / 'transaction').write_text(json.dumps(metadata))
    return metadata


with tempfile.TemporaryDirectory(prefix='inplace-test-', dir=args.work) as root:
    root = Path(root)
    for source in ([] if args.prepare_only else sorted(fixtures.glob('*-csum*.img'))):
        if '-output' in source.name:
            continue
        before = sha(source)
        template = root / (source.stem + '-prepared')
        run(['prepare', source, template, args.work / 'prototype'])
        assert sha(template / 'image.img') == before
        meta = json.loads((template / 'transaction').read_text())
        count = meta['count']
        assert count > 1 and (template / 'pages').stat().st_size == count * RECORD.size
        phases = ('validated', 'started:pending', 'started:renamed', 'started', 'half:0:0', f'half:{count // 2}:0',
                  f'page:{count - 1}', 'applied', 'synced', 'complete:pending', 'complete:renamed', 'complete', None)
        for number, phase in enumerate(phases):
            session = root / (source.stem + '-crash-' + str(number))
            clone(template, session)
            run(['recover', session], phase)
            if phase in ('validated', 'started:pending', 'started:renamed', 'started'):
                assert sha(session / 'image.img') == before
            if phase == 'half:0:0':
                with (session / 'pages').open('rb') as log:
                    index, old, new = RECORD.unpack(log.read(RECORD.size))
                with (session / 'image.img').open('rb') as image:
                    image.seek(index * 4096)
                    assert image.read(4096) == new[:2048] + old[2048:]
            run(['recover', session])
            run(['recover', session])
            assert sha(session / 'image.img') == meta['image_sha256'] and sha(source) == before
            result = subprocess.run(['e2fsck', '-f', '-n', str(session / 'image.img')], capture_output=True)
            assert result.returncode == 0, result.stdout + result.stderr
            extracted = session / 'extracted'
            result = subprocess.run(['debugfs', '-R', f'dump /renamed-file {extracted}', str(session / 'image.img')], capture_output=True)
            assert result.returncode == 0 and extracted.read_bytes() == bytes(((i * 131 + (i >> 8)) ^ 0x5a) & 255 for i in range(160 * 1024))
            extracted.unlink()
            result = subprocess.run(['debugfs', '-R', f'dump /existing-file {extracted}', str(session / 'image.img')], capture_output=True)
            assert result.returncode == 0 and extracted.read_bytes() == bytes((i * 19 + 13) & 255 for i in range(32768))
            checks += 4
            shutil.rmtree(session)
        for damage in ('log', 'count', 'duplicate', 'range', 'undo', 'finalhash',
                       'clean', 'dirty-before-start', 'identity', 'hardlink', 'marker', 'completed-edit', 'pending-alias', 'pending-symlink'):
            session = root / (source.stem + '-damage-' + damage)
            metadata = clone(template, session)
            pages = bytearray((session / 'pages').read_bytes())
            first, old, new = RECORD.unpack(pages[:RECORD.size])
            if damage == 'log':
                pages[-1] ^= 1
                (session / 'pages').write_bytes(pages)
            elif damage in ('count', 'duplicate', 'range', 'undo', 'finalhash'):
                if damage == 'count':
                    metadata['count'] = 2**64
                elif damage == 'duplicate':
                    pages[RECORD.size:RECORD.size + 8] = pages[:8]
                elif damage == 'range':
                    pages[:8] = struct.pack('<Q', metadata['size'] // 4096)
                elif damage == 'undo':
                    pages[8] ^= 1
                else:
                    metadata['image_sha256'] = '0' * 64
                (session / 'pages').write_bytes(pages)
                metadata['log_sha256'] = sha(session / 'pages')
                (session / 'transaction').write_text(json.dumps(metadata))
            elif damage == 'identity':
                replacement = session / 'replacement'
                shutil.copyfile(session / 'image.img', replacement)
                os.replace(replacement, session / 'image.img')
            elif damage == 'hardlink':
                os.link(session / 'image.img', session / 'extra-link')
            elif damage == 'pending-alias':
                extra = session / 'extra'
                extra.write_bytes(b'preserve marker alias')
                os.link(extra, session / 'started.pending')
            elif damage == 'pending-symlink':
                os.symlink('image.img', session / 'started.pending')
            elif damage == 'marker':
                (session / 'started').write_text('{bad')
            else:
                if damage in ('clean', 'completed-edit'):
                    run(['recover', session], 'started' if damage == 'clean' else None)
                dirty = {RECORD.unpack(pages[i:i + RECORD.size])[0] for i in range(0, len(pages), RECORD.size)}
                index = next(i for i in range(metadata['size'] // 4096) if i not in dirty) if damage == 'clean' else first
                with (session / 'image.img').open('r+b') as image:
                    image.seek(index * 4096)
                    value = image.read(1)
                    image.seek(index * 4096)
                    image.write(bytes([value[0] ^ 1]))
            damaged = sha(session / 'image.img')
            run(['recover', session], ok=False)
            assert sha(session / 'image.img') == damaged, 'rejection modified image'
            checks += 1
            shutil.rmtree(session)
        # A competing image or journal lock must prevent any write.
        for name in ('image.img', 'transaction'):
            session = root / (source.stem + '-lock-' + name)
            clone(template, session)
            with (session / name).open('rb') as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                run(['recover', session], ok=False)
                assert sha(session / 'image.img') == before
            shutil.rmtree(session)
        assert sha(source) == before
        rows.append({'fixture': source.stem, 'pages': count, 'undo_redo_bytes': count * RECORD.size,
                     'source_unchanged': True, 'torn_page_recovered': True, 'fsck_clean': True})
        shutil.rmtree(template)
        print('PASS in-place', source.stem, flush=True)
    assert args.prepare_only or len(rows) == 12
    source = next(p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name)
    before = sha(source)
    for phase in ('cloned', 'undo-log', 'transaction:pending', 'transaction:renamed', 'prepared'):
        session = root / ('prepare-' + phase.replace(':', '-'))
        run(['prepare', source, session, args.work / 'prototype'], phase)
        assert sha(session / 'image.img') == before and sha(source) == before
        if phase in ('cloned', 'undo-log', 'transaction:pending'):
            run(['recover', session], ok=False)
            assert sha(session / 'image.img') == before
        else:
            run(['recover', session])
            expected = json.loads((session / 'transaction').read_text())['image_sha256']
            assert sha(session / 'image.img') == expected
            result = subprocess.run(['e2fsck', '-f', '-n', str(session / 'image.img')], capture_output=True)
            assert result.returncode == 0
        checks += 2
        shutil.rmtree(session)
    producer = root / 'empty-producer'
    producer.write_text('#!/usr/bin/env python3\nimport pathlib,struct,sys\nsys.stdout.buffer.write(struct.pack("<8sQQ",b"E4OVL001",pathlib.Path(sys.argv[1]).stat().st_size,0))\n')
    producer.chmod(0o700)
    session = root / 'noop'
    run(['prepare', source, session, producer])
    assert (session / 'pages').stat().st_size == 0
    run(['recover', session])
    run(['recover', session])
    assert sha(session / 'image.img') == before and sha(source) == before
    checks += 2
report = {'checks': checks, 'result': 'passed', 'configurations': rows,
          'scope': 'private disposable regular-file copies; process interruption, not power-loss certification'}
(args.work / ('inplace-prepare-results.json' if args.prepare_only else 'inplace-results.json')).write_text(json.dumps(report, indent=2) + '\n')
print('PASS', checks, 'in-place checks')
