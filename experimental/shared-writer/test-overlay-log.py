#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate direct C overlay capture without exporting a candidate image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--fixtures', type=Path)
parser.add_argument('--parser-only', action='store_true')
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows = 0, []


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(arguments, crash=None, ok=True):
    global checks
    env = dict(os.environ)
    if crash:
        env['EXT4_TEST_CRASH'] = crash
    result = subprocess.run(['python3', str(here / 'block-log.py'), *map(str, arguments)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert (result.returncode == (77 if crash else 0)) if ok else result.returncode != 0, result.stderr
    checks += 1


with tempfile.TemporaryDirectory(prefix='overlay-log-', dir=args.work) as root:
    root = Path(root)
    for source in ([] if args.parser_only else sorted(fixtures.glob('*-csum*.img'))):
        if '-output' in source.name:
            continue
        before = sha(source)
        pattern = bytes(((i * 131 + (i >> 8)) ^ 0x5a) & 255 for i in range(160 * 1024))
        for phase in ('created', 'record', 'snapshot', 'manifest', 'sealed', 'verified',
                      'copy', 'copied', 'patch', 'replayed', 'linked', 'published', None):
            transaction = root / (source.stem + '-' + str(phase))
            transaction.mkdir()
            target, journal = transaction / 'result.img', transaction / 'redo'
            prepare = ['prepare-overlay', source, target, journal, args.work / 'prototype']
            if phase in ('created', 'record', 'snapshot', 'manifest', 'sealed'):
                run(prepare, phase)
                assert not target.exists()
                if phase != 'sealed':
                    run(['recover', journal], ok=False)
                    assert not target.exists()
                    continue
            else:
                run(prepare)
                # Capture has created no complete output/candidate image.
                assert set(p.name for p in journal.iterdir()) == {'blocks', 'manifest'}
                assert (journal / 'blocks').stat().st_size < source.stat().st_size // 10
                run(['recover', journal], phase)
            expected = json.loads((journal / 'manifest').read_text())['image_sha256']
            run(['recover', journal])
            run(['recover', journal])
            assert sha(target) == expected and sha(source) == before
            result = subprocess.run(['e2fsck', '-f', '-n', str(target)], capture_output=True)
            assert result.returncode == 0, result.stdout + result.stderr
            extracted = transaction / 'extracted'
            dumped = subprocess.run(['debugfs', '-R', f'dump /renamed-file {extracted}', str(target)], capture_output=True)
            assert dumped.returncode == 0 and extracted.read_bytes() == pattern
            extracted.unlink()
            dumped = subprocess.run(['debugfs', '-R', f'dump /existing-file {extracted}', str(target)], capture_output=True)
            assert dumped.returncode == 0 and extracted.read_bytes() == bytes((i * 19 + 13) & 255 for i in range(32768))
            extracted.unlink()
            checks += 5
        rows.append({'fixture': source.stem, 'log_bytes': (journal / 'blocks').stat().st_size,
                     'no_candidate_export': True, 'fsck_clean': True, 'source_unchanged': True})
        print('PASS direct overlay', source.stem, flush=True)
    assert args.parser_only or len(rows) == 12
    # Exercise the stream parser independently of a well-behaved C producer.
    source = root / 'tiny.img'
    source.write_bytes(b'\x00' * 16384)
    old, new = b'\x00' * 4096, b'\x01' * 4096
    header = struct.pack('<8sQQ', b'E4OVL001', 16384, 1)
    record = struct.pack('<Q4096s4096s', 0, old, new)
    streams = {
        'short-header': header[:12], 'short-record': header + record[:-1],
        'trailing': header + record + b'extra',
        'bounds': header + struct.pack('<Q4096s4096s', 4, old, new),
        'preimage': header + struct.pack('<Q4096s4096s', 0, new, new),
        'duplicate': struct.pack('<8sQQ', b'E4OVL001', 16384, 2) + record * 2,
        'limit': struct.pack('<8sQQ', b'E4OVL001', 16384, 2**64 - 1),
        'size': struct.pack('<8sQQ', b'E4OVL001', 8192, 1) + record,
        'magic': b'INVALID!' + header[8:] + record,
        'producer-failed': header + record,
    }
    for name, data in streams.items():
        transaction = root / name
        transaction.mkdir()
        producer = transaction / 'producer'
        payload = transaction / 'payload'
        payload.write_bytes(data)
        producer.write_text('#!/usr/bin/env python3\nimport pathlib,sys\nsys.stdout.buffer.write(pathlib.Path(__file__).with_name("payload").read_bytes())\nsys.exit(' + ('1' if name == 'producer-failed' else '0') + ')\n')
        producer.chmod(0o700)
        target, journal = transaction / 'result.img', transaction / 'redo'
        run(['prepare-overlay', source, target, journal, producer], ok=False)
        assert not (journal / 'manifest').exists() and not target.exists()
        run(['recover', journal], ok=False)
        assert not target.exists()
        checks += 2
    for name, data, expected, expected_records in (
        ('valid', header + record, new + old * 3, 1),
        ('unchanged', header + struct.pack('<Q4096s4096s', 0, old, old), old * 4, 0),
        ('empty', struct.pack('<8sQQ', b'E4OVL001', 16384, 0), old * 4, 0),
    ):
        transaction = root / name
        transaction.mkdir()
        producer = transaction / 'producer'
        (transaction / 'payload').write_bytes(data)
        producer.write_text('#!/usr/bin/env python3\nimport pathlib,sys\nsys.stdout.buffer.write(pathlib.Path(__file__).with_name("payload").read_bytes())\n')
        producer.chmod(0o700)
        target, journal = transaction / 'result.img', transaction / 'redo'
        run(['prepare-overlay', source, target, journal, producer])
        assert (journal / 'blocks').stat().st_size == expected_records * 4168
        run(['recover', journal])
        run(['recover', journal])
        assert target.read_bytes() == expected
        checks += 2

report = {'checks': checks, 'result': 'passed', 'configurations': rows,
          'scope': 'direct serialized C overlay capture; no candidate export; process interruption, no device/in-place writes'}
(args.work / ('overlay-parser-results.json' if args.parser_only else 'overlay-log-results.json')).write_text(json.dumps(report, indent=2) + '\n')
print('PASS', checks, 'direct-overlay checks')
