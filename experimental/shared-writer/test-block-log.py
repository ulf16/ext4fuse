#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Kill transaction processes at each persistence boundary on real ext4 fixtures."""
import argparse
import hashlib
import fcntl
import struct
import json
import os
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
args = parser.parse_args()
checks = 0
rows = []

def run(arguments, crash=None, ok=True):
    global checks
    env = dict(os.environ)
    if crash:
        env['EXT4_TEST_CRASH'] = crash
    result = subprocess.run(['python3', str(here / 'block-log.py'), *map(str, arguments)],
                            env=env, capture_output=True, text=True, timeout=60)
    expected = 77 if crash else 0
    assert (result.returncode == expected) if ok else (result.returncode != 0), result.stderr
    checks += 1


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


with tempfile.TemporaryDirectory(prefix='durable-', dir=args.work) as root:
    root = Path(root)
    for source in sorted((args.work / 'fixtures').glob('*-csum*.img')):
        if '-output' in source.name:
            continue
        candidate = source.with_name(source.stem + '-output.img')
        original = sha(source)
        expected = sha(candidate)
        for point in ('created', 'record', 'snapshot', 'manifest', 'sealed', 'verified', 'copy', 'copied', 'patch', 'replayed', 'linked', 'published', None):
            transaction = root / (source.stem + '-' + str(point))
            transaction.mkdir()
            target, journal = transaction / 'result.img', transaction / 'redo'
            if point in ('created', 'record', 'snapshot', 'manifest', 'sealed'):
                run(['prepare', source, candidate, target, journal], point)
                assert not target.exists()
                if point != 'sealed':
                    run(['recover', journal], ok=False)
                    assert not target.exists()
                    continue
            else:
                run(['prepare', source, candidate, target, journal])
                run(['recover', journal], point)
            run(['recover', journal])
            run(['recover', journal])
            assert sha(target) == expected and sha(source) == original
            fsck = subprocess.run(['e2fsck', '-f', '-n', str(target)], capture_output=True)
            assert fsck.returncode == 0, fsck.stdout + fsck.stderr
            checks += 3
        # A damaged snapshot must not become visible, and must not overwrite a target.
        for damage in ('truncate', 'corrupt', 'base', 'collision', 'manifest', 'duplicate', 'range', 'oldhash', 'newhash', 'count', 'trailing', 'finalhash'):
            transaction = root / (source.stem + '-damage-' + damage)
            transaction.mkdir()
            target, journal = transaction / 'result.img', transaction / 'redo'
            base = transaction / 'base.img'
            base.write_bytes(source.read_bytes())
            run(['prepare', base, candidate, target, journal])
            assert (journal / 'blocks').stat().st_size < base.stat().st_size // 10, 'log is not incremental'
            if damage == 'truncate':
                with (journal / 'blocks').open('r+b') as stream:
                    stream.truncate(4096)
            elif damage == 'corrupt':
                with (journal / 'blocks').open('r+b') as stream:
                    stream.write(b'corrupt!')
            elif damage == 'base':
                with base.open('r+b') as stream:
                    stream.write(b'changed!')
            elif damage == 'collision':
                target.write_bytes(b'preserve me')
            elif damage == 'manifest':
                (journal / 'manifest').write_text('{broken')
            else:
                meta = json.loads((journal / 'manifest').read_text())
                records = bytearray((journal / 'blocks').read_bytes())
                record_size = 4168
                if damage == 'duplicate':
                    records[record_size:record_size + 8] = records[:8]
                elif damage == 'range':
                    records[:8] = struct.pack('<Q', base.stat().st_size // 4096)
                elif damage == 'oldhash':
                    records[8] ^= 1
                elif damage == 'newhash':
                    records[40] ^= 1
                elif damage == 'count':
                    meta['count'] = 2**64
                elif damage == 'trailing':
                    records += b'extra'
                else:
                    meta['image_sha256'] = '0' * 64
                (journal / 'blocks').write_bytes(records)
                meta['log_sha256'] = sha(journal / 'blocks')
                (journal / 'manifest').write_text(json.dumps(meta))
            run(['recover', journal], ok=False)
            assert target.read_bytes() == b'preserve me' if damage == 'collision' else not target.exists()
            checks += 1
        rows.append({'fixture': source.stem, 'image_bytes': source.stat().st_size, 'log_bytes': (journal / 'blocks').stat().st_size - (5 if damage == 'trailing' else 0), 'fsck_clean': True})
        print('PASS block log', source.stem, flush=True)
    # No-op transactions have empty logs and must still recover exactly.
    transaction = root / 'noop'
    transaction.mkdir()
    target, journal = transaction / 'result.img', transaction / 'redo'
    run(['prepare', source, source, target, journal])
    assert (journal / 'blocks').stat().st_size == 0
    # A competing recovery must reject the held manifest lock without output.
    with (journal / 'manifest').open('rb') as manifest:
        fcntl.flock(manifest, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run(['recover', journal], ok=False)
        assert not target.exists()
    run(['recover', journal])
    assert sha(target) == sha(source)
    checks += 2
    assert len(rows) == 12, "expected all 12 filesystem configurations"
    assert checks > 0
report = {'checks': checks, 'result': 'passed', 'scope': 'process interruption; incremental block redo; source unchanged; no device or in-place writes', 'configurations': rows}
(args.work / 'block-log-results.json').write_text(json.dumps(report, indent=2) + '\n')
print(report)
