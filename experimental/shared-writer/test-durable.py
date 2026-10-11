#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Kill transaction processes at each persistence boundary on real ext4 fixtures."""
import argparse
import hashlib
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

def run(arguments, crash=None, ok=True):
    global checks
    env = dict(os.environ)
    if crash:
        env['EXT4_TEST_CRASH'] = crash
    result = subprocess.run(['python3', str(here / 'durable.py'), *map(str, arguments)],
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
        for point in ('created', 'snapshot', 'manifest', 'sealed', 'verified', 'linked', 'published', None):
            transaction = root / (source.stem + '-' + str(point))
            transaction.mkdir()
            target, journal = transaction / 'result.img', transaction / 'redo'
            if point in ('created', 'snapshot', 'manifest', 'sealed'):
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
        for damage in ('truncate', 'corrupt', 'base', 'collision', 'manifest'):
            transaction = root / (source.stem + '-damage-' + damage)
            transaction.mkdir()
            target, journal = transaction / 'result.img', transaction / 'redo'
            base = transaction / 'base.img'
            base.write_bytes(source.read_bytes())
            run(['prepare', base, candidate, target, journal])
            if damage == 'truncate':
                with (journal / 'image').open('r+b') as stream:
                    stream.truncate(4096)
            elif damage == 'corrupt':
                with (journal / 'image').open('r+b') as stream:
                    stream.write(b'corrupt!')
            elif damage == 'base':
                with base.open('r+b') as stream:
                    stream.write(b'changed!')
            elif damage == 'collision':
                target.write_bytes(b'preserve me')
            else:
                (journal / 'manifest').write_text('{broken')
            run(['recover', journal], ok=False)
            assert target.read_bytes() == b'preserve me' if damage == 'collision' else not target.exists()
            checks += 1
        print('PASS durable', source.stem, flush=True)
    assert checks > 0
report = {'checks': checks, 'result': 'passed', 'scope': 'process interruption; sealed full-image redo; source unchanged; no device or in-place writes'}
(args.work / 'durable-results.json').write_text(json.dumps(report, indent=2) + '\n')
print(report)
