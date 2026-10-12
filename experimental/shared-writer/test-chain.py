#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Chain commits on one inode and keep a live reader across refresh/recovery."""
import argparse
import fcntl
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--fixtures', type=Path)
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows = 0, []


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(arguments, step=None, crash=None, ok=True):
    global checks
    env = dict(os.environ)
    if step is not None:
        env['EXT4_STEP'] = str(step)
    if crash:
        env['EXT4_TEST_CRASH'] = crash
    result = subprocess.run(['python3', str(here / 'chain.py'), *map(str, arguments)], env=env,
                            capture_output=True, text=True, timeout=60)
    assert (result.returncode == (77 if crash else 0)) if ok else result.returncode != 0, result.stderr
    checks += 1
    return json.loads(result.stdout) if result.returncode == 0 else None


def command(reader, text, expected=0):
    global checks
    reader.stdin.write(str(text) + '\n'); reader.stdin.flush()
    reply = reader.stdout.readline()
    assert reply == str(expected) + '\n', (text, reply)
    checks += 1


with tempfile.TemporaryDirectory(prefix='chain-test-', dir=args.work) as root:
    root = Path(root)
    for source in sorted(fixtures.glob('*-csum*.img')):
        if '-output' in source.name:
            continue
        before = sha(source)
        session = root / source.stem
        state = run(['init', source, session, args.work / 'prototype'])
        assert state['head'] == 0
        image = session / 'image.img'
        identity = image.stat().st_ino
        reader = subprocess.Popen([str(args.work / 'reader-watch'), str(image)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            command(reader, 0)
            # Failed preparation, partial page writes, completed-but-unpublished
            # heads, and normal commits all feed the same reader and image inode.
            phases = ('chain-intent', 'record', 'prepared', 'half:0:0', 'complete',
                      'chain-state:pending', 'chain-state:renamed', 'head-ready', 'head-published', None)
            committed = 0
            for phase in phases:
                step = committed + 1
                command(reader, 'pause')
                command(reader, committed, expected=errno.EBUSY)  # EBUSY on Linux/Darwin
                prior = sha(image)
                run(['append', session, args.work / 'step-writer'], step=step, crash=phase)
                command(reader, committed, expected=errno.EBUSY)
                recovered = run(['recover', session])
                run(['recover', session])
                # Intent/record fail before sealing; state publication faults in
                # append hit its initial intent publication, before generation work.
                aborted = phase in ('chain-intent', 'record', 'chain-state:pending', 'chain-state:renamed')
                if aborted:
                    assert recovered['head'] == committed and sha(image) == prior
                else:
                    committed += 1
                    assert recovered['head'] == committed
                command(reader, 'resume')
                command(reader, committed)
                assert image.stat().st_ino == identity
                result = subprocess.run(['e2fsck', '-f', '-n', str(image)], capture_output=True)
                assert result.returncode == 0, result.stdout + result.stderr
                checks += 2
            # Chain-wide serialization must reject competing operations.
            with (session / 'chain-lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                run(['append', session, args.work / 'step-writer'], step=committed + 1, ok=False)
                run(['recover', session], ok=False)
            # A valid checksum on a generation with the wrong predecessor is
            # rejected before changing the image.
            command(reader, 'pause')
            run(['append', session, args.work / 'step-writer'], step=committed + 1, crash='chain-prepared')
            pending = json.loads((session / 'chain-state').read_text())['pending']
            metadata_path = session / f'g-{pending:08d}' / 'transaction'
            metadata = json.loads(metadata_path.read_text())
            metadata['base_sha256'] = '0' * 64
            metadata_path.write_text(json.dumps(metadata))
            unchanged = sha(image)
            run(['recover', session], ok=False)
            assert sha(image) == unchanged
            checks += 1
        finally:
            reader.stdin.close()
            reader.wait(timeout=20)
            assert reader.returncode == 0
        assert sha(source) == before
        rows.append({'fixture': source.stem, 'commits_after_initial': committed,
                     'same_inode': True, 'resident_reader_refreshed': True,
                     'pending_reader_blocked': True, 'fsck_clean': True, 'source_unchanged': True})
        print('PASS chain', source.stem, flush=True)
    assert len(rows) == 12
report = {'checks': checks, 'result': 'passed', 'configurations': rows,
          'scope': 'serialized managed disposable image; live reader paused during commits; logs retained'}
(args.work / 'chain-results.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS', checks, 'chain checks')
