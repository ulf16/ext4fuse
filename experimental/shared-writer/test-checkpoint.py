#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Crash checkpoint publication and retirement on managed disposable ext4 images."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
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


def log_bytes(root):
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and p.name in ('pages', 'blocks'))


def tree_hash(root):
    # Negative operations must preserve all transaction history, not just data.
    return {str(p.relative_to(root)): sha(p) for p in root.rglob('*') if p.is_file()}


with tempfile.TemporaryDirectory(prefix='checkpoint-test-', dir=args.work) as root:
    root = Path(root)
    for source in sorted(fixtures.glob('*-csum*.img')):
        if '-output' in source.name:
            continue
        original = sha(source)
        session = root / source.stem
        run(['init', source, session, args.work / 'prototype'])
        run(['append', session, args.work / 'step-writer'], step=1)
        # Unsealed preparation becomes an aborted directory and is retired too.
        run(['append', session, args.work / 'step-writer'], step=2, crash='record')
        run(['recover', session])
        assert list(session.glob('aborted-*'))
        image = session / 'image.img'
        before = sha(image)
        identity = image.stat().st_ino
        head = 1
        bytes_before = log_bytes(session)
        assert bytes_before > 0
        for phase in ('checkpoint-validated', 'checkpoint:pending', 'checkpoint:renamed',
                      'checkpoint-published', 'retire-entry', 'retire-directory',
                      'retirement-complete'):
            run(['checkpoint', session], crash=phase)
            assert sha(image) == before and image.stat().st_ino == identity
            recovered = run(['recover', session])
            assert recovered['head'] == head
            if phase == 'retirement-complete':
                assert log_bytes(session) == 0
            # Rebuild fresh history for the next fault boundary without copying
            # the image or resetting its generation identity.
            if phase != 'retirement-complete':
                # Since each cleanup retry may consume old files, append a no-op
                # is unnecessary: currently the tested boundary still has targets
                # except after retiring directories. Finish and add the next step.
                run(['checkpoint', session])
                step = recovered['head'] + 1
                run(['append', session, args.work / 'step-writer'], step=step)
                head += 1
                before = sha(image)
        run(['checkpoint', session])
        run(['checkpoint', session])
        assert log_bytes(session) == 0
        # Restore state solely from the latest checkpoint after logs are gone.
        (session / 'chain-state').unlink()
        saved = run(['recover', session])
        expected_head = saved['head']
        assert sha(image) == before and image.stat().st_ino == identity
        # New generations can follow a fully retired checkpoint.
        run(['append', session, args.work / 'step-writer'], step=expected_head + 1, crash='half:0:0')
        snapshots = tree_hash(session)
        run(['checkpoint', session], ok=False)
        assert tree_hash(session) == snapshots, 'pending logs were changed'
        run(['recover', session])
        run(['checkpoint', session])
        # A corrupt checkpoint fails closed, without deleting history.
        run(['append', session, args.work / 'step-writer'], step=expected_head + 2, crash='chain-prepared')
        pending_state = (session / 'chain-state').read_bytes()
        (session / 'chain-state').unlink()
        pending_history = tree_hash(session)
        run(['recover', session], ok=False)
        assert tree_hash(session) == pending_history, 'matching checkpoint lost pending successor'
        (session / 'chain-state').write_bytes(pending_state)
        run(['recover', session])
        good_checkpoint = (session / 'checkpoint').read_bytes()
        checkpoint = json.loads(good_checkpoint)
        checkpoint['state']['sha256'] = '0' * 64
        (session / 'checkpoint').write_text(json.dumps(checkpoint))
        snapshots = tree_hash(session)
        run(['checkpoint', session], ok=False)
        assert tree_hash(session) == snapshots
        (session / 'checkpoint').write_bytes(good_checkpoint)
        state = json.loads((session / 'chain-state').read_text())
        latest = session / f"g-{state['head']:08d}"
        note = latest / 'notes.txt'
        note.write_text('preserve unexpected data')
        snapshots = tree_hash(session)
        run(['checkpoint', session], ok=False)
        assert tree_hash(session) == snapshots
        note.unlink()
        with (session / 'chain-lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(['checkpoint', session], ok=False)
        (session / 'chain-state').unlink()
        damaged = tree_hash(session)
        run(['recover', session], ok=False)
        assert tree_hash(session) == damaged, 'stale checkpoint replay changed history'
        assert sha(source) == original
        result = subprocess.run(['e2fsck', '-f', '-n', str(image)], capture_output=True)
        assert result.returncode == 0, result.stdout + result.stderr
        rows.append({'fixture': source.stem, 'original_log_bytes': bytes_before, 'logs_retired': True,
                     'pending_logs_preserved': True, 'checkpoint_restored_state': True,
                     'stale_checkpoint_rejected': True, 'source_unchanged': True, 'fsck_clean': True})
        checks += 8
        print('PASS checkpoint', source.stem, flush=True)
    assert len(rows) == 12
report = {'checks': checks, 'result': 'passed', 'configurations': rows,
          'scope': 'managed disposable image checkpoint and restartable log retirement; process interruption'}
(args.work / 'checkpoint-results.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS', checks, 'checkpoint checks')
