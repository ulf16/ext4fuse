#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Seeded atomic mixed-operation endurance, crashes and real storage error injection."""
import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from unittest.mock import patch
import chain
import durable
import inplace
import session
from credentials import Credentials
import endurance_model as model

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--fixtures', type=Path)
p.add_argument('--rounds', type=int, default=240)
p.add_argument('--seed', type=int, default=918273)
p.add_argument('--limit', type=int)
p.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
a = p.parse_args()


def opened(root, checkpoint=0):
    return session.Session(root, a.work/'mutation-producer', a.work/'reader-server',
                           Credentials(0, 0), checkpoint_every=checkpoint)


def worker(request):
    config = json.loads(request.read_text())
    with opened(Path(config['root'])) as s:
        os.environ['EXT4_TEST_CRASH'] = config['point']
        s.applyat(model.batch(a.seed, config['number'], config['previous']))
        # Parent may rely on this durable acknowledgement only after apply returns.
        with Path(config['ack']).open('x') as ack:
            ack.write(str(config['number'])); ack.flush(); durable.sync(ack.fileno())
        durable.directory(Path(config['ack']).parent)
        if config['checkpoint']:
            s.checkpoint()
    return 0


if a.worker:
    raise SystemExit(worker(a.worker))
if not 1 <= a.rounds <= 100000:
    p.error('--rounds must be 1..100000')

# Descriptor-based fault selection works on macOS and Linux without relying on
# private /dev/fd path semantics. Every failure reaches a real I/O call site.
@contextlib.contextmanager
def io_fault(root, target, action, code, persistent=False):
    original_sync = os.fsync
    original_pwrite = os.pwrite
    hits = []
    calls = 0
    def selected(fd):
        info = os.fstat(fd)
        if target == 'image':
            image = os.stat(root/'image.img')
            return (info.st_dev, info.st_ino) == (image.st_dev, image.st_ino)
        if target == 'directory':
            return stat.S_ISDIR(info.st_mode)
        for path in root.rglob(target):
            st = os.stat(path)
            if (st.st_dev, st.st_ino) == (info.st_dev, info.st_ino):
                return True
        return False
    def sync(fd):
        if selected(fd) and (persistent or not hits):
            hits.append('fsync'); raise OSError(code, 'injected durability sync failure')
        return original_sync(fd)
    def write(fd, data, offset):
        nonlocal calls
        if selected(fd):
            calls += 1
            if action == 'short' and (persistent or not hits):
                hits.append('short'); return original_pwrite(fd, data[:min(113, len(data))], offset)
            if persistent or not hits:
                hits.append('pwrite')
                if action == 'torn':
                    original_pwrite(fd, data[:min(137, len(data))], offset)
                if action == 'zero': return 0
                raise OSError(code, 'injected device write failure')
        return original_pwrite(fd, data, offset)
    with patch.object(os, 'fsync', sync if action == 'sync' else original_sync), patch.object(os, 'pwrite', write if action != 'sync' else original_pwrite):
        yield hits


base = Path(tempfile.mkdtemp(prefix='endurance-', dir=a.work))
fixtures = a.fixtures or a.work/'fixtures'
sources = sorted(path for path in fixtures.glob('*-csum*.img') if '-output' not in path.name)
if a.limit: sources = sources[:a.limit]
assert sources, 'no fixtures'
rows = []
points = ['chain-state:renamed', 'record', 'snapshot', 'undo-log', 'transaction:pending',
          'transaction:renamed', 'prepared', 'started:pending', 'started:renamed',
          'half:0:0', 'applied', 'synced', 'complete:pending', 'complete:renamed',
          'head-ready', 'head-published', 'checkpoint-validated', 'checkpoint:pending',
          'checkpoint:renamed', 'checkpoint-published', 'retire-entry', 'retirement-complete']
for source in sources:
    root = base/source.stem; chain.clone(source, root)
    seed_hash = model.command(['shasum', '-a', '256', source]).split()[0]
    head = None; history = set(); transactions = crashes = faults = 0
    with opened(root, checkpoint=17) as s:
        s.mkdir('/history'); s.symlink('current', '/pointer')
        # Keep a handle to a removed inode across many commits/checkpoints.
        orphan = s.openat(None, '/held-orphan', 'rw', create=True)
        orphan.write(b'held lifetime'); s.unlink('/held-orphan')
        for number in range(a.rounds):
            operations = model.batch(a.seed, number, head)
            s.applyat(operations); head = number; history.add(number); transactions += 1
            if number and number % 80 == 0:
                print('Progress', source.name, number, 'durable batches', flush=True)
            if number % 19 == 0:
                model.verify(s, a.seed, head, history)
                assert orphan.read() == b'held lifetime'
            if number % 23 == 0:
                # A late failing operation must undo all earlier staged changes.
                before = s.state.copy()
                bad = [dict(kind='chmod', path='/current', mode=0o777),
                       dict(kind='rename', path='/current', target='/should-not-exist'),
                       dict(kind='unlink', path='/missing-never-created')]
                try: s.applyat(bad)
                except OSError as error: assert error.errno == errno.ENOENT
                else: raise AssertionError('invalid batch succeeded')
                assert s.state == before and not s._failed
                model.verify(s, a.seed, head, history)
            if number % 47 == 0:
                s.checkpoint()
        orphan.close(); model.verify(s, a.seed, head, history)
    model.independent(root/'image.img', a.seed, head, history)
    for number, point in enumerate(points, start=a.rounds):
        ack = base/f'{source.stem}-{number}.ack'
        request = base/f'{source.stem}-{number}.request'
        request.write_text(json.dumps(dict(root=str(root), number=number, previous=head,
                           ack=str(ack), point=point, checkpoint=point.startswith(('checkpoint', 'retire')))))
        result = subprocess.run([sys.executable, __file__, '--work', str(a.work), '--seed', str(a.seed), '--worker', str(request)],
                                capture_output=True, timeout=120)
        assert result.returncode == 77, (point, result.returncode, result.stderr)
        with opened(root) as s:
            head, history = model.actual(s, a.seed, head, number, history)
            if ack.exists(): assert head == number, 'acknowledged transaction lost'
            s.checkpoint()
        model.independent(root/'image.img', a.seed, head, history)
        crashes += 1
        print('PASS crash', source.name, point, flush=True)
    # Fail actual redo/marker/image/directory syncs and page writes, including
    # permanent errors that must prevent continued use of the live session.
    cases = [(target, 'sync') for target in ('pages', 'transaction.pending', 'started.pending',
             'complete.pending', 'chain-state.pending', 'image', 'directory')]
    cases += [('image', action) for action in ('short', 'zero', 'torn', 'error')]
    for target, action in cases:
        for persistent in (False, True):
            number = a.rounds + len(points) + faults
            with opened(root) as s:
                reported = False
                with io_fault(root, target, action, errno.ENOSPC if faults % 2 else errno.EIO, persistent) as hit:
                    try: s.applyat(model.batch(a.seed, number, head))
                    except (OSError, ValueError): reported = True
                    assert hit, (target, action, 'injection missed')
                    assert (not reported) == (action == 'short'), (target, action, persistent, reported)
                    if persistent and action != 'short' and target not in ('pages', 'transaction.pending', 'chain-state.pending'):
                        assert s._failed, (target, action, 'persistent fault did not fail closed')
                # Do not acknowledge an errored call; either complete atomic state
                # is valid after recovery, but every earlier acknowledgement holds.
            with opened(root) as s:
                head, history = model.actual(s, a.seed, head, number, history)
                s.checkpoint()
            model.independent(root/'image.img', a.seed, head, history)
            faults += 1
            print('PASS I/O fault', source.name, target, action, 'persistent' if persistent else 'transient', flush=True)
    assert model.command(['shasum', '-a', '256', source]).split()[0] == seed_hash
    row = dict(profile=source.name, transactions=transactions, crash_points=crashes,
               io_faults=faults, history_entries=len(history), result='passed')
    rows.append(row); print(json.dumps(row), flush=True)
report = dict(result='passed', seed=a.seed, rounds=a.rounds, profiles=rows,
              retained=str(base), scope='process crash and reported I/O faults; no physical power-loss certification')
(a.work/'endurance-results.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS endurance', len(rows), 'profiles', flush=True)
