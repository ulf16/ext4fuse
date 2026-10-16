#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Concurrent mounted writes, durable external acknowledgements and launcher loss."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import durable
import endurance_model as model
from mount_state import attached

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--prefix', type=Path, required=True)
p.add_argument('--cycles', type=int, default=3)
p.add_argument('--acks', type=int, default=32)
p.add_argument('--seed', type=int, default=442211)
p.add_argument('--worker', nargs=3, metavar=('MOUNT', 'CYCLE', 'WRITER'), help=argparse.SUPPRESS)
a = p.parse_args()


def name(cycle, writer, number):
    return f'c{cycle}-w{writer}-{number:06d}'


def content(cycle, writer, number):
    return model.payload(a.seed + cycle*32 + writer, number) + f'\n{cycle}:{writer}:{number}\n'.encode()


if a.worker:
    mount, cycle, writer = a.worker; mount = Path(mount); cycle = int(cycle); writer = int(writer)
    directory = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for number in range(100000):
            target = name(cycle, writer, number)
            temporary = mount/('.pending-'+target)
            value = content(cycle, writer, number)
            fd = os.open(temporary, os.O_CREAT|os.O_EXCL|os.O_RDWR, 0o600)
            try:
                # Split and overwrite across cache/page boundaries before the
                # application durability barrier. Sparse gaps are actual zeros.
                for offset in range(0, len(value), 997):
                    part = memoryview(value)[offset:offset+997]
                    while part:
                        written = os.pwrite(fd, part, offset)
                        assert written > 0
                        offset += written; part = part[written:]
                os.fsync(fd)
                os.rename(temporary, mount/target)
                os.link(mount/target, mount/(target+'.alias'))
                os.fsync(directory)
                assert os.pread(fd, len(value), 0) == value
            finally:
                os.close(fd)
            # Parent records only acknowledgements actually received, never
            # infers durability from merely observing a directory entry.
            print(json.dumps(dict(cycle=cycle, writer=writer, number=number)), flush=True)
    finally:
        os.close(directory)
    raise SystemExit(0)


if not 1 <= a.cycles <= 100 or not 2 <= a.acks <= 10000:
    p.error('invalid cycle/ack count')
cli = a.prefix/'bin'/'ext4fuse-writer'
base = Path(tempfile.mkdtemp(prefix='mounted-endurance-', dir=a.work))
source = a.work/'fixtures'/'4096-extents-csum1.img'
seed = base/'seed.img'
import shutil
shutil.copyfile(source, seed)
# The native owner-only frontend preserves numeric ownership; prepare only this
# disposable fixture for the real launching UID/GID.
model.command(['debugfs', '-w', '-R', f'set_inode_field / uid {os.getuid()}', seed])
model.command(['debugfs', '-w', '-R', f'set_inode_field / gid {os.getgid()}', seed])
state = base/'state'; mount = base/'mount'; mount.mkdir()
model.command([cli, 'init', '--image', seed, state])
acknowledged = []


def start(label):
    path = base/(label+'.log')
    with path.open('wb') as log:
        child = subprocess.Popen([cli, 'mount', state, mount], stdout=log, stderr=log, start_new_session=True)
    deadline = time.monotonic()+30
    while not attached(mount):
        if child.poll() is not None: raise AssertionError(path.read_text())
        if time.monotonic() >= deadline: raise TimeoutError(path.read_text())
        time.sleep(.1)
    return child


def kill(child, group=False):
    if child is not None and child.poll() is None:
        try:
            if group:
                try: os.killpg(child.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): child.kill()
            else:
                # Workers have no children. Target the Popen child directly; a
                # just-exited group may already be gone while poll raced exit.
                child.kill()
        except ProcessLookupError:
            pass
        child.wait(timeout=30)


def verify_mounted():
    for ack in acknowledged:
        target = name(**ack)
        expected = content(**ack)
        for path in (mount/target, mount/(target+'.alias')):
            assert path.read_bytes() == expected, ('acknowledged mounted data lost', target)
        assert os.stat(mount/target).st_ino == os.stat(mount/(target+'.alias')).st_ino


broker = None
workers = []
ledger = base/'acknowledgements.jsonl'
try:
    for cycle in range(a.cycles):
        broker = start('mount-'+str(cycle))
        verify_mounted()
        with selectors.DefaultSelector() as poll, ledger.open('ab', buffering=0) as recorded:
            workers = []
            for writer in range(2):
                log = (base/f'worker-{cycle}-{writer}.log').open('wb')
                child = subprocess.Popen([sys.executable, __file__, '--work', str(a.work), '--prefix', str(a.prefix),
                    '--seed', str(a.seed), '--worker', str(mount), str(cycle), str(writer)],
                    stdout=subprocess.PIPE, stderr=log, start_new_session=True)
                log.close(); workers.append(child); poll.register(child.stdout, selectors.EVENT_READ)
            count = 0; seen = set(); deadline = time.monotonic()+240
            while count < a.acks or len(seen) < 2:
                if time.monotonic() >= deadline: raise TimeoutError('mounted writers stalled: '+str(base))
                for key, unused in poll.select(1):
                    raw = key.fileobj.readline(4097)
                    if not raw: raise AssertionError('mounted worker exited: '+str(base))
                    ack = json.loads(raw)
                    acknowledged.append(ack); seen.add(ack['writer'])
                    recorded.write(raw); durable.sync(recorded.fileno())
                    count += 1
                    if count >= a.acks and len(seen) == 2: break
        # Crash while both writers may have the next unacknowledged operation
        # in flight. Kill workers too, so their open descriptors cannot hold the
        # stale attachment during normal unmount.
        kill(broker, group=True); broker = None
        for child in workers: kill(child); child.stdout.close()
        workers = []
        detached = subprocess.run([cli, 'unmount', state], capture_output=True, timeout=120)
        assert detached.returncode == 1, (detached.stdout, detached.stderr)
        assert not attached(mount), 'stale mount survived normal detach'
        model.command([cli, 'recover', state])
        model.command(['e2fsck', '-fn', state/'chain'/'image.img'])
        for ack in acknowledged:
            target = name(**ack)
            assert model.command(['debugfs', '-R', 'cat /'+target, state/'chain'/'image.img']) == content(**ack), target
        print('PASS mounted endurance cycle', cycle, 'durable acknowledgements', len(acknowledged), flush=True)
    broker = start('final-remount'); verify_mounted()
    model.command([cli, 'unmount', state]); assert broker.wait(timeout=60) == 0; broker = None
    model.command(['e2fsck', '-fn', state/'chain'/'image.img'])
finally:
    for child in workers: kill(child); child.stdout.close()
    kill(broker, group=True)
    if attached(mount):
        subprocess.run([cli, 'unmount', state], timeout=120)

report = dict(result='passed', cycles=a.cycles, writers=2, acknowledgements=len(acknowledged),
              seed=a.seed, retained=str(base), scope='application fsync/rename/directory fsync before process loss; no host power-loss certification')
(a.work/'mounted-endurance-results.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS mounted endurance', json.dumps(report), flush=True)
