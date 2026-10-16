#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Lose or tear unflushed device sectors on disposable hdiutil/loop targets only.

This is a software model of honest cache flush semantics, not hardware power-loss
certification. The external recovery filesystem remains durable in this model.
"""
import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import plistlib
import random
import shutil
import subprocess
import sys
import tempfile
import time
import direct_device as direct
import durable
import endurance_model as model
import session
from credentials import Credentials
from device_admission import Device

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--fixtures', type=Path)
p.add_argument('--limit', type=int)
p.add_argument('--seed', type=int, default=77123)
p.add_argument('--focused', action='store_true', help='focus on data flushes and repeated recovery; guard phase matrix is covered separately')
p.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
a = p.parse_args()
HERE = Path(__file__).resolve().parent


def admission(call):
    deadline = time.monotonic()+15
    while True:
        try: return call()
        except OSError as error:
            if sys.platform != 'linux' or error.errno not in (errno.EAGAIN, errno.EBUSY) or time.monotonic() >= deadline:
                raise
            time.sleep(.2)


@contextlib.contextmanager
def controller(root, device):
    target = admission(lambda: direct.Controller(root, device, a.work).__enter__())
    try: yield target
    finally: target.__exit__()


def opened(target):
    return session.Session(target.chain, a.work/'mutation-producer', a.work/'reader-server',
                           Credentials(0, 0), commit_sink=target)


def worker(request):
    config = json.loads(request.read_text())
    original = Device.flush
    mirror = Path(config['mirror'])
    def flush(target):
        original(target)
        # Publish a fully durable test oracle for exactly the writes preceding
        # this successful device flush. No crash boundary runs inside this copy.
        with mirror.open('r+b', buffering=0) as stable:
            for offset in range(0, target.size, 1024**2):
                data = direct.old.read_at(target.fd, min(1024**2, target.size-offset), offset)
                direct.old.write_at(stable.fileno(), data, offset)
            durable.sync(stable.fileno())
    Device.flush = flush
    # Arm before Controller enters so guard installation/clean-close boundaries
    # are part of the same device cache model as ordinary data writes.
    os.environ['EXT4_TEST_CRASH'] = config['point']
    with controller(Path(config['root']), config['device']) as target:
        with opened(target) as s:
            if not config.get('recovery_only'):
                s.applyat(model.batch(a.seed, config['number'], config['previous']))
                with Path(config['ack']).open('x') as ack:
                    ack.write(str(config['number'])); ack.flush(); durable.sync(ack.fileno())
                durable.directory(Path(config['ack']).parent)
        target.finish()
    return 0


if a.worker:
    raise SystemExit(worker(a.worker))


def attach(image, sector):
    if sys.platform == 'darwin':
        data = plistlib.loads(model.command(['hdiutil', 'attach', '-nomount', '-imagekey',
                                           'diskimage-class=CRawDiskImage', '-plist', image]))
        return min((n['dev-entry'] for n in data['system-entities'] if 'dev-entry' in n), key=len)
    result = model.command(['losetup', '--find', '--show', '--sector-size', sector, image]).decode().strip()
    if shutil.which('udevadm'): model.command(['udevadm', 'settle', '--timeout=15'])
    return result


def detach(device):
    model.command(['hdiutil', 'detach', device] if sys.platform == 'darwin' else ['losetup', '--detach', device])


def lose_cache(device, root, backing, mirror, mode, seed):
    """Restore only a disposable target's volatile differences to its flush oracle."""
    target = admission(lambda: Device(device, root).__enter__())
    changed = dropped = 0
    try:
        identity = target.identity
        assert identity.get('kind') in ('disk-image', 'loop'), 'physical devices are forbidden in this test'
        assert Path(identity['backing']['path']).resolve() == backing.resolve(), 'wrong disposable backing'
        rng = random.Random(seed)
        with mirror.open('rb') as stable:
            for offset in range(0, target.size, 1024**2):
                length = min(1024**2, target.size-offset)
                current = direct.old.read_at(target.fd, length, offset)
                saved = stable.read(length)
                assert len(saved) == length
                for at in range(0, length, target.sector):
                    volatile = current[at:at+target.sector]; durable_bytes = saved[at:at+target.sector]
                    if volatile == durable_bytes: continue
                    changed += 1
                    if mode == 'lost': restored = durable_bytes
                    else:
                        # Arbitrary byte tears in logged pages are repairable;
                        # this also models some sectors reaching storage early.
                        cut = rng.randrange(target.sector+1)
                        restored = durable_bytes[:cut] + volatile[cut:]
                    if restored != volatile: dropped += 1
                    direct.old.write_at(target.fd, restored, offset+at)
        target.flush()
        # Surviving early/torn bytes are now the physical baseline for a second
        # outage; a later outage must not erase already persistent bytes.
        with mirror.open('r+b', buffering=0) as saved:
            for offset in range(0, target.size, 1024**2):
                data = direct.old.read_at(target.fd, min(1024**2, target.size-offset), offset)
                direct.old.write_at(saved.fileno(), data, offset)
            durable.sync(saved.fileno())
    finally:
        target.__exit__()
    return changed, dropped


base = Path(tempfile.mkdtemp(prefix='device-cache-loss-', dir=a.work))
fixtures = a.fixtures or a.work/'fixtures'
sources = sorted(p for p in fixtures.glob('*-csum*.img') if '-output' not in p.name)
# Representative minimum/maximum block and mapping/checksum combinations by
# default; --limit can select the complete matrix with a large enough value.
sources = [p for p in sources if p.name in ('1024-classic-csum0.img', '4096-extents-csum1.img')] if a.limit is None else sources[:a.limit]
assert sources
points = ('direct:arming', 'live:guarded', 'direct:active', 'record', 'snapshot',
          'prepared', 'started', 'half:0:0', 'applied', 'direct:flushed',
          'complete', 'head-ready', 'direct:acknowledge-ready',
          'direct:closing', 'direct:magic-restored', 'direct:closed')
if a.focused:
    points = ('prepared', 'half:0:0', 'applied', 'direct:flushed', 'direct:acknowledge-ready', 'direct:closing', 'direct:magic-restored')
rows = []
for source in sources:
    image = base/(source.stem+'.img'); shutil.copyfile(source, image)
    original_hash = model.command(['shasum', '-a', '256', source]).split()[0]
    mirror = base/(source.stem+'.durable'); shutil.copyfile(image, mirror)
    root = base/source.stem; device = None
    head = None; history = set(); crashes = dropped = changed = double_crashes = acknowledgements = 0
    try:
        device = attach(image, 4096 if source.name.startswith('4096-') else 512)
        admission(lambda: direct.init(device, root, a.work))
        with controller(root, device) as target:
            with opened(target) as s:
                s.mkdir('/history'); s.symlink('current', '/pointer')
            target.finish()
        for number, (point, mode) in enumerate((p, m) for p in points for m in ('lost', 'torn')):
            # Re-establish the last durable physical state before each experiment.
            with image.open('rb') as source_bytes, mirror.open('wb') as saved:
                shutil.copyfileobj(source_bytes, saved); saved.flush(); durable.sync(saved.fileno())
            ack = base/f'{source.stem}-{number}.ack'
            request = base/f'{source.stem}-{number}.request'
            config = dict(root=str(root), device=device, mirror=str(mirror), ack=str(ack),
                          point=point, number=number, previous=head)
            request.write_text(json.dumps(config))
            result = subprocess.run([sys.executable, __file__, '--work', str(a.work), '--seed', str(a.seed), '--worker', str(request)],
                                    capture_output=True, timeout=180)
            assert result.returncode == 77, (point, result.returncode, result.stderr)
            c, d = lose_cache(device, root, image, mirror, mode, a.seed+number)
            changed += c; dropped += d; crashes += 1
            if point in ('half:0:0', 'applied'):
                # A second outage during recovery must retain the same sealed
                # intent and every earlier acknowledged history entry.
                config.update(point='half:0:0', recovery_only=True)
                request.write_text(json.dumps(config))
                retry = subprocess.run([sys.executable, __file__, '--work', str(a.work), '--seed', str(a.seed), '--worker', str(request)],
                                       capture_output=True, timeout=180)
                assert retry.returncode == 77, (point, retry.returncode, retry.stderr)
                c, d = lose_cache(device, root, image, mirror, mode, a.seed+number+1000)
                changed += c; dropped += d; double_crashes += 1
            with controller(root, device) as target:
                with opened(target) as s:
                    head, history = model.actual(s, a.seed, head, number, history)
                    if ack.exists():
                        assert head == number, 'acknowledged device transaction lost'
                        acknowledgements += 1
                    s.checkpoint()
                target.finish()
            model.independent(image, a.seed, head, history)
            # Second cold recovery must be idempotent and cleanly publish again.
            with controller(root, device) as target:
                with opened(target) as s: model.verify(s, a.seed, head, history)
                target.finish()
            print('PASS', source.name, point, mode, 'volatile sectors', c, 'lost/torn', d, flush=True)
        assert dropped > 0 and changed >= dropped, 'cache-loss model never discarded actual writes'
        assert (root/'chain'/'image.img').stat().st_blocks == 0
        assert model.command(['shasum', '-a', '256', source]).split()[0] == original_hash
        row = dict(profile=source.name, crashes=crashes, repeated_recovery_crashes=double_crashes,
                   acknowledged_commits=acknowledgements, volatile_sectors=changed, discarded_or_torn_sectors=dropped,
                   history_entries=len(history), result='passed')
        rows.append(row)
    finally:
        if device: detach(device)
report = dict(result='passed', seed=a.seed, profiles=rows, retained=str(base),
              scope='simulated target-device volatile-cache loss; recovery filesystem durable; no hardware certification')
(a.work/'device-cache-loss-results.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS device-cache-loss', json.dumps(rows), flush=True)
