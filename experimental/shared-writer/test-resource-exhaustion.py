#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real bounded filesystem exhaustion and process-local memory exhaustion.

Never fills the host filesystem or selects an existing device. Linux log tests
need root for a private size-limited tmpfs; macOS uses a new 64 MiB HFS+ image.
"""
import argparse
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import resource
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch
import chain
import direct_device as direct
import time
import durable
import inplace
import session
from credentials import Credentials
import endurance_model as model

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--phase', choices=('all', 'volume', 'log', 'direct-log', 'memory'), default='all')
p.add_argument('--memory-worker', type=Path, help=argparse.SUPPRESS)
a = p.parse_args()
MiB = 1024**2


def opened(root, target=None):
    return session.Session(root, a.work/'mutation-producer', a.work/'reader-server',
                           Credentials(0, 0), commit_sink=target)


def checked(image):
    model.command(['e2fsck', '-fn', image])


def seed(path, inodes=1024):
    with path.open('xb') as f: f.truncate(16*MiB)
    model.command(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', '-N', inodes,
                   '-O', '^orphan_file', path])
    checked(path)


def read_all(s, path, length):
    return b''.join(s.read(path, offset, min(MiB, length-offset)) for offset in range(0, length, MiB))


def verify(s, expected):
    for path, data in expected.items():
        assert read_all(s, path, len(data)) == data, ('acknowledged bytes changed', path)
        assert s.statat(None, path)['size'] == len(data), path


def absent(s, path):
    try: s.statat(None, path)
    except OSError as e: assert e.errno == errno.ENOENT, e
    else: raise AssertionError(('partial batch published', path))


def fresh(source, root):
    chain.clone(source, root)
    with opened(root) as s:
        s.applyat([dict(kind='create', path='/ack', data_hex=b'previously acknowledged'.hex())])
        s.checkpoint()


def finish(root, expected):
    for _ in range(2):
        with opened(root) as s:
            verify(s, expected)
            s.checkpoint()
        checked(root/'image.img')
    for path, data in expected.items():
        assert model.command(['debugfs', '-R', 'cat '+path, root/'image.img']) == data


def volume(base, block_size):
    source = base/f'seed-{block_size}.img'
    with source.open('xb') as f: f.truncate(16*MiB)
    model.command(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', block_size, '-N', '128',
                   '-O', '^orphan_file', source])
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    rows = []
    for kind in ('blocks', 'inodes'):
        root = base/f'{block_size}-{kind}'; fresh(source, root)
        expected = {'/ack': b'previously acknowledged'}; committed = []; chunk_size = MiB
        with opened(root) as s:
            for n in range(512):
                name = f'/fill-{n}'
                data = bytes([n % 251 + 1])*chunk_size if kind == 'blocks' else b''
                # Earlier staged metadata and a fresh name must also roll back.
                old_mode = s.statat(None, '/ack')['mode'] & 0o777
                ops = [dict(kind='chmod', path='/ack', mode=0o600 if old_mode != 0o600 else 0o640),
                       dict(kind='create', path=name, data_hex=data.hex())]
                try: s.applyat(ops)
                except OSError as e:
                    assert e.errno == errno.ENOSPC, (kind, repr(e))
                    assert not s._failed, 'ordinary ext4 exhaustion poisoned session'
                    absent(s, name); verify(s, expected)
                    assert s.statat(None, '/ack')['mode'] & 0o777 == old_mode
                    if kind == 'blocks' and chunk_size > block_size:
                        chunk_size //= 2
                        continue
                    break
                committed.append(name); expected[name] = data
                s.checkpoint()
            else: raise AssertionError('bounded ext4 filesystem did not exhaust')
            assert committed
            stats = model.command(['debugfs', '-R', 'stats', root/'image.img'])
            free_blocks = int(re.search(rb'Free blocks:\s+(\d+)', stats).group(1))
            free_inodes = int(re.search(rb'Free inodes:\s+(\d+)', stats).group(1))
            assert (free_blocks if kind == 'blocks' else free_inodes) == 0, stats
            # A failed write must preserve existing bytes, not just allocation maps.
            before = s.read('/ack')
            if kind == 'blocks':
                try: s.applyat([dict(kind='write', path='/ack', offset=0, data_hex=(b'X'*(4*MiB)).hex())])
                except OSError as e: assert e.errno == errno.ENOSPC, e
                else: raise AssertionError('overwrite unexpectedly fit')
                assert s.read('/ack') == before
            freed = committed.pop(); s.unlink(freed); expected.pop(freed)
            s.applyat([dict(kind='create', path='/after-space-returned', data_hex=b'resumed'.hex())])
            expected['/after-space-returned'] = b'resumed'
            s.checkpoint()
        finish(root, expected)
        rows.append(dict(kind=kind, block_size=block_size, acknowledged=len(committed)+1,
                         failure='ENOSPC', recovered=True, free_blocks=free_blocks, free_inodes=free_inodes))
        print('PASS actual ext4 exhaustion', block_size, kind, len(committed)+1, flush=True)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original
    return rows


@contextlib.contextmanager
def bounded_volume(base, sparse=False):
    mount = base/'log-volume'; mount.mkdir(exist_ok=True)
    if sys.platform == 'darwin':
        image = base/('bounded-log-'+uuid.uuid4().hex+'.dmg')
        model.command(['hdiutil', 'create', '-size', '128m' if sparse else '64m', '-fs', 'APFS' if sparse else 'HFS+', '-volname',
                       'ext4-exhaustion-test', image])
        info = plistlib.loads(model.command(['hdiutil', 'attach', '-nobrowse', '-mountpoint', mount, '-plist', image]))
        device = next(e['dev-entry'] for e in info['system-entities'] if e.get('mount-point') == str(mount))
        try: yield mount
        finally: model.command(['hdiutil', 'detach', device])
    else:
        if os.geteuid() != 0: raise RuntimeError('private bounded tmpfs requires root on Linux')
        model.command(['mount', '-t', 'tmpfs', '-o', 'size=64m,nr_inodes=8192,mode=0700', 'ext4-exhaustion-test', mount])
        try: yield mount
        finally: model.command(['umount', mount])


def fill(path):
    """Bounded destination only: physically write until the OS returns ENOSPC."""
    assert os.stat(path.parent).st_dev != os.stat(path.parent.parent).st_dev, 'not a separate bounded volume'
    written = 0
    with path.open('xb', buffering=0) as f:
        chunk = b'F'*65536
        while True:
            try:
                n = f.write(chunk)
                assert n > 0
                written += n
                assert written <= 144*MiB, 'bounded volume exceeded safety ceiling'
            except OSError as e:
                assert e.errno == errno.ENOSPC, e
                # Consume any smaller tail left after a large write was refused.
                if len(chunk) > 512: chunk = chunk[:512]; continue
                break
        os.fsync(f.fileno())
    assert written > 0
    return written


def logs(base):
    source = base/'log-seed.img'; seed(source)
    rows = []
    with bounded_volume(base) as mount:
        for stage in ('before-request', 'record', 'prepared', 'applied', 'head-ready'):
            root = mount/'chain'; fresh(source, root)
            filler = mount/'space-filler'; hits = []
            original = inplace.boundary
            def boundary(name):
                original(name)
                if name == stage and not hits: hits.append(fill(filler))
            try:
                with opened(root) as s:
                    if stage == 'before-request': hits.append(fill(filler))
                    with patch.object(inplace, 'boundary', boundary):
                        try:
                            s.applyat([dict(kind='create', path='/candidate', data_hex=(b'C'*(2*MiB)).hex()),
                                       dict(kind='link', path='/candidate', target='/candidate-alias')])
                        except (OSError, ValueError) as e:
                            failure = type(e).__name__+': '+str(e)
                        else: raise AssertionError(('log exhaustion did not reject call', stage))
                    assert hits, ('boundary missed', stage)
                    # No space is released until the failed session closes.
                    failed_closed = s._failed
                    if failed_closed:
                        try: s.read('/ack')
                        except OSError as e: assert e.errno == errno.EIO
                        else: raise AssertionError('failed session served a stale reader')
            finally:
                filler.unlink(missing_ok=True)
                durable.directory(mount)
            with opened(root) as s:
                verify(s, {'/ack': b'previously acknowledged'})
                try: s.statat(None, '/candidate')
                except OSError as e:
                    assert e.errno == errno.ENOENT
                    absent(s, '/candidate-alias'); committed = False
                else:
                    assert read_all(s, '/candidate', 2*MiB) == b'C'*(2*MiB)
                    assert s.statat(None, '/candidate')['inode'] == s.statat(None, '/candidate-alias')['inode']
                    assert s.statat(None, '/candidate')['links'] == 2
                    committed = True
                if stage in ('before-request', 'record'): assert not committed
                if stage in ('prepared', 'applied', 'head-ready'):
                    assert committed, 'sealed redo was lost'
                    assert failed_closed, 'blocked replay must fail closed'
                s.applyat([dict(kind='create', path='/resumed', data_hex=b'resumed'.hex())]); s.checkpoint()
            expected = {'/ack': b'previously acknowledged', '/resumed': b'resumed'}
            if committed:
                expected.update({'/candidate': b'C'*(2*MiB), '/candidate-alias': b'C'*(2*MiB)})
            finish(root, expected)
            rows.append(dict(stage=stage, bytes_filled=hits[0], error=failure,
                             failed_closed=failed_closed, sealed_recovered=committed))
            print('PASS actual recovery-volume exhaustion', stage, flush=True)
            shutil.rmtree(root)
    return rows


def admit(call):
    deadline = time.monotonic()+15
    while True:
        try: return call()
        except OSError as e:
            if sys.platform != 'linux' or e.errno not in (errno.EAGAIN, errno.EBUSY) or time.monotonic() >= deadline: raise
            time.sleep(.2)


@contextlib.contextmanager
def direct_target(root, device):
    target = admit(lambda: direct.Controller(root, device, a.work).__enter__())
    try: yield target
    finally: target.__exit__()


def direct_logs(base):
    backing = base/'device.img'; seed(backing)
    if sys.platform == 'darwin':
        info = plistlib.loads(model.command(['hdiutil', 'attach', '-nomount', '-imagekey',
                                            'diskimage-class=CRawDiskImage', '-plist', backing]))
        device = min((e['dev-entry'] for e in info['system-entities'] if 'dev-entry' in e), key=len)
    else:
        device = model.command(['losetup', '--find', '--show', backing]).decode().strip()
        if shutil.which('udevadm'): model.command(['udevadm', 'settle', '--timeout=15'])
    rows = []
    try:
        with bounded_volume(base, sparse=True) as mount:
            root = mount/'direct'
            admit(lambda: direct.init(device, root, a.work))
            with direct_target(root, device) as target:
                # Admission must identify exactly our newly created backing image.
                assert target.target.identity['kind'] in ('disk-image', 'loop')
                assert Path(target.target.identity['backing']['path']).resolve() == backing.resolve()
                with opened(target.chain, target) as s:
                    s.applyat([dict(kind='create', path='/ack', data_hex=b'device acknowledged'.hex())])
                    s.checkpoint()
                target.finish()
            for number, stage in enumerate(('record', 'prepared', 'applied', 'head-ready', 'direct:closing')):
                filler = mount/'space-filler'; hits = []
                original = inplace.boundary
                def boundary(name):
                    original(name)
                    if name == stage and not hits: hits.append(fill(filler))
                candidate = f'/candidate-{number}'
                failure = None
                try:
                    with direct_target(root, device) as target:
                        with patch.object(inplace, 'boundary', boundary), patch.object(direct, 'boundary', boundary):
                            try:
                                with opened(target.chain, target) as s:
                                    s.applyat([dict(kind='create', path=candidate, data_hex=(bytes([number+1])*MiB).hex())])
                                target.finish()
                            except (OSError, ValueError) as e: failure = type(e).__name__+': '+str(e)
                            else:
                                # APFS can reserve metadata space after data
                                # allocation reports ENOSPC. A tiny final clean
                                # marker may still publish durably. Require the
                                # exact full-volume boundary and checked clean
                                # publication; larger redo stages must fail.
                                assert stage == 'direct:closing' and hits, ('direct log exhaustion did not fail', stage)
                                assert direct.old.load(root, 'direct-state')['phase'] == 'clean'
                                assert direct.live_device.magic(target.target) == b'\x53\xef'
                        assert hits, ('direct boundary missed', stage)
                finally:
                    filler.unlink(missing_ok=True); durable.directory(mount)
                with direct_target(root, device) as target:
                    with opened(target.chain, target) as s:
                        assert s.read('/ack') == b'device acknowledged'
                        if stage == 'record': absent(s, candidate)
                        else: assert s.read(candidate) == bytes([number+1])*MiB
                        # Every earlier successfully acknowledged close-stage file remains.
                        for prior in rows:
                            if prior['committed']:
                                assert s.read(prior['path']) == bytes([prior['number']+1])*MiB
                        for prior_number in range(number):
                            assert s.read(f'/resumed-{prior_number}') == b'resumed'
                        s.applyat([dict(kind='create', path=f'/resumed-{number}', data_hex=b'resumed'.hex())])
                        s.checkpoint()
                    target.finish()
                with direct_target(root, device) as target:
                    with opened(target.chain, target) as s:
                        assert s.read('/ack') == b'device acknowledged'
                        assert s.read(f'/resumed-{number}') == b'resumed'
                        if stage == 'record': absent(s, candidate)
                        else: assert s.read(candidate) == bytes([number+1])*MiB
                    target.finish()
                checked(backing)
                assert (root/'chain/image.img').stat().st_blocks == 0
                rows.append(dict(stage=stage, number=number, path=candidate, committed=stage!='record',
                                 bytes_filled=hits[0], error=failure))
                print('PASS actual off-device recovery-log exhaustion', stage, flush=True)
    finally:
        model.command(['hdiutil', 'detach', device] if sys.platform == 'darwin' else ['losetup', '--detach', device])
    return rows


def memory_worker(request):
    cfg = json.loads(request.read_text()); root = Path(cfg['root'])
    # RLIMIT_AS is not implemented reliably by Darwin. Linux gives a hard,
    # process-local bound without putting the machine under global pressure.
    with opened(root) as s:
        ops = [dict(kind='create', path='/candidate', data_hex=(b'M'*(2*MiB)).hex())]
        resource.setrlimit(resource.RLIMIT_AS, (cfg['limit'], cfg['limit']))
        held = []; failure = None; hits = []; allocated = 0
        def exhaust():
            nonlocal allocated
            hits.append(True)
            try:
                while True:
                    chunk = bytearray(64*1024)
                    # Touch each page so retained allocations consume resident memory.
                    chunk[::4096] = b'M'*16
                    held.append(chunk); allocated += len(chunk)
            except MemoryError: pass
        original = inplace.boundary
        def boundary(name):
            original(name)
            if name == cfg['stage'] and not hits: exhaust()
        if cfg['stage'] == 'before-request': exhaust()
        try:
            with patch.object(inplace, 'boundary', boundary): s.applyat(ops)
        except (MemoryError, OSError, ValueError) as e:
            failure = type(e).__name__
        finally: held.clear()
        assert hits and failure and allocated > 8*MiB, ('memory budget did not reject transaction', cfg, allocated, hits, failure)
        failed_closed = s._failed
        if cfg['stage'] != 'before-request':
            assert failed_closed, 'memory-starved replay did not fail closed'
            try: s.read('/ack')
            except OSError as e: assert e.errno == errno.EIO
            else: raise AssertionError('memory-failed session served a stale reader')
    request.with_suffix('.result').write_text(json.dumps(dict(limit=cfg['limit'], stage=cfg['stage'],
                                               failure=failure, failed_closed=failed_closed, resident_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                                               touched_bytes=allocated)))



if a.memory_worker:
    memory_worker(a.memory_worker); raise SystemExit(0)


def memory(base):
    if sys.platform != 'linux':
        return dict(result='not-run', reason='Darwin does not reliably enforce RLIMIT_AS; Linux CI is required')
    source = base/'memory-seed.img'; seed(source)
    rows = []
    # The verifier introduces a service thread. glibc otherwise reserves a
    # mostly empty 64 MiB arena per thread, exhausting RLIMIT_AS without
    # touching memory. Cap arenas in the worker process so these same hard
    # 96/128 MiB limits still exercise actual retained allocations and replay.
    for limit in (96*MiB, 128*MiB):
        for stage in ('before-request', 'prepared', 'applied'):
            root = base/f'memory-{limit}-{stage}'; fresh(source, root)
            request = base/f'memory-{limit}-{stage}.json'
            request.write_text(json.dumps(dict(root=str(root), limit=limit, stage=stage)))
            result = subprocess.run([sys.executable, __file__, '--work', str(a.work), '--memory-worker', str(request)],
                                    capture_output=True, timeout=120,
                                    env=dict(os.environ,MALLOC_ARENA_MAX='1'))
            assert result.returncode == 0, (result.returncode, result.stderr)
            expected = {'/ack': b'previously acknowledged', '/resumed': b'resumed'}
            with opened(root) as s:
                verify(s, {'/ack': b'previously acknowledged'})
                if stage == 'before-request': absent(s, '/candidate')
                else:
                    assert read_all(s, '/candidate', 2*MiB) == b'M'*(2*MiB)
                    expected['/candidate'] = b'M'*(2*MiB)
                s.applyat([dict(kind='create', path='/resumed', data_hex=b'resumed'.hex())]); s.checkpoint()
            finish(root, expected)
            rows.append(json.loads(request.with_suffix('.result').read_text()))
            print('PASS actual memory exhaustion', limit, stage, flush=True)
    return dict(result='passed', cases=rows, scope='process-local hard address-space limit, not system-wide swapping')


base = Path(tempfile.mkdtemp(prefix='resource-exhaustion-', dir=a.work)).resolve()
report = dict(result='running', diagnostics=str(base), platform=sys.platform)
try:
    if a.phase in ('all', 'volume'): report['volume'] = volume(base, 1024)+volume(base, 4096)
    if a.phase in ('all', 'log'): report['log'] = logs(base)
    if a.phase in ('all', 'direct-log'): report['direct_log'] = direct_logs(base)
    if a.phase in ('all', 'memory'): report['memory'] = memory(base)
    report['result'] = 'passed'
except BaseException as e:
    report['result'] = 'failed'; report['error'] = type(e).__name__+': '+str(e)
    raise
finally:
    (a.work/('resource-exhaustion-results.json' if a.phase == 'all' else f'resource-exhaustion-{a.phase}-results.json')).write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, sort_keys=True), flush=True)
