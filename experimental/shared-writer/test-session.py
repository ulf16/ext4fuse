#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Resident reader coordination, competing requests and fail-closed recovery."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from unittest.mock import patch
import session

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--fixtures', type=Path)
parser.add_argument('--extra-only', action='store_true')
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows, extras = 0, [], []


def check(condition, detail='check failed'):
    global checks
    assert condition, detail
    checks += 1


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def command(argv, code=0, env=None):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60, env=env)
    check(result.returncode == code, result.stdout + result.stderr)
    return result


def denied(function, error=None):
    try:
        function()
    except Exception as e:
        check(error is None or getattr(e, 'errno', None) == error, repr(e))
    else:
        raise AssertionError('operation unexpectedly accepted')


def write(offset, data, path='/existing-file'):
    return dict(kind='write', path=path, offset=offset, data_hex=data.hex())


def verify(s, model):
    check(s.size('/existing-file') == len(model), 'stale size')
    check(s.read('/existing-file', 0, len(model)) == bytes(model), 'stale content')
    check(s.read('/existing-file', len(model) + 5, 17) == b'', 'EOF read')
    check(s.read('/existing-file', 0, 0) == b'', 'empty read')
    result = command(['debugfs', '-R', 'stats', s.root / 'image.img']).stdout.decode()
    expected = tuple(int(re.search(r'Free ' + name + r':\s+(\d+)', result).group(1)) for name in ('blocks', 'inodes'))
    check(s.counters() == expected, 'stale allocation counters')
    dump = s.root / 'session-dump'
    command(['debugfs', '-R', f'dump /existing-file {dump}', s.root / 'image.img'])
    check(dump.read_bytes() == bytes(model), 'debugfs content mismatch')
    dump.unlink()
    command(['e2fsck', '-fn', s.root / 'image.img'])


with tempfile.TemporaryDirectory(prefix='session-test-', dir=args.work) as directory:
    directory = Path(directory)
    for source in ([] if args.extra_only else sorted(fixtures.glob('*-csum*.img'))):
        if '-output' in source.name: continue
        original = sha(source)
        root = directory / source.stem
        command(['python3', here / 'chain.py', 'init', source, root, args.work / 'prototype'])
        model = bytearray((i * 19 + 13) & 255 for i in range(32768))
        image_inode = (root / 'image.img').stat().st_ino
        with session.Session(root, args.work / 'mutation-producer', args.work / 'reader-server') as s:
            pid = s._process.pid
            verify(s, model)
            # Session lifetime excludes all other cooperating administrative APIs.
            denied(lambda: session.Session(root, s.producer, args.work / 'reader-server'), errno.EAGAIN)
            denied(lambda: session.write_api.apply(root, s.producer, [write(0, b'competing')]), errno.EAGAIN)
            denied(lambda: session.chain.checkpoint(root), errno.EAGAIN)
            denied(lambda: s.size('/missing'), errno.ENOENT)
            denied(lambda: s.read('/'), errno.EISDIR)
            for path in ('relative', '/a//b', '/a/../b', '/a\0b', '/' + 'x' * 256):
                denied(lambda path=path: s.read(path))
            for offset, length in ((-1, 1), (2**63, 1), (True, 1), (0, session.LIMIT + 1)):
                denied(lambda offset=offset, length=length: s.read('/existing-file', offset, length))
            # Observe the actual native gate before staging and after committing.
            apply_locked = session.write_api.apply_encoded_locked
            entered, release, waiting, finished = (threading.Event() for _ in range(4))
            def guarded(*arguments):
                denied(lambda: s._rpc(2, b'/existing-file', 0, 16), errno.EBUSY)
                denied(lambda: s._rpc(1, b'/existing-file'), errno.EBUSY)
                denied(lambda: s._rpc(5), errno.EBUSY)
                entered.set()
                check(release.wait(10), 'test release timed out')
                result = apply_locked(*arguments)
                denied(lambda: s._rpc(2, b'/existing-file', 0, 16), errno.EBUSY)
                return result
            payload = b'arbitrary binary\0\xffdata'
            def concurrent_read():
                waiting.set()
                data = s.read('/existing-file', 111, len(payload))
                finished.set()
                return data
            with patch.object(session.write_api, 'apply_encoded_locked', guarded):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    writer = pool.submit(s.apply, [write(111, payload)])
                    check(entered.wait(10), 'writer did not start')
                    reader = pool.submit(concurrent_read)
                    check(waiting.wait(10), 'read request did not start')
                    check(not finished.wait(.05), 'reader crossed mutation gate')
                    release.set()
                    check(writer.result(timeout=30)['head'] == 1)
                    check(reader.result(timeout=30) == payload)
            model[111:111 + len(payload)] = payload
            verify(s, model)
            s.apply([dict(kind='truncate', path='/existing-file', size=71)])
            del model[71:]
            verify(s, model)
            s.apply([dict(kind='truncate', path='/existing-file', size=12000),
                     dict(kind='create', path='/session-created', data_hex='00ff63616c6c6572')])
            model.extend(b'\0' * (12000 - len(model)))
            check(s.size('/session-created') == 8)
            check(s.read('/session-created') == b'\0\xffcaller')
            verify(s, model)
            # Independent writes from two callers are serialized, with no lost head.
            head = s.state['head']
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(s.apply, [write(81, b'first')])
                second = pool.submit(s.apply, [write(200, b'second')])
                check(sorted([first.result(timeout=30)['head'], second.result(timeout=30)['head']]) == [head + 1, head + 2])
            model[81:86] = b'first'; model[200:206] = b'second'
            verify(s, model)
            before, head = sha(root / 'image.img'), s.state['head']
            denied(lambda: s.apply([write(0, b'atomic prefix'), write(0, b'bad', '/missing')]))
            check(s.state['head'] == head and sha(root / 'image.img') == before)
            verify(s, model)
            with patch.dict(os.environ, {'EXT4_TEST_MUTATION_FAIL_WRITES': '0'}):
                denied(lambda: s.apply([write(0, b'injected')]))
            check(s.state['head'] == head and sha(root / 'image.img') == before)
            verify(s, model)
            check(s._process.pid == pid and s._process.poll() is None, 'resident reader replaced')
            # Leave an unsealed intent and force recovery failure: reads must stay blocked.
            recover = session.chain.recover_locked
            calls = [0]
            def failed_recovery(*arguments):
                calls[0] += 1
                if calls[0] > 1: raise ValueError('injected recovery failure')
                return recover(*arguments)
            with patch.object(session.chain, 'recover_locked', failed_recovery), \
                 patch.object(session.write_api.inplace, 'capture_overlay', side_effect=ValueError('injected producer transport failure')):
                denied(lambda: s.apply([write(0, b'incomplete')]))
            denied(lambda: s.read('/existing-file'), errno.EIO)
            denied(lambda: s.size('/existing-file'), errno.EIO)
            denied(lambda: s.counters(), errno.EIO)
            denied(lambda: s.apply([write(0, b'blocked')]), errno.EIO)
            denied(lambda: s._rpc(2, b'/existing-file', 0, 16), errno.EBUSY)
        check(s._process.poll() == 0, 'reader did not shut down')
        denied(lambda: s.read('/existing-file'), errno.EIO)
        # A new owner recovers the aborted intent before starting its reader.
        with session.Session(root, s.producer, args.work / 'reader-server') as reopened:
            verify(reopened, model)
            check(reopened.state['head'] == head)
        # Torn commit from another process is recovered before serving any new reads.
        request = root / 'session-request.json'
        request.write_text(json.dumps([write(305, b'after restart')]))
        command(['python3', here / 'write-api.py', root, s.producer, request], code=77,
                env=dict(os.environ, EXT4_TEST_CRASH='half:0:0'))
        request.unlink()
        model[305:318] = b'after restart'
        with session.Session(root, s.producer, args.work / 'reader-server') as reopened:
            check(reopened.state['head'] == head + 1)
            verify(reopened, model)
            # Reader death is sticky and does not authorize another write.
            before = sha(root / 'image.img')
            reopened._process.kill(); reopened._process.wait(timeout=5)
            denied(lambda: reopened.read('/existing-file'))
            denied(lambda: reopened.apply([write(0, b'dead-reader')]), errno.EIO)
            check(sha(root / 'image.img') == before)
        command(['python3', here / 'chain.py', 'checkpoint', root])
        check((root / 'image.img').stat().st_ino == image_inode)
        check(sha(source) == original)
        rows.append(dict(fixture=source.stem, resident_reader=True, serialized_requests=True,
                         blocked_during_mutation=True, failed_closed=True, restart_recovered=True, fsck_clean=True))
        print('PASS session', source.stem, flush=True)
    if not args.extra_only:
        check(len(rows) == 12)
    for source in sorted(fixtures.glob('*-csum*.img')):
        if '-output' in source.name: continue
        root = directory / ('extra-' + source.stem)
        original = sha(source)
        command(['python3', here / 'chain.py', 'init', source, root, args.work / 'prototype'])
        model = bytearray((i * 19 + 13) & 255 for i in range(32768))
        # Malformed native frames must terminate without a partial reply.
        frames = [b'short',
                  session.REQUEST.pack(b'badmagic', 1, 1, 0, 0) + b'/',
                  session.REQUEST.pack(b'E4RD0001', 9, 0, 0, 0),
                  session.REQUEST.pack(b'E4RD0001', 2, 1, 0, session.LIMIT + 1) + b'/',
                  session.REQUEST.pack(b'E4RD0001', 1, 4097, 0, 0),
                  session.REQUEST.pack(b'E4RD0001', 1, 2, 0, 0) + b'/\0',
                  session.REQUEST.pack(b'E4RD0001', 1, 2, 0, 0) + b'/',
                  session.REQUEST.pack(b'E4RD0001', 3, 1, 0, 0) + b'/']
        for frame in frames:
            native = subprocess.run([str(args.work / 'reader-server'), str(root / 'image.img')],
                                    input=frame, capture_output=True, timeout=30)
            check(native.returncode == 2 and not native.stdout, native.stderr)
        with session.Session(root, args.work / 'mutation-producer', args.work / 'reader-server') as s:
            rpc = s._rpc
            def failed_refresh(op, *arguments):
                if op == 4:
                    raise OSError(errno.EIO, 'injected refresh failure')
                return rpc(op, *arguments)
            with patch.object(s, '_rpc', failed_refresh):
                denied(lambda: s.apply([write(401, b'refresh committed')]), errno.EIO)
            model[401:418] = b'refresh committed'
            check(s.state['head'] == 1, 'commit not published before refresh failure')
            denied(lambda: s.read('/existing-file'), errno.EIO)
            denied(lambda: rpc(2, b'/existing-file', 0, 16), errno.EBUSY)
        with session.Session(root, s.producer, args.work / 'reader-server') as reopened:
            check(reopened.state['head'] == 1)
            verify(reopened, model)
        check(sha(source) == original)
        extras.append(dict(fixture=source.stem, refresh_failure_closed=True, malformed_frames_rejected=True))
        print('PASS session transport/refresh', source.stem, flush=True)
    check(len(extras) == 12)
report = dict(checks=checks, result='passed', configurations=rows, extra_configurations=extras,
              scope='private offline image session; no mount or permission policy')
(args.work / ('session-extra-results.json' if args.extra_only else 'session-results.json')).write_text(json.dumps(report, indent=2) + '\n')
print('PASS', checks, 'session checks')
