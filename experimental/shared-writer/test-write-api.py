#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Caller-data mutations, independent file models, atomic rejection and recovery."""
import argparse
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
parser.add_argument('--extra-only', action='store_true')
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows = 0, []


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv, expected=0, env=None):
    global checks
    result = subprocess.run(list(map(str, argv)), env=env, capture_output=True, text=True, timeout=60)
    assert (result.returncode == expected) if expected is not None else result.returncode != 0, result.stdout + result.stderr
    checks += 1
    return result


def chain(action, session):
    return command(['python3', here / 'chain.py', action, session])


def apply(session, operations, crash=None, failure=None, ok=True):
    request = session / 'batch.json'
    request.write_text(json.dumps(operations))
    env = dict(os.environ)
    if crash: env['EXT4_TEST_CRASH'] = crash
    if failure is not None: env['EXT4_TEST_MUTATION_FAIL_WRITES'] = str(failure)
    result = command(['python3', here / 'write-api.py', session, args.work / 'mutation-producer', request],
                     expected=(77 if crash else 0) if ok else None, env=env)
    request.unlink()
    return result


def verify(session, path, model):
    expected = session / 'expected'
    expected.write_bytes(model)
    command([args.work / 'verify-reader', session / 'image.img', path, expected])
    extracted = session / 'extracted'
    command(['debugfs', '-R', f'dump {path} {extracted}', session / 'image.img'])
    assert extracted.read_bytes() == bytes(model)
    expected.unlink(); extracted.unlink()
    command(['e2fsck', '-f', '-n', session / 'image.img'])


def write(path, offset, data):
    return {'kind': 'write', 'path': path, 'offset': offset, 'data_hex': bytes(data).hex()}


def model_write(model, offset, data):
    if not data: return
    if offset + len(data) > len(model): model.extend(b'\0' * (offset + len(data) - len(model)))
    model[offset:offset + len(data)] = data


with tempfile.TemporaryDirectory(prefix='write-api-', dir=args.work) as root:
    root = Path(root)
    for source in ([] if args.extra_only else sorted(fixtures.glob('*-csum*.img'))):
        if '-output' in source.name: continue
        original = sha(source)
        seeded = root / (source.stem + '-seed.img')
        shutil.copyfile(source, seeded)
        command(['debugfs', '-w', '-R', 'mkdir /directory', seeded])
        command(['debugfs', '-w', '-R', 'symlink /symlink existing-file', seeded])
        command(['debugfs', '-w', '-R', 'symlink /dir-link directory', seeded])
        assert 'symlink' in command(['debugfs', '-R', 'stat /symlink', seeded]).stdout
        assert 'symlink' in command(['debugfs', '-R', 'stat /dir-link', seeded]).stdout
        command(['e2fsck', '-f', '-n', seeded])
        session = root / source.stem
        command(['python3', here / 'chain.py', 'init', seeded, session, args.work / 'prototype'])
        model = bytearray((i * 19 + 13) & 255 for i in range(32768))
        path = '/existing-file'
        overwrite = bytes((i * 7 + 3) & 255 for i in range(137))
        apply(session, [write(path, 103, overwrite)])
        model_write(model, 103, overwrite); verify(session, path, model)
        tail = bytes((i * 71 + 9) & 255 for i in range(20000))
        apply(session, [write(path, len(model), tail)])
        model_write(model, len(model), tail); verify(session, path, model)
        sparse = b'caller bytes\x00with a sparse gap'
        apply(session, [write(path, len(model) + 8195, sparse)])
        model_write(model, len(model) + 8195, sparse); verify(session, path, model)
        apply(session, [{'kind': 'truncate', 'path': path, 'size': 73}])
        del model[73:]; verify(session, path, model)
        apply(session, [{'kind': 'truncate', 'path': path, 'size': 9000}])
        model.extend(b'\0' * (9000-len(model))); verify(session, path, model)
        apply(session, [write(path, 9000, b''), write(path, 81, b'after truncate')])
        model_write(model, 81, b'after truncate'); verify(session, path, model)
        created = b'new file\0\xffcaller content'
        apply(session, [{'kind':'create', 'path':'/directory/new-file', 'mode':0o640, 'uid':70000, 'gid':80000, 'data_hex':created.hex()}])
        verify(session, '/directory/new-file', created)
        stats = command(['debugfs', '-R', 'stat /directory/new-file', session / 'image.img']).stdout
        assert '70000' in stats and '80000' in stats and '0640' in stats
        apply(session, [{'kind':'create', 'path':'/empty', 'mode':0o600}])
        verify(session, '/empty', b'')
        # Entire batches are discarded even if a previous operation staged data.
        bad = [write('/missing',0,b'x'), write('/symlink',0,b'x'), write('/dir-link/new',0,b'x'),
               write('/directory',0,b'x'), write('/directory/../existing-file',0,b'x'),
               write('//existing-file',0,b'x'), {'kind':'truncate','path':path,'size':-1},
               write(path,2**64-1,b'x'), {'kind':'create','path':'/empty'}, {'kind':'unknown','path':path}]
        for operation in bad:
            before = sha(session / 'image.img')
            head = json.loads((session / 'chain-state').read_text())['head']
            apply(session, [write(path, 0, b'atomic prefix'), operation], ok=False)
            assert sha(session / 'image.img') == before
            chain('recover', session)
            assert json.loads((session / 'chain-state').read_text())['head'] == head
        for failure in (0,1,3):
            before = sha(session / 'image.img')
            apply(session, [write(path,0,b'x'*8192)], failure=failure, ok=False)
            chain('recover', session)
            assert sha(session / 'image.img') == before
        verify(session, path, model)
        # Sealed operations survive a torn first-page commit and checkpoint GC.
        data = bytes((i * 43 + 1) & 255 for i in range(6000))
        apply(session, [write(path, 500, data), {'kind':'create','path':'/recovered','data_hex':'00ff'}], crash='half:0:0')
        chain('recover', session); chain('recover', session)
        model_write(model, 500, data)
        verify(session, path, model); verify(session, '/recovered', b'\0\xff')
        chain('checkpoint', session)
        assert not list(session.glob('g-*')) and not list(session.glob('aborted-*'))
        apply(session, [write(path, 19, b'after checkpoint')])
        model_write(model, 19, b'after checkpoint'); verify(session, path, model)
        assert sha(source) == original
        rows.append({'fixture':source.stem,'caller_data_verified':True,'sparse_and_truncate_zeroes':True,
                     'creation_metadata_verified':True,'failed_batch_atomic':True,'torn_write_recovered':True,'source_unchanged':True})
        print('PASS write API',source.stem,flush=True)
    assert args.extra_only or len(rows)==12
    # Flag enforcement is tested on classic mappings so setting flags does not
    # accidentally clear an extents-layout bit in the test fixture.
    source = fixtures / '1024-classic-csum0.img'
    for name, flag in (('immutable', '0x10'), ('append-only', '0x20')):
        seeded = root / (name + '.img'); shutil.copyfile(source, seeded)
        command(['debugfs', '-w', '-R', 'set_inode_field /existing-file flags ' + flag, seeded])
        session = root / name
        command(['python3', here / 'chain.py', 'init', seeded, session, args.work / 'prototype'])
        before = sha(session / 'image.img')
        apply(session, [write('/existing-file', 0, b'forbidden')], ok=False)
        chain('recover', session)
        apply(session, [{'kind':'truncate','path':'/existing-file','size':2}], ok=False)
        chain('recover', session)
        assert sha(session / 'image.img') == before
        if name == 'append-only':
            apply(session, [write('/existing-file',32768,b'allowed append')])
            verify(session, '/existing-file', bytes((i*19+13)&255 for i in range(32768)) + b'allowed append')
    seeded = root / 'metadata.img'
    shutil.copyfile(fixtures / '1024-classic-csum1.img', seeded)
    command(['debugfs','-w','-R','ea_set /existing-file user.note preserve-me',seeded])
    assert 'preserve-me' in command(['debugfs','-R','ea_get /existing-file user.note',seeded]).stdout
    session = root / 'metadata'
    command(['python3',here/'chain.py','init',seeded,session,args.work/'prototype'])
    apply(session,[write('/existing-file',4,b'preserve metadata')])
    assert 'preserve-me' in command(['debugfs','-R','ea_get /existing-file user.note',session/'image.img']).stdout
    command(['e2fsck','-f','-n',session/'image.img'])
    # Malformed transport frames cannot emit any successful overlay stream.
    import struct
    for name, frame in (('short', b'E4REQ001'), ('count', b'E4REQ001'+struct.pack('<I',65)),
                        ('trailing', b'E4REQ001'+struct.pack('<I',1)+struct.pack('<IIIIIIQQ',1,14,0,0,0,0,0,0)+b'/existing-file'+b'extra'),
                        ('nul', b'E4REQ001'+struct.pack('<I',1)+struct.pack('<IIIIIIQQ',1,3,0,0,0,0,0,0)+b'/a\0')):
        request = root / (name+'-request'); request.write_bytes(frame)
        env = dict(os.environ, EXT4_MUTATION_REQUEST=str(request))
        result = command([args.work/'mutation-producer',source,'--stream'],expected=None,env=env)
        assert not result.stdout

report={'checks':checks,'result':'passed','configurations':rows,'scope':'bounded offline regular-file mutation batches on managed disposable images'}
(args.work/('write-api-extra-results.json' if args.extra_only else 'write-api-results.json')).write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'write API checks')
