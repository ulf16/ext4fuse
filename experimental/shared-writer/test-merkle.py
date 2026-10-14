#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Incremental integrity, legacy migration and every Merkle durability boundary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import struct
import sys
import tempfile
from unittest.mock import patch

import chain
import inplace
import merkle

checks = 0

def check(value, message='check failed'):
    global checks
    assert value, message
    checks += 1


def denied(call):
    try:
        call()
    except (ValueError, OSError):
        check(True)
    else:
        raise AssertionError('unsafe input accepted')


def full(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def activate(root):
    with chain.locked(root):
        return merkle.activate(root, chain.recover_locked(root))


def mutate(root, producer, cache):
    with chain.locked(root):
        state = chain.recover_locked(root, cache)
        state['pending'] = state['head'] + 1
        inplace.seal(root, 'chain-state', state)
        generation = root / f"g-{state['pending']:08d}"
        generation.mkdir(mode=0o700)
        inplace.directory(root)
        inplace.capture_overlay(root / 'image.img', generation, producer,
                                expected_base=state['sha256'], integrity=cache)
        return chain.recover_locked(root, cache)


p = argparse.ArgumentParser()
p.add_argument('--work', type=Path, required=True)
a = p.parse_args()
a.work.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='merkle-', dir=a.work) as temporary:
    tmp = Path(temporary)
    source = tmp / 'source.img'
    # Non-power-of-two leaf count and a partial final chunk. The contents are
    # arbitrary here: integrity replay itself does not parse the filesystem.
    source.write_bytes(random.Random(741).randbytes(4 * merkle.CHUNK + 3 * merkle.PAGE))
    pristine = full(source)
    producer = tmp / 'producer'
    producer.write_text('#!/usr/bin/env python3\nimport sys,struct\nf=open(sys.argv[1],"rb");f.seek(0,2);size=f.tell()\nindices=[0,255,256,size//4096-1]\nsys.stdout.buffer.write(struct.pack("<8sQQ",b"E4OVL001",size,len(indices)))\nfor i in indices:\n f.seek(i*4096);old=f.read(4096);new=bytes(v^0xa5 for v in old);sys.stdout.buffer.write(struct.pack("<Q4096s4096s",i,old,new))\n')
    producer.chmod(0o700)
    root = tmp / 'live'
    original = chain.clone(source, root)
    state, cache = activate(root)
    check(original['version'] == 1 and state['version'] == 2)
    check(full(root / 'image.img') == pristine)
    for n in range(5):
        state = mutate(root, producer, cache)
        check(state['head'] == n + 1 and cache.root() == state['sha256'])
        with merkle.regular(root / 'image.img') as image:
            rebuilt = merkle.scan(image, state)
        check(rebuilt.root() == cache.root())
        check(chain.recover(root) == state)
    check(chain.checkpoint(root) == state)
    check(not list(root.glob('g-*')))
    # Both administrative APIs still work after a Session migrates its state.
    state = chain.append(root, producer)
    check(state['head'] == 6 and state['version'] == 2)
    check(chain.recover(root) == state)
    # Stale live cache rejects a change to a untouched bytes before intent (even if mtime is restored).
    state, cache = activate(root)
    image_path = root / 'image.img'
    with image_path.open('r+b') as f:
        f.seek(merkle.CHUNK + merkle.PAGE);old=f.read(1)
        f.seek(merkle.CHUNK + merkle.PAGE);f.write(bytes([old[0]^1]));f.flush();os.fsync(f.fileno())
    os.utime(image_path, ns=(os.stat(image_path).st_atime_ns, cache.stamp[3]))
    changed = full(image_path)
    denied(lambda: mutate(root, producer, cache))
    check(chain.read_state(root)['pending'] is None and full(image_path) == changed)
    denied(lambda: chain.recover(root))
    denied(lambda: chain.checkpoint(root))
    # A full scan detects clean corruption even if metadata detection is bypassed
    # in this test, modeling latent media corruption with no timestamp change.
    cache.stamp = merkle.fingerprint(os.stat(image_path))
    denied(lambda: mutate(root, producer, cache)) # changed chunk is touched
    check(full(image_path) == changed)

    clean_root = tmp / 'silent-clean'
    chain.clone(source, clean_root); clean_state, clean_cache = activate(clean_root)
    with (clean_root/'image.img').open('r+b') as f:
        f.seek(2*merkle.CHUNK);f.write(b'silent clean corruption')
    clean_cache.stamp = merkle.fingerprint(os.stat(clean_root/'image.img'))
    # Warm checks intentionally cannot detect simulated silent corruption in a
    # chunk they never read. Neither a checkpoint nor cold recovery accepts it.
    mutate(clean_root, producer, clean_cache)
    denied(lambda: chain.checkpoint(clean_root))
    denied(lambda: chain.recover(clean_root))

    boundaries = ['chain-state:pending', 'chain-state:renamed', 'record', 'snapshot',
                  'undo-log', 'transaction:pending', 'transaction:renamed', 'prepared',
                  'validated', 'started:pending', 'started:renamed', 'started',
                  'half:0:0', 'half:0:1', 'page:0', 'half:3:0', 'page:3',
                  'applied', 'synced', 'complete:pending', 'complete:renamed',
                  'complete', 'head-ready', 'head-published']
    driver = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
              'import chain,merkle,inplace;'
              'r=Path(sys.argv[2]);p=Path(sys.argv[3]);'
              '\nwith chain.locked(r):\n'
              ' s=chain.recover_locked(r);s,t=merkle.activate(r,s);'
              's["pending"]=s["head"]+1;inplace.seal(r,"chain-state",s);'
              'g=r/"g-00000001";g.mkdir(mode=0o700);inplace.directory(r);'
              'inplace.capture_overlay(r/"image.img",g,p,expected_base=s["sha256"],integrity=t);'
              'chain.recover_locked(r,t)')
    expected = bytearray(source.read_bytes())
    for index in (0, 255, 256, len(expected)//4096-1):
        start = index * 4096
        expected[start:start+4096] = bytes(v^0xa5 for v in expected[start:start+4096])
    expected_hash = hashlib.sha256(expected).hexdigest()
    for n, point in enumerate(boundaries):
        r = tmp / f'crash-{n}'
        chain.clone(source, r); activate(r)
        env = dict(os.environ, EXT4_TEST_CRASH=point)
        proc = subprocess.run([sys.executable,'-c',driver,str(Path(__file__).parent),str(r),str(producer)],env=env,capture_output=True)
        check(proc.returncode == 77, (point, proc.stderr.decode()))
        sealed = (r/'g-00000001/transaction').exists()
        recovered = chain.recover(r)
        check(recovered['pending'] is None)
        check(full(r/'image.img') == (expected_hash if sealed else pristine))
        check(chain.recover(r) == recovered)
        check(chain.checkpoint(r) == recovered)
        # Checkpoint fallback uses the Merkle algorithm and rejects clean edits.
        (r/'chain-state').unlink()
        check(chain.recover(r) == recovered)
        print('PASS Merkle crash', point, flush=True)

    # Construct a sealed, partly replayed transaction for corruption cases.
    r = tmp / 'torn'
    chain.clone(source, r); activate(r)
    proc = subprocess.run([sys.executable,'-c',driver,str(Path(__file__).parent),str(r),str(producer)],env=dict(os.environ,EXT4_TEST_CRASH='half:0:0'),capture_output=True)
    check(proc.returncode == 77)
    for case in ('clean', 'old', 'new', 'order', 'log-hash', 'root', 'algorithm', 'marker', 'identity', 'log-link', 'manifest-link', 'marker-link'):
        copied = tmp / ('bad-' + case)
        shutil.copytree(r, copied)
        # Copies have different inodes; update only identity so each case tests
        # its intended integrity violation rather than failing at identity first.
        st = os.stat(copied/'image.img')
        state = chain.read_state(copied)
        state.update(device=st.st_dev,inode=st.st_ino)
        inplace.seal(copied,'chain-state',state)
        generation = copied/'g-00000001'
        meta = json.loads((generation/'transaction').read_text())
        meta.update(device=st.st_dev,inode=st.st_ino)
        marker = dict(log_sha256=meta['log_sha256'],inode=st.st_ino)
        inplace.seal(generation,'started',marker)
        if case == 'clean':
            with (copied/'image.img').open('r+b') as f:
                f.seek(merkle.CHUNK+2*4096);f.write(b'corrupt')
        elif case in ('old','new','order','log-hash'):
            data = bytearray((generation/'pages').read_bytes())
            if case == 'order':
                struct.pack_into('<Q', data, 0, 255)
            else:
                data[8 if case=='old' else 4104 if case=='new' else 0] ^= 1
            (generation/'pages').write_bytes(data)
            if case != 'log-hash':
                meta['log_sha256']=full(generation/'pages')
                marker['log_sha256']=meta['log_sha256']
                inplace.seal(generation,'started',marker)
        elif case == 'root':meta['image_sha256']='0'*64
        elif case == 'algorithm':meta['algorithm']='sha256'
        elif case == 'marker':inplace.seal(generation,'started',dict(marker,inode=0))
        elif case == 'identity':meta['inode']+=1
        inplace.seal(generation,'transaction',meta)
        if case in ('log-link', 'manifest-link', 'marker-link'):
            name = {'log-link':'pages', 'manifest-link':'transaction', 'marker-link':'started'}[case]
            os.link(generation/name, tmp/(case+'-alias'))
        before=full(copied/'image.img')
        denied(lambda: chain.recover(copied))
        check(full(copied/'image.img') == before)
    # Empty transactions and one-leaf trees exercise roots with no ancestors.
    noop = tmp / 'noop'
    noop.write_text('#!/usr/bin/env python3\nimport os,sys,struct\nsys.stdout.buffer.write(struct.pack("<8sQQ",b"E4OVL001",os.stat(sys.argv[1]).st_size,0))\n')
    noop.chmod(0o700)
    for size in (4096, merkle.CHUNK, merkle.CHUNK+4096, 2*merkle.CHUNK):
        small = tmp / f'small-{size}.img'
        small.write_bytes(bytes(size))
        r = tmp / f'edge-{size}'
        chain.clone(small, r); state, cache = activate(r)
        saved = cache.root()
        next_state = mutate(r, noop, cache)
        check(next_state['head'] == 1 and cache.root() == saved)
        check(chain.recover(r) == next_state)
        with (r/'image.img').open('r+b') as f:
            f.seek(size-1);f.write(b'x')
        with merkle.regular(r/'image.img') as image:
            rebuilt = merkle.scan(image, next_state)
            index = (size-1)//merkle.CHUNK
            image.seek(index*merkle.CHUNK)
            changes = cache.updates({index:merkle.leaf(index,image.read(merkle.CHUNK))})
        check(cache.root(changes) == rebuilt.root())
        check(cache.root() == saved) # preview must not mutate the trusted tree
        cache.commit(changes)
        check(cache.root() == rebuilt.root())
    # Cache allocation and format errors fail before a huge allocation.
    denied(lambda: merkle.Tree(0))
    denied(lambda: merkle.Tree(4097))
    denied(lambda: merkle.Tree(8*1024**4))
    check(full(source) == pristine)
(a.work/'merkle-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n')
print('PASS',checks,'Merkle integrity checks',flush=True)
