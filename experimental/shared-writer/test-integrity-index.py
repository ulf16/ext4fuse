#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Persistent root authentication, publication crashes, bounded loading and native reuse."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import chain
import integrity_index as index
import merkle
import merkle_store
from durable import regular
from verified_reads import Reader

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--devices', action='store_true')
a = p.parse_args()
base = Path(tempfile.mkdtemp(prefix='persistent-index-', dir=a.work))
checks = 0


def check(value):
    global checks
    assert value
    checks += 1


def denied(call):
    try:
        call()
    except (ValueError, OSError):
        check(True)
    else:
        raise AssertionError('corruption accepted')


def command(argv):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=180)
    check(result.returncode == 0)
    return result.stdout


source = base/'source.img'
source.write_bytes(bytes(3*merkle.CHUNK + 4096))
root = base/'chain'
chain.clone(source, root)
with chain.locked(root):
    state, tree = merkle.activate(root, chain.read_state(root))
    check(index.load(root, state) is None)
    check(index.save(root, state, tree))
    saved = (root/index.NAME).read_bytes()
    restored = index.load(root, state)
    check(restored.root() == tree.root())
    check(all(restored.get(i) == tree.get(i) for i in range(1, tree.width*2)))
    restored.close()
    check(len(saved) == index.HEADER + tree.count*32)
    # The authoritative state, not a root supplied by the sidecar, grants trust.
    for bad in (b'', saved[:100], saved[:-1], saved+b'X',
                saved[:index.HEADER]+bytes([saved[index.HEADER]^1])+saved[index.HEADER+1:],
                b'[]'.ljust(index.HEADER,b'\0')+saved[index.HEADER:]):
        (root/index.NAME).write_bytes(bad)
        check(index.load(root, state) is None)
    (root/index.NAME).write_bytes(saved)
    check(index.load(root, dict(state,head=state['head']+1)) is None)
    check(index.load(root, dict(state,pending=state['head']+1)) is None)
    (root/index.NAME).chmod(0o644)
    check(index.load(root,state) is None)
    (root/index.NAME).chmod(0o600)
    hard = root/'hard-index'
    os.link(root/index.NAME,hard)
    check(index.load(root,state) is None)
    hard.unlink()
    (root/index.NAME).unlink()
    os.symlink(source,root/index.NAME)
    check(index.load(root,state) is None)
    (root/index.NAME).unlink()
    check(index.save(root,state,tree))
    # ENOSPC leaves the last complete snapshot available, never a partial file.
    with patch.object(index,'sync',side_effect=OSError(28,'test index exhaustion')):
        check(not index.save(root,state,tree))
    check((root/index.NAME).read_bytes()==saved)
    check(not list(root.glob('.integrity-index-*')))
    # Out-of-band content changes invalidate the normal file fingerprint.
    with (root/'image.img').open('r+b') as f:
        f.seek(merkle.CHUNK);f.write(b'changed')
    check(index.load(root,state) is None)
    # Simulate invisible media corruption: the trusted leaf, not the fingerprint,
    # must still reject changed bytes after a fast mount.
    with patch.object(merkle,'fingerprint',return_value=tree.stamp):
        restored=index.load(root,state)
        check(restored is not None)
        verifier=Reader(root/'image.img',lambda:(state,restored))
        try:denied(lambda:verifier.read(merkle.CHUNK,7))
        finally:verifier.close();restored.close()
    denied(lambda:chain.recover(root))

# A complete index is usable only after atomic rename. Real process termination
# exercises every index publication boundary against both absent and stale files.
crashes=[]
worker = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
          'import chain,merkle,integrity_index;'
          '\nwith chain.locked(Path(sys.argv[2])) as root:\n'
          ' state=chain.read_state(root);state,tree=merkle.activate(root,state);'
          'integrity_index.save(root,state,tree)')
for previous in (False,True):
    for point in ('index:written','index:synced','index:renamed','index:published'):
        target=base/f'crash-{previous}-{point.replace(":","-")}'
        chain.clone(source,target)
        with chain.locked(target):
            current,cache=merkle.activate(target,chain.read_state(target))
            if previous:
                check(index.save(target,current,cache))
                current=dict(current,head=1)
                import inplace
                inplace.seal(target,'chain-state',current)
        child=subprocess.run([sys.executable,'-c',worker,str(Path(__file__).parent),str(target)],
            env=dict(os.environ,EXT4_TEST_CRASH=point),capture_output=True,timeout=60)
        check(child.returncode==77)
        loaded=index.load(target,current)
        check((loaded is not None)==(point in ('index:renamed','index:published')))
        if loaded:loaded.close()
        check(chain.recover(target)==current)
        crashes.append(dict(previous=previous,point=point))

# Bounded loading into paged authenticated scratch, with no volume reads. This
# constructs synthetic leaves over a sparse 128 GiB identity, not a disk audit.
large=base/'large';large.mkdir(mode=0o700)
with (large/'image.img').open('xb') as f:f.truncate(128*1024**3)
info=os.stat(large/'image.img')
with patch.object(merkle,'MAX_CACHE',4*merkle_store.PAGE):
    tree=merkle.Tree(info.st_size)
    for i in range(tree.count):tree.set(tree.width+i,hashlib.sha256(str(i).encode()).digest())
    tree.finish();tree.stamp=merkle.fingerprint(info)
    state=dict(version=2,algorithm=merkle.ALGORITHM,head=0,pending=None,
        device=info.st_dev,inode=info.st_ino,size=info.st_size,sha256=tree.root())
    check(index.save(large,state,tree))
    loaded=index.load(large,state)
    check(isinstance(loaded.nodes,merkle_store.Nodes))
    check(loaded.root()==tree.root())
    check(len(loaded.nodes.pages)<=4)
    tree.close();loaded.close()

# Actual native reader/producer: fast reopen, writes, persisted successor root,
# and fallback after index corruption. Administrative APIs retain full scans.
import session
from credentials import Credentials
fixture=a.work/'fixtures/4096-extents-csum1.img'
native=base/'native';chain.clone(fixture,native)
options=dict(persistent_index=True)
with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
    s.applyat([dict(kind='create',path='/indexed',data_hex=b'first'.hex())])
with patch.object(merkle,'scan',side_effect=AssertionError('fast reopen read whole image')):
    with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
        check(s.read('/indexed')==b'first')
        s.applyat([dict(kind='write',path='/indexed',offset=0,data_hex=b'next!'.hex())])
        s.checkpoint()
with patch.object(merkle,'scan',side_effect=AssertionError('successor index missing')):
    with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
        check(s.read('/indexed')==b'next!')
# Missing chain-state still uses established checkpoint restoration, not a cache.
(native/'chain-state').unlink()
with patch.object(merkle,'scan',wraps=merkle.scan) as scans:
    with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
        check(s.read('/indexed')==b'next!')
    check(scans.call_count==1)
with (native/index.NAME).open('r+b') as f:f.seek(index.HEADER);f.write(b'X'*32)
with patch.object(merkle,'scan',wraps=merkle.scan) as scans:
    with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
        check(s.read('/indexed')==b'next!')
    check(scans.call_count==1)
# A pending torn transaction cannot use the old snapshot even if it exists.
crash_worker=('import sys,os;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
    'import session;from credentials import Credentials;'
    '\nwith session.Session(Path(sys.argv[2]),Path(sys.argv[3])/"mutation-producer",Path(sys.argv[3])/"reader-server",Credentials(0,0),persistent_index=True) as s:\n'
    ' os.environ["EXT4_TEST_CRASH"]="half:0:0";s.applyat([dict(kind="write",path="/indexed",offset=0,data_hex=b"replay".hex())])')
child=subprocess.run([sys.executable,'-c',crash_worker,str(Path(__file__).parent),str(native),str(a.work)],capture_output=True,timeout=120)
check(child.returncode==77)
with patch.object(merkle,'plan',wraps=merkle.plan) as plans:
    with session.Session(native,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**options) as s:
        check(s.read('/indexed')==b'replay')
    check(any(call.args[-1] is True for call in plans.call_args_list if len(call.args)>5))
command(['e2fsck','-fn',native/'image.img'])

device_result=None
if a.devices:
    import direct_device as direct
    import live_device
    backing=base/'device.img';shutil.copyfile(fixture,backing)
    if sys.platform=='darwin':
        data=plistlib.loads(command(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',backing]))
        device=min((e['dev-entry'] for e in data['system-entities'] if 'dev-entry' in e),key=len)
    else:
        device=command(['losetup','--find','--show',backing]).decode().strip()
        if shutil.which('udevadm'):command(['udevadm','settle','--timeout=15'])
    def admit(call):
        deadline=time.monotonic()+15
        while True:
            try:return call()
            except OSError as e:
                if sys.platform!='linux' or e.errno not in (11,16) or time.monotonic()>=deadline:raise
                time.sleep(.2)
    device_root=base/'direct'
    try:
        admit(lambda:direct.init(device,device_root,a.work))
        # First use establishes the snapshot; second use must not scan on either
        # admission or close. Metadata checks and direct identity checks remain.
        for iteration in range(2):
            scans=[]
            scan_image=merkle.scan;scan_device=live_device.scan
            def image_scan(*args,**kw):scans.append('image');return scan_image(*args,**kw)
            def device_scan(*args,**kw):scans.append('device');return scan_device(*args,**kw)
            with patch.object(merkle,'scan',image_scan),patch.object(live_device,'scan',device_scan):
                target=admit(lambda:direct.Controller(device_root,device,a.work,persistent_index=True).__enter__())
                try:
                    with session.Session(target.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=target,persistent_index=True) as s:
                        s.applyat([dict(kind='create',path=f'/indexed-{iteration}',data_hex=b'USB'.hex())])
                    startup=len(scans);target.finish()
                    check(len(scans)==startup)
                    check(startup==(1 if iteration==0 else 0))
                    device_result=dict(reopen_full_scans=startup,close_full_scans=len(scans)-startup)
                finally:target.__exit__()
        # A physical token fingerprint does not change when raw media changes.
        # The persistent snapshot must still detect corruption on a native read.
        mapped=command(['debugfs','-R','bmap /indexed-1 0',backing]).strip().splitlines()[-1]
        offset=int(mapped)*4096
        from live_device import offline
        target=admit(lambda:direct.Controller(device_root,device,a.work,persistent_index=True).__enter__())
        try:
            with session.Session(target.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=target,persistent_index=True) as s:
                stamp=merkle.fingerprint(os.stat(target.chain/'image.img'))
                old=offline.read_at(target.target.fd,target.target.sector,offset)
                damaged=bytes([old[0]^1])+old[1:]
                offline.write_at(target.target.fd,damaged,offset);target.target.flush()
                check(merkle.fingerprint(os.stat(target.chain/'image.img'))==stamp)
                s._verified.cache.clear()
                try:denied(lambda:s.read('/indexed-1'))
                finally:
                    offline.write_at(target.target.fd,old,offset);target.target.flush()
                check(s._failed or s._verified.failed.is_set())
            denied(target.finish)
        finally:target.__exit__()
        # Restore only this disposable test sector, then exercise cold recovery.
        with direct.Controller(device_root,device,a.work) as target:
            with session.Session(target.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=target) as s:
                check(s.read('/indexed-1')==b'USB')
            target.finish()
        command(['e2fsck','-fn',backing])
        check(command(['debugfs','-R','cat /indexed-1',backing])==b'USB')
    finally:
        command(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])

result=dict(result='passed',checks=checks,publication_crashes=crashes,device=device_result,
            paged_geometry_bytes=128*1024**3,diagnostics=str(base))
(a.work/'integrity-index-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
