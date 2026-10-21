#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hash paging, >4 TiB node geometry, and measured scan reuse with integrity checks."""
import argparse
import plistlib
import shutil
import time
import direct_device as direct
import live_device
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from unittest.mock import patch
import chain
import durable
import merkle
import merkle_store
from merkle_store import Nodes, PAGE as HASH_PAGE
import session
from credentials import Credentials
import endurance_model as model

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True)
p.add_argument('--devices',action='store_true',help='also verify scan counts on a newly created virtual device (Linux needs root)')
a=p.parse_args(); base=Path(tempfile.mkdtemp(prefix='integrity-scaling-',dir=a.work))
checks=0

def check(value):
    global checks
    assert value
    checks+=1


def refused(call):
    try:call()
    except (ValueError,OSError):check(True)
    else:raise AssertionError('unsafe input accepted')


# Complete independent in-memory and paged trees with the same deterministic
# synthetic leaf digests. No claim that a 128 GiB volume was read is made here.
size=128*1024**3
reference=merkle.Tree(size)
with patch.object(merkle,'MAX_CACHE',4*HASH_PAGE): paged=merkle.Tree(size)
check(isinstance(paged.nodes,Nodes))
for i in range(reference.count):
    digest=hashlib.sha256(b'independent-leaf'+i.to_bytes(8,'little')).digest()
    reference.set(reference.width+i,digest);paged.set(paged.width+i,digest)
reference.finish();paged.finish();check(reference.root()==paged.root())
rng=random.Random(49117)
for iteration in range(20):
    leaves={rng.randrange(reference.count):rng.randbytes(32) for _ in range(17)}
    left=reference.updates(leaves);right=paged.updates(leaves)
    check(left==right and reference.root(left)==paged.root(right))
    reference.commit(left);paged.commit(right)
    check(len(paged.nodes.pages)<=4)
backing=paged.nodes.file;check(backing.seek(0,2)==reference.width*64)
paged.close();check(backing.closed);refused(lambda:paged.get(1))

# Exercise offsets on both sides of the old ceiling, and the last valid node.
# Sparse scratch allocation and four cached pages suffice; this is geometry/
# high-offset coverage, not a full multi-terabyte filesystem qualification.
large=merkle.Tree(8*1024**4)
check(isinstance(large.nodes,Nodes))
for i in (0,4*1024**4//merkle.CHUNK,large.count-1):
    digest=hashlib.sha256(str(i).encode()).digest()
    large.set(large.width+i,digest);check(large.get(large.width+i)==digest)
check(large.nodes.size==512*1024**2)
check(len(large.nodes.pages)*HASH_PAGE<=merkle.MAX_CACHE)
large.close();refused(lambda:merkle.Tree(2**63));refused(lambda:merkle.Tree(4097))

# Cache I/O errors cannot turn a partially flushed page into a trusted node.
nodes=Nodes(8*HASH_PAGE,HASH_PAGE)
nodes.set(1,b'A'*32)
original=os.pwrite
with patch.object(os,'pwrite',side_effect=OSError(28,'test scratch exhausted')):
    refused(lambda:nodes.get(2*HASH_PAGE//32))
check(nodes.get(1)==b'A'*32)
# Short writes must be completed rather than silently dropping hash bytes.
with patch.object(os,'pwrite',side_effect=lambda fd,data,offset:original(fd,data[:113],offset)):
    nodes.set(2*HASH_PAGE//32,b'B'*32)
check(nodes.get(1)==b'A'*32)
nodes.close()

# Persisted temporary pages must be authenticated, including recursively paged
# checksum metadata. Neither data corruption nor corruption of its stored tag
# may turn a trusted cached root into a false future root.
bad=Nodes(8*HASH_PAGE,HASH_PAGE)
bad.set(1,b'A'*32);bad.set(2*HASH_PAGE//32,b'B'*32)
os.pwrite(bad.file.fileno(),b'X',32)
refused(lambda:bad.get(1));bad.close()
recursive=Nodes(512*1024**2,HASH_PAGE)
check(isinstance(recursive.tags,Nodes))
recursive.set(1,b'A'*32)
recursive.set(4096*HASH_PAGE//32,b'B'*32)
recursive.set(4097*HASH_PAGE//32,b'C'*32)
# Page zero's checksum page has now been evicted into its own temporary file.
os.pwrite(recursive.tags.file.fileno(),b'X',0)
refused(lambda:recursive.get(1));recursive.close()

source=a.work/'fixtures/4096-extents-csum1.img'
assert source.exists(), 'prepare run-matrix fixtures first'
root=base/'chain';chain.clone(source,root)
info=os.stat(root/'image.img');identity=(info.st_dev,info.st_ino)
counts={'bytes':0,'verified_bytes':0}
# Keep measuring complete scan I/O separately from the new authenticated
# chunk reads. A native read is now serviced in Python, too.
from contextvars import ContextVar
from verified_reads import Reader
verified_io=ContextVar('verified_io',default=False)
original_verified_read=Reader.read
def measured_verified(self,*args,**kwargs):
    token=verified_io.set(True)
    try:return original_verified_read(self,*args,**kwargs)
    finally:verified_io.reset(token)
class Counted:
    def __init__(self,f):self.f=f
    def __getattr__(self,name):return getattr(self.f,name)
    def __enter__(self):return self
    def __exit__(self,*args):return self.f.__exit__(*args)
    def read(self,*args):
        data=self.f.read(*args);counts['verified_bytes' if verified_io.get() else 'bytes']+=len(data);return data
    def readinto(self,buffer):
        n=self.f.readinto(buffer);counts['verified_bytes' if verified_io.get() else 'bytes']+=n;return n
fdopen=os.fdopen

def measured(*args,**kwargs):
    f=fdopen(*args,**kwargs)
    st=os.fstat(f.fileno())
    return Counted(f) if (st.st_dev,st.st_ino)==identity else f

measurements={}
with patch.object(os,'fdopen',measured),patch.object(Reader,'read',measured_verified):
    with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        measurements['legacy_startup']=counts['bytes'];check(counts['bytes']==info.st_size)
        s.applyat([dict(kind='create',path='/scale',data_hex=b'acknowledged'.hex())])
        counts['bytes']=0;s.checkpoint()
        measurements['warm_checkpoint']=counts['bytes'];check(counts['bytes']==0)
        counts['bytes']=0;s.scrub()
        measurements['explicit_scrub']=counts['bytes'];check(counts['bytes']==info.st_size)
    counts['bytes']=0
    with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        measurements['cold_startup']=counts['bytes'];check(counts['bytes']==info.st_size)
        check(s.read('/scale')==b'acknowledged')
    counts['bytes']=0;chain.checkpoint(root)
    measurements['administrative_checkpoint']=counts['bytes'];check(counts['bytes']==info.st_size)
    (root/'chain-state').unlink();counts['bytes']=0
    with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        measurements['checkpoint_fallback_startup']=counts['bytes'];check(counts['bytes']==info.st_size)

# Real process loss: the sole cold pass builds a verified preimage tree, then
# replay checks the changed chunk and hands the resulting tree to Session.
worker=('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import session;'
        'from credentials import Credentials;'
        '\nwith session.Session(Path(sys.argv[2]),Path(sys.argv[3])/"mutation-producer",Path(sys.argv[3])/"reader-server",Credentials(0,0)) as s:\n'
        ' import os;os.environ["EXT4_TEST_CRASH"]="half:0:0";'
        's.applyat([dict(kind="write",path="/scale",offset=0,data_hex=b"recovered".hex())])')
proc=subprocess.run([sys.executable,'-c',worker,str(Path(__file__).parent),str(root),str(a.work)],capture_output=True,timeout=120)
check(proc.returncode==77)
counts['bytes']=0
with patch.object(os,'fdopen',measured),patch.object(Reader,'read',measured_verified):
    with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        measurements['dirty_startup']=counts['bytes']
        check(info.st_size<=counts['bytes']<=info.st_size+2*merkle.CHUNK)
        check(s.read('/scale').startswith(b'recovered'))
        # Normal timestamp-changing external edits must be rejected by warm retirement.
        with (root/'image.img').open('r+b') as f:
            f.seek(10*merkle.CHUNK);f.write(b'outside edit');f.flush();os.fsync(f.fileno())
        refused(s.checkpoint);check(s._failed)

# Same-metadata latent corruption is tested separately: warm retirement is not
# advertised as a full media scrub. Explicit scrub and cold open must detect it.
clean=base/'silent';chain.clone(source,clean)
with session.Session(clean,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
    with (clean/'image.img').open('r+b') as f:
        f.seek(10*merkle.CHUNK);f.write(b'silent corruption')
    s._integrity.stamp=merkle.fingerprint(os.stat(clean/'image.img'))
    s.checkpoint()
    refused(s.scrub);check(s._failed)
refused(lambda:chain.recover(clean))
# Drive actual ext4 mutations and cold replay through paged storage, using
# smaller hash pages/budgets to force eviction on a bounded 128 MiB fixture.
paged_source=base/'paged-source.img'
with paged_source.open('xb') as f:f.truncate(128*1024**2)
model.command(['mke2fs','-q','-F','-t','ext4','-b','4096','-N','256','-O','^orphan_file',paged_source])
paged_root=base/'paged-chain';chain.clone(paged_source,paged_root)
with patch.object(merkle,'MAX_CACHE',4096),patch.object(merkle_store,'PAGE',1024):
    with session.Session(paged_root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        check(isinstance(s._integrity.nodes,Nodes))
        for i in range(5):
            value=bytes([i+1])*131073
            s.applyat([dict(kind='create' if i==0 else 'write',path='/scale',data_hex=value.hex())])
            s.checkpoint();check(s.read('/scale')==value)
            check(len(s._integrity.nodes.pages)<=4)
        s.scrub();check(s.read('/scale')==value)
        scratch=s._integrity.nodes.file
    check(scratch.closed)
    proc=subprocess.run([sys.executable,'-c',worker,str(Path(__file__).parent),str(paged_root),str(a.work)],capture_output=True,timeout=120)
    check(proc.returncode==77)
    with session.Session(paged_root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
        check(isinstance(s._integrity.nodes,Nodes))
        check(s.read('/scale').startswith(b'recovered'))
        s.checkpoint();s.scrub()
model.command(['e2fsck','-fn',paged_root/'image.img'])
check(model.command(['debugfs','-R','cat /scale',paged_root/'image.img'])==b'recovered'+value[len(b'recovered'):])

device_measurements=None
if a.devices:
    backing=base/'device.img';shutil.copyfile(source,backing)
    if sys.platform=='darwin':
        data=plistlib.loads(model.command(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',backing]))
        device=min((e['dev-entry'] for e in data['system-entities'] if 'dev-entry' in e),key=len)
    else:
        device=model.command(['losetup','--find','--show',backing]).decode().strip()
        if shutil.which('udevadm'):model.command(['udevadm','settle','--timeout=15'])
    def admit(call):
        deadline=time.monotonic()+15
        while True:
            try:return call()
            except OSError as error:
                if sys.platform!='linux' or error.errno not in (11,16) or time.monotonic()>=deadline:raise
                time.sleep(.2)
    device_root=base/'direct'
    scan_counts={'device':0,'image':0}
    scan_device=live_device.scan;scan_image=merkle.scan
    def device_scan(target):
        scan_counts['device']+=1
        return scan_device(target)
    def image_scan(*args,**kwargs):
        scan_counts['image']+=1
        return scan_image(*args,**kwargs)
    try:
        admit(lambda:direct.init(device,device_root,a.work))
        with patch.object(live_device,'scan',device_scan),patch.object(merkle,'scan',image_scan):
            target=admit(lambda:direct.Controller(device_root,device,a.work).__enter__())
            try:
                check(target.target.identity['kind'] in ('disk-image','loop'))
                check(Path(target.target.identity['backing']['path']).resolve()==backing.resolve())
                with session.Session(target.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=target) as s:
                    device_measurements={'startup_full_passes':sum(scan_counts.values())}
                    check(device_measurements['startup_full_passes']==1)
                    s.applyat([dict(kind='create',path='/scaling-device',data_hex=b'device acknowledged'.hex())])
                    scan_counts.update(device=0,image=0);s.checkpoint()
                    device_measurements['warm_checkpoint_full_passes']=sum(scan_counts.values())
                    check(device_measurements['warm_checkpoint_full_passes']==0)
                scan_counts.update(device=0,image=0);target.finish()
                device_measurements['close_full_passes']=sum(scan_counts.values())
                check(device_measurements['close_full_passes']==1)
            finally:target.__exit__()
        model.command(['e2fsck','-fn',backing])
        check(model.command(['debugfs','-R','cat /scaling-device',backing])==b'device acknowledged')
        check((device_root/'chain/image.img').stat().st_blocks==0)
    finally:
        model.command(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])

report=dict(result='passed',checks=checks,image_size=info.st_size,image_bytes_read=measurements,
            verified_read_bytes=counts['verified_bytes'],geometry_test_bytes=8*1024**4,geometry_scope='node geometry and high offsets only; no full 8 TiB filesystem scan',
            paged_ext4_replay=True,device_full_passes=device_measurements,paged_reference_bytes=size,paged_resident_budget=4*HASH_PAGE,diagnostics=str(base))
(a.work/'integrity-scaling-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
