#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Mount broker permission, metadata, cleanup and wire guards without a kernel mount."""
import argparse
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import chain
import session
from credentials import Credentials
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('mount_broker',here/'mount-broker.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work',type=Path,required=True);parser.add_argument('--fixtures',type=Path);parser.add_argument('--limit',type=int)
a=parser.parse_args();fixtures=a.fixtures or a.work/'fixtures';checks=0;rows=[]
def check(c,detail='check failed'):
    global checks
    assert c,detail;checks+=1

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def run(cmd):
    r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=90);check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def denied(fn,e):
    try:fn()
    except OSError as error:check(error.errno==e,repr(error))
    else:raise AssertionError('unexpected success')

with tempfile.TemporaryDirectory(prefix='mount-broker-',dir=a.work) as tmp:
    tmp=Path(tmp);sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if a.limit:sources=sources[:a.limit]
    check(bool(sources))
    for source in sources:
        before=sha(source);seed=tmp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        script=tmp/'seed.cmd';script.write_text(f'set_inode_field / mode 040777\nset_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\n')
        run(['debugfs','-w','-f',script,seed]);root=tmp/source.stem;state=chain.clone(seed,root);check(state['head']==0 and sha(root/'image.img')==sha(seed))
        with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(os.getuid(),os.getgid())) as s:
            b=module.Broker(s)
            def call(op,path=b'',data=b'',token=0,offset=0,arg=0,uid=None,mask=0o022):
                return b.dispatch(op,path,data,os.getuid() if uid is None else uid,os.getgid(),mask,os.getgroups(),token,offset,arg)
            denied(lambda:call(1,b'/'),errno.EBUSY);denied(lambda:call(22,uid=os.getuid()+1),errno.EACCES)
            check(call(22)==(0,b''));denied(lambda:call(22),errno.EPERM)
            stat=call(1,b'/')[1];check(len(stat)==128);f=struct.unpack('<8QqQqQqQqQ',stat)
            check(f[0]==2 and f[1]&0o170000==0o040000 and f[3]==os.getuid());check(f[7]==int(source.name.split('-')[0]))
            geom=struct.unpack('<10Q',call(18)[1]);check(geom[0]==geom[1]==f[7] and geom[8]==255 and geom[9]==0)
            token,_=call(3,b'/file',arg=(0o666<<32)|os.O_RDWR|os.O_CREAT|os.O_EXCL,mask=0o077)
            check(call(1,b'/file')[1][0:8]==call(1,token=token)[1][0:8])
            f=struct.unpack('<8QqQqQqQqQ',call(1,token=token)[1]);check(f[1]&0o777==0o600)
            check(call(5,data=b'abc',token=token)==(3,b''));check(call(4,token=token,arg=8)==(0,b'abc'))
            check(call(19,token=token)==(0,b''));check(call(19,token=token)==(0,b''));check(token in b.handles)
            denied(lambda:call(5,data=b'x',token=token,uid=os.getuid()+1),errno.EACCES);check(call(4,token=token,arg=8)[1]==b'abc')
            denied(lambda:call(5,data=b'x',token=token,offset=64*1024*1024),errno.EFBIG)
            call(6,token=token,offset=2);check(call(4,token=token,arg=8)[1]==b'ab')
            hidden=b'/.fuse_hidden0000000100000001';call(14,b'/file',hidden);check(hidden in b.hidden)
            denied(lambda:call(23,b'/existing-file'),errno.EACCES)
            call(7,token=token);call(23,hidden);check(not b.hidden and not b.handles)
            denied(lambda:call(1,hidden),errno.ENOENT);denied(lambda:call(4,token=token,arg=8),errno.EBADF)
            call(11,b'/dir',arg=0o777);directory,_=call(8,b'/dir')
            size,page=call(9,token=directory);check(size>0 and struct.unpack_from('<II',page)==(1,2))
            call(10,token=directory);call(12,b'/dir')
            denied(lambda:call(14,b'/existing-file',b'/x',arg=1),errno.EOPNOTSUPP)
            call(21,b'/',arg=7)
            # Malformed private transport framing cannot execute a mutation.
            frame=module.HEADER.pack(b'badmagic',3,0,0,os.getuid(),os.getgid(),0,0,0,0,0)
            transport=SimpleNamespace(stdout=io.BytesIO(frame),stdin=io.BytesIO())
            denied(lambda:module.serve(b,transport),errno.EIO)
            # A well-formed error response is bounded and keeps the session live.
            frame=module.HEADER.pack(b'E4FM0001',1,8,0,os.getuid(),os.getgid(),0,0,0,0,0)+b'/missing'
            transport=SimpleNamespace(stdout=io.BytesIO(frame),stdin=io.BytesIO());module.serve(b,transport)
            check(module.REPLY.unpack(transport.stdin.getvalue())==(b'E4FP0001',errno.ENOENT,0,0,0))
            check(not s._failed);run(['e2fsck','-fn',root/'image.img'])
        check(sha(source)==before);rows.append(dict(fixture=source.name,result='passed'));print('PASS broker',source.name,flush=True)
(a.work/'mount-broker-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows),indent=2)+'\n')
print('PASS',checks,'mount broker checks',flush=True)
