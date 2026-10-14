#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sparse writable sizes, 32-bit offset crossings, format bounds and recovery."""
import argparse,errno,hashlib,json,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch
import chain,inplace,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int);a=p.parse_args();checks=0

def check(v):
 global checks
 assert v;checks+=1

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

fixtures=a.fixtures or a.work/'fixtures';sources=sorted(p for p in fixtures.glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='large-writes-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sources):
  before=sha(source);root=tmp/str(index);chain.clone(source,root)
  block=int(source.name.split('-')[0]);extent='extents' in source.name;pointers=block//4
  maximum=((2**32-1) if extent else 12+pointers+pointers**2+pointers**3)*block
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   h=s.openat(None,'/large','rw',create=True,mode=0o600)
   for offset in (64*1024**2+17,2**32-2,8*1024**3+31):
    data=b'large write crossing boundary';check(h.write(data,offset)==len(data));check(h.read(offset,len(data))==data)
    check(h.read(offset-16,16)==bytes(16))
   check(h.size()==8*1024**3+31+len(data))
   app=s.open('/large','w',append=True);check(app.write(b'append',0)==6);app.close();check(h.read(h.size()-6,6)==b'append')
   h.truncate(64*1024**2+21);h.truncate(9*1024**3+3);check(h.read(8*1024**3+31,32)==bytes(32))
   # Exact mapping bound is sparse; one byte beyond it fails before allocation.
   h.truncate(maximum);check(h.size()==maximum)
   saved,head=sha(root/'image.img'),s.state['head']
   for call in (lambda:h.truncate(maximum+1),lambda:h.write(b'x',maximum)):
    try:call()
    except OSError as e:check(e.errno==errno.EFBIG)
    else:raise AssertionError('format bound accepted')
    check(sha(root/'image.img')==saved and s.state['head']==head)
   h.truncate(9*1024**3+3)
   hit=[];original=inplace.boundary
   def stop(name):
    if name=='half:0:0' and not hit:hit.append(name);raise OSError(errno.EIO,'large write torn page')
    return original(name)
   with patch.object(inplace,'boundary',stop):
    try:h.write(b'recovered large data',8*1024**3)
    except OSError as e:check(e.errno==errno.EIO)
    else:raise AssertionError('interruption missed')
   check(bool(hit));check(h.read(8*1024**3,20)==b'recovered large data')
   h.close()
  r=subprocess.run(['e2fsck','-fn',str(root/'image.img')],capture_output=True);check(r.returncode==0)
  check(sha(source)==before);print('PASS large writable sizes',source.name,flush=True)
(a.work/'large-write-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources)),indent=2)+'\n');print('PASS',checks,'large writable checks',flush=True)
