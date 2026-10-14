#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real allocation/punch mutations, byte edges, inode lifetime and recovery."""
import argparse,errno,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch
import chain,inplace,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int);a=p.parse_args();checks=0

def check(v,detail='allocation check failed'):
 global checks
 assert v,detail;checks+=1
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def opened(root):return session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0))
sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='allocation-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for n,source in enumerate(sources):
  initial=sha(source);root=tmp/str(n);chain.clone(source,root);block=int(source.name.split('-')[0])
  with opened(root) as s:
   h=s.openat(None,'/allocated','rw',create=True);data=bytes(range(256))*(block*8//256);h.write(data)
   if 'extents' in source.name:
    h.allocate(block*16+17,block*4,1);check(h.size()==len(data));check(h.read()==data)
    allocation=subprocess.check_output(['debugfs','-R','stat /allocated',str(root/'image.img')],stderr=subprocess.DEVNULL)
    check(int(re.search(rb'Blockcount: (\d+)',allocation).group(1))>len(data)//512)
    subprocess.run(['e2fsck','-fn',str(root/'image.img')],check=True,capture_output=True)
    h.allocate(0,block*2,4);h.allocate(0,block*2,4);check(h.size()==len(data))
    subprocess.run(['e2fsck','-fn',str(root/'image.img')],check=True,capture_output=True)
   else:
    before=sha(root/'image.img');head=s.state['head']
    try:h.allocate(block*16+17,block*4,1)
    except OSError as e:check(e.errno==errno.EOPNOTSUPP)
    else:raise AssertionError('invalid classic keep-size allocation admitted')
    check(sha(root/'image.img')==before and s.state['head']==head)
   h.allocate(block*16+17,block*4,0);check(h.size()==block*20+17);check(h.read(len(data),block*12+17)==bytes(block*12+17))
   h.allocate(17,block*6+39,3);expected=bytearray(data);expected[17:block*6+56]=bytes(block*6+39)
   check(h.read(0,len(data))==expected);check(h.size()==block*20+17)
   # Same block, aligned beginning, unaligned end and a range wholly in a hole.
   for start,length in ((block*7+11,19),(block*7,23),(block*10+13,11)):
    h.allocate(start,length,3)
    if start<len(expected):expected[start:start+length]=bytes(length)
    check(h.read(0,len(data))==expected)
   h.allocate(0,block*24,3);check(h.size()==block*20+17);check(h.read()==bytes(h.size()))
   h.allocate(0,block*2,1);h.write(b'kept');s.unlink('/allocated');h.allocate(block,block,3);check(h.read(0,4)==b'kept');h.close()
   h=s.openat(None,'/bounds','rw',create=True);saved=sha(root/'image.img');head=s.state['head']
   for call in (lambda:h.allocate(-1,10),lambda:h.allocate(0,0),lambda:h.allocate(0,10,2),lambda:h.allocate(2**63-1,2)):
    try:call()
    except (ValueError,OSError):check(True)
    else:raise AssertionError('invalid range accepted')
    check(sha(root/'image.img')==saved and s.state['head']==head)
   try:h.allocate(0,source.stat().st_size*2)
   except OSError as e:check(e.errno==errno.ENOSPC)
   else:raise AssertionError('reservation larger than device admitted')
   check(sha(root/'image.img')==saved and s.state['head']==head)
   h.close();readonly=s.open('/bounds','r')
   try:readonly.allocate(0,block)
   except OSError as e:check(e.errno==errno.EBADF)
   else:raise AssertionError('read grant allocated blocks')
   readonly.close()
   # Bounded overlay failures must discard every staged allocation.
   h=s.open('/bounds','rw');saved=sha(root/'image.img');head=s.state['head']
   with patch.dict(os.environ,EXT4_TEST_MUTATION_FAIL_WRITES='0'):
    try:h.allocate(0,block*4)
    except OSError:check(True)
    else:raise AssertionError('injected allocation failure did not occur')
   check(sha(root/'image.img')==saved and s.state['head']==head);h.close()
  subprocess.run(['e2fsck','-fn',str(root/'image.img')],check=True,capture_output=True)
  check(sha(source)==initial)
 # Tear a sealed punch replay and recover independently in a new session.
 root=tmp/'crash';chain.clone(sources[0],root)
 with opened(root) as s:
  h=s.openat(None,'/punch','rw',create=True);h.write(b'A'*16384);h.close()
 hit=[]
 # A durable boundary selected from actual replay; fail closed if it is missing.
 original=inplace.boundary
 with opened(root) as s:
  h=s.open('/punch','rw')
  def fail(name):
   if name.startswith('page:') and not hit:hit.append(name);raise OSError(errno.EIO,'interrupted punch replay')
   original(name)
  with patch.object(inplace,'boundary',fail):
   try:h.allocate(1024,8192,3)
   except OSError:check(bool(hit))
   else:raise AssertionError('punch fault boundary not reached')
  h.close()
 with opened(root) as s:
  with s.open('/punch') as h:check(h.read()==b'A'*1024+bytes(8192)+b'A'*(16384-9216))
 subprocess.run(['e2fsck','-fn',str(root/'image.img')],check=True,capture_output=True)
(a.work/'allocation-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources)),indent=2)+'\n');print('PASS',checks,'allocation checks')
