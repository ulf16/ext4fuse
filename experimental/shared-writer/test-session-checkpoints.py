#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Retire live-session history while retaining file grants, dir handles and cwd."""
import argparse,hashlib,json,os,subprocess,tempfile
from pathlib import Path
import chain,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);a=p.parse_args();checks=0

def check(v):
 global checks
 assert v;checks+=1

sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='session-checkpoint-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for n,source in enumerate(sources):
  root=tmp/str(n);chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),checkpoint_every=3) as s:
   h=s.openat(None,'/pinned','rw',create=True);h.write(b'pinned bytes');s.unlink('/pinned')
   check(not list(root.glob('g-*')));check(h.read()==b'pinned bytes')
   s.mkdir('/dir');d=s.opendir('/dir');s.chdir('/dir');s.apply([dict(kind='create',path='a',data_hex='61')]);h.write(b'more')
   check(not list(root.glob('g-*')));check(h.read(0,4)==b'more');h.close()
   s.rename('/dir','/moved');s.checkpoint();check(d.path()=='/moved' and s.getcwd()=='/moved')
   s.apply([dict(kind='unlink',path='/moved/a'),dict(kind='rmdir',path='/moved')]);s.checkpoint();check(d.listdir()==[])
   d.close();s.chdir('/');s.checkpoint();check(not list(root.glob('g-*')))
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:check(s.size('/existing-file')>0)
  r=subprocess.run(['e2fsck','-fn',str(root/'image.img')],capture_output=True);check(r.returncode==0)
  # Performance optimization must still detect changes to untouched bytes.
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   image=root/'image.img'
   with image.open('r+b') as f:f.seek(-1,2);v=f.read(1);f.seek(-1,2);f.write(bytes([v[0]^1]));f.flush();os.fsync(f.fileno())
   before=hashlib.sha256(image.read_bytes()).digest()
   try:s.apply([dict(kind='create',path='/unsafe',data_hex='')])
   except ValueError:check(True)
   else:raise AssertionError('clean-byte corruption was not detected')
   check(hashlib.sha256(image.read_bytes()).digest()==before)
  print('PASS live checkpoint',source.name,flush=True)
(a.work/'session-checkpoint-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n');print('PASS',checks,'live checkpoint checks',flush=True)
