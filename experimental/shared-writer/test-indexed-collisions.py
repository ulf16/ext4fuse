#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Mutate real hash collisions across leaf/node boundaries and recover torn writes."""
import argparse,errno,hashlib,json,re,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch
import chain,inplace,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
state=0x835689ac;seen={}
def legacy(name):
 x=0x12a3fe2d;y=0x37abe8f9
 for b in name.encode():
  h=(y+(x^(b*7152373)))&0xffffffff
  if h&0x80000000:h=(h-0x7fffffff)&0xffffffff
  y=x;x=h
 return (x<<1)&0xffffffff
for unused in range(200000):
 chars=[]
 for i in range(40):state=(state*1664525+1013904223)&0xffffffff;chars.append(chr(97+((state>>16)%26)))
 name=''.join(chars);h=legacy(name)
 if h in seen and seen[h]!=name:pair=(seen[h],name);break
 seen[h]=name
else:raise AssertionError('missing hash collision')
def check(v):
 global checks
 assert v;checks+=1
def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120);assert r.returncode==0,r.stdout+r.stderr;return r.stdout
with tempfile.TemporaryDirectory(prefix='indexed-collisions-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for block in (1024,2048,4096):
  for checksum in (False,True):
   for depth in (0,1):
    seed=tmp/'seed.img'
    with seed.open('wb') as f:f.truncate(16*1024**2)
    run(['mke2fs','-q','-F','-t','ext4','-b',block,'-O','^orphan_file,'+('metadata_csum' if checksum else '^metadata_csum,^uninit_bg'),seed])
    commands=tmp/'commands';payload=tmp/'payload';payload.write_bytes(b'collision payload')
    commands.write_text('mkdir /collision\n'+''.join(f'write {payload} /collision/{name}\n' for name in pair));run(['debugfs','-w','-f',commands,seed])
    ino=re.search(rb'Inode:\s*(\d+)',run(['debugfs','-R','stat /collision',seed])).group(1).decode()
    run([a.work/'index-collision-fixture',seed,ino,*pair,depth]);run(['e2fsck','-fn',seed]);before=hashlib.sha256(seed.read_bytes()).digest()
    root=tmp/f'{block}-{checksum}-{depth}';chain.clone(seed,root)
    with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
     for name in pair:check(s.read('/collision/'+name)==b'collision payload')
     s.apply([dict(kind='create',path='/collision/fill%03d'%i+'x'*180,data_hex='61') for i in range(60)])
     s.link('/collision/'+pair[0],'/collision/alias');s.unlink('/collision/'+pair[0]);check(s.read('/collision/'+pair[1])==b'collision payload')
     s.rename('/collision/alias','/collision/'+pair[0]);check(s.read('/collision/'+pair[0])==b'collision payload')
     hit=[];original=inplace.boundary
     def interrupt(name):
      if name=='half:0:0' and not hit:hit.append(name);raise OSError(errno.EIO,'torn indexed rename')
      return original(name)
     with patch.object(inplace,'boundary',interrupt):
      try:s.rename('/collision/'+pair[0],'/collision/recovered')
      except OSError as e:check(e.errno==errno.EIO)
      else:raise AssertionError('interruption missed')
     check(bool(hit));check(s.read('/collision/recovered')==b'collision payload');check(s.read('/collision/'+pair[1])==b'collision payload')
     run(['e2fsck','-fn',root/'image.img'])
    check(hashlib.sha256(seed.read_bytes()).digest()==before)
    print('PASS collision mutation',block,checksum,depth,flush=True)
(a.work/'indexed-collision-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n');print('PASS',checks,'indexed collision/recovery checks',flush=True)
