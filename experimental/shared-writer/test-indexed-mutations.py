#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""HTree growth, namespace/lifetime, rollback and independent fsck validation."""
import argparse,errno,hashlib,json,os,re,shutil,struct,subprocess,tempfile
from pathlib import Path
from unittest.mock import patch
import chain,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--profile',type=int);a=p.parse_args();checks=0;rows=[]
def check(value,detail='indexed mutation check failed'):
 global checks
 assert value,detail;checks+=1
def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120);check(r.returncode==0,r.stdout+r.stderr);return r.stdout
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def debug(image,command):return run(['debugfs','-R',command,image]).decode()
def name(i):return 'entry%05d'%i+'é'+'x'*190
def indexed(image,path):
 text=debug(image,'stat '+path);check(int(re.search(r'Flags:\s*(0x[0-9a-f]+)',text).group(1),16)&0x1000)
 return int(re.search(r'Size:\s*(\d+)',text).group(1))
def batches(s,operations):
 for offset in range(0,len(operations),64):s.apply(operations[offset:offset+64])
def clean(image):run(['e2fsck','-fn',image])
profiles=[(b,cs,ex) for b in (1024,2048,4096) for cs in (False,True) for ex in (False,True)]
profiles=list(enumerate(profiles))
if a.profile is not None:profiles=[profiles[a.profile]]
if a.limit:profiles=profiles[:a.limit]
with tempfile.TemporaryDirectory(prefix='indexed-mutations-',dir=a.work) as tmp:
 tmp=Path(tmp);payload=tmp/'payload';payload.write_bytes(b'index seed')
 for number,(block,cs,ex) in profiles:
  root=tmp/str(number);root.mkdir();seed=root/'seed.img'
  with seed.open('wb') as f:f.truncate(32*1024**2)
  features=['dir_index','^orphan_file','extents' if ex else '^extents,^64bit','metadata_csum' if cs else '^metadata_csum,^uninit_bg']
  run(['mke2fs','-q','-F','-t','ext4','-b',block,'-O',','.join(features),seed])
  kind=('legacy','half_md4','tea')[number%3];unsigned=bool(number%2)
  commands=root/'seed.commands';commands.write_text('set_super_value def_hash_version '+kind+'\nset_super_value flags '+('2' if unsigned else '1')+'\n'+''.join('mkdir /'+d+'\n'+''.join(f'write {payload} /{d}/{name(i)}\n' for i in range(200)) for d in ('many','other','empty')))
  run(['debugfs','-w','-f',commands,seed]);r=subprocess.run(['e2fsck','-fyD',str(seed)],capture_output=True);check(r.returncode in (0,1),r.stdout+r.stderr)
  clean(seed);before=sha(seed);oldsize=indexed(seed,'/many');indexed(seed,'/other');indexed(seed,'/empty')
  chain.clone(seed,root/'chain')
  with session.Session(root/'chain',a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   # Enough long names to split leaves and grow the 1 KiB tree to depth one.
   additions=900 if block==1024 else 400
   batches(s,[dict(kind='create',path='/many/'+name(i),mode=0o600,data_hex=b'new indexed data'.hex()) for i in range(200,200+additions)])
   check(indexed(s.root/'image.img','/many')>oldsize);clean(s.root/'image.img')
   for i in (0,199,200,199+additions):
    try:actual=s.read('/many/'+name(i))
    except OSError:
     shutil.copytree(root,a.work/'failed-indexed',dirs_exist_ok=True);print('Failed name:',name(i),flush=True);raise
    check(actual==(b'index seed' if i<200 else b'new indexed data'))
   directory=s.opendir('/many');check(name(200) in directory.listdir())
   s.mkdir('/many/sub');s.symlink('../'+name(0),'/many/sub/sym');check(s.readat(None,'/many/sub/sym')==b'index seed')
   s.link('/many/'+name(200),'/other/hard');s.rename('/many/'+name(201),'/other/moved');check(s.read('/other/moved')==b'new indexed data')
   s.rename('/many/sub','/other/sub');check(s.readlink('/other/sub/sym')==('../'+name(0)).encode());s.unlink('/other/sub/sym');s.rmdir('/other/sub')
   held=s.open('/other/hard','rw');s.unlink('/other/hard');check(held.read()==b'new indexed data');held.close()
   s.rename('/many/'+name(202),'/other/'+name(0));check(s.read('/other/'+name(0))==b'new indexed data')
   # Relative operations through an indexed directory inode handle.
   h=s.openat(directory,'relative','rw',create=True);h.write(b'relative indexed');h.close();check(s.read('/many/relative')==b'relative indexed')
   empty=s.opendir('/empty');batches(s,[dict(kind='unlink',path='/empty/'+name(i)) for i in range(200)]);s.rmdir('/empty');check(empty.stat()['links']==0);empty.close()
   # A later error rolls back earlier changes in the same indexed batch.
   digest,head=sha(s.root/'image.img'),s.state['head']
   try:s.apply([dict(kind='create',path='/many/rollback',data_hex=''),dict(kind='unlink',path='/many/absent')])
   except OSError:check(True)
   else:raise AssertionError('failed indexed batch committed')
   check(sha(s.root/'image.img')==digest and s.state['head']==head)
   directory.close();clean(s.root/'image.img');indexed(s.root/'image.img','/many');indexed(s.root/'image.img','/other')
   # Native reader enumeration/lookup agrees with libext2fs/debugfs after growth.
   check(int(re.search(r'Inode:\s*(\d+)',debug(s.root/'image.img','stat /many/relative')).group(1))==s.statat(None,'/many/relative')['inode'])
  for damage in ('cycle','duplicate','range'):
   bad=root/(damage+'.img');shutil.copyfile(seed,bad);run([a.work/'index-corrupt',bad,'/many',damage])
   chain.clone(bad,root/(damage+'-chain'))
   with session.Session(root/(damage+'-chain'),a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as broken:
    original=sha(broken.root/'image.img');head=broken.state['head']
    try:broken.apply([dict(kind='create',path='/many/rejected',data_hex='')])
    except OSError:check(True)
    else:raise AssertionError('corrupt index accepted: '+damage)
    check(sha(broken.root/'image.img')==original and broken.state['head']==head)
  check(sha(seed)==before)
  rows.append(dict(block=block,checksum=cs,extents=ex,hash=kind,unsigned=unsigned,result='passed'))
  print('PASS indexed mutations',block,cs,ex,kind,unsigned,flush=True)
(a.work/'indexed-mutation-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=rows),indent=2)+'\n');print('PASS',checks,'indexed mutation checks',flush=True)
