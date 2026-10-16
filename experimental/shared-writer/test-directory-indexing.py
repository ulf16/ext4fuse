#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automatic HTree conversion, retained identity, rollback and torn recovery."""
import argparse,errno,hashlib,json,os,re,shutil,struct,subprocess,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
import chain,session
from credentials import Credentials
from fault_injection import torn_replay
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--mount',action='store_true');a=p.parse_args();a.work=a.work.resolve();checks=0;rows=[]
def check(value,detail='directory indexing check failed'):
 global checks
 assert value,detail;checks+=1

def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=180);check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def name(i):return f'entry-{i:05d}-é'+'x'*190

def rawstat(image,path):
 text=run(['debugfs','-R','stat '+path,image]).decode();return int(re.search(r'Flags:\s*(0x[0-9a-f]+)',text).group(1),16),int(re.search(r'Size:\s*(\d+)',text).group(1))

def stat(s,path):
 result=s.statat(None,path);raw=s._mount_stat(path);result['uid'],result['gid']=struct.unpack_from('<QQ',raw,24);return result

def denied(fn,code):
 try:fn()
 except OSError as e:check(e.errno==code,repr(e))
 else:raise AssertionError('failed directory batch unexpectedly committed')

def batch(s,ops):
 for start in range(0,len(ops),64):s.apply(ops[start:start+64])

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='directory-indexing-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sources):
  seed=tmp/f'{index}.img';shutil.copyfile(source,seed);payload=tmp/'payload';payload.write_bytes(b'preserved data')
  commands=tmp/'commands';commands.write_text('set_super_value def_hash_version '+('legacy','half_md4','tea')[index%3]+'\nset_super_value flags '+('2' if index%2 else '1')+'\nmkdir /legacy\n'+''.join(f'write {payload} /legacy/{name(i)}\n' for i in range(1000)))
  run(['debugfs','-w','-f',commands,seed]);run(['e2fsck','-fn',seed]);check(not rawstat(seed,'/legacy')[0]&0x1000)
  if index in (0,3,8,11):
   compact=tmp/f'compact-{index}.img';shutil.copyfile(seed,compact)
   commands.write_text('mkdir /sparse\n'+''.join(f'write {payload} /sparse/{name(i)}\n' for i in range(1000))+''.join('rm /sparse/'+name(i)+'\n' for i in range(100,1000)))
   run(['debugfs','-w','-f',commands,compact]);run(['e2fsck','-fn',compact]);digest=sha(compact)
   result=json.loads(run([a.work/'index-convert-unit',compact,tmp/f'converted-{index}.img']));check(result['failed_write_boundaries']>=5)
   check(sha(compact)==digest);run(['e2fsck','-fn',tmp/f'converted-{index}.img']);print('PASS compact conversion and failure boundaries',result,flush=True)

  root=tmp/f'chain-{index}';chain.clone(seed,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   s.setxattr('/legacy','user.conversion',b'keep');legacy=s.opendir('/legacy');before=stat(s,'/legacy');held=s.open('/legacy/'+name(0))
   # A multi-block directory must convert as soon as its current blocks cannot fit.
   for i in range(1000,1100):
    s.apply([dict(kind='create',path='/legacy/'+name(i),data_hex='')])
    if rawstat(root/'image.img','/legacy')[0]&0x1000:break
   else:raise AssertionError('legacy linear directory did not convert')
   after=stat(s,'/legacy')
   for key in ('inode','generation','mode','uid','gid','links'):check(after[key]==before[key],key)
   check(s.getxattr('/legacy','user.conversion')==b'keep');check(held.read()==b'preserved data');held.close()
   check(len(legacy.listdir())==i+1);legacy.close()
   s.mkdir('/fresh');s.setxattr('/fresh','user.conversion',b'new');fresh=s.opendir('/fresh');before=stat(s,'/fresh')
   # Retain an empty snapshot across the conversion and subsequent tree growth.
   snapshot=fresh.readdir();check(snapshot['eof'] and len(snapshot['entries'])==2)
   batch(s,[dict(kind='create',path='/fresh/'+name(i),data_hex='') for i in range(650)])
   check(rawstat(root/'image.img','/fresh')[0]&0x1000);after=stat(s,'/fresh')
   for key in ('inode','generation','mode','uid','gid','links'):check(after[key]==before[key],key)
   check(fresh.readdir()['entries']==[]);fresh.rewind();check(len(fresh.listdir())==650);fresh.close()
   check(s.getxattr('/fresh','user.conversion')==b'new')
   s.mkdir('/rollback');image=root/'image.img';digest=sha(image);head=s.state['head']
   denied(lambda:s.apply([dict(kind='create',path='/rollback/'+name(i),data_hex='') for i in range(32)]+[dict(kind='unlink',path='/missing')]),errno.ENOENT)
   check(sha(image)==digest and s.state['head']==head);check(not rawstat(image,'/rollback')[0]&0x1000)
   for boundary in (0,5,12):
    with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':str(boundary)}):
     denied(lambda:s.apply([dict(kind='create',path='/rollback/'+name(i),data_hex='') for i in range(32)]),errno.ENOSPC)
    check(sha(image)==digest and s.state['head']==head)
   # Recovery of a sealed conversion survives an actual half-page replay.
   with torn_replay() as fault:
    denied(lambda:s.apply([dict(kind='create',path='/rollback/'+name(i),data_hex='') for i in range(32)]),errno.EIO)
   check(fault['hit']);s.statat(None,'/rollback');check(rawstat(image,'/rollback')[0]&0x1000)
   with s.opendir('/rollback') as d:check(len(d.listdir())==32)
   if a.mount and index==0:s.chmod('/',0o777)
  run(['e2fsck','-fn',root/'image.img'])
  if a.mount and index==0:
   mount=tmp/'mnt';mount.mkdir();logpath=tmp/'mount.log';proc=None;fds=[];active=False;cwd=os.open('.',os.O_RDONLY)
   try:
    with logpath.open('wb') as log:
     proc=subprocess.Popen([sys.executable,Path(__file__).resolve().parent/'mount-broker.py','--root',root,'--work',a.work,'--mountpoint',mount],stdout=log,stderr=log)
     for unused in range(200):
      if os.path.ismount(mount):active=True;break
      if proc.poll() is not None:break
      time.sleep(.1)
     check(active,logpath.read_text());native=mount/'native';native.mkdir(mode=0o750);before=native.stat()
     dfd=os.open(native,os.O_RDONLY|os.O_DIRECTORY);fds.append(dfd)
     fd=os.open(native/'held',os.O_CREAT|os.O_RDWR,0o640);fds.append(fd);os.write(fd,b'before')
     os.fchdir(dfd)
     for i in range(80):
      created=os.open(name(i),os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o640)
      try:os.write(created,b'indexed')
      finally:os.close(created)
     renamed=mount/'native-renamed';os.rename(native,renamed)
     after=renamed.stat();check((before.st_ino,before.st_uid,before.st_gid,before.st_mode)==(after.st_ino,after.st_uid,after.st_gid,after.st_mode))
     check(os.fstat(dfd).st_ino==before.st_ino);check(os.getcwd()==str(renamed));check(len(os.listdir(dfd))==81)
     check(os.pread(fd,6,0)==b'before');os.pwrite(fd,b'after!',0);os.fsync(fd)
     check(rawstat(root/'image.img','/native-renamed')[0]&0x1000)
     os.fchdir(cwd)
     for value in fds:os.close(value)
     fds=[]
     command=['/sbin/umount',mount] if sys.platform=='darwin' else ['fusermount3','-u',mount]
     run(command);active=False;check(proc.wait(timeout=30)==0,logpath.read_text())
   finally:
    os.fchdir(cwd);os.close(cwd)
    for value in fds:os.close(value)
    if active and os.path.ismount(mount):subprocess.run(['/sbin/umount',mount] if sys.platform=='darwin' else ['fusermount3','-u',mount],check=True)
    if proc and proc.poll() is None:proc.wait(timeout=30)
   run(['e2fsck','-fn',root/'image.img']);print('PASS native mounted automatic indexing and retained cwd/fds',flush=True)
  rows.append(dict(profile=source.name,result='passed'));print('PASS automatic directory indexing',source.name,flush=True)
 # Volumes without dir_index retain ordinary linear growth; no feature is enabled implicitly.
 plain=tmp/'plain.img'
 with plain.open('wb') as f:f.truncate(32*1024**2)
 run(['mke2fs','-q','-F','-t','ext4','-b','1024','-O','^dir_index,^orphan_file',plain]);chain.clone(plain,tmp/'plain-chain')
 with session.Session(tmp/'plain-chain',a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
  s.mkdir('/plain');batch(s,[dict(kind='create',path='/plain/'+name(i),data_hex='') for i in range(100)])
  flags,size=rawstat(tmp/'plain-chain'/'image.img','/plain');check(not flags&0x1000 and size>1024)
 run(['e2fsck','-fn',tmp/'plain-chain'/'image.img']);print('PASS linear fallback without dir_index',flush=True)
 (a.work/'directory-indexing-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=rows),indent=2)+'\n');print('PASS',checks,'automatic indexing checks',flush=True)
