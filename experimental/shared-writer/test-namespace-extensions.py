#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Atomic rename flags and special inode identity, authority and recovery."""
import argparse,errno,json,os,stat,struct,subprocess,sys,tempfile
from pathlib import Path
import chain,session,journal_fixtures as fixture
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--worker',nargs=2);a=p.parse_args();checks=0;here=Path(__file__).resolve().parent

def opened(root,credentials=None):return session.Session(root,a.work/'mutation-producer',a.work/'reader-server',credentials or Credentials(0,0))
def check(v,detail='namespace extension check failed'):
 global checks
 assert v,detail;checks+=1

def fields(s,path=None,handle=None):return struct.unpack('<16Q',s._mount_stat(path,handle))
def put(s,path,data):
 with s.openat(None,path,'rw',create=True,exclusive=True) as f:f.write(data)
def read(s,path):
 with s.open(path) as f:return f.read()
def atomic(s,call,code):
 before=fixture.sha(s.root/'image.img');head=s.state['head']
 try:call()
 except (OSError,ValueError) as e:check(isinstance(e,ValueError) if code is ValueError else getattr(e,'errno',None)==code,repr(e))
 else:raise AssertionError('unexpected success')
 check(fixture.sha(s.root/'image.img')==before and s.state['head']==head)

def fault_ops(kind):
 if kind=='exchange':return [dict(kind='rename',path='/a',target='/b',flags=2)]
 return [dict(kind='mknod',path='/device',mode=stat.S_IFCHR|0o640,major=259,minor=70001)]
if a.worker:
 root,kind=a.worker
 with opened(Path(root)) as s:s.applyat(fault_ops(kind))
 raise SystemExit(0)

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='namespace-extensions-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sources):
  root=tmp/f'profile-{index}';chain.clone(source,root);original=fixture.sha(source)
  with opened(root) as s:
   put(s,'/a',b'A');put(s,'/b',b'B')
   ia,ib=fields(s,'/a')[0],fields(s,'/b')[0]
   atomic(s,lambda:s.rename('/a','/b',flags=1),errno.EEXIST)
   atomic(s,lambda:s.rename('/a','/a',flags=1),errno.EEXIST)
   s.link('/a','/alias');atomic(s,lambda:s.rename('/a','/alias',flags=1),errno.EEXIST)
   atomic(s,lambda:s.rename('/a','/missing',flags=2),errno.ENOENT)
   atomic(s,lambda:s.rename('/a','/b',flags=3),ValueError)
   with s.open('/a') as old:
    s.rename('/a','/b',flags=2);check(read(s,'/a')==b'B' and read(s,'/b')==b'A');check(old.read()==b'A')
    check((fields(s,'/a')[0],fields(s,'/b')[0])==(ib,ia))
   s.rename('/b','/new',flags=1);check(read(s,'/new')==b'A')
   s.rename('/new','/alias',flags=2);check(fields(s,'/new')[0]==fields(s,'/alias')[0])
   s.mkdir('/left');s.mkdir('/right');s.mkdir('/left/dir');put(s,'/left/dir/child',b'child');put(s,'/right/file',b'file')
   left,right=fields(s,'/left')[2],fields(s,'/right')[2]
   with s.opendir('/left/dir') as d:
    s.fchdir(d);s.rename('/left/dir','/right/file',flags=2)
    check(s.getcwd()=='/right/file');check(d.listdir()==['child']);s.chdir('/')
    check(read(s,'/right/file/child')==b'child' and read(s,'/left/dir')==b'file')
   check(fields(s,'/left')[2]==left-1 and fields(s,'/right')[2]==right+1)
   s.mkdir('/left/other');put(s,'/left/other/second',b'second')
   s.rename('/right/file','/left/other',flags=2)
   check(read(s,'/left/other/child')==b'child' and read(s,'/right/file/second')==b'second')
   atomic(s,lambda:s.rename('/left','/left/other',flags=2),errno.EINVAL)
   s.symlink('missing','/link');s.rename('/link','/a',flags=2);check(s.readlink('/a')==b'missing' and read(s,'/link')==b'B')
   s._mount_nodes()
   for name,kind,major,minor in [('fifo',stat.S_IFIFO,0,0),('socket',stat.S_IFSOCK,0,0),('char',stat.S_IFCHR,259,70001),('block',stat.S_IFBLK,4095,1048575)]:
    path='/'+name;s.mknod(path,kind|0o640,major=major,minor=minor)
    info=fields(s,path);check(stat.S_IFMT(info[1])==kind and info[2]==1 and info[5]==0 and info[6]==0)
    if kind in (stat.S_IFCHR,stat.S_IFBLK):check(info[7]==major<<32|minor)
    atomic(s,lambda:s.mknod(path,kind|0o640,major=major,minor=minor),errno.EEXIST)
    h,ino,generation=s._mount_lookup(None,name.encode())
    try:
     s.link(path,path+'-link');s.rename(path+'-link',path+'-moved',flags=1);s.unlink(path);check(fields(s,handle=h)[2]==1)
     # External EA allocation must be freed without following rdev as block pointers.
     s.setxattr(None,'user.special',b'x'*600,handle=h);s.unlink(path+'-moved');check(fields(s,handle=h)[2]==0)
     s.chmod(None,0o600,handle=h);check(fields(s,handle=h)[1]&0o777==0o600)
    finally:h.close()
   s.mknod('/replace',stat.S_IFIFO|0o600);put(s,'/regular',b'data');s.rename('/regular','/replace');check(read(s,'/replace')==b'data')
   s.mknod('/regular-target',stat.S_IFSOCK|0o600);s.rename('/regular-target','/replace');check(stat.S_ISSOCK(fields(s,'/replace')[1]))
   # Failed batches must roll back an earlier exchange and failed creation.
   atomic(s,lambda:s.applyat([dict(kind='rename',path='/left',target='/right',flags=2),dict(kind='mkdir',path='/left')]),errno.EEXIST)
   check(s._rpc(12)[0]==0)
  fixture.run(['e2fsck','-fn',root/'image.img']);check(fixture.sha(source)==original)
  print('PASS namespace extensions',source.name,flush=True)
 # Caller authority, umask and inherited access ACLs apply to non-data inodes.
 root=tmp/'policy';chain.clone(sources[0],root)
 with opened(root) as s:
  s.mkdir('/public',0o777);s.chmod('/public',0o777);s.mkdir('/sticky',0o1777);s.chmod('/sticky',0o1777);s.mknod('/sticky/root',stat.S_IFIFO|0o666)
  acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',t,p,i) for t,p,i in [(1,7,2**32-1),(2,4,34567),(4,7,2**32-1),(16,7,2**32-1),(32,7,2**32-1)])
  s.setxattr('/public','system.posix_acl_default',acl)
 with opened(root,Credentials(12345,23456,(),0o027)) as s:
  s.mknodat(None,'/public/user',stat.S_IFIFO|0o666);check(fields(s,'/public/user')[3:5]==(12345,23456));check(bool(s.getxattr('/public/user','system.posix_acl_access')))
  atomic(s,lambda:s.mknod('/public/denied',stat.S_IFCHR|0o600,major=1,minor=3),errno.EPERM)
  s.mknod('/public/own',stat.S_IFSOCK|0o600)
  atomic(s,lambda:s.rename('/public/own','/sticky/root',flags=2),errno.EPERM)
 fixture.run(['e2fsck','-fn',root/'image.img'])
 for kind in ('exchange','mknod'):
  for number,phase in enumerate(('record','prepared','started','half:0:0','synced','head-published')):
   root=tmp/f'fault-{kind}-{number}';chain.clone(sources[0],root)
   with opened(root) as s:put(s,'/a',b'A');put(s,'/b',b'B')
   result=subprocess.run([sys.executable,Path(__file__).resolve(),'--work',a.work,'--worker',root,kind],env=dict(os.environ,EXT4_TEST_CRASH=phase),capture_output=True,timeout=120)
   check(result.returncode==77,(kind,phase,result.stdout,result.stderr))
   with opened(root) as s:
    if kind=='exchange':check((read(s,'/a'),read(s,'/b'))==((b'A',b'B') if phase=='record' else (b'B',b'A')))
    elif phase=='record':atomic(s,lambda:s.statat(None,'/device'),errno.ENOENT)
    else:check(fields(s,'/device')[7]==259<<32|70001)
   fixture.run(['e2fsck','-fn',root/'image.img'])
(a.work/'namespace-extensions-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources)),indent=2)+'\n')
print('PASS',checks,'namespace extension checks',flush=True)
