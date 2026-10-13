#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Transactional metadata authorization, ACL consistency and inode lifetime."""
import argparse,errno,hashlib,json,os,shutil,stat,struct,subprocess,tempfile,time
from pathlib import Path
from unittest.mock import patch
import chain,session
from credentials import Credentials
from fault_injection import torn_replay
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int)
a=p.parse_args();fixtures=a.fixtures or a.work/'fixtures';checks=0;rows=[]
def check(v,detail='metadata check failed'):
 global checks
 assert v,detail;checks+=1
def denied(fn,code):
 try:fn()
 except OSError as e:check(e.errno==code,repr(e))
 else:raise AssertionError('unexpected metadata success')
def run(cmd):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=60);check(r.returncode==0,r.stdout+r.stderr);return r.stdout
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def acl(named=2001):
 return struct.pack('<I',2)+b''.join(struct.pack('<HHI',t,p,i) for t,p,i in [(1,6,2**32-1),(2,4,named),(4,2,2**32-1),(16,4,2**32-1),(32,0,2**32-1)])
def st(s,path=None,h=None):return struct.unpack('<8QqQqQqQqQ',s._mount_stat(path,h))
def atomic(s,fn,code):
 before=sha(s.root/'image.img');denied(fn,code);check(sha(s.root/'image.img')==before);check(not s._failed)
owner=Credentials(1001,1002,(1003,));peer=Credentials(2001,2002);rootcaller=Credentials(0,0)
sources=sorted(p for p in fixtures.glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='metadata-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for source in sources:
  original=sha(source);root=tmp/source.stem;chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',rootcaller) as s:
   s.chmod('/',0o777);s.chown('/existing-file',1001,1002);s._mount_context(owner)
   s.chmod('/existing-file',0o6750);check(st(s,'/existing-file')[1]&0o7777==0o6750)
   s.chown('/existing-file',gid=1003);check(st(s,'/existing-file')[4]==1003);check(not st(s,'/existing-file')[1]&0o6000)
   atomic(s,lambda:s.chown('/existing-file',2001),errno.EPERM)
   atomic(s,lambda:s.chown('/existing-file',gid=9999),errno.EPERM)
   s._mount_context(peer)
   for fn in [lambda:s.chmod('/existing-file',0o600),lambda:s.chown('/existing-file',2001),lambda:s.utimens('/existing-file',(1,0),(2,0)),lambda:s.setxattr('/existing-file','system.posix_acl_access',acl())]:atomic(s,fn,errno.EPERM)
   s._mount_context(owner);s.utimens('/existing-file',(-1,123456789),(2345678901,987654321))
   fields=st(s,'/existing-file');check(fields[8:12]==(-1,123456789,2345678901,987654321))
   before=fields[8:14];s.utimens('/existing-file','omit','omit');check(st(s,'/existing-file')[8:14]==before)
   s.utimens('/existing-file','omit',(123,456));check(st(s,'/existing-file')[8:12]==(-1,123456789,123,456))
   s.utimens('/existing-file');check(abs(st(s,'/existing-file')[8]-int(time.time()))<5)
   s.chmod('/existing-file',0o666);s._mount_context(peer);s.utimens('/existing-file');check(abs(st(s,'/existing-file')[10]-int(time.time()))<5)
   s.setxattr('/existing-file','user.shared',b'peer');check(s.getxattr('/existing-file','user.shared')==b'peer')
   s._mount_context(owner);s.setxattr('/existing-file','user.binary',b'a\0b\xff',1)
   check(s.getxattr('/existing-file','user.binary')==b'a\0b\xff');check(set(s.listxattrs('/existing-file'))=={'user.shared','user.binary'})
   atomic(s,lambda:s.setxattr('/existing-file','user.binary',b'x',1),errno.EEXIST)
   atomic(s,lambda:s.setxattr('/existing-file','user.missing',b'x',2),errno.ENODATA)
   atomic(s,lambda:s.removexattr('/existing-file','user.missing'),errno.ENODATA)
   s.setxattr('/existing-file','user.binary',b'',2);check(s.getxattr('/existing-file','user.binary')==b'')
   for name in ['security.capability','trusted.test','system.richacl']:
    atomic(s,lambda name=name:s.setxattr('/existing-file',name,b'x'),errno.EOPNOTSUPP)
   atomic(s,lambda:s.applyat([dict(kind='chmod',path='/existing-file',mode=0o600),dict(kind='setxattr',path='/existing-file',name='user.too-large',value_hex=(bytes(65536)).hex())]),errno.ENOSPC)
   large_acl=struct.pack('<I',2)+struct.pack('<HHI',1,6,2**32-1)+b''.join(struct.pack('<HHI',2,4,300000+i) for i in range(508))+b''.join(struct.pack('<HHI',tag,perm,2**32-1) for tag,perm in [(4,2),(16,4),(32,0)])
   atomic(s,lambda:s.setxattr('/existing-file','system.posix_acl_access',large_acl),errno.ENOSPC)
   s.setxattr('/existing-file','system.posix_acl_access',acl());check(s.getxattr('/existing-file','system.posix_acl_access')==acl());check(st(s,'/existing-file')[1]&0o777==0o640)
   s._mount_context(peer);check(bool(s.readat(None,'/existing-file')));denied(lambda:s.openat(None,'/existing-file','w'),errno.EACCES)
   s._mount_context(owner);s.chmod('/existing-file',0o600)
   changed=s.getxattr('/existing-file','system.posix_acl_access');check(changed[12:20]==acl()[12:20]);check(struct.unpack_from('<H',changed,30)[0]==0)
   s._mount_context(peer);denied(lambda:s.openat(None,'/existing-file'),errno.EACCES)
   s._mount_context(owner);s.chmod('/existing-file',0o660);s.removexattr('/existing-file','system.posix_acl_access');check(st(s,'/existing-file')[1]&0o777==0o660)
   # Malformed disk ACLs never enter the staged filesystem.
   for bad in [b'bad',struct.pack('<I',3)+acl()[4:],acl()+acl()[4:12],acl()[:12]+struct.pack('<HHI',2,4,2**32-1)+acl()[20:]]:
    atomic(s,lambda bad=bad:s.setxattr('/existing-file','system.posix_acl_access',bad),errno.EINVAL)
   minimal=struct.pack('<I',2)+b''.join(struct.pack('<HHI',t,p,2**32-1) for t,p in [(1,6),(4,4),(32,0)])
   s.setxattr('/existing-file','system.posix_acl_access',minimal);denied(lambda:s.getxattr('/existing-file','system.posix_acl_access'),errno.ENODATA);check(st(s,'/existing-file')[1]&0o777==0o640)
   s.mkdir('/acl-dir');s.setxattr('/acl-dir','system.posix_acl_default',acl())
   with s.openat(None,'/acl-dir/child','rw',create=True,mode=0o666) as child:child.write(b'child')
   check(s.getxattr('/acl-dir/child','system.posix_acl_access')==acl());check(st(s,'/acl-dir/child')[1]&0o777==0o640)
   with s.openat(None,'/acl-dir/child') as read_only:
    s.chmod(None,0o600,handle=read_only);check(st(s,h=read_only)[1]&0o777==0o600)
    s._mount_context(rootcaller);s.chown(None,gid=9999,handle=read_only);s._mount_context(owner)
    s.chmod(None,0o2770,handle=read_only);check(st(s,h=read_only)[1]&0o7777==0o770)
    s._mount_context(rootcaller);s.chown(None,gid=1002,handle=read_only);s._mount_context(owner);s.chmod(None,0o640,handle=read_only)
   atomic(s,lambda:s.setxattr('/existing-file','system.posix_acl_default',acl()),errno.EACCES)
   s.removexattr('/acl-dir','system.posix_acl_default');check(s.listxattrs('/acl-dir')==[])
   s.symlink('/existing-file','/sym');old_target=st(s,'/existing-file')[8:12]
   s.utimens('/sym',(77,123),(88,456),follow_symlinks=False);check(st(s,'/sym')[8:12]==(77,123,88,456));check(st(s,'/existing-file')[8:12]==old_target)
   atomic(s,lambda:s.chmod('/sym',0o600,follow_symlinks=False),errno.EOPNOTSUPP)
   atomic(s,lambda:s.setxattr('/sym','user.no',b'x'),errno.EOPNOTSUPP)
   # Data grants survive revocation; metadata authority never follows that grant.
   with s.openat(None,'/existing-file','rw') as f:
    s.chmod(None,0o000,handle=f);check(f.write(b'grant',0)==5);check(f.read(0,5)==b'grant')
    s._mount_context(rootcaller);s.chown(None,2001,2002,handle=f);s._mount_context(owner)
    atomic(s,lambda:s.chmod(None,0o600,handle=f),errno.EPERM);check(f.write(b'held',0)==4)
    s._mount_context(rootcaller);s.chown(None,1001,1002,handle=f);s._mount_context(owner)
    s.unlink('/existing-file');s.chmod(None,0o600,handle=f);s.utimens(None,(1,2),(3,4),handle=f)
    s.setxattr(None,'user.orphan',b'alive',handle=f);check(s.getxattr(None,'user.orphan',handle=f)==b'alive');check(st(s,h=f)[2]==0)
   denied(lambda:s.chmod(None,0o600,handle=f),errno.EBADF)
   s.mkdir('/held-dir');d=s.openat(None,'/held-dir',directory_only=True);s.rmdir('/held-dir');s.chmod(None,0o700,handle=d);check(st(s,h=d)[1]&0o777==0o700);d.close()
   with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):atomic(s,lambda:s.chmod('/acl-dir',0o711),errno.ENOSPC)
   with torn_replay() as fault:denied(lambda:s.setxattr('/acl-dir','user.recovered',b'replayed'),errno.EIO)
   check(fault['hit']);check(s.getxattr('/acl-dir','user.recovered')==b'replayed')
   s._mount_context(rootcaller);s.chown('/acl-dir',123456,234567);check(st(s,'/acl-dir')[3:5]==(123456,234567))
  run(['e2fsck','-fn',root/'image.img']);check(sha(source)==original)
  if not rows:
   for flag in (16,32):
    protected=tmp/f'protected-{flag}.img';shutil.copyfile(source,protected)
    script=tmp/'flags.commands';script.write_text(f'set_inode_field /existing-file uid 1001\nset_inode_field /existing-file gid 1002\nset_inode_field /existing-file mode 0100600\nset_inode_field /existing-file flags {flag}\n')
    run(['debugfs','-w','-f',script,protected]);protectedroot=tmp/f'protected-{flag}';chain.clone(protected,protectedroot)
    with session.Session(protectedroot,a.work/'mutation-producer',a.work/'reader-server',owner) as held:
     for fn in [lambda:held.chmod('/existing-file',0o644),lambda:held.chown('/existing-file',gid=1003),lambda:held.utimens('/existing-file'),lambda:held.setxattr('/existing-file','user.no',b'x')]:atomic(held,fn,errno.EPERM)
     before=sha(protectedroot/'image.img');held.utimens('/existing-file','omit','omit');check(sha(protectedroot/'image.img')==before)
    run(['e2fsck','-fn',protectedroot/'image.img'])
   legacy=tmp/'legacy.img'
   with legacy.open('wb') as f:f.truncate(16*1024*1024)
   run(['mke2fs','-q','-F','-t','ext2','-I','128',legacy]);legacyroot=tmp/'legacy';chain.clone(legacy,legacyroot)
   with session.Session(legacyroot,a.work/'mutation-producer',a.work/'reader-server',rootcaller) as old:
    old.chmod('/',0o777);old._mount_context(owner)
    with old.openat(None,'/time','rw',create=True) as f:f.write(b'old inode')
    old.utimens('/time',(1,0),(2,0));check(st(old,'/time')[8:12]==(1,0,2,0))
    atomic(old,lambda:old.utimens('/time',(1,1),(2,0)),errno.EOVERFLOW)
    atomic(old,lambda:old.utimens('/time',(2147483648,0),(2,0)),errno.EOVERFLOW)
    old.utimens('/time');check(st(old,'/time')[9]==st(old,'/time')[11]==0)
   run(['e2fsck','-fn',legacyroot/'image.img'])
  rows.append(dict(fixture=source.name,result='passed'));print('PASS metadata',source.name,flush=True)
(a.work/'metadata-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows),indent=2)+'\n');print('PASS',checks,'metadata checks',flush=True)
