#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native inheritance transaction, authority, propagation and recovery tests."""
import argparse,errno,hashlib,importlib.util,json,shutil,struct,subprocess,tempfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import chain,native_acl as n,session
from credentials import Credentials
from fault_injection import torn_replay
spec=importlib.util.spec_from_file_location('mount_broker',Path(__file__).with_name('mount-broker.py'))
broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int);a=p.parse_args();checks=0;rows=[]
def check(v):
 global checks
 assert v;checks+=1
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def denied(fn,code):
 try:fn()
 except OSError as e:check(e.errno==code)
 else:raise AssertionError('unexpected success')
def atomic(s,fn,code):
 before=sha(s.root/'image.img');denied(fn,code);check(sha(s.root/'image.img')==before)
def mode(s,path):return struct.unpack_from('<Q',s._mount_stat(path),8)[0]&0o777
def policy(kind,bits):return n.POLICY_MAGIC+struct.pack('<I',1)+struct.pack('<IIII',2,2001,kind,bits)
def raw_acl():return struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in [(1,7,2**32-1),(2,4,2001),(4,0,2**32-1),(16,4,2**32-1),(32,0,2**32-1)])
owner=Credentials(1001,1002,(),0o077);peer=Credentials(2001,2002,(),0o077);root=Credentials(0,0)
sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='native-inherit-',dir=a.work) as tmp:
 for source in sources:
  before=sha(source);managed=Path(tmp)/source.stem
  seed=Path(tmp)/(source.stem+'-seed.img');shutil.copyfile(source,seed)
  payload=Path(tmp)/'legacy.policy';payload.write_bytes(policy(1,2))
  commands=Path(tmp)/'legacy.commands';commands.write_text(f'mkdir /legacy\nset_inode_field /legacy uid 1001\nset_inode_field /legacy mode 040777\nea_set -f {payload} /legacy {n.LEGACY_KEY}\nset_inode_field /existing-file uid 1001\nea_set -f {payload} /existing-file {n.LEGACY_KEY}\n')
  result=subprocess.run(['debugfs','-w','-f',commands,seed],capture_output=True);check(result.returncode==0)
  chain.clone(seed,managed)
  with session.Session(managed,a.work/'mutation-producer',a.work/'reader-server',root) as s:
   s.chmod('/',0o777);s._mount_context(owner)
   check(s.getxattr('/legacy',n.LEGACY_KEY)==policy(1,2))
   atomic(s,lambda:s.openat(None,'/legacy/rejected','w',create=True,mode=0o600),errno.EOPNOTSUPP)
   b=broker.Broker(s)
   with patch.object(n,'Membership',return_value=SimpleNamespace(resolve=None)):
    atomic(s,lambda:b.native_get('/legacy'),errno.EOPNOTSUPP)
    atomic(s,lambda:b.native_set('/legacy',n.pack_native([])),errno.EOPNOTSUPP)
   s._mount_context(peer);atomic(s,lambda:s.removexattr('/legacy',n.LEGACY_KEY),errno.EPERM)
   s._mount_context(owner);s.removexattr('/legacy',n.LEGACY_KEY);s.removexattr('/existing-file',n.LEGACY_KEY)
   with patch.object(n,'Membership',return_value=SimpleNamespace(resolve=None)):
    denied(lambda:b.native_get('/legacy'),errno.ENODATA)
   h=s.openat(None,'/legacy/cleaned','w',create=True,mode=0o600);h.close()
   s.mkdirat(None,'/parent',0o700)
   s.setxattr('/parent',n.INHERIT_KEY,policy(1,2))
   check(n.INHERIT_KEY in s.listxattrs('/parent'))
   atomic(s,lambda:s.setxattr('/parent',n.LEGACY_KEY,policy(1,2)),errno.EOPNOTSUPP)
   h=s.openat(None,'/parent/file','w',create=True,exclusive=True,mode=0o200);h.write(b'inherited');h.close()
   check(mode(s,'/parent/file')==0o240);check((2,4,2001) in n.posix(s.getxattr('/parent/file','system.posix_acl_access')))
   s.mkdirat(None,'/parent/sub',0o700);check(mode(s,'/parent/sub')==0o740)
   check(s.getxattr('/parent/sub',n.INHERIT_KEY)==policy(1,2))
   h=s.openat(None,'/parent/sub/grand','w',create=True,mode=0o200);h.write(b'grandchild');h.close();check(mode(s,'/parent/sub/grand')==0o240)
   s.symlinkat(b'file',None,'/parent/link');denied(lambda:s.getxattr('/parent/link','system.posix_acl_access'),errno.ENODATA)
   # Grant search on the containing directory independently of inheritance.
   s.chmod('/parent',0o711);s._mount_context(peer);check(s.readat(None,'/parent/file')==b'inherited')
   s._mount_context(owner);s.chmod('/parent/file',0o200);s._mount_context(peer);denied(lambda:s.readat(None,'/parent/file'),errno.EACCES)
   s._mount_context(owner);check(s.getxattr('/parent',n.INHERIT_KEY)==policy(1,2))
   # A native named grant plus unequal group/other fallback cannot always be
   # represented by a single POSIX named-user entry. Reject before creation.
   s._mount_context(Credentials(1001,1002,(),0));atomic(s,lambda:s.openat(None,'/parent/bad','w',create=True,mode=0o620),errno.EOPNOTSUPP)
   denied(lambda:s._mount_stat('/parent/bad'),errno.ENOENT)
   s._mount_context(owner);atomic(s,lambda:s.setxattr('/parent',n.INHERIT_KEY,b'bad'),errno.EIO)
   atomic(s,lambda:s.setxattr('/parent','system.posix_acl_default',raw_acl()),errno.EOPNOTSUPP)
   atomic(s,lambda:s.setxattr('/parent/file',n.INHERIT_KEY,policy(1,2)),errno.EACCES)
   s.chmod('/parent',0o777);s._mount_context(peer)
   atomic(s,lambda:s.setxattr('/parent',n.INHERIT_KEY,policy(2,n.DATA|64)),errno.EPERM)
   # Alias: the named UID becomes the child's owner. Owner-role conversion is
   # evaluated again, rather than reusing the parent's identity assumptions.
   h=s.openat(None,'/parent/alias','w',create=True,mode=0o200);h.write(b'alias');h.close();check(mode(s,'/parent/alias')==0o600)
   check(s.readat(None,'/parent/alias')==b'alias')
   s._mount_context(owner);old_mode=mode(s,'/parent')
   atomic(s,lambda:s.applyat([dict(kind='setxattr',path='/parent',name='system.posix_acl_access',value_hex=raw_acl().hex()),dict(kind='setxattr',path='/parent',name=n.INHERIT_KEY,value_hex=b'bad'.hex())]),errno.EIO)
   check(mode(s,'/parent')==old_mode);denied(lambda:s.getxattr('/parent','system.posix_acl_access'),errno.ENODATA)
   # Real half-page durable replay: both ACL components recover together.
   with torn_replay() as fault:
    denied(lambda:s.applyat([dict(kind='setxattr',path='/parent',name='system.posix_acl_access',value_hex=raw_acl().hex()),dict(kind='setxattr',path='/parent',name=n.INHERIT_KEY,value_hex=policy(2,n.DATA|64).hex())]),errno.EIO)
   check(fault['hit']);check(s.getxattr('/parent',n.INHERIT_KEY)==policy(2,n.DATA|64));check(s.getxattr('/parent','system.posix_acl_access')==raw_acl())
   h=s.openat(None,'/parent/denied','w',create=True,mode=0o600);h.write(b'denied');h.close()
   check((2,0,2001) in n.posix(s.getxattr('/parent/denied','system.posix_acl_access')))
   s.removexattr('/parent',n.INHERIT_KEY);s.setxattr('/parent','system.posix_acl_default',raw_acl())
   atomic(s,lambda:s.setxattr('/parent',n.INHERIT_KEY,policy(1,2)),errno.EOPNOTSUPP)
  r=subprocess.run(['e2fsck','-fn',managed/'image.img'],capture_output=True);check(r.returncode==0);check(sha(source)==before);rows.append(dict(fixture=source.name,result='passed'));print('PASS native inheritance transactions',source.name,flush=True)
(a.work/'native-inherit-transactions.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows),indent=2)+'\n');print('PASS',checks,'native inheritance transaction checks')
