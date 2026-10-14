#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Kernel lookup/open lifetime, identity pins and inode-only mutation protocol."""
import argparse,errno,hashlib,importlib.util,json,os,struct,subprocess,tempfile
from unittest.mock import patch
from pathlib import Path
import chain,session
from credentials import Credentials
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('mount_broker',here/'mount-broker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int);a=p.parse_args();checks=0

def check(v,detail='low-level broker check failed'):
 global checks
 assert v,detail;checks+=1

def denied(fn,code):
 try:fn()
 except OSError as e:check(e.errno==code,repr(e))
 else:raise AssertionError('unsafe low-level request accepted')

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='lowlevel-broker-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sources):
  original=sha(source);root=tmp/str(index);chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),checkpoint_every=3) as s:
   s.chmod('/',0o777);s.chown('/',os.getuid(),os.getgid())
   s.chmod('/',0)
   b=m.LowBroker(s)
   def call(op,ino=1,path=b'',data=b'',fh=0,arg=0,uid=None):
    return b.dispatch(op,path,data,os.getuid() if uid is None else uid,os.getgid(),0o022,os.getgroups(),ino,fh,arg)
   check(call(100,ino=0)==(0,b''))
   check(struct.unpack_from('<Q',call(103)[1],8)[0]&0o777==0)
   denied(lambda:call(101,path=b'.'),errno.EACCES)
   s.chmod('/',0o777)
   denied(lambda:call(100,ino=0),errno.EPERM)
   denied(lambda:call(101,path=b'.',uid=os.getuid()+1),errno.EACCES)
   node,entry=call(105,path=b'file',arg=(0o666<<32)|os.O_RDWR|os.O_CREAT|os.O_EXCL)
   fh=struct.unpack_from('<Q',entry)[0]
   check(len(entry)==144);check(call(107,node,data=b'abc',fh=fh)==(3,b''))
   check(call(106,node,data=struct.pack('<Q',8),fh=fh)[1]==b'abc')
   denied(lambda:call(106,node,data=b'bad',fh=fh),errno.EINVAL)
   denied(lambda:call(104,node,data=b'unexpected'),errno.EINVAL)
   lookup,raw=call(101,path=b'file');check(lookup==node and b.node(node)['lookups']==2)
   linked,raw=call(117,node,path=b'alias',arg=1);check(linked==node and b.node(node)['lookups']==3)
   call(115,path=b'file');check(struct.unpack_from('<Q',call(103,node)[1],16)[0]==1)
   call(115,path=b'alias');check(struct.unpack_from('<Q',call(103,node)[1],16)[0]==0)
   with s.opendir('/') as listing:check(not any(n.startswith('.fuse_hidden') for n in listing.listdir()))
   call(102,node,arg=3);check(node in b.nodes and b.node(node)['lookups']==0)
   check(call(106,node,data=struct.pack('<Q',8),fh=fh)[1]==b'abc')
   call(107,node,data=b'!',fh=fh,arg=2);check(call(106,node,data=struct.pack('<Q',8),fh=fh)[1]==b'ab!')
   payload=struct.pack('<IIQQQqQqQ',1|16|32,0o640,0,0,0,1,2,3,4)
   call(108,node,data=payload,fh=fh);check(struct.unpack_from('<Q',call(103,node,fh=fh)[1],8)[0]&0o777==0o640)
   call(109,node,fh=fh);check(node not in b.nodes);denied(lambda:call(103,node),errno.ESTALE)
   check(s._rpc(12)[0]==0)
   # Metadata-only pins must never confer file-data rights.
   n,entry=call(105,path=b'closed',arg=(0o600<<32)|os.O_RDWR|os.O_CREAT);f=struct.unpack_from('<Q',entry)[0];call(109,n,fh=f)
   denied(lambda:s._rpc(8,s._file(b.node(n)['handle']),0,1),errno.EBADF)
   payload=struct.pack('<IIQQQqQqQ',1,0,0,0,0,0,0,0,0);call(108,n,data=payload)
   denied(lambda:call(104,n,arg=os.O_RDONLY),errno.EACCES)
   payload=struct.pack('<IIQQQqQqQ',1,0o600,0,0,0,0,0,0,0);call(108,n,data=payload)
   # A combined setattr is atomic: an invalid uid cannot leave a truncate.
   before,head=sha(root/'image.img'),s.state['head']
   payload=struct.pack('<IIQQQqQqQ',8|2,0,2**32,0,7,0,0,0,0)
   try:call(108,n,data=payload)
   except (ValueError,OSError):check(True)
   else:raise AssertionError('invalid combined setattr accepted')
   check(s.state['head']==head and sha(root/'image.img')==before)
   call(102,n,arg=1);denied(lambda:call(103,n),errno.ESTALE)
   n2,_=call(101,path=b'closed');check(n2!=n)
   denied(lambda:call(102,n2,arg=2),errno.EINVAL);check(b.node(n2)['lookups']==1)
   # A name-free inode pin survives removal even without an open data handle.
   call(115,path=b'closed');check(s._rpc(12)[0]!=0);check(struct.unpack_from('<Q',call(103,n2)[1],16)[0]==0)
   call(102,n2,arg=1);check(s._rpc(12)[0]==0)
   # Empty removed directories and their removed ancestors remain addressable.
   parent,_=call(113,path=b'parent',arg=0o777)
   child,_=call(113,parent,path=b'child',arg=0o777)
   call(114,parent,path=b'child');call(114,path=b'parent')
   call(102,parent,arg=1);check(parent not in b.nodes)
   up,_=call(101,child,path=b'..');check(up!=parent)
   check(struct.unpack_from('<Q',call(103,up)[1],16)[0]==0)
   check(struct.unpack_from('<Q',call(103,child)[1],16)[0]==0)
   denied(lambda:call(105,child,path=b'new',arg=(0o600<<32)|os.O_RDWR|os.O_CREAT),errno.ENOENT)
   call(102,up,arg=1);call(102,child,arg=1);check(s._rpc(12)[0]==0)
   # Symlink lookup pins belong to the same durable orphan protocol.
   link,_=call(118,path=b'link',data=b'/existing-file')
   check(call(119,link)[1]==b'/existing-file')
   copy,_=call(117,link,path=b'link-copy',arg=1);check(copy==link)
   call(115,path=b'link');call(115,path=b'link-copy')
   check(call(119,link)[1]==b'/existing-file');call(102,link,arg=2);check(s._rpc(12)[0]==0)
   # New-node exhaustion must precede a mutation; existing lookup still works.
   old_limit=b.NODE_LIMIT;b.NODE_LIMIT=len(b.nodes)
   before,head=sha(root/'image.img'),s.state['head']
   denied(lambda:call(113,path=b'over-limit',arg=0o777),errno.EMFILE)
   check(s.state['head']==head and sha(root/'image.img')==before)
   same,_=call(101,path=b'.');check(same==1)
   b.NODE_LIMIT=old_limit
   # Attribute failure before an entry reply balances references and open slots.
   with patch.object(b,'entry',side_effect=OSError(errno.EIO,'bad entry attributes')):
    denied(lambda:call(105,path=b'failed-reply',arg=(0o600<<32)|os.O_RDWR|os.O_CREAT),errno.EIO)
   check(not b.handles and not b.bindings and len(b.nodes)==1)
   # The durable create may exist after a failed reply, but no invisible handle
   # or lookup reference is leaked. Its name can be looked up afresh.
   created,_=call(101,path=b'failed-reply');call(102,created,arg=1)
   # More than 128 lookup pins do not consume any of the 128 open slots.
   if index==0:
    for start in range(0,140,64):s.applyat([dict(kind='create',path=f'/pool-{i}',data_hex='') for i in range(start,min(start+64,140))])
    pool=[call(101,path=f'pool-{i}'.encode())[0] for i in range(140)]
    check(len(pool)==len(set(pool))==140)
    readfh,_=call(104,pool[0],arg=os.O_RDONLY);call(109,pool[0],fh=readfh)
    for ino in pool:call(102,ino,arg=1)
    check(len(b.nodes)==1)
  run=subprocess.run(['e2fsck','-fn',str(root/'image.img')],capture_output=True);check(run.returncode==0,run.stdout+run.stderr)
  check(sha(source)==original);print('PASS low-level broker',source.name,flush=True)
(a.work/'lowlevel-broker-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources)),indent=2)+'\n');print('PASS',checks,'low-level broker checks',flush=True)
