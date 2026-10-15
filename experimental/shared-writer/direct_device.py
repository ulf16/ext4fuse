# SPDX-License-Identifier: GPL-2.0-only
"""Guarded physical I/O with sealed page redo and no persistent data shadow."""
import contextlib,os,stat,sys
from pathlib import Path
import chain,image_io,inplace,journal_recovery,live_device,merkle
from durable import regular,sync,directory,boundary
from device_admission import Device,refuse
old=live_device.offline
FIELDS={'version','identity','size','sector','uuid','phase','token_device','token_inode'}

class Stream:
 def __init__(self,view,writable):
  self.view=view;self.position=0;self.writable=writable
  self.file=os.fdopen(os.open(view.path,(os.O_RDWR if writable else os.O_RDONLY)|os.O_NOFOLLOW),'r+b' if writable else 'rb',buffering=0)
  info=os.fstat(self.file.fileno())
  if (info.st_dev,info.st_ino,info.st_size)!=(view.device,view.inode,view.target.size) or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_blocks:
   self.file.close();refuse('direct image token identity or sparse allocation changed')
 def __enter__(self):return self
 def __exit__(self,*unused):self.file.close()
 def fileno(self):return self.file.fileno()
 def readable(self):return True
 def seekable(self):return True
 def seek(self,offset,whence=0):
  position=offset+(self.position if whence==1 else self.view.target.size if whence==2 else 0)
  if whence not in (0,1,2) or not 0<=position<=self.view.target.size:raise ValueError('direct image seek outside capacity')
  self.position=position;return position
 def tell(self):return self.position
 def read(self,n=-1):
  target=self.view.target;n=target.size-self.position if n<0 else min(n,target.size-self.position)
  if not n:return b''
  start=self.position//target.sector*target.sector;end=(self.position+n+target.sector-1)//target.sector*target.sector
  data=bytearray(old.read_at(target.fd,end-start,start))
  if start<=live_device.MAGIC and live_device.MAGIC+2<=end:data[live_device.MAGIC-start:live_device.MAGIC-start+2]=b'\x53\xef'
  result=bytes(data[self.position-start:self.position-start+n]);self.position+=n;return result
 def readinto(self,buffer):
  data=self.read(len(buffer));buffer[:len(data)]=data;return len(data)
 def write_at(self,data,offset):
  if not self.writable:raise PermissionError('read-only direct device view')
  target=self.view.target;target.check();self.view.require_guard()
  if offset<0 or offset+len(data)>target.size:raise ValueError('direct write outside capacity')
  start=offset//target.sector*target.sector;end=(offset+len(data)+target.sector-1)//target.sector*target.sector
  block=bytearray(old.read_at(target.fd,end-start,start));block[offset-start:offset-start+len(data)]=data
  if start<=live_device.MAGIC and live_device.MAGIC+2<=end:block[live_device.MAGIC-start:live_device.MAGIC-start+2]=bytes(2)
  for position in range(0,len(block),target.sector):
   target.check();old.write_at(target.fd,block[position:position+target.sector],start+position)
   boundary('direct:sector-written');boundary(f'direct:sector:{(start+position)//target.sector}')
  self.view.writes+=1;os.utime(self.file.fileno(),None)
  return len(data)
 def flush_device(self):
  self.view.target.flush();self.view.flushed=self.view.writes;self.view.require_guard();boundary('direct:flushed')

class View:
 def __init__(self,path,target,require_guard):
  self.path=Path(path);self.target=target;self.require_guard=require_guard;self.writes=0;self.flushed=0
  info=os.lstat(path);self.device,self.inode=info.st_dev,info.st_ino
  raw=Path('/dev/r'+target.path.name.removeprefix('r')) if sys.platform=='darwin' else target.path
  self.read_fd=os.open(raw,os.O_RDONLY|os.O_NOFOLLOW)
  info=os.fstat(self.read_fd)
  if (info.st_dev,info.st_ino,info.st_rdev)!=target.node:os.close(self.read_fd);refuse('read-only direct descriptor identity changed')
 def open(self,writable=False):return Stream(self,writable)
 def close(self):os.close(self.read_fd)
 def config(self):
  self.target.check();info=os.fstat(self.read_fd)
  return ','.join(map(str,(self.read_fd,self.target.sector,self.target.size,self.device,self.inode,info.st_dev,info.st_ino,info.st_rdev)))

def token(path,size):
 fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.ftruncate(fd,size);sync(fd)
  if os.fstat(fd).st_blocks:refuse('recovery filesystem must support sparse identity tokens')
 finally:os.close(fd)
 directory(path.parent)

def checked(path,target,work,root,budget):
 """Full metadata fsck with sparse scratch; ordinary file contents are omitted."""
 header=journal_recovery.inspect(path)
 if header['needed']:refuse('direct mode requires native journal recovery before initialization')
 snapshot=root/'metadata-check.img'
 if snapshot.exists() or snapshot.is_symlink():
  with regular(snapshot) as saved:
   info=os.fstat(saved.fileno())
   if info.st_uid!=os.getuid() or info.st_nlink!=1:refuse('unsafe metadata scratch image')
  snapshot.unlink();directory(root)
 options=image_io.child(path)
 result,output=journal_recovery.command([Path(work)/'metadata-snapshot',path,snapshot,budget],options['env'],pass_fds=options.get('pass_fds',()))
 if result:raise OSError('metadata snapshot failed: '+output.decode(errors='replace')[-2048:])
 result,output=journal_recovery.command([journal_recovery.tool('e2fsck'),'-fn',snapshot],dict(os.environ,LC_ALL='C',E2FSCK_CONFIG='/dev/null'))
 if result:raise OSError('direct filesystem did not pass read-only metadata check: '+output.decode(errors='replace')[-2048:])
 used=os.stat(snapshot).st_blocks*512;snapshot.unlink();directory(root)
 boundary('direct:checked')
 return header['uuid'],used

def budget_check(value):
 if type(value) is not int or not 4096<=value<=2**40:raise ValueError('metadata scratch budget must be 4 KiB..1 TiB')

def init(device,root,work,*,check_bytes=1024**3):
 budget_check(check_bytes)
 root=inplace.block.canonical(root);root.mkdir(mode=0o700);directory(root.parent)
 with old.locked(root),Device(device,root) as target:
  if live_device.magic(target)!=b'\x53\xef':refuse('initial direct device must have intact ext4 magic')
  baseline=live_device.scan(target)
  managed=root/'chain';managed.mkdir(mode=0o700);directory(root);path=managed/'image.img';token(path,target.size)
  view=View(path,target,lambda:refuse('initialization cannot write device'))
  try:
   with image_io.register(path,view):
    uuid,_=checked(path,target,work,root,check_bytes)
    if live_device.scan(target).root()!=baseline.root() or live_device.magic(target)!=b'\x53\xef':refuse('direct source changed during admission')
    info=os.lstat(path)
    inplace.seal(managed,'chain-state',dict(version=2,algorithm=merkle.ALGORITHM,head=0,pending=None,sha256=baseline.root(),device=info.st_dev,inode=info.st_ino,size=target.size))
    inplace.seal(root,'direct-state',dict(version=1,identity=target.identity,size=target.size,sector=target.sector,uuid=uuid,phase='clean',token_device=info.st_dev,token_inode=info.st_ino))
  finally:view.close()
 return root

class Controller:
 def __init__(self,root,device,work,*,check_bytes=1024**3):
  budget_check(check_bytes)
  self.root=Path(root);self.path=device;self.work=Path(work);self.check_bytes=check_bytes;self.failed=False;self.head=None
 def seal(self,**changes):
  self.state=dict(self.state,**changes);inplace.seal(self.root,'direct-state',self.state)
 def require_guard(self):
  self.target.check()
  if live_device.magic(self.target)!=bytes(2):refuse('direct device guard changed')
 def __enter__(self):
  self.stack=contextlib.ExitStack()
  try:
   self.root=self.stack.enter_context(old.locked(self.root));self.chain=self.root/'chain'
   self.target=self.stack.enter_context(Device(self.path,self.root));self.state=old.load(self.root,'direct-state')
   s=self.state
   if not isinstance(s,dict) or set(s)!=FIELDS or type(s['version']) is not int or s['version']!=1 or (s['identity'],s['size'],s['sector'])!=(self.target.identity,self.target.size,self.target.sector) or s['phase'] not in ('clean','arming','active','closing') or not isinstance(s['uuid'],str) or len(s['uuid'])!=32:
    refuse('invalid direct target state or identity')
   info=os.lstat(self.chain/'image.img')
   if (info.st_dev,info.st_ino)!=(s['token_device'],s['token_inode']):refuse('direct token replaced')
   if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_blocks or info.st_size!=self.target.size or info.st_mode&0o077):refuse('invalid sparse direct identity token')
   current=chain.read_state(self.chain)
   if (current['device'],current['inode'],current['size'])!=(info.st_dev,info.st_ino,self.target.size):refuse('direct chain token identity changed')
   if any(type(s[k]) is not int or s[k]<0 for k in ('size','sector','token_device','token_inode')) or any(c not in '0123456789abcdef' for c in s['uuid']) or s['uuid']=='0'*32:refuse('invalid direct state fields')
   if current['version']!=2 or current['algorithm']!=merkle.ALGORITHM:refuse('direct chain version changed')
   if s['phase']!='active':
    if current['pending'] is not None:refuse('pending direct transaction without active guard')
    if s['phase']=='clean' and live_device.magic(self.target)!=b'\x53\xef':refuse('clean direct device was changed')
    if live_device.scan(self.target).root()!=current['sha256']:refuse('direct device changed outside recovery')
    view=live_device.DeviceView(self.target);view.seek(0);sb=view.read(4096)[1024:2048]
    if sb[104:120].hex()!=s['uuid'] or int.from_bytes(sb[58:60],'little')!=1 or int.from_bytes(sb[96:100],'little')&4:refuse('direct source identity or clean state changed')
    self.seal(phase='arming');boundary('direct:arming')
    live_device.guard(self.target);self.seal(phase='active');boundary('direct:active')
   self.require_guard()
   self.view=View(self.chain/'image.img',self.target,self.require_guard);self.stack.callback(self.view.close)
   self.stack.enter_context(image_io.register(self.chain/'image.img',self.view))
   return self
  except BaseException:self.stack.close();raise
 def __exit__(self,*unused):self.stack.close()
 def recover(self,current):
  self.require_guard()
  if live_device.scan(self.target).root()!=current['sha256']:refuse('recovered direct device differs from chain')
  header=journal_recovery.inspect(self.chain/'image.img')
  if header['needed'] or header['uuid']!=self.state['uuid']:refuse('direct device needs native journal recovery or changed identity')
  self.head=(current['head'],current['sha256']);boundary('direct:recovered')
 def before_request(self):
  if self.failed:refuse('failed direct session requires recovery')
  self.require_guard()
 def publish(self,previous,current):
  try:
   self.require_guard()
   if self.head!=(previous['head'],previous['sha256']) or current['head']!=previous['head']+1 or chain.read_state(self.chain)!=current or self.view.flushed!=self.view.writes:refuse('direct publication is unflushed or has a stale head')
   self.head=(current['head'],current['sha256']);boundary('direct:acknowledge-ready')
  except BaseException:self.failed=True;raise
 def checkpoint(self,current):
  if self.failed:refuse('failed direct session requires recovery')
  self.require_guard()
  if chain.read_state(self.chain)!=current or current['pending'] is not None or live_device.scan(self.target).root()!=current['sha256']:refuse('direct checkpoint changed or outstanding transaction')
  boundary('direct:checkpoint-verified')
 def abort(self):self.failed=True
 def finish(self):
  if self.failed:refuse('failed direct session must keep device guarded')
  with chain.locked(self.chain):
   current=chain.recover_locked(self.chain);self.recover(current)
   uuid,_=checked(self.chain/'image.img',self.target,self.work,self.root,self.check_bytes)
   if uuid!=self.state['uuid']:refuse('direct filesystem identity changed')
   self.checkpoint(current);self.seal(phase='closing');boundary('direct:closing')
   start=live_device.MAGIC//self.target.sector*self.target.sector;data=bytearray(old.read_at(self.target.fd,self.target.sector,start));at=live_device.MAGIC-start;data[at:at+2]=b'\x53\xef'
   old.write_at(self.target.fd,data,start);self.target.flush();boundary('direct:magic-restored')
   if live_device.magic(self.target)!=b'\x53\xef' or live_device.scan(self.target).root()!=current['sha256']:refuse('direct clean publication changed')
   self.seal(phase='clean');boundary('direct:closed')
