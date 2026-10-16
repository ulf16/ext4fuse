#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native shared/private mappings, durable page writeback and cache coherence."""
import argparse,ctypes,errno,json,os,resource,shutil,signal,socket,subprocess,sys,tempfile,time
from pathlib import Path
import chain,session,journal_fixtures as fixture
from credentials import Credentials
here=Path(__file__).resolve().parent
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.restype=ctypes.c_void_p;libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong]
libc.msync.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
PAGE=os.sysconf('SC_PAGE_SIZE');SYNC=16 if sys.platform=='darwin' else 4;MAPPINGS=set()
class Mapping:
 def __init__(self,fd,size,*,private=False,writable=True):
  self.size=size;self.address=libc.mmap(None,size,1|(2 if writable else 0),2 if private else 1,fd,0)
  if self.address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),'mmap')
  MAPPINGS.add(self)
 def read(self,off,n):return ctypes.string_at(self.address+off,n)
 def write(self,off,data):ctypes.memmove(self.address+off,data,len(data))
 def sync(self):
  if libc.msync(self.address,self.size,SYNC):raise OSError(ctypes.get_errno(),'msync')
 def close(self):
  if self.address is not None:
   address,self.address=self.address,None;MAPPINGS.discard(self)
   if libc.munmap(address,self.size):raise OSError(ctypes.get_errno(),'munmap')
 def __enter__(self):return self
 def __exit__(self,*unused):self.close()

p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--sigbus-worker',type=Path);a=p.parse_args();checks=0
if a.sigbus_worker:
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));fd=os.open(a.sigbus_worker,os.O_RDWR)
 with Mapping(fd,PAGE*4) as m:
  os.ftruncate(fd,PAGE);m.read(PAGE*2,1)
 raise SystemExit('expected SIGBUS after truncate')
def check(c,detail='mapped I/O check failed'):
 global checks
 assert c,detail;checks+=1
def denied(fn,code):
 try:value=fn()
 except OSError as e:check(e.errno==code,repr(e))
 else:
  if isinstance(value,Mapping):value.close()
  raise AssertionError('unexpected mapped permission success')
def run(cmd):return fixture.run(cmd)
def unmount(m):
 command=['/sbin/umount',m] if sys.platform=='darwin' else ['fusermount3','-u',m]
 for attempt in range(20):
  r=subprocess.run(list(map(str,command)),capture_output=True,timeout=20)
  if r.returncode==0 or not os.path.ismount(m):return
  # A SIGBUS worker can leave its mapping in asynchronous kernel teardown.
  time.sleep(.25)
 raise RuntimeError('unmount failed: '+repr(r.stderr))
def control(path,name,start,length):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
  c.settimeout(45);c.connect(str(path));c.sendall(json.dumps(dict(operation='punch',path=name,offset=start,length=length)).encode()+b'\n')
  with c.makefile('rb') as stream:reply=json.loads(stream.readline(4097))
  check(reply['error']==0,reply)
sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources));base=Path(tempfile.mkdtemp(prefix='mounted-mmap-',dir=a.work));ok=False
try:
 for index,source in enumerate(sources):
  root=base/f'chain-{index}';chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   s.chmod('/',0o777)
   with s.openat(None,'/cold','rw',create=True,mode=0o600) as f:f.write(b'C'*(PAGE*2+17))
   s.chown('/cold',os.getuid(),os.getgid())
   with s.openat(None,'/cold-write-only','w',create=True,mode=0o200) as f:f.write(b'W'*(PAGE*2))
   s.chown('/cold-write-only',os.getuid(),os.getgid())
  mount=base/f'mnt-{index}';mount.mkdir();logpath=base/f'mount-{index}.log';control_path=base/f'c{index}.sock';proc=None;fds=[];active=False
  try:
   with logpath.open('wb') as log:
    proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--root',root,'--work',a.work,'--mountpoint',mount,'--control-socket',control_path],stdout=log,stderr=log)
    for unused in range(200):
     if os.path.ismount(mount):active=True;break
     if proc.poll() is not None:break
     time.sleep(.1)
    check(active,logpath.read_text())
    cold=os.open(mount/'cold',os.O_RDWR)
    try:
     with Mapping(cold,PAGE*2+17) as cm:
      check(cm.read(0,PAGE*2+17)==b'C'*(PAGE*2+17),'cold page-in failed');cm.write(PAGE-2,b'COLD');cm.sync();os.fsync(cold);check(os.pread(cold,4,PAGE-2)==b'COLD')
    finally:os.close(cold)
    # macFUSE needs a separate internal reader for cold partial-page writes.
    # That helper must never permit application reads or read mappings.
    wo=mount/'cold-write-only';wfd=os.open(wo,os.O_WRONLY);fds.append(wfd)
    def forbidden_open(flags):
     f=os.open(wo,flags);os.close(f)
    for flags in (os.O_RDONLY,os.O_RDWR):denied(lambda:forbidden_open(flags),errno.EACCES)
    denied(lambda:os.pread(wfd,1,0),errno.EBADF)
    denied(lambda:Mapping(wfd,PAGE,writable=False),errno.EACCES)
    check(os.pwrite(wfd,b'edge',PAGE-2)==4);os.fsync(wfd)
    for flags in (os.O_RDONLY,os.O_RDWR):denied(lambda:forbidden_open(flags),errno.EACCES)
    denied(lambda:os.pread(wfd,1,0),errno.EBADF)
    denied(lambda:Mapping(wfd,PAGE,writable=False),errno.EACCES)
    os.close(wfd);fds.remove(wfd);os.chmod(wo,0o600)
    rfd=os.open(wo,os.O_RDWR);fds.append(rfd)
    with Mapping(rfd,PAGE*2) as wm:
     check(wm.read(0,PAGE*2)==b'W'*(PAGE-2)+b'edge'+b'W'*(PAGE-2),'cold partial write damaged surrounding bytes')
     wm.write(12,b'MAP');wm.sync();os.fsync(rfd);check(os.pread(rfd,3,12)==b'MAP')
     os.pwrite(rfd,b'FD',20);check(wm.read(20,2)==b'FD','write-only open poisoned later mapped coherence')
    os.close(rfd);fds.remove(rfd)
    path=mount/'mapped';size=PAGE*3+137;expected=bytearray(b'A'*size)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);fds.append(fd);check(os.write(fd,expected)==size)
    other=os.open(path,os.O_RDWR);fds.append(other)
    with Mapping(fd,size) as m,Mapping(other,size) as second:
     for off,data in [(3,b'mapped'),(PAGE-3,b'cross-page'),(size-3,b'END')]:m.write(off,data);expected[off:off+len(data)]=data
     check(os.pread(other,size,0)==expected,'pread missed dirty mapping');check(second.read(0,size)==expected,'second mapping missed dirty mapping')
     os.pwrite(other,b'ordinary',PAGE+20);expected[PAGE+20:PAGE+28]=b'ordinary';check(m.read(0,size)==expected,'pwrite lost mapping coherence')
     # Reopening a dirty inode must not purge modified cached pages.
     fresh=os.open(path,os.O_RDONLY)
     try:check(os.pread(fresh,size,0)==expected)
     finally:os.close(fresh)
     peer=subprocess.run([sys.executable,'-c','import os,sys; f=os.open(sys.argv[1],os.O_RDONLY); sys.stdout.buffer.write(os.pread(f,int(sys.argv[2]),0)); os.close(f)',str(path),str(size)],capture_output=True,timeout=30)
     check(peer.returncode==0 and peer.stdout==expected,'cross-process read missed mapping')
     peer=subprocess.run([sys.executable,'-c','import mmap,os,sys; f=os.open(sys.argv[1],os.O_RDWR); m=mmap.mmap(f,0); m[60:64]=b"PEER"; m.flush(); os.fsync(f); m.close(); os.close(f)',str(path)],capture_output=True,timeout=45)
     expected[60:64]=b'PEER';check(peer.returncode==0 and m.read(0,size)==expected,'cross-process mapped write missed parent mapping')
     m.sync();os.fsync(fd);check(os.fstat(fd).st_size==size,'page writeback extended partial EOF')
     check(run(['debugfs','-R','cat /mapped',root/'image.img'])==expected,'msync did not commit image bytes')
     with Mapping(other,size,private=True) as private:
      private.write(0,b'PRIVATE');private.sync();check(private.read(0,7)==b'PRIVATE');check(m.read(0,size)==expected,'private mapping changed shared pages')
     if os.getuid()!=0:
      os.fchmod(fd,0);denied(lambda:os.open(path,os.O_RDWR),errno.EACCES)
      m.write(30,b'held');expected[30:34]=b'held';m.sync();check(os.pread(other,size,0)==expected,'permission change revoked existing mapping');os.fchmod(fd,0o600)
     m.write(50,b'prefix');expected[50:56]=b'prefix';m.write(PAGE+50,b'dirty-tail')
     os.ftruncate(fd,PAGE+37);check(m.read(0,PAGE+37)==expected[:PAGE+37]);os.ftruncate(fd,size)
     expected[PAGE+37:]=bytes(size-PAGE-37);check(m.read(0,size)==expected,'truncated bytes reappeared on growth')
     m.write(PAGE+40,b'grow');expected[PAGE+40:PAGE+44]=b'grow';m.sync();check(os.pread(other,size,0)==expected)
    with Mapping(fd,((size+PAGE-1)//PAGE)*PAGE) as tail:
     tail.write(size+10,b'outside');tail.sync();check(os.fstat(fd).st_size==size,'tail padding write extended file');check(run(['debugfs','-R','cat /mapped',root/'image.img'])==expected)
    readonly=os.open(path,os.O_RDONLY)
    try:
     with Mapping(readonly,size,writable=False) as ro:check(ro.read(0,size)==expected);ro.sync()
     denied(lambda:Mapping(readonly,size),errno.EACCES)
     with Mapping(readonly,size,private=True) as cow:cow.write(0,b'COW');cow.sync();check(os.pread(readonly,size,0)==expected)
    finally:os.close(readonly)
    # Native mapping holds the kernel file/inode after every user fd is closed.
    m=Mapping(fd,size);os.close(fd);fds.remove(fd);os.close(other);fds.remove(other)
    renamed=mount/'renamed';hard=mount/'hard';os.rename(path,renamed);os.link(renamed,hard);os.unlink(renamed)
    m.write(70,b'after-close');expected[70:81]=b'after-close';m.sync();check(hard.read_bytes()==expected)
    os.unlink(hard);m.write(90,b'unlinked');m.sync();check(m.read(90,8)==b'unlinked');m.close();check(not hard.exists())
    late=mount/'late-fault';late.write_bytes(b'L'*PAGE);lfd=os.open(late,os.O_RDWR);lm=Mapping(lfd,PAGE);os.close(lfd)
    if os.getuid()!=0:os.chmod(late,0)
    lm.write(10,b'late');lm.sync();check(lm.read(10,4)==b'late');lm.close();os.chmod(late,0o600);check(late.read_bytes()[10:14]==b'late')
    # Mapped stores ignore O_APPEND; ordinary writes continue appending.
    append=mount/'append';append.write_bytes(b'B'*(PAGE+23));afd=os.open(append,os.O_RDWR|os.O_APPEND);fds.append(afd)
    with Mapping(afd,PAGE+23) as m:
     m.write(5,b'MAP');m.sync();check(os.fstat(afd).st_size==PAGE+23,'mapped append grew file');check(os.pread(afd,3,5)==b'MAP')
     os.write(afd,b'TAIL');check(os.fstat(afd).st_size==PAGE+27);check(m.read(5,3)==b'MAP')
    os.fsync(afd);os.close(afd);fds.remove(afd)
    # Dirty pages must be drained before an out-of-band hole punch, then invalidated.
    punched=mount/'punched';pfd=os.open(punched,os.O_CREAT|os.O_RDWR,0o600);fds.append(pfd);os.write(pfd,b'P'*(PAGE*4))
    with Mapping(pfd,PAGE*4) as m:
     m.write(PAGE,b'D'*(PAGE*2));control(control_path,'/punched',PAGE,PAGE*2)
     check(m.read(PAGE,PAGE*2)==bytes(PAGE*2),'dirty pages resurrected punched data');check(os.pread(pfd,PAGE*2,PAGE)==bytes(PAGE*2));m.sync();check(os.pread(pfd,PAGE*2,PAGE)==bytes(PAGE*2))
    os.close(pfd);fds.remove(pfd)
    # Unaligned O_WRONLY updates must not require a user read grant for read-modify-write.
    wo=mount/'write-only';wo.write_bytes(b'W'*(PAGE*2));wfd=os.open(wo,os.O_WRONLY);fds.append(wfd);os.pwrite(wfd,b'edge',PAGE-2);os.fsync(wfd);os.close(wfd);fds.remove(wfd)
    check(wo.read_bytes()==b'W'*(PAGE-2)+b'edge'+b'W'*(PAGE-2))
    # The destructive SIGBUS probe is Linux-CI-only: do not launch repeated
    # Python crash reports on the user's macOS desktop.
    if sys.platform=='linux':
     bus=mount/'truncated-map';bus.write_bytes(b'Z'*(PAGE*4))
     result=subprocess.run([sys.executable,__file__,'--work',a.work,'--sigbus-worker',bus],capture_output=True,timeout=45)
     check(result.returncode==-signal.SIGBUS,repr((result.returncode,result.stdout,result.stderr)))
    unmount(mount);active=False;check(proc.wait(timeout=30)==0,logpath.read_text())
  finally:
   for mapping in list(MAPPINGS):mapping.close()
   for fd in fds:
    try:os.close(fd)
    except OSError:pass
   if active and os.path.ismount(mount):unmount(mount)
   if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=20)
  run(['e2fsck','-fn',root/'image.img'])
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   with s.open('/append') as f:check(f.size()==PAGE+27 and f.read(5,3)==b'MAP' and f.read(PAGE+23,4)==b'TAIL')
   with s.open('/punched') as f:check(f.read(PAGE,PAGE*2)==bytes(PAGE*2))
  print('PASS mounted mmap',source.name,flush=True)
 (a.work/'mounted-mmap-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources),platform=sys.platform,page_size=PAGE,sigbus_probe=sys.platform=='linux'),indent=2)+'\n');ok=True
 print('PASS',checks,'mounted mmap and coherence checks',flush=True)
finally:
 if ok:shutil.rmtree(base)
 else:print('Fixtures retained:',base,file=sys.stderr)
