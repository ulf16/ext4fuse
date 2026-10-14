#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real kernel advisory locks and native allocation/punch syscalls on FUSE."""
import argparse,ctypes,errno,fcntl,json,os,re,select,shutil,signal,socket,subprocess,sys,tempfile,time
from pathlib import Path
import chain
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0;here=Path(__file__).resolve().parent

def check(v,detail='mounted allocation/lock check failed'):
 global checks
 assert v,detail;checks+=1
def run(args):return subprocess.check_output(list(map(str,args)),stderr=subprocess.PIPE,timeout=90)
def unmount(mount,force=False):run((['/sbin/umount']+(['-f'] if force else [])+[mount]) if sys.platform=='darwin' else ['fusermount3','-uz' if force else '-u',mount])
def peer(path,kind='posix',shared=False,start=0,length=10,write=False):
 code='''import errno,fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
 if sys.argv[2]=='posix':fcntl.lockf(fd,(fcntl.LOCK_SH if int(sys.argv[3]) else fcntl.LOCK_EX)|fcntl.LOCK_NB,int(sys.argv[5]),int(sys.argv[4]))
 else:fcntl.flock(fd,(fcntl.LOCK_SH if int(sys.argv[3]) else fcntl.LOCK_EX)|fcntl.LOCK_NB)
except OSError as e:
 assert e.errno in (errno.EAGAIN,errno.EACCES);print('conflict')
else:print('acquired')
if int(sys.argv[6]):os.pwrite(fd,b'Z',0)
os.close(fd)
'''
 return run([sys.executable,'-c',code,path,kind,int(shared),start,length,int(write)]).decode().strip()
def allocate(fd,start,length,mode):
 if sys.platform=='linux':
  libc=ctypes.CDLL(None,use_errno=True);f=libc.fallocate;f.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_longlong,ctypes.c_longlong]
  if f(fd,mode,start,length):raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
 else:
  if mode==3:fcntl.fcntl(fd,99,bytes(ctypes.c_uint32(0))+bytes(ctypes.c_uint32(0))+bytes(ctypes.c_int64(start))+bytes(ctypes.c_int64(length)))
  elif mode==1:
   class Store(ctypes.Structure):_fields_=[('flags',ctypes.c_uint),('position',ctypes.c_int),('offset',ctypes.c_int64),('length',ctypes.c_int64),('allocated',ctypes.c_int64)]
   # Darwin's preallocation API allocates beyond physical EOF, keeping size.
   fcntl.fcntl(fd,42,bytes(Store(4,3,0,length,0)))
  else:raise ValueError('Darwin uses preallocation then explicit size changes')

with tempfile.TemporaryDirectory(prefix='mounted-allocation-locks-',dir=a.work) as tmp:
 tmp=Path(tmp);source=a.work/'fixtures/4096-extents-csum1.img';seed=tmp/'seed.img';shutil.copyfile(source,seed)
 commands=tmp/'seed.commands';commands.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n');run(['debugfs','-w','-f',commands,seed])
 root=tmp/'chain';chain.clone(seed,root);mount=tmp/'mount';mount.mkdir();log=(tmp/'mount.log').open('wb');active=False;proc=None;fds=[];child=None
 try:
  proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount,'--control-socket',tmp/'control.sock'],stdout=log,stderr=log,start_new_session=True)
  for unused in range(180):
   if os.path.ismount(mount):active=True;break
   if proc.poll() is not None:break
   time.sleep(.1)
  check(active,(tmp/'mount.log').read_text())
  path=mount/'file';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600);fds.append(fd);data=b'A'*32768;os.write(fd,data)
  fcntl.lockf(fd,fcntl.LOCK_EX,10,20);check(peer(path,start=20)=='conflict');check(peer(path,start=0)=='acquired');check(peer(path,start=20,write=True)=='conflict');check(os.pread(fd,1,0)==b'Z')
  # F_GETLK reports the competing process and exact byte range.
  class Lock(ctypes.Structure):
   _fields_=([('start',ctypes.c_int64),('length',ctypes.c_int64),('pid',ctypes.c_int),('type',ctypes.c_short),('whence',ctypes.c_short)] if sys.platform=='darwin' else [('type',ctypes.c_short),('whence',ctypes.c_short),('start',ctypes.c_int64),('length',ctypes.c_int64),('pid',ctypes.c_int)])
  query='''import ctypes,fcntl,os,sys
fields=[('start',ctypes.c_int64),('length',ctypes.c_int64),('pid',ctypes.c_int),('type',ctypes.c_short),('whence',ctypes.c_short)] if sys.platform=='darwin' else [('type',ctypes.c_short),('whence',ctypes.c_short),('start',ctypes.c_int64),('length',ctypes.c_int64),('pid',ctypes.c_int)]
class Lock(ctypes.Structure):_fields_=fields
l=Lock();l.type=fcntl.F_WRLCK;l.whence=os.SEEK_SET;l.start=20;l.length=10
fd=os.open(sys.argv[1],os.O_RDWR);r=Lock.from_buffer_copy(fcntl.fcntl(fd,fcntl.F_GETLK,bytes(l)));assert r.type==fcntl.F_WRLCK and r.pid==int(sys.argv[2]) and r.start==20 and r.length==10
'''
  run([sys.executable,'-c',query,path,os.getpid()]);check(True)
  hard=mount/'hard';os.link(path,hard);check(peer(hard,start=20)=='conflict');renamed=mount/'renamed';os.rename(path,renamed);check(peer(renamed,start=20)=='conflict')
  fcntl.lockf(fd,fcntl.LOCK_UN,5,23);check(peer(hard,start=23,length=5)=='acquired');check(peer(hard,start=20,length=3)=='conflict')
  fcntl.lockf(fd,fcntl.LOCK_UN);fcntl.lockf(fd,fcntl.LOCK_SH,0);check(peer(hard,shared=True)=='acquired');check(peer(hard)=='conflict')
  other=os.open(hard,os.O_RDWR);os.close(other);check(peer(hard)=='acquired') # Any close releases process POSIX locks.
  # Blocking waits must not stall ordinary FUSE traffic. Killing a waiter must
  # cancel it; a second waiter acquires after the holder explicitly unlocks.
  for kind in ('posix','flock'):
   take=(lambda op:fcntl.lockf(fd,op)) if kind=='posix' else (lambda op:fcntl.flock(fd,op))
   take(fcntl.LOCK_EX)
   code='''import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR);print('ready',flush=True)
(fcntl.lockf if sys.argv[2]=='posix' else fcntl.flock)(fd,fcntl.LOCK_EX)
print('acquired',flush=True);os.close(fd)
'''
   for killed in (True,False):
    child=subprocess.Popen([sys.executable,'-c',code,hard,kind],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    check(child.stdout.readline().strip()=='ready');check(not select.select([child.stdout],[],[],.2)[0])
    check(os.pread(fd,1,0)==b'Z');(mount/'unrelated').write_bytes(b'lock waits do not stall writes')
    if killed:child.kill();check(child.wait(timeout=10)==-signal.SIGKILL)
    else:take(fcntl.LOCK_UN);out,error=child.communicate(timeout=10);check(child.returncode==0 and out.strip()=='acquired',(out,error))
    child=None
  fcntl.flock(fd,fcntl.LOCK_EX);duplicate=os.dup(fd);os.close(fd);fds.remove(fd);fd=duplicate;fds.append(fd);check(peer(hard,kind='flock')=='conflict');fcntl.flock(fd,fcntl.LOCK_UN)
  # Native syscalls reach the transactional allocation backend.
  size=os.fstat(fd).st_size;oldblocks=os.fstat(fd).st_blocks;allocate(fd,0,65536,1)
  check(os.fstat(fd).st_size==size);check(os.fstat(fd).st_blocks>=oldblocks);check(os.pread(fd,size,0)==b'Z'+data[1:])
  if sys.platform=='linux':allocate(fd,65536,4096,0);check(os.fstat(fd).st_size==69632);check(os.pread(fd,4096,65536)==bytes(4096))
  before=os.fstat(fd).st_blocks
  def disk_blocks():return int(re.search(rb'Blockcount: (\d+)',run(['debugfs','-R','stat /hard',root/'image.img'])).group(1))
  allocated_before=disk_blocks()
  if sys.platform=='linux':
   allocate(fd,4096,16384,3);check(os.fstat(fd).st_blocks<before,(before,os.fstat(fd).st_blocks));check(os.pread(fd,16384,4096)==bytes(16384));check(os.pread(fd,1,0)==b'Z');check(os.pread(fd,1,20480)==b'A')
  else:
   try:allocate(fd,4096,16384,3)
   except OSError as e:check(e.errno in (errno.ENOTSUP,errno.EOPNOTSUPP,errno.ENOTTY))
   else:raise AssertionError('macFUSE native hole-punch transport changed: require success checks')
   check(os.fstat(fd).st_blocks==before);check(os.pread(fd,size,0)==b'Z'+data[1:])
   run([sys.executable,here/'mount-control.py','--socket',tmp/'control.sock','punch','/hard',4096,16384])
   check(disk_blocks()==allocated_before-32);
   check(os.pread(fd,16384,4096)==bytes(16384));check(os.pread(fd,1,0)==b'Z');check(os.pread(fd,1,20480)==b'A')
  run([sys.executable,here/'mount-control.py','--socket',tmp/'control.sock','punch','/hard',20480,4096])
  check(os.pread(fd,4096,20480)==bytes(4096))
  # Invalid control frames must not mutate data or stop the mount.
  for request in (dict(operation='punch',path='/hard',offset=-1,length=10),dict(operation='bad',path='/hard',offset=0,length=10)):
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
    client.settimeout(10);client.connect(str(tmp/'control.sock'));client.sendall(json.dumps(request).encode()+b'\n')
    with client.makefile('rb') as stream:reply=json.loads(stream.readline(4097))
    check(reply['error']==errno.EINVAL)
  check(os.pread(fd,1,0)==b'Z')
  # Lifetime continues through unlink and lock owner cleanup on last close.
  os.unlink(hard);os.unlink(renamed);check(os.fstat(fd).st_nlink==0)
  if sys.platform=='linux':allocate(fd,20480,4096,3);check(os.pread(fd,4096,20480)==bytes(4096))
  os.close(fd);fds.remove(fd)
  unmount(mount);active=False;check(proc.wait(timeout=30)==0);proc=None
  run(['e2fsck','-fn',root/'image.img'])
 finally:
  if child and child.poll() is None:child.kill();child.wait(timeout=10)
  for fd in fds:
   try:os.close(fd)
   except OSError:pass
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=15)
  if active:unmount(mount,True)
  log.close()
  if sys.exc_info()[0]:print((tmp/'mount.log').read_text(),file=sys.stderr)
(a.work/'mounted-allocation-locks-results.json').write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform,native_hole_punch=sys.platform=='linux',native_block_reporting=sys.platform=='linux'),indent=2)+'\n');print('PASS',checks,'mounted allocation and lock checks')
