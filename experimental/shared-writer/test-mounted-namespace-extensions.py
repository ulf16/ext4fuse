#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native rename flags, FIFO/socket traffic and nodev special inode metadata."""
import argparse,ctypes,errno,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
import chain,session,journal_fixtures as fixture
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--allow-device-nodes',action='store_true');p.add_argument('--probe-host-io',action='store_true');p.add_argument('--result-name',default='mounted-namespace-extensions-results.json');a=p.parse_args();here=Path(__file__).resolve().parent;checks=0;fifo_io=True;fifo_errno=None;device_errno=None;device_io=None
libc=ctypes.CDLL(None,use_errno=True)
if sys.platform=='darwin':
 native=libc.renamex_np;native.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint]
 def rename(old,new,flags):
  if native(os.fsencode(old),os.fsencode(new),{1:4,2:2,3:6}[flags]):raise OSError(ctypes.get_errno(),'renamex_np')
else:
 native=libc.renameat2;native.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
 def rename(old,new,flags):
  if native(-100,os.fsencode(old),-100,os.fsencode(new),flags):raise OSError(ctypes.get_errno(),'renameat2')

def check(v,detail='mounted namespace extension check failed'):
 global checks
 assert v,detail;checks+=1

def denied(call,errors):
 try:value=call()
 except OSError as e:check(e.errno in ((errors,) if isinstance(errors,int) else errors),repr(e))
 else:
  if isinstance(value,int):os.close(value)
  raise AssertionError('unexpected native success')
def unmount(m):fixture.run(['/sbin/umount',m] if sys.platform=='darwin' else ['fusermount3','-u',m])
sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
if a.allow_device_nodes and os.getuid()!=0:raise PermissionError('--allow-device-nodes tests require root')
check(bool(sources))
if os.getuid()!=0:
 for command in [
  [a.work/'mount-frontend','/missing-mountpoint','--allow-device-nodes'],
  [sys.executable,here/'mount-broker.py','--root','/missing-root','--work',a.work,'--mountpoint','/missing-mountpoint','--allow-device-nodes'],
  [sys.executable,here/'direct-device.py','mount','/missing-device','/missing-root','--work',a.work,'--mountpoint','/missing-mountpoint','--allow-device-nodes'],
  [sys.executable,here/'live-device.py','mount','/missing-device','/missing-root','--work',a.work,'--mountpoint','/missing-mountpoint','--allow-device-nodes']]:
  result=subprocess.run(list(map(str,command)),capture_output=True,timeout=20);check(result.returncode!=0 and b'requires root' in result.stderr,result.stderr)
tmp=Path(tempfile.mkdtemp(prefix='mounted-namespace-extensions-',dir=a.work));short=Path(tempfile.mkdtemp(prefix='e4ns-',dir='/private/tmp' if sys.platform=='darwin' else '/tmp'));ok=False
try:
 for index,source in enumerate(sources):
  root=tmp/f'chain-{index}';chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   s.chmod('/',0o777);s.mknod('/char-seed',stat.S_IFCHR|0o666,major=1,minor=3);s.mknod('/block-seed',stat.S_IFBLK|0o666,major=8,minor=1);s.chown('/char-seed',os.getuid(),os.getgid());s.chown('/block-seed',os.getuid(),os.getgid())
   if sys.platform=='linux' and os.getuid()!=0:
    for name,tag,identity,permissions in [('acl-fifo',2,os.getuid(),6),('acl-denied-fifo',2,os.getuid(),0),('group-fifo',8,os.getgid(),6),('group-denied-fifo',8,os.getgid(),0)]:
     s.mknod('/'+name,stat.S_IFIFO|0o600)
     acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,uid) for tag,perm,uid in ([(1,0,2**32-1)]+([(2,permissions,identity)] if tag==2 else [])+[(4,0,2**32-1)]+([(8,permissions,identity)] if tag==8 else [])+[(16,6,2**32-1),(32,0,2**32-1)]))
     s.setxattr('/'+name,'system.posix_acl_access',acl)
  mount=short/f'm{index}';mount.mkdir();logpath=tmp/f'mount-{index}.log';proc=None;active=False
  try:
   with logpath.open('wb') as log:
    proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--root',root,'--work',a.work,'--mountpoint',mount]+(['--allow-device-nodes'] if a.allow_device_nodes else []),stdout=log,stderr=log)
    for unused in range(200):
     if os.path.ismount(mount):active=True;break
     if proc.poll() is not None:break
     time.sleep(.1)
    check(active,logpath.read_text());a1=mount/'a';b1=mount/'b';a1.write_bytes(b'A');b1.write_bytes(b'B')
    ia,ib=a1.stat().st_ino,b1.stat().st_ino
    denied(lambda:rename(a1,b1,1),errno.EEXIST)
    # Darwin VFS short-circuits identical paths before calling the filesystem.
    if sys.platform=='darwin':rename(a1,a1,1);check(a1.read_bytes()==b'A')
    else:denied(lambda:rename(a1,a1,1),errno.EEXIST)
    with a1.open('rb') as held:
     rename(a1,b1,2);check(a1.read_bytes()==b'B' and b1.read_bytes()==b'A');check(held.read()==b'A');check((a1.stat().st_ino,b1.stat().st_ino)==(ib,ia))
    denied(lambda:rename(a1,mount/'absent',2),errno.ENOENT);denied(lambda:rename(a1,b1,3),(errno.EINVAL,errno.ENOTSUP))
    rename(a1,mount/'new',1);check((mount/'new').read_bytes()==b'B')
    (mount/'left').mkdir();(mount/'right').mkdir();d=mount/'left/dir';d.mkdir();(d/'child').write_bytes(b'child');f=mount/'right/file';f.write_bytes(b'file')
    held_dir=os.open(d,os.O_RDONLY)
    try:
     rename(d,f,2);check((f/'child').read_bytes()==b'child' and d.read_bytes()==b'file')
     check(os.stat('child',dir_fd=held_dir).st_size==5)
    finally:os.close(held_dir)
    denied(lambda:rename(mount/'right',f,2),errno.EINVAL)
    if sys.platform=='linux' and os.getuid()!=0:
     for prefix in ['acl','group']:
      fd=os.open(mount/(prefix+'-fifo'),os.O_RDONLY|os.O_NONBLOCK);os.close(fd);check(True)
      denied(lambda:os.open(mount/(prefix+'-denied-fifo'),os.O_RDONLY|os.O_NONBLOCK),errno.EACCES)
    os.mkfifo(mount/'fifo',0o640);check(stat.S_ISFIFO((mount/'fifo').stat().st_mode))
    if sys.platform=='linux' and os.getuid()!=0:
     os.chmod(mount/'fifo',0);denied(lambda:os.open(mount/'fifo',os.O_RDONLY|os.O_NONBLOCK),errno.EACCES);os.chmod(mount/'fifo',0o640)
    try:rd=os.open(mount/'fifo',os.O_RDONLY|os.O_NONBLOCK)
    except OSError as e:
     if sys.platform!='darwin' or e.errno!=errno.EPERM:raise
     fifo_io=False;fifo_errno=e.errno;check(True);rd=None
    try:
     if rd is not None:
      wr=os.open(mount/'fifo',os.O_WRONLY|os.O_NONBLOCK)
      try:check(os.write(wr,b'kernel fifo')==11);check(os.read(rd,20)==b'kernel fifo')
      finally:os.close(wr)
     os.chmod(mount/'fifo',0o600);check(stat.S_IMODE((mount/'fifo').stat().st_mode)==0o600)
     os.link(mount/'fifo',mount/'fifo-link');os.unlink(mount/'fifo');os.unlink(mount/'fifo-link')
     if rd is not None:check(stat.S_ISFIFO(os.fstat(rd).st_mode))
    finally:
     if rd is not None:os.close(rd)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
     listener.bind(str(mount/'sock'));listener.listen(1);listener.settimeout(5);check(stat.S_ISSOCK((mount/'sock').stat().st_mode))
     if sys.platform=='linux' and os.getuid()!=0:
      os.chmod(mount/'sock',0)
      with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as blocked:
       blocked.settimeout(5);denied(lambda:blocked.connect(str(mount/'sock')),errno.EACCES)
      os.chmod(mount/'sock',0o600)
     with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
      client.settimeout(5);client.connect(str(mount/'sock'));peer,_=listener.accept()
      with peer:client.sendall(b'unix socket');check(peer.recv(20)==b'unix socket')
     os.rename(mount/'sock',mount/'socket-moved');os.unlink(mount/'socket-moved')
    if sys.platform=='linux':
     white_source=mount/'white-source';white_target=mount/'white-target';white_source.write_bytes(b'white-source');white_target.write_bytes(b'old')
     if os.getuid():denied(lambda:rename(white_source,white_target,4),errno.EPERM)
     else:
      with white_source.open('rb') as held:
       rename(white_source,white_target,4);check(held.read()==b'white-source' and white_target.read_bytes()==b'white-source')
      marker=white_source.stat();check(stat.S_ISCHR(marker.st_mode) and marker.st_rdev==0 and stat.S_IMODE(marker.st_mode)==0)
      denied(lambda:rename(white_target,white_source,5),errno.EEXIST)
      rename(white_target,mount/'white-new',5);check(stat.S_ISCHR(white_target.stat().st_mode) and (mount/'white-new').read_bytes()==b'white-source')
      denied(lambda:rename(white_target,white_source,6),errno.EINVAL)
    if a.allow_device_nodes:
     null=os.stat('/dev/null');os.mknod(mount/'host-null',stat.S_IFCHR|0o600,null.st_rdev)
     try:fd=os.open(mount/'host-null',os.O_RDWR)
     except OSError as e:
      if not a.probe_host_io or sys.platform!='darwin':raise
      device_io=False;device_errno=e.errno;check(True)
     else:
      try:check(os.read(fd,8)==b'');check(os.write(fd,b'host null')==9);device_io=True
      finally:os.close(fd)
     os.unlink(mount/'host-null')
    for path,kind,major,minor in [('char-seed',stat.S_IFCHR,1,3),('block-seed',stat.S_IFBLK,8,1)]:
     info=(mount/path).stat();check(stat.S_IFMT(info.st_mode)==kind);check((os.major(info.st_rdev),os.minor(info.st_rdev))==(major,minor))
     # Device nodes are stored and movable, but nodev forbids hardware access.
     if not a.allow_device_nodes:denied(lambda:os.open(mount/path,os.O_RDONLY),(errno.EACCES,errno.EPERM,errno.ENXIO,errno.ENODEV,errno.EOPNOTSUPP))
     os.link(mount/path,mount/(path+'-link'));os.unlink(mount/path);check((mount/(path+'-link')).stat().st_nlink==1);os.unlink(mount/(path+'-link'))
    if os.getuid()==0:
     os.mknod(mount/'native-char',stat.S_IFCHR|0o600,os.makedev(1,3));check(stat.S_ISCHR((mount/'native-char').stat().st_mode));check(os.minor((mount/'native-char').stat().st_rdev)==3);os.unlink(mount/'native-char')
    else:denied(lambda:os.mknod(mount/'denied-char',stat.S_IFCHR|0o600,os.makedev(1,3)),errno.EPERM)
    unmount(mount);active=False;check(proc.wait(timeout=30)==0,logpath.read_text())
  finally:
   if active and os.path.ismount(mount):unmount(mount)
   if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=15)
  fixture.run(['e2fsck','-fn',root/'image.img']);print('PASS mounted namespace extensions',source.name,flush=True)
 (a.work/a.result_name).write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources),platform=sys.platform,uid=os.getuid(),allow_device_nodes=a.allow_device_nodes,native_fifo_io=fifo_io,native_fifo_errno=fifo_errno,native_device_io=device_io,native_device_errno=device_errno),indent=2)+'\n');ok=True
 print('PASS',checks,'mounted namespace extension checks',flush=True)
finally:
 if ok:shutil.rmtree(tmp);shutil.rmtree(short)
 else:print('Fixtures retained:',tmp,short,file=sys.stderr)
