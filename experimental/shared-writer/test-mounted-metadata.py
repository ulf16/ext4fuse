#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real private FUSE 3 metadata callbacks on disposable managed clones."""
import argparse,ctypes,errno,hashlib,json,os,shutil,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
import chain
here=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int)
a=p.parse_args();fixtures=a.fixtures or a.work/'fixtures';checks=0;rows=[]
def check(v,detail='mounted metadata check failed'):
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
def unmount(path):
 run(['/sbin/umount',path] if sys.platform=='darwin' else ['fusermount3','-u',path]);check(not os.path.ismount(path))
def acl():return struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,id) for tag,perm,id in [(1,6,2**32-1),(2,4,12345),(4,0,2**32-1),(16,4,2**32-1),(32,0,2**32-1)])
libc=ctypes.CDLL(None,use_errno=True)
libc.getxattr.restype=ctypes.c_ssize_t
if sys.platform=='darwin':libc.getxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int]
else:libc.getxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]
def raw_get(path,name,size):
 buf=ctypes.create_string_buffer(max(size,1));args=[os.fsencode(path),os.fsencode(name),buf if size else None,size]
 if sys.platform=='darwin':args+=[0,0]
 got=libc.getxattr(*args)
 if got<0:raise OSError(ctypes.get_errno(),'native getxattr')
 return got,buf.raw[:got] if size else b''

CREATE=2 if sys.platform=='darwin' else 1
REPLACE=4 if sys.platform=='darwin' else 2
libc.setxattr.restype=ctypes.c_int
libc.setxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]+([ctypes.c_uint32,ctypes.c_int] if sys.platform=='darwin' else [ctypes.c_int])
libc.listxattr.restype=ctypes.c_ssize_t
libc.listxattr.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]+([ctypes.c_int] if sys.platform=='darwin' else [])
libc.removexattr.restype=ctypes.c_int
libc.removexattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p]+([ctypes.c_int] if sys.platform=='darwin' else [])
def set_attr(path,name,value,flags=0):
 buf=ctypes.create_string_buffer(value);args=[os.fsencode(path),os.fsencode(name),buf,len(value)]
 args+=([0,flags] if sys.platform=='darwin' else [flags])
 if libc.setxattr(*args):raise OSError(ctypes.get_errno(),'native setxattr')
def get_attr(path,name):
 n,_=raw_get(path,name,0);return raw_get(path,name,n)[1]
def list_attrs(path):
 args=[os.fsencode(path),None,0]+([0] if sys.platform=='darwin' else [])
 n=libc.listxattr(*args)
 if n<0:raise OSError(ctypes.get_errno(),'native listxattr')
 check(n<=65536);buf=ctypes.create_string_buffer(max(n,1));args[1:3]=[buf,n];got=libc.listxattr(*args)
 if got<0:raise OSError(ctypes.get_errno(),'native listxattr')
 raw=buf.raw[:got];check(not raw or raw.endswith(b'\0'))
 return [os.fsdecode(v) for v in raw[:-1].split(b'\0')] if raw else []
def remove_attr(path,name):
 args=[os.fsencode(path),os.fsencode(name)]+([0] if sys.platform=='darwin' else [])
 if libc.removexattr(*args):raise OSError(ctypes.get_errno(),'native removexattr')

sources=sorted(p for p in fixtures.glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources));tmp=Path(tempfile.mkdtemp(prefix='mounted-metadata-',dir=a.work));ok=False
try:
 for source in sources:
  before=sha(source);seed=tmp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
  commands=tmp/'seed.commands';commands.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n')
  run(['debugfs','-w','-f',commands,seed]);run(['e2fsck','-fn',seed]);seed_hash=sha(seed)
  root=tmp/source.stem;chain.clone(seed,root);mount=tmp/(source.stem+'-mount');mount.mkdir()
  logpath=tmp/(source.stem+'-mount.log');log=logpath.open('wb')
  process=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount],stdout=log,stderr=log)
  try:
   for unused in range(120):
    if process.poll() is not None:raise AssertionError('mount exited: '+logpath.read_text())
    if os.path.ismount(mount):break
    time.sleep(.1)
   check(os.path.ismount(mount),'mount timeout')
   path=mount/'metadata';path.write_bytes(b'contents');os.chmod(path,0o640);check(stat.S_IMODE(path.stat().st_mode)==0o640)
   read_only=os.open(path,os.O_RDONLY)
   try:os.fchmod(read_only,0o604);check(stat.S_IMODE(os.fstat(read_only).st_mode)==0o604);os.fchmod(read_only,0o640)
   finally:os.close(read_only)
   os.chown(path,os.getuid(),os.getgid());check((path.stat().st_uid,path.stat().st_gid)==(os.getuid(),os.getgid()))
   os.utime(path,ns=(1234567890123456789,2345678901987654321));info=path.stat();check((info.st_atime_ns,info.st_mtime_ns)==(1234567890123456789,2345678901987654321))
   attr='com.ext4fuse.binary' if sys.platform=='darwin' else 'user.ext4fuse.binary'
   missing='com.ext4fuse.missing' if sys.platform=='darwin' else 'user.ext4fuse.missing'
   noattr=getattr(errno,'ENOATTR',errno.ENODATA) if sys.platform=='darwin' else errno.ENODATA
   set_attr(path,attr,b'binary\0\xff',flags=CREATE);check(get_attr(path,attr)==b'binary\0\xff');check(attr in list_attrs(path))
   check(raw_get(path,attr,0)[0]==8);denied(lambda:raw_get(path,attr,1),errno.ERANGE)
   denied(lambda:set_attr(path,attr,b'x',flags=CREATE),errno.EEXIST)
   denied(lambda:set_attr(path,missing,b'x',flags=REPLACE),noattr)
   set_attr(path,attr,b'',flags=REPLACE);check(get_attr(path,attr)==b'')
   remove_attr(path,attr);denied(lambda:get_attr(path,attr),noattr)
   access='system.posix_acl_access';default='system.posix_acl_default'
   set_attr(path,access,acl());check(get_attr(path,access)==acl());check(stat.S_IMODE(path.stat().st_mode)==0o640)
   os.chmod(path,0o600);updated=get_attr(path,access);check(struct.unpack_from('<H',updated,30)[0]==0);check(updated[12:20]==acl()[12:20])
   remove_attr(path,access);check(access not in list_attrs(path))
   directory=mount/'dir';directory.mkdir();set_attr(directory,default,acl())
   child=directory/'child';child.write_bytes(b'inherited');check(get_attr(child,access)==acl());check(stat.S_IMODE(child.stat().st_mode)==0o640)
   remove_attr(directory,default);check(default not in list_attrs(directory))
   # Descriptor metadata works while mode changes revoke new pathname opens.
   fd=os.open(path,os.O_RDWR)
   try:
    os.fchmod(fd,0o000);check(os.pread(fd,8,0)==b'contents');denied(lambda:os.open(path,os.O_RDONLY),errno.EACCES)
    os.fchmod(fd,0o600);os.rename(path,mount/'renamed');path=mount/'renamed'
    os.unlink(path);os.fchmod(fd,0o640);os.fchown(fd,os.getuid(),os.getgid());os.utime(fd,ns=(1000000001,2000000002))
    info=os.fstat(fd);check(stat.S_IMODE(info.st_mode)==0o640 and info.st_nlink==0);check((info.st_atime_ns,info.st_mtime_ns)==(1000000001,2000000002));check(os.pwrite(fd,b'open',0)==4);os.fsync(fd)
   finally:os.close(fd)
   check(not any(name.startswith('.fuse_hidden') for name in os.listdir(mount)))
   # Copy tools can now preserve modes, times and binary user attributes.
   sourcefile=mount/'source';sourcefile.write_bytes(b'copy metadata');os.chmod(sourcefile,0o604);os.utime(sourcefile,ns=(111000000222,333000000444));set_attr(sourcefile,attr,b'copied')
   destination=mount/'copied'
   if sys.platform=='darwin':run(['/bin/cp','-p',sourcefile,destination])
   else:shutil.copy2(sourcefile,destination)
   check(destination.read_bytes()==b'copy metadata');check(stat.S_IMODE(destination.stat().st_mode)==0o604);check(destination.stat().st_mtime_ns==333000000444);check(get_attr(destination,attr)==b'copied')
   unmount(mount);check(process.wait(timeout=30)==0,logpath.read_text(errors='replace'))
  except BaseException:
   log.flush();print(logpath.read_text(errors='replace'),file=sys.stderr);raise
  finally:
   if os.path.ismount(mount):unmount(mount)
   if process.poll() is None:
    process.terminate()
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
   log.close()
  run(['e2fsck','-fn',root/'image.img']);check(run(['debugfs','-R','cat /copied',root/'image.img'])==b'copy metadata');check(sha(source)==before and sha(seed)==seed_hash)
  rows.append(dict(fixture=source.name,result='passed'));print('PASS mounted metadata',source.name,flush=True)
 (a.work/'mounted-metadata-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows),indent=2)+'\n');print('PASS',checks,'mounted metadata checks',flush=True);ok=True
finally:
 if ok and not any(os.path.ismount(p) for p in tmp.iterdir() if p.is_dir()):shutil.rmtree(tmp)
 elif not ok:print('Fixtures retained:',tmp,file=sys.stderr)
