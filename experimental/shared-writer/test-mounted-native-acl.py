#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual macOS ACL APIs/chmod on owned disposable FUSE mounts; no sudo."""
import argparse,ctypes,errno,hashlib,json,os,shutil,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
import chain,native_acl
assert sys.platform=='darwin'
here=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);p.add_argument('--limit',type=int)
a=p.parse_args();fixtures=a.fixtures or a.work/'fixtures';checks=0;rows=[]
def check(v,detail='native ACL check failed'):
 global checks
 assert v,detail;checks+=1
def run(cmd):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=60);check(r.returncode==0,r.stdout+r.stderr);return r.stdout
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unmount(path):run(['/sbin/umount',path]);check(not os.path.ismount(path))
lib=ctypes.CDLL(None,use_errno=True)
def bind(name,result,args):
 fn=getattr(lib,name);fn.restype=result;fn.argtypes=args;return fn
init=bind('acl_init',ctypes.c_void_p,[ctypes.c_int]);create=bind('acl_create_entry',ctypes.c_int,[ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_void_p)])
tag=bind('acl_set_tag_type',ctypes.c_int,[ctypes.c_void_p,ctypes.c_int]);qualifier=bind('acl_set_qualifier',ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p]);perms=bind('acl_get_permset',ctypes.c_int,[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]);add=bind('acl_add_perm',ctypes.c_int,[ctypes.c_void_p,ctypes.c_uint32])
setfile=bind('acl_set_file',ctypes.c_int,[ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p]);getfile=bind('acl_get_file',ctypes.c_void_p,[ctypes.c_char_p,ctypes.c_int]);size=bind('acl_size',ctypes.c_ssize_t,[ctypes.c_void_p]);external=bind('acl_copy_ext',ctypes.c_ssize_t,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ssize_t]);free=bind('acl_free',ctypes.c_int,[ctypes.c_void_p])
ACL_TYPE=0x100;membership=native_acl.Membership();daemon=membership.resolve(False,1)
check(membership.identify(daemon)==(False,1))
def set_ace(path,uuid,bits,kind=1,expected=0):
 acl=ctypes.c_void_p(init(1));check(bool(acl));entry=ctypes.c_void_p()
 try:
  check(create(ctypes.byref(acl),ctypes.byref(entry))==0);check(tag(entry,kind)==0);raw=ctypes.create_string_buffer(uuid);check(qualifier(entry,raw)==0)
  perm=ctypes.c_void_p();check(perms(entry,ctypes.byref(perm))==0)
  for bit in (2,4,8,16,32,64,1<<13):
   if bits&bit:check(add(perm,bit)==0)
  result=setfile(os.fsencode(path),ACL_TYPE,acl)
  check(result==0 if not expected else result==-1 and ctypes.get_errno()==expected,('acl_set_file',result,ctypes.get_errno(),expected))
 finally:free(acl)
def get_native(path):
 acl=getfile(os.fsencode(path),ACL_TYPE);check(bool(acl),('acl_get_file',ctypes.get_errno()))
 try:
  n=size(acl);check(44<=n<=44+128*24);buf=ctypes.create_string_buffer(n);check(external(buf,acl,n)==n);return buf.raw
 finally:free(acl)
def raw_attr(path,name):
 get=bind('getxattr',ctypes.c_ssize_t,[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int])
 n=get(os.fsencode(path),name,None,0,0,0)
 if n<0:raise OSError(ctypes.get_errno(),'getxattr')
 buf=ctypes.create_string_buffer(max(n,1));check(get(os.fsencode(path),name,buf,n,0,0)==n);return buf.raw[:n]
sources=sorted(p for p in fixtures.glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources));tmp=Path(tempfile.mkdtemp(prefix='mounted-native-acl-',dir=a.work));ok=False
try:
 for source in sources:
  before=sha(source);seed=tmp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
  commands=tmp/'seed.commands';commands.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n')
  run(['debugfs','-w','-f',commands,seed])
  preset=tmp/'directory.acl';preset.write_bytes(struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in [(1,7,2**32-1),(2,7,os.getuid()),(4,0,2**32-1),(16,7,2**32-1),(32,0,2**32-1)]))
  commands.write_text(f'mkdir /foreign-dir\nset_inode_field /foreign-dir uid 0\nset_inode_field /foreign-dir gid 0\nset_inode_field /foreign-dir mode 040770\nea_set -f {preset} /foreign-dir system.posix_acl_access\n')
  run(['debugfs','-w','-f',commands,seed]);run(['e2fsck','-fn',seed]);seed_hash=sha(seed)
  root=tmp/source.stem;chain.clone(seed,root);mount=tmp/(source.stem+'-mount');mount.mkdir();logpath=tmp/(source.stem+'-mount.log');log=logpath.open('wb')
  process=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount],stdout=log,stderr=log)
  try:
   for unused in range(120):
    if process.poll() is not None:raise AssertionError(logpath.read_text())
    if os.path.ismount(mount):break
    time.sleep(.1)
   check(os.path.ismount(mount));path=mount/'native';path.write_bytes(b'native ACL contents');os.chmod(path,0o600)
   set_ace(path,daemon,2)
   stored=raw_attr(path,b'system.posix_acl_access');check((2,4,1) in native_acl.posix(stored));check(path.read_bytes()==b'native ACL contents')
   native=get_native(path);converted=native_acl.decode(native,path.stat().st_mode,os.getuid(),os.getgid(),membership.identify);check((2,4,1) in native_acl.posix(converted))
   # Native chmod inserts before the projected ordered rules, preserving real
   # allow/deny semantics rather than simply collecting ACE permission bits.
   run(['/bin/chmod','+a#','0','user:daemon allow write,append',path]);check((2,6,1) in native_acl.posix(raw_attr(path,b'system.posix_acl_access')))
   run(['/bin/ls','-le',path]);check(len(get_native(path))>=44)
   # Unsupported changes leave both mode and the stored ACL unchanged.
   old=raw_attr(path,b'system.posix_acl_access');oldmode=path.stat().st_mode;oldhash=sha(root/'image.img')
   set_ace(path,daemon,4,expected=errno.EOPNOTSUPP);check(raw_attr(path,b'system.posix_acl_access')==old and path.stat().st_mode==oldmode)
   set_ace(path,daemon,16,expected=errno.EOPNOTSUPP);check(raw_attr(path,b'system.posix_acl_access')==old)
   set_ace(path,daemon,1<<13,expected=errno.EOPNOTSUPP);check(raw_attr(path,b'system.posix_acl_access')==old)
   r=subprocess.run(['/bin/chmod','+a#','0','user:daemon allow read,file_inherit',str(path)],capture_output=True);check(r.returncode!=0);check(raw_attr(path,b'system.posix_acl_access')==old)
   check(sha(root/'image.img')==oldhash);check(not any(name.startswith('._') for name in os.listdir(mount)))
   copied=mount/'copy';run(['/bin/cp','-p',path,copied]);check(raw_attr(copied,b'system.posix_acl_access')==old)
   os.chmod(path,0o600);check(struct.unpack_from('<H',raw_attr(path,b'system.posix_acl_access'),30)[0]==0)
   run(['/bin/chmod','-N',path]);check(path.read_bytes()==b'native ACL contents')
   try:raw_attr(path,b'system.posix_acl_access')
   except OSError as e:check(e.errno==errno.ENOATTR)
   else:raise AssertionError('native removal retained access ACL')
   set_ace(path,daemon,2);run(['/bin/chmod','-N',path]);check(stat.S_IMODE(path.stat().st_mode)==0o640)
   descriptor=os.open(path,os.O_RDONLY)
   try:
    set_ace(path,native_acl.OWNER,2,kind=2);check(stat.S_IMODE(path.stat().st_mode)==0o240)
    try:path.read_bytes()
    except OSError as e:check(e.errno==errno.EACCES)
    else:raise AssertionError('native owner deny failed to revoke new reads')
    check(os.pread(descriptor,19,0)==b'native ACL contents')
    set_ace(path,native_acl.OWNER,2);check(path.read_bytes()==b'native ACL contents')
   finally:os.close(descriptor)
   before_denial=sha(root/'image.img')
   set_ace(mount/'existing-file',daemon,2,expected=errno.EPERM);check(sha(root/'image.img')==before_denial)
   foreign_dir=mount/'foreign-dir';child=foreign_dir/'created';child.write_bytes(b'parent ACL');check(child.read_bytes()==b'parent ACL');child.unlink();check(not child.exists())
   sub=foreign_dir/'sub';sub.mkdir();sub.rmdir();check(not sub.exists())
   directory=mount/'editable-dir';directory.mkdir();os.chmod(directory,0o700)
   set_ace(directory,daemon,4|32|8|64);check((2,3,1) in native_acl.posix(raw_attr(directory,b'system.posix_acl_access')));check(len(get_native(directory))>=44)
   run(['/bin/chmod','-N',directory]);directory.rmdir()
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
  run(['e2fsck','-fn',root/'image.img']);check(sha(source)==before and sha(seed)==seed_hash);rows.append(dict(fixture=source.name,result='passed'));print('PASS mounted native ACL',source.name,flush=True)
 (a.work/'mounted-native-acl-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows),indent=2)+'\n');print('PASS',checks,'mounted native ACL checks',flush=True);ok=True
finally:
 if ok and not any(os.path.ismount(p) for p in tmp.iterdir() if p.is_dir()):shutil.rmtree(tmp)
 elif not ok:print('Fixtures retained:',tmp,file=sys.stderr)
