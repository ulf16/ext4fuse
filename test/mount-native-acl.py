#!/usr/bin/env python3
"""Native macFUSE named-user ACLs and fail-closed invalid/unsupported ACLs."""
import argparse, ctypes, errno, hashlib, os, pathlib, shutil, struct, subprocess, sys, tempfile, time
assert sys.platform=='darwin'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',default='./ext4fuse');a=p.parse_args()
reader=str(pathlib.Path(a.reader).resolve())
mkfs,debugfs=shutil.which('mke2fs'),shutil.which('debugfs');assert mkfs and debugfs
root=pathlib.Path(tempfile.mkdtemp(prefix='ext4-native-acl-',dir='/private/tmp'))
mount=root/'mount';mount.mkdir();image=root/'image';payload=root/'payload';payload.write_bytes(b'native acl fixture\n')
image.write_bytes(bytes(32*1024**2))
subprocess.run([mkfs,'-q','-F','-t','ext4','-b','4096','-O','^metadata_csum,^uninit_bg',str(image)],check=True,capture_output=True)
def debug(command):
 r=subprocess.run([debugfs,'-w','-R',command,str(image)],check=True,capture_output=True,text=True)
 assert not any(x in r.stderr for x in ('not found','Usage:','Could not')),r.stderr
undefined=0xffffffff;uid=os.getuid();foreign=uid+65536
cases={
 'grant': ([(1,0,undefined),(2,4,uid),(4,0,undefined),(16,4,undefined),(32,0,undefined)],0o040,0),
 'deny': ([(1,0,undefined),(2,0,uid),(4,0,undefined),(16,4,undefined),(32,4,undefined)],0o044,errno.EACCES),
 'bad': ([(1,0,undefined),(2,4,uid),(4,0,undefined),(16,4,undefined),(32,4,undefined)],0o044,errno.EIO),
 'split': ([(1,0,undefined),(4,0,undefined),(8,4,1000001),(8,1,1000002),(16,5,undefined),(32,4,undefined)],0o054,errno.EOPNOTSUPP),
 'huge': ([(1,0,undefined)]+[(2,4,i) for i in range(10000000,10000080)]+[(4,0,undefined),(16,4,undefined),(32,4,undefined)],0o044,errno.E2BIG),
}
libc=ctypes.CDLL(None,use_errno=True);libc.mbr_gid_to_uuid.argtypes=[ctypes.c_uint,ctypes.c_void_p]
uuid=ctypes.create_string_buffer(16);assert libc.mbr_gid_to_uuid(12,uuid)==0
if uuid.raw==bytes.fromhex('abcdefabcdefabcdefabcdef0000000c'):
 cases['reserved']=([(1,0,undefined),(4,0,undefined),(8,4,12),(16,4,undefined),(32,4,undefined)],0o044,errno.EOPNOTSUPP)
for name,(spec,mode,error) in cases.items():
 debug(f'write {payload} /{name}')
 acl=root/(name+'.acl');acl.write_bytes(struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in spec))
 debug(f'ea_set -f {acl} /{name} system.posix_acl_access')
 for field,value in [('uid',foreign),('gid',1000003),('mode',0o100000|mode)]:debug(f'set_inode_field /{name} {field} {value}')
# Corrupt the named-user tag, without checksums hiding structural validation.
spec=cases['bad'][0]
raw=struct.pack('<I',1)+b''.join(struct.pack('<HH',t,p)+(struct.pack('<I',i) if t in (2,8) else b'') for t,p,i in spec)
data=bytearray(image.read_bytes());assert data.count(raw)==1
position=data.find(raw);data[position+8]=3;image.write_bytes(data)
before=hashlib.sha256(image.read_bytes()).digest()
def mounted():return ' on '+str(mount)+' (' in subprocess.check_output(['/sbin/mount'],text=True)
process=None;checks=0
try:
 with (root/'daemon.log').open('w+') as log:
  process=subprocess.Popen([reader,str(image),str(mount),'-f','-s','-o','ro,default_permissions'],stdout=log,stderr=log)
  for _ in range(80):
   if mounted():break
   if process.poll() is not None:log.seek(0);raise AssertionError(log.read())
   time.sleep(.1)
  else:raise AssertionError('mount timeout')
  for repeat in range(2):
   for name,(spec,mode,error) in cases.items():
    if name=='deny':
     st=os.stat(mount/name);assert st.st_uid==foreign and st.st_mode&0o777==mode;checks+=1
    elif error:
     try:os.stat(mount/name)
     except OSError as e:assert e.errno==error,(name,e,error)
     else:raise AssertionError((name,'invalid ACL admitted by getattr'))
     checks+=1
    try:content=(mount/name).read_bytes()
    except OSError as e:assert e.errno==error,(name,e,error)
    else:assert error==0 and content==payload.read_bytes(),(name,'unexpected permission grant')
    checks+=1
  subprocess.run(['/sbin/umount',str(mount)],check=True)
  process.wait(timeout=10);assert hashlib.sha256(image.read_bytes()).digest()==before
 print(f'PASS: {checks} native ACL grant/deny, corruption, unsupported-rule and overflow checks; source unchanged')
finally:
 if mounted():subprocess.run(['/sbin/umount',str(mount)],check=True)
 if process and process.poll() is None:process.terminate();process.wait(timeout=10)
 assert not mounted();shutil.rmtree(root)
