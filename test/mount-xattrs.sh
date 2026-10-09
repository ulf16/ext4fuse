#!/bin/sh
# Read-only extended attributes through an actual macFUSE mount.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Requires macOS/macFUSE'; exit 1; }
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-xattr-mount.XXXXXX")
reader_pid=
cleanup() {
    /sbin/umount "$fixture_dir/mount" 2>/dev/null || true
    if [ -n "$reader_pid" ]; then
        kill "$reader_pid" 2>/dev/null || true
        wait "$reader_pid" 2>/dev/null || true
    fi
    if /sbin/mount | grep -F " on $fixture_dir/mount (" >/dev/null; then
        echo "Mount remains active; retaining $fixture_dir" >&2
    else
        rm -rf "$fixture_dir"
    fi
}
trap cleanup EXIT HUP INT TERM
python3 - "$fixture_dir" <<'PY'
import pathlib,subprocess,sys,shutil,struct
r=pathlib.Path(sys.argv[1]);tree=r/'tree';tree.mkdir();(tree/'file').write_bytes(b'inline payload');(tree/'empty').touch();(tree/'folder').mkdir();(tree/'link').symlink_to('file')
with (r/'image').open('wb') as f:f.truncate(32*1024**2)
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');assert mkfs and debugfs
subprocess.run([mkfs,'-q','-F','-t','ext4','-O','inline_data,metadata_csum_seed','-d',str(tree),str(r/'image')],check=True)
values={'user.note':b'hello','user.empty':b'','user.binary':bytes(range(256))*2,'security.selinux':b'unconfined_u:object_r:default_t:s0\0','trusted.archive':b'yes','user.com.apple.FinderInfo':bytes(32)}
acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(2,4,70001),(4,5,0xffffffff),(16,5,0xffffffff),(32,0,0xffffffff)])
values['system.posix_acl_access']=acl
for i,(name,value) in enumerate(values.items()):
    host=r/('value'+str(i));host.write_bytes(value)
    p=subprocess.run([debugfs,'-w','-R','ea_set -f %s /file %s'%(host,name),str(r/'image')],capture_output=True,check=True)
    assert b'while ' not in p.stderr,p.stderr
p=subprocess.run([debugfs,'-w','-R','ea_set /link user.note link-metadata',str(r/'image')],capture_output=True,check=True);assert b'while ' not in p.stderr,p.stderr
PY
mkdir "$fixture_dir/mount"
"${READER:-./ext4fuse}" "$fixture_dir/image" "$fixture_dir/mount" -f -s -o ro,default_permissions > "$fixture_dir/reader.log" 2>&1 &
reader_pid=$!
attempt=0
until [ -f "$fixture_dir/mount/file" ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 40 ] || ! kill -0 "$reader_pid" 2>/dev/null; then
        cat "$fixture_dir/reader.log" >&2
        exit 1
    fi
    sleep 0.25
done
python3 - "$fixture_dir" <<'PY'
import ctypes,errno,hashlib,os,pathlib,struct,subprocess,sys
lib=ctypes.CDLL(None,use_errno=True)
lib.getxattr.restype=lib.listxattr.restype=ctypes.c_ssize_t
def get(path,name,follow=True):
    args=(os.fsencode(path),name.encode());opts=0 if follow else 1
    n=lib.getxattr(*args,None,0,0,opts)
    if n<0: raise OSError(ctypes.get_errno(),name)
    if not n: return b''
    b=ctypes.create_string_buffer(n)
    got=lib.getxattr(*args,b,n,0,opts)
    if got<0: raise OSError(ctypes.get_errno(),name)
    return b.raw[:got]
def listing(path):
    n=lib.listxattr(os.fsencode(path),None,0,0)
    if n<0: raise OSError(ctypes.get_errno(),str(path))
    if not n: return []
    b=ctypes.create_string_buffer(n)
    got=lib.listxattr(os.fsencode(path),b,n,0)
    if got<0: raise OSError(ctypes.get_errno(),str(path))
    return [x.decode() for x in b.raw[:got].split(b"\0") if x]
def mutate(path,name,value=None):
    args=(os.fsencode(path),name.encode())
    n=lib.removexattr(*args,0) if value is None else lib.setxattr(*args,value,len(value),0,0)
    if n<0: raise OSError(ctypes.get_errno(),name)
r=pathlib.Path(sys.argv[1]);mount=r/'mount';f=mount/'file';before=hashlib.sha256((r/'image').read_bytes()).digest()
values={'user.note':b'hello','user.empty':b'','user.binary':bytes(range(256))*2,'security.selinux':b'unconfined_u:object_r:default_t:s0\0','trusted.archive':b'yes','user.com.apple.FinderInfo':bytes(32)}
values['system.posix_acl_access']=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(2,4,70001),(4,5,0xffffffff),(16,5,0xffffffff),(32,0,0xffffffff)])
assert set(listing(f))==set(values),listing(f)
for name,value in values.items(): assert get(f,name)==value,(name,get(f,name))
assert listing(mount/'empty')==[]
assert get(mount/'link','user.note',follow=False)==b'link-metadata'
for name in ['user.missing','system.data','com.apple.FinderInfo']:
    try: get(f,name)
    except OSError as e: assert e.errno==getattr(errno,'ENOATTR',errno.ENODATA),(name,e)
    else: raise AssertionError('unexpected attribute '+name)
for action in [lambda:mutate(f,'user.note',b'changed'),lambda:mutate(f,'user.note')]:
    try:action()
    except OSError as e: assert e.errno==errno.EROFS,e
    else: raise AssertionError('write succeeded')
assert subprocess.run(['/usr/bin/xattr','-p','user.note',str(f)],capture_output=True,check=True).stdout.rstrip(b'\n')==b'hello'
assert f.read_bytes()==b'inline payload'
assert before==hashlib.sha256((r/'image').read_bytes()).digest()
print('PASS: mounted inode/block binary xattrs, empty values, symlinks, Linux ACL metadata and read-only enforcement')
PY
