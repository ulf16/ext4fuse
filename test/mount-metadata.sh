#!/bin/sh
# Disposable macFUSE test of distributed descriptors and exact timestamps.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Requires macOS/macFUSE'; exit 1; }
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-metadata-mount.XXXXXX")
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
python3 - "$fixture_dir" "$(dirname "$0")/native-stat.c" <<'PY'
import pathlib,subprocess,sys,shutil
r=pathlib.Path(sys.argv[1]);subprocess.run(['/usr/bin/cc',sys.argv[2],'-o',str(r/'native-stat')],check=True);tree=r/'tree';tree.mkdir();(tree/'folder').mkdir()
(tree/'file').write_bytes(bytes(range(100)));(tree/'folder/child').write_bytes(b'meta_bg child')
with (r/'image').open('wb') as f:f.truncate((33*256+1)*1024)
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');assert mkfs and debugfs
subprocess.run([mkfs,'-q','-F','-t','ext4','-b','1024','-g','256','-N','1024','-O','meta_bg,^resize_inode,^has_journal,64bit,sparse_super2,inline_data','-d',str(tree),str(r/'image')],check=True)
commands=r/'commands'
commands.write_text('\n'.join('set_inode_field /file '+field+' '+hex(value) for field,value in [
    ('atime',0xffffffff),('atime_extra',1<<2),
    ('mtime',0),('mtime_extra',(123456789<<2)|1),
    ('ctime',1700000000),('ctime_extra',999999999<<2),
    ('crtime',946684800),('crtime_extra',987654321<<2)])+'\n')
subprocess.run([debugfs,'-w','-f',str(commands),str(r/'image')],capture_output=True,check=True)
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
import hashlib,os,pathlib,sys
r=pathlib.Path(sys.argv[1]);mount=r/'mount';before=hashlib.sha256((r/'image').read_bytes()).digest()
st=(mount/'file').stat()
assert st.st_atime_ns==-1000000000+1,st.st_atime_ns
assert st.st_mtime_ns==4294967296*1000000000+123456789,st.st_mtime_ns
assert st.st_ctime_ns==1700000000*1000000000+999999999,st.st_ctime_ns
# Verify all four native timespec values, including exact birthtime nanos.
import subprocess
native=list(map(int,subprocess.run([str(r/'native-stat'),str(mount/'file')],capture_output=True,text=True,check=True).stdout.split()))
assert native==[-1,1,4294967296,123456789,1700000000,999999999,946684800,987654321],native
assert (mount/'file').read_bytes()==bytes(range(100))
assert (mount/'folder/child').read_bytes()==b'meta_bg child'
assert os.listdir(mount/'folder')==['child']
assert before==hashlib.sha256((r/'image').read_bytes()).digest()
print('PASS: mounted meta_bg + inline contents, signed/extended seconds, nanoseconds and birthtime')
PY
