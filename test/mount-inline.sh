#!/bin/sh
# Disposable macFUSE integration test for inode-body files and directories.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Requires macOS/macFUSE'; exit 1; }
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-inline-mount.XXXXXX")
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
import pathlib,subprocess,sys,shutil
r=pathlib.Path(sys.argv[1]);tree=r/'tree';tree.mkdir();(tree/'folder').mkdir()
for size in [0,1,60,61,100,156,200]: (tree/('file'+str(size))).write_bytes(bytes((i*19+size)%256 for i in range(size)))
for i in range(3): (tree/('folder/f'+str(i))).write_bytes(b'child'+bytes([i]))
(tree/'link').symlink_to('file100')
with (r/'image').open('wb') as f:f.truncate(32*1024**2)
mkfs=shutil.which('mke2fs');assert mkfs,'Put e2fsprogs sbin in PATH'
subprocess.run([mkfs,'-q','-F','-t','ext4','-O','inline_data','-d',str(tree),str(r/'image')],check=True)
PY
mkdir "$fixture_dir/mount"
"${READER:-./ext4fuse}" "$fixture_dir/image" "$fixture_dir/mount" -f -s -o ro,default_permissions > "$fixture_dir/reader.log" 2>&1 &
reader_pid=$!
attempt=0
until [ -f "$fixture_dir/mount/file100" ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 40 ] || ! kill -0 "$reader_pid" 2>/dev/null; then
        cat "$fixture_dir/reader.log" >&2
        exit 1
    fi
    sleep 0.25
done
python3 - "$fixture_dir" <<'PY'
import errno,hashlib,os,pathlib,sys
r=pathlib.Path(sys.argv[1]);mount=r/'mount';before=hashlib.sha256((r/'image').read_bytes()).digest()
for source in (r/'tree').glob('file*'):
    actual=mount/source.name;assert actual.read_bytes()==source.read_bytes()
    assert actual.stat().st_size==source.stat().st_size
assert sorted(os.listdir(mount/'folder'))==['f0','f1','f2']
assert (mount/'folder/../file100').read_bytes()==(r/'tree/file100').read_bytes()
assert (mount/'folder/f2').read_bytes()==b'child\x02'
assert os.readlink(mount/'link')=='file100'
try: (mount/'file100').open('wb')
except OSError as e: assert e.errno in [errno.EROFS,errno.EACCES]
else: raise AssertionError('write unexpectedly permitted')
assert before==hashlib.sha256((r/'image').read_bytes()).digest()
print('PASS: mounted inline files/directories, sizes, parent paths, symlink and write rejection')
PY
