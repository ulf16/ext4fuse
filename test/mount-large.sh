#!/bin/sh
# Slow mounted large-file regression. Disposable images/files only.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Requires macOS/macFUSE'; exit 1; }
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-large-mount.XXXXXX")
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
LARGE_FIXTURE="$fixture_dir/image" python3 "$(dirname "$0")/large-files.py"
mkdir "$fixture_dir/mount"
"${READER:-./ext4fuse}" "$fixture_dir/image" "$fixture_dir/mount" -f -s -o ro,default_permissions > "$fixture_dir/reader.log" 2>&1 &
reader_pid=$!
attempt=0
until [ -f "$fixture_dir/mount/large" ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 20 ] || ! kill -0 "$reader_pid" 2>/dev/null; then
        cat "$fixture_dir/reader.log" >&2
        exit 1
    fi
    sleep 0.25
done
python3 - "$fixture_dir" <<'PY'
import hashlib, os, pathlib, shutil, subprocess, sys, re
root=pathlib.Path(sys.argv[1]); source=root/'mount/large'; size=5*1024**3+13
before=hashlib.sha256((root/'image').read_bytes()).digest()
assert source.stat().st_size==size
chunk=8*1024**2; zeros=bytes(chunk)
# Read every byte through FUSE and copy to a sparse host file.
digest=hashlib.sha256(); copied=root/'copy'; total=0
with source.open('rb') as src,copied.open('wb') as dst:
    while True:
        data=src.read(chunk)
        if not data: break
        digest.update(data); total+=len(data)
        if total % (1024**3)==0: print("READ: %d GiB through macFUSE"%(total//(1024**3)),flush=True)
        if data==zeros[:len(data)]: dst.seek(len(data),1)
        else: dst.write(data)
    dst.truncate(total)
assert total==size and copied.stat().st_size==size
assert copied.stat().st_blocks*512<256*1024**2,'copy lost sparseness'
# Independently hash Linux debugfs output without storing another 5GiB file.
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs'); assert debugfs
with (root/'debugfs.log').open('wb') as log:
    proc=subprocess.Popen([debugfs,'-R','cat /large',str(root/'image')],stdout=subprocess.PIPE,stderr=log)
    reference=hashlib.sha256(); reference_size=0
    while True:
        data=proc.stdout.read(chunk)
        if not data: break
        reference.update(data); reference_size+=len(data)
    assert proc.wait()==0
assert reference_size==size and reference.digest()==digest.digest()
copy_hash=hashlib.sha256()
with copied.open('rb') as src:
    while True:
        data=src.read(chunk)
        if not data: break
        copy_hash.update(data)
assert copy_hash.digest()==digest.digest()
stat=subprocess.run([debugfs,'-R','stat /large',str(root/'image')],capture_output=True,text=True,check=True).stdout
expected_blocks=int(re.search(r'Blockcount:\s*(\d+)',stat).group(1))
backend=subprocess.run(['./test/corruption-probe',str(root/'image'),'allocation','/large'],capture_output=True,text=True,check=True)
assert list(map(int,backend.stdout.splitlines()[1].split()))[:2]==[size,expected_blocks]
mounted=source.stat()
if mounted.st_blocks!=expected_blocks:
    # macFUSE 5.4.0 derives mounted allocation from logical size (upstream #1121).
    rounded=(size+mounted.st_blksize-1)//mounted.st_blksize*mounted.st_blksize//512
    assert mounted.st_blocks==rounded,(mounted.st_blocks,expected_blocks,rounded)
    print('NOTE: macFUSE mounted allocation uses logical size; callback matches debugfs (upstream #1121)')
assert before==hashlib.sha256((root/'image').read_bytes()).digest()
print('PASS: mounted 5GiB+13-byte sparse file, full SHA-256 matches debugfs and sparse copy')
PY
