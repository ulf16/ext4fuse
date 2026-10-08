#!/bin/sh
# Disposable-image integration check for macOS/macFUSE. Never uses a real disk.
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'This check requires macOS' >&2; exit 1; }
MKE2FS=${MKE2FS:-$(command -v mke2fs || true)}
DEBUGFS=${DEBUGFS:-$(command -v debugfs || true)}
[ -n "$MKE2FS" ] && [ -n "$DEBUGFS" ] || { echo 'e2fsprogs sbin must be in PATH' >&2; exit 1; }
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-mount.XXXXXX")
reader_pid=
cleanup() {
    /sbin/umount "$fixture_dir/mount" 2>/dev/null || true
    if [ -n "$reader_pid" ]; then
        kill "$reader_pid" 2>/dev/null || true
        wait "$reader_pid" 2>/dev/null || true
    fi
    # Do not delete the directory unless the mount has gone away.
    if /sbin/mount | grep -F " on $fixture_dir/mount (" >/dev/null; then
        echo "Mount still active: $fixture_dir/mount; leaving fixtures intact" >&2
    else
        rm -rf "$fixture_dir"
    fi
}
trap cleanup EXIT HUP INT TERM
printf 'ext4 fixture\n' > "$fixture_dir/payload"
dd if=/dev/zero of="$fixture_dir/ext4.img" bs=1048576 count=32 2>/dev/null
"$MKE2FS" -q -F -t ext4 "$fixture_dir/ext4.img"
"$DEBUGFS" -w -R "write $fixture_dir/payload /payload" "$fixture_dir/ext4.img" >/dev/null 2>&1
long_name=$(printf '%0255d' 0)
"$DEBUGFS" -w -R "write $fixture_dir/payload /$long_name" "$fixture_dir/ext4.img" >/dev/null 2>&1
for directory in /.ssh /blocked; do
    "$DEBUGFS" -w -R "mkdir $directory" "$fixture_dir/ext4.img" >/dev/null 2>&1
done
for name in /.hidden /.ssh/config /07:12:35.jpeg /owner /foreign /locked /blocked/payload; do
    "$DEBUGFS" -w -R "write $fixture_dir/payload $name" "$fixture_dir/ext4.img" >/dev/null 2>&1
done
mount_uid=$(id -u)
mount_gid=$(id -g)
foreign_uid=$((mount_uid + 65536))
foreign_gid=$((mount_gid + 131072))
for name in /owner /locked; do
    "$DEBUGFS" -w -R "set_inode_field $name uid $mount_uid" "$fixture_dir/ext4.img" >/dev/null 2>&1
    "$DEBUGFS" -w -R "set_inode_field $name gid $mount_gid" "$fixture_dir/ext4.img" >/dev/null 2>&1
done
"$DEBUGFS" -w -R "set_inode_field /owner mode 0100600" "$fixture_dir/ext4.img" >/dev/null 2>&1
"$DEBUGFS" -w -R "set_inode_field /locked mode 0100000" "$fixture_dir/ext4.img" >/dev/null 2>&1
"$DEBUGFS" -w -R "set_inode_field /foreign uid $foreign_uid" "$fixture_dir/ext4.img" >/dev/null 2>&1
"$DEBUGFS" -w -R "set_inode_field /foreign gid $foreign_gid" "$fixture_dir/ext4.img" >/dev/null 2>&1
"$DEBUGFS" -w -R "set_inode_field /foreign mode 0100600" "$fixture_dir/ext4.img" >/dev/null 2>&1
"$DEBUGFS" -w -R "set_inode_field /blocked mode 040000" "$fixture_dir/ext4.img" >/dev/null 2>&1
mkdir "$fixture_dir/mount"
"${READER:-./ext4fuse}" "$fixture_dir/ext4.img" "$fixture_dir/mount" -f -s -o "${MOUNT_OPTIONS:-ro,defer_permissions}" > "$fixture_dir/reader.log" 2>&1 &
reader_pid=$!
attempt=0
until [ -f "$fixture_dir/mount/payload" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 20 ] || ! kill -0 "$reader_pid" 2>/dev/null; then
        cat "$fixture_dir/reader.log" >&2
        echo 'FAIL: macFUSE mount did not become accessible' >&2
        exit 1
    fi
    sleep 0.25
done
cmp "$fixture_dir/payload" "$fixture_dir/mount/payload"
ls -l "$fixture_dir/mount" >/dev/null
cmp "$fixture_dir/payload" "$fixture_dir/mount/$long_name"
[ ! -e "$fixture_dir/mount/missing" ]
if touch "$fixture_dir/mount/should-not-exist" 2>/dev/null; then
    echo 'FAIL: mount accepted a write' >&2
    exit 1
fi
python3 - "$fixture_dir/mount" "${MOUNT_OPTIONS:-ro,defer_permissions}" <<'PYTEST'
import errno, os, pathlib, subprocess, sys
root=pathlib.Path(sys.argv[1]); options=sys.argv[2].split(',')
expected=b'ext4 fixture\n'
for name in ['.hidden','.ssh/config','07:12:35.jpeg','owner']:
    assert (root/name).read_bytes()==expected,name
assert '07:12:35.jpeg' in os.listdir(root)
assert 'config' in os.listdir(root/'.ssh')
foreign=os.stat(root/'foreign')
assert foreign.st_uid==os.getuid()+65536 and foreign.st_gid==os.getgid()+131072,foreign
owner=os.stat(root/'owner'); assert owner.st_uid==os.getuid() and owner.st_gid==os.getgid()
assert owner.st_mode & 0o777 == 0o400
for repeat in range(3):
    for name in ['missing','missing/child','.ssh/missing']:
        for operation in [os.stat,os.listdir,lambda p: pathlib.Path(p).read_bytes()]:
            try: operation(root/name)
            except OSError as error: assert error.errno==errno.ENOENT,(name,error)
            else: raise AssertionError('missing path succeeded: '+name)
    assert (root/'.ssh/config').read_bytes()==expected
result=subprocess.run(['/bin/ls','-l',str(root/'missing')],capture_output=True)
assert result.returncode!=0 and not result.stdout,result
for name in ['foreign','locked','blocked/payload']:
    if 'default_permissions' in options and os.getuid()!=0:
        try: (root/name).read_bytes()
        except OSError as error: assert error.errno==errno.EACCES,(name,error)
        else: raise AssertionError('permission check allowed '+name)
    elif 'defer_permissions' in options:
        assert (root/name).read_bytes()==expected,name
print('PASS: mounted hidden/colon/missing paths, full ownership and '+','.join(options))
PYTEST
echo 'PASS: macFUSE mounted contents, long names and write rejection'
