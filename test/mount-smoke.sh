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
mkdir "$fixture_dir/mount"
./ext4fuse "$fixture_dir/ext4.img" "$fixture_dir/mount" -f -s -o ro,defer_permissions > "$fixture_dir/reader.log" 2>&1 &
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
[ ! -e "$fixture_dir/mount/missing" ]
if touch "$fixture_dir/mount/should-not-exist" 2>/dev/null; then
    echo 'FAIL: mount accepted a write' >&2
    exit 1
fi
echo 'PASS: macFUSE mounted image, exact contents, missing path, write rejection'
