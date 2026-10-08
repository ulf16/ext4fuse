#!/bin/sh
set -eu
MKE2FS=${MKE2FS:-$(command -v mke2fs || true)}
DEBUGFS=${DEBUGFS:-$(command -v debugfs || true)}
if [ -z "$MKE2FS" ] || [ -z "$DEBUGFS" ]; then
    echo "e2fsprogs is required: set MKE2FS and DEBUGFS or add its sbin to PATH" >&2
    exit 1
fi
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-images.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
printf 'ext4 fixture\n' > "$fixture_dir/payload"
long_name=$(printf '%0255d' 0)
for block_size in 1024 2048 4096; do
    image="$fixture_dir/ext4-$block_size.img"
    dd if=/dev/zero of="$image" bs=1048576 count=32 2>/dev/null
    "$MKE2FS" -q -F -t ext4 -b "$block_size" "$image"
    "$DEBUGFS" -w -R "write $fixture_dir/payload /payload" "$image" >/dev/null 2>&1
    "$DEBUGFS" -w -R "write $fixture_dir/payload /$long_name" "$image" >/dev/null 2>&1
    echo "ext4 block size: $block_size"
    ./test/image-reader "$image"
done
