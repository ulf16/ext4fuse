# ext4fuse — Sequoia maintenance fork

Read-only ext4 access using FUSE, based on [gerard/ext4fuse](https://github.com/gerard/ext4fuse).
This fork starts with macOS Sequoia 15 on Intel and macFUSE's FUSE 3 API.
FUSE 3 is the default; FUSE 2 remains available as a build-time fallback.
It does not require a VM. It preserves the upstream GPLv2 license and copyright notices.

## Status

The first milestone builds and passes disposable-image reader and mounted-access tests
on Intel macOS 15.8.1 with macFUSE 5.4.0. This is an experimental maintenance fork,
not a claim that every upstream issue or ext4 feature is fixed.

Changes so far:

- Validate directory records and bounded extent trees, propagating read errors to FUSE.
- Return zeroes for sparse holes and unwritten extents, including partial-block reads.
- Bound symlink reads and report path errors consistently.
- Reject overlong path components without overflowing the length counter or hanging.
- Reject unsupported features, unclean volumes, truncated images, and invalid metadata geometry before mounting.
- Support FUSE 3 and FUSE 2 through small callback adapters.
- Keep separate object directories for each API, so switching does not mix ABIs.
- Fix a stack buffer overflow when listing a valid 255-byte filename.
- Default macOS deployment target to 15.0 (overridable).
- Diagnose missing FUSE development metadata and support `PKG_CONFIG`/`FUSE_PKG` overrides.
- Preserve required build flags when supplying custom `CFLAGS`, including sanitizers.
- Resolve the SDK's `MIN` macro conflict and quote the fallback version string.
- Add disposable ext4 image regression tests and Linux CI.
- Make the legacy test loops propagate failures.

## Build on Sequoia

Install macFUSE from its official installer or Homebrew cask if it is not already installed.
Use its normal macOS approval process; this project does not change system security settings.

```sh
brew install pkgconf e2fsprogs
# Only if macFUSE is not already installed:
# brew install --cask macfuse
make -j4
```

`pkg-config --modversion fuse3` should find the FUSE 3 library.
For a nonstandard install, set `PKG_CONFIG_PATH` to the directory containing `fuse3.pc`.
For the FUSE 2 fallback, use `make FUSE_API=2` and `make test-images FUSE_API=2`.
Both APIs use the same read-only filesystem reader. Objects are stored separately,
and switching API versions relinks the binary. Clean before changing optimization
or sanitizer flags.

On macOS, FUSE 3 uses `FUSE_DARWIN_ENABLE_EXTENSIONS=0` to select macFUSE's portable
`struct stat` API. Darwin-specific extended attributes and READDIR_PLUS optimization
are not implemented in this milestone.

The binary stays in the checkout; building does not replace an installed ext4fuse.
For an older macOS target, explicitly set `MACOSX_DEPLOYMENT_TARGET` (not tested here).

## Tests

The new tests use e2fsprogs to create temporary **regular-file images**, never physical disks.
They check ext4 filesystems with 1 KiB and 4 KiB blocks, exact file contents, partial reads,
EOF, read-only mode bits, repeated missing-path lookups, and 255-byte directory entries.

```sh
export PATH="$(brew --prefix e2fsprogs)/sbin:$PATH"
make test-images
```

For sanitizer validation, clean first so every object uses the same instrumentation:

```sh
make clean
make -j4 CFLAGS='-O1 -g -fsanitize=address,undefined'
make test-images CFLAGS='-O1 -g -fsanitize=address,undefined'
```

On macOS, separately test the actual macFUSE mount:

```sh
./test/mount-smoke.sh
```

This checks file contents, missing paths and write rejection, then unmounts the image.
It requires a working, approved macFUSE installation. CI currently tests the reader on
Linux for both FUSE 2 and FUSE 3 without mounting; it does not certify macOS mounting.

The older `make test` / `make test-slow` suites remain available but contain Linux-specific
mounting tools and privileged operations. They are not the Sequoia validation entry point.

## Mounting real partitions

Identify the correct **partition** using `diskutil list`. Unmount it before mounting here.
Create a mount directory and use your checkout's binary:

```sh
./ext4fuse /dev/diskNsM /path/to/mountpoint -s -o ro,defer_permissions
```

Replace the placeholders with your actual partition and directory. Raw-device access may
require `sudo`; a root-owned mount may additionally need macFUSE's `allow_other` option for
other users. Prefer the disposable-image test before trying a real partition.
Unmount with `umount /path/to/mountpoint`.

Read-only prevents intentional filesystem writes; it does not guarantee correct parsing
of every image. Keep backups of important files.

## Feature and metadata preflight

Before starting FUSE, the reader inspects the superblock and every group descriptor.
Unknown incompatible and read-only-compatible feature bits are rejected with their hex
mask; known unsupported bits are named. Compatible feature bits are ignored according
to the ext filesystem format's compatibility rules.

Features permitted by preflight include filetype, extents, flex_bg, csum_seed, and
64bit descriptors **with 32-bit block addressing**. The usual sparse_super, large_file,
huge_file, gdt_csum, dir_nlink, extra_isize, quota, metadata_csum, readonly and project
flags are accepted for read-only access. Acceptance is not exhaustive feature certification:
extended attributes are not exposed, and large
file allocation statistics still need an audit.

Encryption, casefold, inline_data, meta_bg, bigalloc, largedir, ea_inode, mmp, dirdata,
compression, external journal devices, shared_blocks, verity, and other unrecognized
layouts are refused in this milestone. Some could be supported with further work;
rejection means this reader has not established support.

Filesystems needing journal replay, marked unclean/erroneous, or containing pending
orphans are also refused. Unmount/check them using Linux before reading. Do not clear
feature bits to bypass these checks.

Geometry checks cover block sizes (1/2/4 KiB), inode size, group capacities, descriptor
size and inode table bounds. Descriptor allocations are limited to 256 MiB. Regular
images shorter than their declared filesystem size are refused; physical-device size
checking needs platform-specific work. These checks are not a replacement for fsck,
and directory and extent records are also checked on demand. Checksums are verified as described below.

```sh
make test-features
# Or use the fallback API:
make test-features FUSE_API=2
```

Tests use real mkfs feature layouts plus deliberately mutated copies, and verify that
the reader leaves the images unchanged. The preflight follows the Linux kernel's
[superblock](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html) and
[group descriptor](https://www.kernel.org/doc/html/latest/filesystems/ext4/group_descr.html)
documentation.

## Metadata checksum verification

When `metadata_csum` is enabled, CRC32C verification covers the primary superblock,
all primary group descriptors, each inode read, directory leaves and htree index
blocks, and external extent nodes traversed. The inode extent root is covered by
its inode checksum. Stored checksum seeds, UUID-derived seeds, 16-bit inode checksums,
and the older `gdt_csum` CRC16 descriptor format are supported. A bad superblock or
descriptor stops preflight; bad inode/directory/extent checksums return I/O errors.
Metadata-checksummed non-Linux inode formats and unknown checksum algorithms are refused.

Verification follows the Linux kernel's
[checksum formats](https://www.kernel.org/doc/html/latest/filesystems/ext4/checksums.html).
It does not verify file payloads, allocation bitmaps, extended attributes, journal
contents, backup metadata, or unused extent subtrees. Filesystems without checksum
features still receive structural validation; missing checksums cannot detect arbitrary
byte corruption. Images must remain unmounted and unchanged while being read.

```sh
make test-checksums
```

The suite uses e2fsprogs-generated checksums and indexed directories, flips individual
bytes in disposable copies, and checks that reader operations leave images unchanged.
Structural mutation suites use separate non-checksummed fixtures so checksum rejection
does not mask their bounds checks.

## Directory and extent validation

Directory records must advance, stay within their block and directory, have aligned
record lengths, and contain valid names and inode numbers. Invalid offsets and attempts
to traverse regular files as directories return errors. Deleted records and checksum
trailers remain readable using the standard linear-directory representation.

Extent headers and entry counts are bounded by their actual container. Depth is limited
to five; child depth and first-key relationships are checked, along with ordering,
overlap, physical block ranges, and logical overflow. Only nodes visited by the read
are validated, not every unused subtree. Unwritten extents and holes return zeroes.
Legacy direct/indirect block reads also use checked pointers and I/O.

Path lookups currently bypass the old directory cache; this can cost lookup performance.
FUSE's normal caching remains available. Read errors propagate to callbacks instead of
being treated as missing files. This is not a complete filesystem integrity check.

```sh
make test-corruption
```

This suite compares ordinary and sparse-file reads with e2fsprogs `debugfs`, tests
malformed records/trees and symlink buffers, and deliberately truncates disposable images
after preflight to verify that actual short reads return errors. Images are never real disks.

## Remaining work

- Reproduce and triage upstream issues individually, including permissions and directory caching.
- Expand malformed-metadata coverage and audit filesystem allocation statistics.
- Expand support for explicitly rejected features.
- Expand sparse-file, symlink, directory and large-volume tests; compare against Linux tools.
- Replace the bypassed directory cache with a validated, thread-safe implementation if needed.
- Add reproducible packaging through a separate Homebrew tap after broader validation.

Write support and an FSKit port are outside the initial milestone. Existing limitations
include incomplete large-volume addressing; do not assume full support for modern ext4
features, encryption, or LVM containers.

Report reproducible issues to [this fork](https://github.com/ulf16/ext4fuse/issues).
Do not upload private filesystem images or directory logs to public issues.
