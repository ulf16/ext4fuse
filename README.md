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

- Verify metadata checksums for superblocks, descriptors, inodes, directories and traversed extents.

- Preserve full Linux UID/GID ownership and inode numbers; regress hidden/missing/colon paths.
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

## Install with Homebrew

The [ulf16/ext4fuse tap](https://github.com/ulf16/homebrew-ext4fuse) packages a pinned,
checksummed source snapshot. It requires macOS Sequoia or newer and macFUSE's FUSE 3
development files. Install macFUSE if needed, then:

```sh
brew install ulf16/ext4fuse/ext4fuse-maintained
brew test ulf16/ext4fuse/ext4fuse-maintained
```

Run `ext4fuse-maintained` for the packaged fork. It coexists with an older `ext4fuse`
installation. The package builds from source; no bottles are provided. Its Homebrew
test checks version and corrupted-image rejection without mounting. Tested on Intel
Sequoia; Apple Silicon is not yet validated. See the tap's README for macFUSE setup,
mounting, upgrade and removal instructions.

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
`struct stat` API. The reader uses portable xattr callbacks; Darwin resource-fork offsets and
READDIR_PLUS optimization are not implemented.

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
./ext4fuse /dev/diskNsM /path/to/mountpoint -s -o ro,default_permissions
```

Replace the placeholders with your actual partition and directory. Raw-device access may
require `sudo`; a root-owned mount may additionally need macFUSE's `allow_other` option for
other users. Prefer the disposable-image test before trying a real partition.
Unmount with `umount /path/to/mountpoint`.

Read-only prevents intentional filesystem writes; it does not guarantee correct parsing
of every image. Keep backups of important files.

## Ownership and permission modes

Linux-format inodes report the full 32-bit UID/GID, with no translation to local users.
Write mode bits are cleared, and mounts remain read-only. Numeric Linux owners often
have no matching macOS account. Use `default_permissions` to have the kernel enforce
reported Unix owner/group/mode bits. The mounted tests verify access to the mounting
user's private file and rejection of foreign-owned private files, mode-zero files,
and traversal through mode-zero directories.

For intentional data recovery where Linux permissions prevent access, macOS's
`defer_permissions` bypasses kernel checks; this reader does not independently enforce
read permissions. It therefore permits the mounting user to read mode-zero and foreign
private files. Do not combine that recovery mode with `allow_other` when access should
remain private. `allow_other` separately expands who can access the mount.
See [macFUSE's mount options](https://github.com/macfuse/macfuse/wiki/Mount-Options).
Linux ACLs are exposed as attribute metadata but are not enforced by this reader;
mode checks are not full Linux ACL equivalence. Non-Linux inode ownership layouts remain unaudited.

```sh
make test-attributes
./test/mount-smoke.sh
MOUNT_OPTIONS=ro,default_permissions ./test/mount-smoke.sh
# Test an installed package instead of the checkout binary:
READER="$(command -v ext4fuse-maintained)" ./test/mount-smoke.sh
```

Mounted regressions cover hidden directories/files, repeated missing-path operations,
and literal colon filenames. The original upstream reports are not reproduced on
Intel Sequoia/macFUSE 5.4.0 with either FUSE API. This does not certify older macOS
versions, Finder behavior, or cross-user/ACL access.

## Feature and metadata preflight

Before starting FUSE, the reader inspects the superblock and every group descriptor.
Unknown incompatible and read-only-compatible feature bits are rejected with their hex
mask; known unsupported bits are named. Compatible feature bits are ignored according
to the ext filesystem format's compatibility rules.

Features permitted by preflight include filetype, extents, flex_bg, ea_inode, csum_seed, largedir, and
64bit descriptors and checked high physical block addresses. The usual sparse_super, large_file,
huge_file, gdt_csum, dir_nlink, extra_isize, quota, metadata_csum, readonly and project
flags are accepted for read-only access. Acceptance is not exhaustive feature certification:
EA inode values have a 64 KiB limit, and resource/address bounds still apply.

Encryption, casefold, bigalloc, mmp, dirdata,
compression, external journal devices, shared_blocks, verity, and other unrecognized
layouts are refused in this milestone. Some could be supported with further work;
rejection means this reader has not established support.

Filesystems needing journal replay, marked unclean/erroneous, or containing pending
orphans are also refused. Unmount/check them using Linux before reading. Do not clear
feature bits to bypass these checks.

Geometry checks cover block sizes (1/2/4 KiB), inode size, group capacities, descriptor
size and inode table bounds. Descriptor allocations are limited to 256 MiB. Regular
images and supported physical devices shorter than their declared filesystem size are refused.
Device capacity query failures are also refused; see the device/index milestone below. These checks are not a replacement for fsck,
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
blocks, external extent nodes traversed, and external xattr blocks read. The inode extent root is covered by
its inode checksum. Stored checksum seeds, UUID-derived seeds, 16-bit inode checksums,
and the older `gdt_csum` CRC16 descriptor format are supported. A bad superblock or
descriptor stops preflight; bad inode/directory/extent checksums return I/O errors.
Metadata-checksummed non-Linux inode formats and unknown checksum algorithms are refused.

Verification follows the Linux kernel's
[checksum formats](https://www.kernel.org/doc/html/latest/filesystems/ext4/checksums.html).
It does not verify file payloads, allocation bitmaps, journal
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

## Large-file validation and allocation reporting

Logical file sizes use the high and low inode size words; sizes beyond signed 64-bit
`off_t` return an overflow error. Linux-format `huge_file` block counts use both
48-bit count words and, when the inode huge-file flag is set, convert filesystem
blocks into the 512-byte units required by `st_blocks`. This reports allocated blocks,
not the logical size of a sparse file.

```sh
make test-large
# Slow macOS integration test: reads/hashes a full 5GiB file and preserves copy holes.
./test/mount-large.sh
```

The portable suite creates sparse ext4 and ext2 files larger than 4GiB inside small
images, checks data and holes across direct/single/double/triple-indirect boundaries,
and compares sizes, allocation and mappings with `debugfs`. A fragmented ext4 file
requires a real depth-two extent tree and is compared with a `debugfs` dump. Additional
metadata-only count variants exercise huge-file accounting; they are synthetic
encodings, not evidence of physically allocating huge amounts of storage.

CRC32C uses an immutable lookup table, checked against standard vectors and real
e2fsprogs metadata fixtures. Sparse hole runs stop at validated extent/subtree boundaries, avoiding repeated
metadata reads and checksums for every zero-filled block.

On macFUSE 5.4.0, mounted `stat`/`du` derive allocation from logical size even when
our callback supplies the correct sparse count. This matches the open
[macFUSE sparse-file report](https://github.com/macfuse/macfuse/issues/1121).
The mounted test explicitly records this provider limitation and checks the callback
against `debugfs`; it does not claim accurate macOS `du` output or SEEK_HOLE support.
The test's sparse copy skips zero-filled chunks rather than relying on SEEK_HOLE.

The mounted test hashes every byte of a 5GiB+13-byte sparse file through FUSE, hashes
independent `debugfs cat` output, and verifies a sparse host copy against both. It uses
no real disks. Testing large logical files does not certify all volumes, maximum
extent depths, or legacy file-size limits.

## High physical addresses and inline data

Physical extent addresses (48-bit on disk), extent index pointers, inode-table addresses
and the 64-bit superblock block count retain their high words. Preflight rejects byte
sizes beyond signed 64-bit offsets, invalid group counts and out-of-volume metadata.
The 256 MiB descriptor-table resource limit remains. This is
expanded addressing support, not a guarantee that every large ext4 layout is supported.

```sh
# Optional: sparse-capable host filesystem and approximately 1.6 GiB free space.
make test-addresses
make test-inline
```

The address suite creates a real 16 TiB sparse ext4 geometry, then explicitly relocates
file data, an external extent node and an inode table above 2**32 physical blocks.
Reads agree with Linux debugfs; out-of-volume high addresses fail. Those relocation
fixtures test the reader, not full bitmap accounting or e2fsck consistency.

Linux inline regular files and directories are supported. File bytes come from the
60-byte i_block area followed by the inode-body system.data attribute. Directories
keep the two dirent regions separate and synthesize dot/parent entries from the stored
parent inode. The bounded xattr parser requires system.data and rejects malformed,
overlapping-table, out-of-inode, duplicate or external-value references. Inode checksums
protect inline data where enabled. Other extended attributes and Linux ACL metadata are exposed through read-only xattr callbacks.

Real e2fsprogs fixtures cover 1/2/4 KiB blocks, 256/512-byte inodes, checksums on/off,
empty files, the 60-byte boundary, larger files converted to extents, both inline directory
regions, missing names, dot/parent traversal, symlinks and corrupted inline metadata.

## Timestamps and meta_bg descriptors

Timestamp decoding follows Linux ext4: signed 32-bit base seconds plus two extra epoch
bits, and nanoseconds in the remaining extra bits. Extra fields are consumed only when
both the inode size and i_extra_isize declare them. Invalid nanoseconds fail with EIO;
unrepresentable host time values fail with EOVERFLOW. Creation time is exposed as
birthtime on macOS and FreeBSD; ordinary Linux POSIX stat has no birthtime field.

meta_bg primary descriptors are located at their meta-group boundaries, with the proper
superblock offset for sparse_super, sparse_super2 or full backup-super layouts. Early
blocks below s_first_meta_bg retain the classic contiguous placement. Descriptor
checksums, inode-table bounds and the 256 MiB memory cap still apply. Corrupt primary
metadata is rejected; the reader does not repair it from backup copies.

```sh
make test-timestamps
make test-meta-bg
# macOS/macFUSE integration with exact native timespecs, including birthtime:
./test/mount-metadata.sh
```

Timestamp fixtures cover old and extended inodes, negative seconds, epoch boundaries,
all four time fields, nanoseconds and malformed/present-only extensions. Some debugfs
versions display high-bit base seconds unsigned; the reader follows Linux's signed
rule, and the tests distinguish that formatter quirk from actual inode encodings.
The meta_bg suite checks real 1/2/4 KiB, 32/64-byte descriptor, sparse-super and checksum
variants across three descriptor blocks. Mixed classic/meta placement is also exercised
using explicit descriptor copies; those synthetic fixtures do not certify bitmap repair.

## Extended attributes

`listxattr` and `getxattr` expose attributes in the inode body and its external xattr
block. Names retain their Linux namespaces (`user.`, `trusted.`, `security.`, `system.`).
Values are returned unchanged, including embedded NUL bytes and empty values, except
POSIX ACLs: ext4's compact disk encoding is converted to Linux's version-2 xattr encoding.
Access and default ACLs are metadata only; macOS does not enforce these Linux ACLs.
The existing mode-based mount permission policy still applies. Namespace-specific
Linux capabilities or SELinux policy are not reproduced by this recovery reader.

`system.data` is internal inline file/directory storage and is hidden. Unknown namespace
indices are checked structurally but omitted because they have no supported name mapping.
`user.com.apple.*` names remain literal Linux names, without translating them into native
Finder attributes or resource forks. Darwin FUSE 2 calls with a nonzero resource-fork
position are rejected. Attribute modification remains unavailable on the read-only mount.

Size queries return the required length, undersized buffers return ERANGE, and absent
attributes return the host's missing-attribute error. Complete inode and block tables
are validated before returning data: entry/value bounds, table separation, names,
duplicate exposed names, external entry ordering, header fields and unexpected external-value inode
references. Inode checksums cover inode-body attributes; external blocks use CRC32C with
the filesystem seed and full 64-bit block address when metadata_csum is enabled.
Shared xattr blocks and shared value storage are permitted. Large values can be read
from EA inodes as described below.

```sh
make test-xattrs
# macOS integration through native xattr APIs and the xattr command:
./test/mount-xattrs.sh
```

The disposable fixtures compare attributes with debugfs across 1/2/4 KiB blocks,
128/256/512-byte inodes, checksums on/off and stored checksum seeds. They cover binary,
empty and long-name attributes, Linux ACL conversion, symlink metadata, inline files,
size queries, missing paths and checksum-repaired malformed records.

## Large values in EA inodes

Filesystems with `ea_inode` are accepted for read-only access. Referenced internal EA
inodes supply attribute values up to 64 KiB, Linux's userspace xattr limit. Values above
this limit return E2BIG. Entries may be in the inode body or external xattr block;
ordinary attributes, inline files/directories and shared EA values remain supported.
The driver does not create, modify or free EA inodes.

EA references must point to a non-reserved inode, differ from the owning inode and
match the declared value size. The target must be an active regular EA inode with
one link and a nonzero 64-bit reference count. Nested attributes, deleted inodes,
inline EA value storage, missing blocks and unwritten extents are rejected. Ordinary
path lookups reject internal EA inodes even if a corrupt directory names one.
Metadata checksums cover the owning/reference/value inodes and external xattr blocks
where enabled. Listing checks reference metadata and entry hashes without reading
all large value payloads. Retrieval, including size queries, verifies the full value's
seeded CRC32C against its stored hash, plus the name/value entry hash. The historical
signed-byte name-hash variant is accepted; unhashed legacy Lustre EA layouts are not.
EA timestamp/version fields encode hashes and reference counts, and are not interpreted
as normal file timestamps or versions.

```sh
# On Linux, the additional fixture writer needs libext2fs-dev and pkg-config.
# On macOS it uses the existing e2fsprogs development files.
make test-ea-inode
EA_INODE=1 ./test/mount-xattrs.sh
```

The fixture writer uses libext2fs because debugfs `ea_set -f` reads only one filesystem
block of input. Fixtures include complete 64 KiB binary values; e2fsck reconciles
parent EA allocation charging and confirms clean filesystems before reader comparisons.
Tests cover extent/indirect storage, 1/2/4 KiB blocks, 128/256/512-byte inodes, inline
owners, checksums on/off and stored seeds. A shared-value layout is verified by e2fsck.
Corruption fixtures exercise reference numbers, inode state, size/entry hashes, value
CRC, missing/unwritten blocks, short reads and internal-inode isolation. Every test
uses disposable images, not real disks.

## Remaining work

- Reproduce remaining upstream reports; expand supplementary-group, ACL and cross-user tests.
- Expand malformed-metadata coverage and physical large-volume validation.
- Expand support for explicitly rejected features.
- Expand sparse-file, symlink, directory and large-volume tests; compare against Linux tools.
- Replace the bypassed directory cache with a validated, thread-safe implementation if needed.
- Broaden platform and real-filesystem validation of the published Homebrew package.

Write support and an FSKit port are outside the initial milestone. Existing limitations
include resource limits and unsupported large-volume layouts; do not assume full support for modern ext4
features, encryption, or LVM containers.

Report reproducible issues to [this fork](https://github.com/ulf16/ext4fuse/issues).
Do not upload private filesystem images or directory logs to public issues.

## Large directories (0.2.7)

`largedir` (`large_dir` in e2fsprogs) permits the extra htree index level.
The reader accepts root `indirect_levels` through two when this feature is set,
through one otherwise. Root headers, exact index capacity/count, hash order and
28-bit child block bounds are checked even without metadata checksums. Index and
leaf checksums remain verified before their entries are exposed.

Enumeration uses linear block scans, with index nodes skipped as empty records.
Version 0.2.8 adds indexed filename lookup as described below. Listing buffers retain
64-bit resume offsets and directory sizes.

`make test-largedir` builds real indexed directories across 1/2/4 KiB blocks and
checksum modes, inserts valid intermediate nodes using a test-only libext2fs helper,
and certifies the resulting three-level trees with `e2fsck`. It checks complete and
paged name sets, file/missing-name lookup, feature-gated depth and structural
corruption with repaired checksums. Separate synthetic cursor fixtures test beyond
4 GiB; these deliberately contain directory holes and are not fsck-certified
large-directory images. Multi-gigabyte populated directories have not been tested.

```sh
PATH="$(brew --prefix e2fsprogs)/sbin:$PATH" make test-largedir
PATH="$(brew --prefix e2fsprogs)/sbin:$PATH" sh test/mount-largedir.sh
```

The mounted test checks exact 1,100-name listings through macFUSE, repeated/paged
enumeration, contents, missing-name behavior, read-only rejection and unchanged image
bytes. The test helper uses the same libext2fs development files as the EA inode suite.

## Device capacity and indexed lookup (0.2.8)

Before mounting, physical-device capacity is queried using macOS block size/count,
Linux `BLKGETSIZE64`, or FreeBSD `DIOCGMEDIASIZE`. Undersized inputs, failed queries,
zero device capacity and arithmetic overflow are refused. Unsupported input types
are refused. Raw macOS and FreeBSD character-device reads use bounded sector bounce
buffers for metadata or payload ranges that do not meet the device's alignment;
sector sizes above 64 KiB or invalid sector geometry are refused.

Indexed directories now use the htree for filename lookup. The reader implements
legacy, half-MD4 and TEA hashes with signed/unsigned byte variants and the filesystem
hash seed/flags. It binary-searches verified nodes, follows only the selected path,
and continues equal-hash collisions across leaf and index-node boundaries. Invalid
selected-node roles, ancestor cycles, checksum errors and invalid references return
I/O errors; malformed trees do not silently fall back to linear lookup. Regular
linear/inline directories and dot/dotdot still use their existing paths. Readdir
remains linear and preserves paged offsets; no mutable directory cache is added.

The test suite compares 8,640 hashes with libext2fs and all 1,100 names per hash variant
with debugfs inode numbers, including UTF-8 bytes and missing names. Fsck-certified
collision fixtures span 1/2/4 KiB blocks, plain/seeded checksums and index depths zero
through two. Test-only instrumentation measures 3–4 directory-block loads for a miss
versus 162–163 with linear lookup in the 1,100-name fixture. These are directory I/O
counts, not a general wall-clock speedup claim. Indexed reads verify metadata on demand;
corruption in unvisited nodes is not necessarily detected by a particular lookup.

```sh
make test-device-capacity test-indexed test-index-collisions
# macOS: attaches and detaches only disposable read-only disk images.
python3 test/device-capacity-macos.py
RAW_DEVICE=1 sh test/mount-largedir.sh
# Linux: creates/detaches disposable read-only loop devices; needs sudo.
python3 test/device-capacity-linux.py
```

Native macOS tests cover both block and raw device preflight, payload reads, oversize
rejection and a raw-device macFUSE mount. Device tests never target user disks.
FreeBSD capacity/alignment implementation is not validated on a real FreeBSD device.
All previously documented read-only, journal, ACL enforcement and platform limits remain.

## Filesystem space reporting

The `statfs` callback supplies `df` and filesystem space queries with a snapshot
of the clean ext4 superblock: block size, total and free blocks, free blocks after
subtracting the reserved allowance (clamped at zero), and total/free inode counts.
The mount is marked read-only; reported available space describes the source
filesystem and does not permit writing through this reader. Counts are not refreshed
while mounted: modifying the backing filesystem concurrently is unsupported.

Total blocks include filesystem metadata. This is the on-disk geometry, rather
than Linux ext4's default `df` total after subtracting its calculated metadata
overhead. Thus the totals need not match Linux `df` exactly. Impossible free or
reserved counts return `EIO`; values too large for the host's `statvfs` counters
return `EOVERFLOW`. The 64-bit count fields are used only with the `64bit` feature.
No block bitmap scan is performed. See the [ext4 superblock specification](https://www.kernel.org/doc/html/next/filesystems/ext4/super.html).

Run `make test-statfs` with e2fsprogs in PATH for callback/reference checks, and
`python3 test/mount-statfs.py` on macOS/macFUSE for a disposable mounted `statvfs`
and `df` check. Both FUSE APIs are covered by the portable CI suite.

NetBSD builds now link `libexecinfo`, as required by its
[backtrace(3) implementation](https://man.netbsd.org/backtrace.3). This addresses the
missing-library cause reported in upstream issue #67. A native NetBSD build and
mount have not been validated; this is not a claim of complete NetBSD support.
