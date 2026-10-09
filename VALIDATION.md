# First milestone validation — 2026-10-08

Upstream base: `6b23d8d` (master). Platform: Intel macOS 15.8.1, macFUSE 5.4.0,
Apple Clang from the installed Xcode toolchain, e2fsprogs from Homebrew.

## Confirmed locally

- Upstream source builds against the installed FUSE 2 compatibility library.
- The 255-byte filename fixture causes an AddressSanitizer stack-buffer-overflow in
  upstream `op_readdir`; the corrected buffer passes the same test.
- Patched build with AddressSanitizer and UndefinedBehaviorSanitizer succeeds.
- Image-reader tests pass on 1 KiB and 4 KiB ext4 block sizes with e2fsprogs defaults.
- Mounted-image smoke test passes through macFUSE: exact file contents, missing-path
  handling, and attempted-write rejection. Mount removed after the test.

## Limits

No physical Linux disks were mounted. No claim is made about all filesystem feature
combinations, large volumes, corrupted images, multi-threaded cache access or write support.
The new fixtures cover a small normal filesystem, not the entire upstream issue backlog.
No Linux-reference mounted comparison has been performed yet. CI results are tracked on GitHub.

## FUSE 3 milestone — 2026-10-08

- FUSE 3 API 31 build against macFUSE's installed `fuse3` 3.18.2 library.
- Portable macFUSE ABI selected explicitly; no Darwin-specific stat ABI extensions.
- AddressSanitizer/UndefinedBehaviorSanitizer image tests pass for both API versions.
- Mounted smoke tests check both APIs, including directory listings and reading a
  255-byte filename, alongside content, missing-path and write-rejection checks.
- Switching API versions without cleaning uses separate objects and relinks outputs.
- FUSE 3 is the default; FUSE 2 is selectable with `FUSE_API=2`.
- Linux CI covers both APIs; no performance improvement is claimed.

The expanded mounted-directory test exposed a separate upstream hang: filename
length was counted in a uint8_t and wrapped on components longer than 255 bytes.
The parser now uses a bounded size_t counter and rejects such lookups. Regression
checks cover 256- and 257-byte components; both mounted APIs pass long-name listings.

## Feature preflight milestone — 2026-10-08

- Unsupported incompatible/read-only-compatible features are reported before FUSE starts.
- Clean default ext4 images with 32-byte and 64-byte descriptors are accepted.
- Normal image-reader tests cover 1, 2, and 4 KiB block sizes.
- Rejection tests include real mkfs layouts (encrypt, casefold, inline_data, meta_bg,
  bigalloc), unknown bits, recovery/dirty state, malformed geometry, inode-table
  addresses, and truncated regular files. Each probe verifies the image is unchanged.
- Rejected CLI input returns status 1 with a named diagnostic, without a mount or assertion.
- Checked metadata reads handle EOF, read errors and EINTR; existing deeper reader
  assertions and checksum verification remain separate work.
- Features accepted by preflight are documented separately from full feature certification.
- 97 feature/geometry acceptance and rejection checks pass locally under sanitizers
  for each FUSE API. Both mounted smoke tests pass after the preflight change.

## Directory and extent hardening — 2026-10-08

- Checked directory records (length, alignment, block boundaries, names and inode ranges).
- Checked extent headers, depth, parent/child key agreement, ordering, overlaps and pointers.
- Checked legacy block mapping and inode reads; I/O errors propagate to FUSE callbacks.
- Sparse gaps/unwritten extents and partial-block reads return zeroes.
- Symlink buffers are bounded; missing paths and non-directory traversal report errors.
- The old directory cache is bypassed pending a separate correctness/concurrency audit.
- Disposable-image tests compare normal/sparse/fragmented contents with debugfs and use malformed
  trees, directory records, cyclic pointers and deliberate truncation after preflight.
- Checksums and unused extent subtrees are not verified. No real Linux disks were used.
- All 78 hardening checks pass with AddressSanitizer and UndefinedBehaviorSanitizer
  for both FUSE APIs; existing 97 preflight checks and both mounted smoke tests pass.

## Metadata checksums — 2026-10-08

- Verify CRC32C primary superblock/group descriptors, full raw inodes, directory
  leaves/htree nodes, and traversed external extent nodes before consuming metadata.
- Support UUID/stored seeds, 16/32-bit inode checksums, and legacy CRC16 descriptors.
- Structural suites use non-checksummed copies to preserve independent bounds coverage.
- No file-data, bitmap, journal, backup, or unused-subtree checksum certification;
  xattr checksum coverage was added in the later extended-attribute milestone.
- 75 checksum checks pass locally under ASan/UBSan for both FUSE APIs, alongside
  the existing 97 preflight and 78 structural checks. Both macFUSE mount tests pass.

## Ownership and upstream path regressions — 2026-10-08

- Preserve Linux UID/GID high words and expose the inode number through getattr.
- 35 portable tests cover owner/group IDs up to 32 bits, read-only modes, inode identity,
  hidden/space/colon names, repeated missing paths and non-directory errors, for both APIs.
- Both macFUSE APIs pass expanded mounted tests under defer_permissions and
  default_permissions. Strict tests reject foreign private files whose low UID matches
  the mounting user, mode-zero files, and traversal through mode-zero directories.
- Hidden directories, missing-path listings and colon-filename upstream reports are not
  reproduced on this Intel Sequoia/macFUSE setup. Other platforms/Finder remain untested.
- No UID translation, Linux ACL enforcement or cross-user certification is claimed.

## Large-file and allocation milestone — 2026-10-08

- Decode Linux huge-file 48-bit block counts and filesystem-block units into POSIX
  512-byte st_blocks; report block-size hints and reject stat sizes above INT64_MAX.
- 89 portable checks cover real ext4/ext2 logical files over 4GiB, direct through
  triple-indirect transition data/holes, offsets/EOF, real depth-two extent traversal,
  debugfs mapping/allocation/dump comparisons, and synthetic huge-file count encodings.
- The slow mounted test compares full SHA-256 for a 5GiB+13-byte file, debugfs output,
  and a sparse host copy. It deliberately avoids physically allocating a 5GiB copy.
- Physical block addresses remain limited to 32 bits. No real-volume or maximum-depth
  certification is claimed; synthetic accounting variants do not represent huge allocation.
- Return validated contiguous hole runs, capped at the next extent or subtree boundary.
- Replace bit-at-a-time CRC32C with an immutable Castagnoli table; verify standard
  CRC vectors/chaining and e2fsprogs-generated metadata before mounted validation.
- Confirmed macFUSE 5.4.0 derives mounted st_blocks from logical size; the callback
  matches debugfs (80 sectors versus 10485768 mounted). Track macFUSE issue #1121;
  this remains a provider limitation, not a claim of corrected macOS du output.

## High physical addresses and inline data — 2026-10-09

This milestone supersedes the earlier 32-bit physical-address and inline-data limits.

- Preserve the 64-bit superblock block count, high inode-table addresses and 48-bit
  extent data/index addresses. Reject signed-byte-offset overflow, invalid group
  counts and metadata outside the declared volume; retain the descriptor memory cap.
- Optional address fixtures use real mke2fs 16 TiB sparse geometry and explicit high
  data, external-tree and inode-table relocations. Six high-address reads/rejections
  agree with debugfs. The relocations do not certify bitmap accounting/e2fsck consistency.
- Read Linux inline regular files from i_block plus inode-body system.data, including
  zero-length attribute values. Validate xattr bounds, table/value separation,
  required/duplicate system.data entries and unsupported external-value references.
- Read both inline-directory regions separately; synthesize dot/parent entries and
  validate dirent bounds without expecting separate directory-block checksums.
- 817 inline checks cover real 1/2/4 KiB filesystems, 256/512-byte inodes, checksum
  variants, empty/boundary/converted files, two-region directories, path traversal,
  symlinks and malformed xattrs/directory records.
- All portable suites pass with ASan/UBSan for both FUSE APIs: normal images, 98
  feature/geometry checks, 78 corruption checks, 75 checksum checks, 35 ownership/path
  checks, 89 large-file checks and 817 inline checks. Linux CI includes the inline suite.
- Both APIs pass mounted inline contents, directory listing, sizes, parent paths,
  symlinks and write rejection; strict mounted path/permission regression coverage remains.
- The disposable 16 TiB geometry also reads high data/tree/inode addresses through
  macFUSE. No physical disk or Apple Silicon certification is claimed.

meta_bg and other documented unsupported layouts remain refused. No journal replay,
write support, Linux ACL enforcement or macFUSE sparse stat/du allocation fix is added.

## Timestamps and meta_bg — 2026-10-09

This milestone supersedes the earlier rejection of meta_bg layouts.

- Decode timestamps with Linux's signed base seconds, two epoch bits and nanoseconds.
  Extended fields require valid inode-size/i_extra_isize bounds. Reject invalid nanos
  and unrepresentable host time values. Populate macOS/FreeBSD birthtime where present;
  ordinary Linux POSIX stat does not expose creation time.
- 53 timestamp checks cover 128/256-byte inodes, checksum variants, negative seconds,
  2038 and later epoch boundaries, all time fields, nanoseconds, partial field presence
  and invalid encodings. Tests recognize debugfs's unsigned-base display quirk while
  retaining Linux's signed decoding semantics.
- Locate primary meta_bg descriptor blocks according to the Linux placement rule,
  including classic early descriptor blocks, sparse_super, sparse_super2 and complete
  backup-super layouts. Retain descriptor checksums, inode bounds and the memory cap.
- 108 meta_bg checks cover real 1/2/4 KiB filesystems and 32/64-byte descriptors across
  three descriptor blocks, content comparison with debugfs/dumpe2fs, checksum damage,
  invalid transition indices and explicit mixed-layout fixtures. The latter do not
  certify bitmap consistency or repair. No fallback to damaged-primary backups is added.
- All portable suites pass with ASan/UBSan for both FUSE APIs: normal images, 95 feature
  checks, 78 corruption checks, 75 checksum checks, 35 ownership/path checks, 89 large-file
  checks, 817 inline checks, 53 timestamp checks and 108 meta_bg checks.
- Both macFUSE APIs pass mounted meta_bg + inline reads and native stat comparison for
  exact access/modification/change/creation seconds and nanoseconds. Negative access
  time and modification time beyond 2038 are exercised. Strict path/permission smoke
  checks also pass. Temporary volumes are removed after testing.

Apple Silicon and FreeBSD remain untested. No write support, journal replay, Linux ACL
enforcement or macFUSE sparse stat/du allocation fix is included.

## Extended attributes milestone (0.2.5)

- Add read-only listxattr/getxattr for inode-body and external-block attributes.
  Preserve Linux user/trusted/security/system namespace names and binary/empty values;
  hide internal system.data storage and omit unknown namespace indices.
- Convert ext4 disk POSIX ACL v1 into Linux userspace xattr v2, including full named
  UID/GID entries and ACL_UNDEFINED_ID for unnamed principals. Access/default ACLs
  remain metadata: Linux ACL, capability and SELinux policy enforcement is not added.
- Validate full inode/block tables before returning data: entry/name/value bounds,
  table/value separation, duplicate exposed names, sorted external entries, header
  fields and unexpected external-value inode references. Verify inode-body checksums
  through the common raw-inode reader and external block CRC32C using the filesystem
  seed and 64-bit block address. ea_inode-backed values remain unsupported.
- 1,285 xattr checks pass for each FUSE API with ASan/UBSan, covering 1/2/4 KiB blocks,
  128/256/512-byte inodes, checksums on/off, stored seeds, comparison with debugfs,
  empty/binary/long-name values, ACL conversion, symlinks, size queries, ERANGE,
  missing paths/attributes, checksum damage and checksum-repaired malformed metadata.
  The existing image, feature, corruption, checksum, ownership, large-file, inline,
  timestamp and meta_bg suites also pass with both APIs.
- Actual Intel Sequoia/macFUSE mounts pass with both APIs: native Darwin list/get calls,
  the xattr command, inline files with external attributes, ACL metadata, symlink xattrs,
  empty values, namespace preservation and EROFS for attribute writes/removal. Every
  fixture remains byte-identical after reads; temporary mounts are removed.

At this milestone, Darwin resource-fork offsets, Finder namespace translation, ea_inode
support and Linux ACL enforcement were not added. Apple Silicon and FreeBSD remain untested.


## EA inode milestone (0.2.6)

- Accept the ea_inode feature on Linux-format filesystems with a valid first
  non-reserved inode boundary. Read values up to 64 KiB from references in the inode
  body or external xattr block; values above the explicit limit return E2BIG.
- Check target range, owner/self references, regular EA inode flag/type, one link,
  nonzero 64-bit reference count, deletion state and exact size. Reject nested xattrs,
  inline EA value storage, holes and unwritten extents. Ordinary paths and file handles
  reject internal EA inodes even if corrupted directory entries name them.
- Preserve common inode/extent/block metadata checksum validation. Check reference
  entry hashes during listing; retrieval and size queries also check the complete
  seeded value CRC32C and name/value hash. Accept the historical signed-byte name
  hash without bypassing payload verification. Unhashed legacy Lustre layouts remain
  unsupported. EA atime/ctime/version words are hashes/counters, not ordinary times.
- Read value payloads on demand, including ACL values required for decoding, rather
  than allocating every large attribute in a list. No recursive EA metadata traversal
  or production write path is introduced.
- 943 EA checks pass with ASan/UBSan for each FUSE API: real 1/2/4 KiB layouts,
  128/256/512-byte inodes, checksums on/off/stored seeds, inline owners, extent and
  classic indirect storage, values crossing block boundaries and complete 64 KiB
  binary values. Compare bytes with debugfs and certify base/shared-value layouts
  with e2fsck. Exercise repaired-CRC state/reference/hash corruption, payload damage,
  empty/unwritten extents, actual short reads, resource limits and inode isolation.
- Use a libext2fs fixture writer because debugfs -f reads only one block of value input;
  e2fsck reconciles parent EA allocation charging before reader checks. All fixture
  images are disposable. Reads leave valid fixtures byte-identical.
- Both APIs pass all existing sanitizer suites, including 98 feature preflight checks
  and 1,285 prior xattr checks. Both macFUSE APIs pass actual mounted 64 KiB retrieval
  on inline owners, Linux ACL metadata, empty values, symlink attrs and EROFS on writes.
  The optimized FUSE 3 build also passes exact timestamp/meta_bg/inline and strict
  path/permission regressions on Intel Sequoia/macFUSE 5.4.0.

Read-only access, no journal replay, no Linux ACL enforcement, no Finder namespace
translation and the macFUSE sparse stat/du allocation limitation remain. Apple Silicon
and FreeBSD are untested. Values above 64 KiB and unhashed legacy Lustre EA layouts
are not supported.
