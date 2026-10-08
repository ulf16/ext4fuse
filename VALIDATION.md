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
- Portable macFUSE ABI selected explicitly; no Darwin attribute extensions.
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
- No file-data, bitmap, xattr, journal, backup, or unused-subtree checksum certification.
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
