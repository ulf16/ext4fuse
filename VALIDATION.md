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
