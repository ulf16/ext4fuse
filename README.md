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

- Reject overlong path components without overflowing the length counter or hanging.
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

## Remaining work

- Reproduce and triage upstream issues individually, including permissions and directory caching.
- Handle short reads, I/O errors and malformed metadata gracefully instead of assertions.
- Audit unsupported ext4 feature flags and reject incompatible layouts explicitly.
- Expand sparse-file, symlink, directory and large-volume tests; compare against Linux tools.
- Audit cache concurrency (examples above use single-threaded mode).
- Add reproducible packaging through a separate Homebrew tap after broader validation.

Write support and an FSKit port are outside the initial milestone. Existing limitations
include incomplete large-volume addressing; do not assume full support for modern ext4
features, encryption, or LVM containers.

Report reproducible issues to [this fork](https://github.com/ulf16/ext4fuse/issues).
Do not upload private filesystem images or directory logs to public issues.
