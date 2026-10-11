# Shared reader / libext2fs writer experiment

This is an offline feasibility prototype, not writable mount support. It retains
this repository's reader and uses libext2fs for filesystem mutations. Production
reader and Homebrew behavior are unchanged.

The source image is opened read-only and must be a regular file. A custom
libext2fs I/O manager stages writes in bounded 4 KiB copy-on-write pages. A test-only
pread wrapper makes the existing reader consume the same block view. Clean spans
retain bulk reads. Readers are rejected while metadata is being changed or after
a transaction is poisoned. The caller serializes operations, flushes libext2fs,
publishes the overlay, and refreshes reader geometry. There is no concurrency
implementation or retained previous-generation reader snapshot.

Rollback frees the libext2fs handle, discards staged pages, refreshes the reader,
and reopens the writer so stale writer inode/bitmap caches cannot survive.
Publication exports a new image: copy the base, apply staged pages, fsync, then
atomically link the completed file to a new destination without replacing an
existing file. Failures remove staging files. A process crash can leave an orphan
staging file; no source image is modified. Directory-entry durability across power
loss is not certified. Dirty filesystems and pending journal recovery are rejected.

## Run

Install FUSE 3 development files and libext2fs/e2fsprogs, then:

```sh
# macOS/Homebrew: expose the keg-only e2fsprogs development files and utilities.
export PKG_CONFIG_PATH="$(brew --prefix e2fsprogs)/lib/pkgconfig:/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PATH="$(brew --prefix e2fsprogs)/sbin:$PATH"

work="$(mktemp -d /private/tmp/ext4-shared-writer.XXXXXX)"
python3 experimental/shared-writer/build.py --work "$work" --sanitize
"$work/overlay-unit"
python3 experimental/shared-writer/run-matrix.py --work "$work"
python3 experimental/shared-writer/test-durable.py --work "$work"
```

Linux: install `libfuse3-dev libext2fs-dev e2fsprogs pkg-config`, and use `/tmp`
for the work directory. The scripts do not mount filesystems or require root.
Keep the work directory to inspect exported images, logs and matrix-results.json.
The matrix refuses existing output names; use a fresh directory for each run.

## Local validation

Intel macOS Sequoia with libext2fs 1.47.4: 12 combinations of 1/2/4 KiB blocks,
classic/extents mappings and metadata checksums on/off pass creation, growth,
rename, truncation, re-growth, pending-state rejection, rollback, five injected
write-failure points, partial-export rejection and no-overwrite checks.
The unchanged reader verifies staged contents and renamed/missing paths.
`e2fsck -fn` accepts every exported image; debugfs independently verifies new
contents and preservation of an unrelated existing file. Source hashes are unchanged.

The overlay unit suite passes more than 16,000 randomized read/write, publication,
rollback, overflow and memory-limit checks under ASan/UBSan. A small local
transaction peaked at about 5 MiB RSS, with 61–64 staged pages. This does not
predict memory consumption for large or mounted write workloads.

An optional read-bench harness wraps the existing bulk-reader benchmark with the
overlay. Five interleaved samples of four 64 MiB warm-cache passes showed results
within approximately 3% of the original reader for 4 KiB/64 KiB/1 MiB requests,
with one unchanged metadata page staged. Dirty-data-heavy workloads and macFUSE
performance have not been benchmarked for this backend.

## Required before mounted writes

- Incremental durable transactions and in-place crash recovery; the full-image redo
  experiment below is not an ext4 journal commit.
- Feature admission, corruption handling and complete mutation semantics, including
  unlink, directory rename, ownership, ACLs, attributes and open-but-deleted files.
- Concurrency, reader/writer cache invalidation and stable inode/file-handle lifetime.
- FUSE frontend semantics, device locking, journal interaction and multi-mount protection.
- Resource/error bounds, fault injection at every durability boundary and independent
  native Linux recovery tests before any in-place write support is considered.

No in-place commits, physical-device writes, FUSE write frontend or release change
is introduced by this experiment.

## Durable full-image redo experiment

`durable.py prepare SOURCE CANDIDATE TARGET JOURNAL` copies a completed overlay
export into a private journal directory next to the intended target. It records
SHA-256 hashes of both images, syncs the snapshot and manifest, and seals the
manifest with a rename followed by directory fsync. On Darwin regular-file sync
also requests F_FULLFSYNC. `durable.py recover JOURNAL` validates the entire
snapshot and unchanged source before atomically linking the snapshot as TARGET
and syncing the parent directory. Existing unrelated targets are never replaced.
Recovery after publication is idempotent only for the same snapshot inode.

Preparation interrupted before sealing is deliberately rejected; leave the source
unchanged and discard that incomplete private directory. A sealed transaction can
be recovered repeatedly. The journal is retained for inspection; the target and
snapshot are hard links, so do not mutate either while retaining it for recovery.
Use trusted private directories and immutable offline inputs. Locks coordinate
only cooperating processes; this is not protection against an external writer,
hostile directory changes, or concurrent Linux mounts. No filesystem feature
admission is added by this transport: use only the validated prototype exports.

The test kills subprocesses at seven explicit persistence boundaries, repeats
recovery, checks source/result hashes and e2fsck, and rejects truncated or damaged
snapshots, changed sources, broken manifests and target collisions across all
12 filesystem configurations. These are process-interruption tests, not physical
power-cut certification. This full-image approach uses one complete extra image
and hashes the complete images; it establishes the offline recovery protocol,
not an efficient journal for mounted writes. There are still no in-place writes,
JBD2 integration, physical-device writes or changes to the installed reader.
