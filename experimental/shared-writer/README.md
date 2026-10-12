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
python3 experimental/shared-writer/test-block-log.py --work "$work"
python3 experimental/shared-writer/test-overlay-log.py --work "$work"
python3 experimental/shared-writer/test-inplace.py --work "$work"
python3 experimental/shared-writer/test-chain.py --work "$work"
python3 experimental/shared-writer/test-checkpoint.py --work "$work"
python3 experimental/shared-writer/test-write-api.py --work "$work"
python3 experimental/shared-writer/test-session.py --work "$work"
"$work/policy-unit"
python3 experimental/shared-writer/test-policy.py --work "$work"
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

No production in-place commits, physical-device writes, FUSE write frontend or release change
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

## Incremental block redo experiment

`block-log.py prepare SOURCE CANDIDATE TARGET JOURNAL` replaces the full-image
snapshot with fixed records for changed 4096-byte pages. Each little-endian record
contains its page index, SHA-256 preimage digest, SHA-256 replacement digest and
replacement bytes. The sealed manifest binds the log to the full source and result
hashes, image size and record count. Records must be strictly increasing, unique
and within the image. Recovery enforces a 1,048,576-record cap and exact log length,
validates every record before writing an output, and rejects trailing data.

`block-log.py recover JOURNAL` copies the immutable source into a private staging
image, applies the verified records, verifies the reconstructed image hash, syncs
it, then links the completed image to the target and syncs the directory. An
interrupted copy/replay is rebuilt on retry. The staging inode remains linked to
the target so repeated publication can be distinguished from an unrelated target.
A staging file with additional links is rejected before truncation. Concurrent
cooperating recoveries use an exclusive manifest lock. A no-change log is valid.

This reduces persistent log space to changed pages, plus 72 bytes per page and a
small manifest. Preparation still scans both images, and offline recovery still
copies a complete image. It does not yet stream dirty pages directly from the C
overlay or apply transactions in place. The same private-directory, immutable-input
and advisory-lock assumptions as the snapshot experiment apply. No physical-device
writes or writable mounts are enabled. Retain the original source until the log
is retired; do not edit the published image while using the log for recovery.

The additional matrix interrupts preparation, base copying and individual page
replay, verifies e2fsck and source/result hashes, and checks corrupt payloads,
preimages, duplicate/out-of-range records, invalid counts, trailing records,
incorrect final hashes, target collisions, no-op transactions and lock exclusion.
It checks that these fixtures' logs use less than one tenth of the source size.
Process-interruption validation still does not certify physical power-loss safety.

## Direct C overlay capture

`block-log.py prepare-overlay SOURCE TARGET JOURNAL PRODUCER` now starts the
isolated `prototype SOURCE --stream` producer and builds a sealed block log directly
from its published in-memory overlay. No candidate image is exported. The C API
`overlay_stream` rejects pending/poisoned state, sorts bounded page pointers, and
emits a 24-byte header (`E4OVL001`, little-endian image size and staged-page count)
followed by 8200-byte records (little-endian page index, original 4096 bytes,
replacement 4096 bytes). This is a private transport, not the persisted log format.

The consumer checks exact lengths, page order, bounds and preimages, omits staged
pages whose bytes are unchanged, hashes the merged view while reading clean spans
from the source, and writes the existing checksummed block-log format. It rejects
trailing bytes and a nonzero producer exit even after a complete stream. The
manifest is sealed only after successful producer completion and source recheck.
The producer continues to run its rollback/failure tests after emitting the view.
A failed or interrupted capture can leave an incomplete private directory, but it
cannot publish a target. The caller must serialize the C overlay throughout capture;
this does not add thread safety or a writable FUSE frontend.

The source is still scanned for whole-image integrity binding, and recovery still
builds a full output image. This step removes the intermediate full candidate
export from log preparation; disposable in-place commits are described below, while JBD2 interoperability
remains future work. Stream tests cover malformed headers, truncation, duplicates,
bounds, preimages, trailing bytes, producer failure, and preparation/recovery
interruptions across all 12 filesystem configurations. Recovered files are checked
with debugfs and e2fsck; the C unit suite independently compares stream pages with
its randomized reference model. Installed reader and Homebrew packaging are unchanged.

## Disposable in-place commits

`inplace.py prepare SOURCE SESSION PRODUCER` creates a new private session and
copies SOURCE into `SESSION/image.img`. SOURCE is never opened for writing. It
captures the C overlay directly and creates a version-2 undo/redo log with fixed
8200-byte records (little-endian page index, original page, replacement page).
The synced transaction binds the log and original/result hashes to the disposable
copy's size, device and inode. The earlier version-1 export logs are unchanged.

`inplace.py recover SESSION` commits only this fixed disposable image path. It
requires a private owned session, a regular single-link image with matching
identity, exclusive transaction/image locks and a valid complete log. Before any
write it hashes the full image with saved original and replacement pages
substituted into the dirty ranges. Both reconstructed hashes must match, so
corrupt logs, wrong images and changes outside logged ranges fail before writes.
Before the first commit the actual image must also match the original hash.

A synced `started` marker is published before the first image write. Once started,
redo may repair old, new, or torn data within logged pages. Each page is written in
two halves for fault-injection coverage; this makes no claim of page-write
atomicity. The image is synced and its complete result hash checked before a
synced `complete` marker. Recovery can be repeated. A completed image that was
subsequently edited is rejected, rather than silently overwritten. Incomplete
preparation lacks a sealed transaction and cannot commit.

This is an external undo/redo protocol, not JBD2. Keep the session and log until
recovery has completed; do not mount an interrupted image before recovery. Tests
exercise first/middle torn pages, durability boundaries, repeated recovery,
corrupt records, invalid counts and offsets, altered identity, aliases, markers,
clean-range changes and competing locks on all 12 ext4 configurations. e2fsck and
debugfs independently verify recovered contents and filesystem consistency.

Only new disposable copies created by preparation are supported. There is no API
to commit to an arbitrary existing image, block device, or mounted filesystem.
Private directories and cooperating-process locks remain assumptions; concurrent
external writers are unsupported. Tests simulate process termination and torn
pages, not physical power loss or failed hardware. Mounted write support and native
Linux journal interoperability remain future work. Managed transaction chaining
and log retirement are described below. The installed read-only reader and Homebrew package are unchanged.

## Managed transaction chains and reader refresh

`chain.py init SOURCE ROOT PRODUCER` creates and commits the first disposable
image transaction. `chain.py append ROOT PRODUCER` adds a generation to the same
image inode; `chain.py recover ROOT` finishes an interrupted generation. A stable
chain lock serializes preparation, commit, recovery and head publication. The
chain-state file records image identity, completed head hash and a pending
successor. Every successor must use the completed head hash as its preimage.

Pending intent is synced before generation preparation. Recovery retains and
renames incomplete preparation as an aborted directory if the image still matches
the completed head. A sealed generation is recovered in place before the head
advances. Crashes after image commit but before head publication recover through
the pending generation's log and completed marker. Previous logs are retained until an explicit checkpoint retires them;
old-generation logs are not replayed once the chain has advanced. Checkpoint-based
restoration and its limits are described below.

The `step-writer` test producer modifies and grows the same ext4 file each generation.
The `reader-watch` harness keeps one production-reader instance and base descriptor
alive across the chain. Its explicit pause gate rejects reads during mutation;
resume republishes its empty overlay and refreshes reader geometry before content
checks. This is a serialized offline coordination test, not automatic FUSE
concurrency or kernel-cache invalidation. Caller coordination remains mandatory.

The chain matrix covers aborted preparation, partial writes, completed transactions
with unpublished heads, head publication interruption, repeated recovery,
predecessor mismatch and lock exclusion on all 12 configurations. Each successful
head is checked by the resident reader and e2fsck. Cached reader free-block and
free-inode counters are compared with independent debugfs output after refresh. Image inode and original-source
hash are preserved throughout. The earlier single-transaction interface and its
recovery tests remain supported. Physical devices, mounted writes and packaging
remain unchanged.

## Durable checkpoints and log retirement

`chain.py checkpoint ROOT` requires a completed head with no pending generation.
It verifies image identity and the complete head hash, validates all proposed
retirement paths, then seals a checksummed checkpoint containing the head, image
hash and identity. The checkpoint file and parent directory are synced before any
logs are removed. It does not implicitly recover or commit a pending transaction.

Retirement removes initial transaction logs, completed generation directories and
abandoned preparation directories. It only accepts known log filenames, private
owned directories on the same filesystem, and regular single-link owned files.
Unexpected files, aliases and symlinks cause preflight rejection. Image data,
chain state, chain lock, checkpoint and unrelated root files are preserved.
Every unlink/rmdir is followed by directory fsync; interrupted cleanup is safely
repeatable. The checkpoint is retained even after all older logs are gone.

When chain-state is missing, recovery may restore it from a valid latest checkpoint
whose image identity/hash still match and which has no successor directories.
A stale checkpoint is rejected; this is not arbitrary reconstruction of a later
history after state loss. A corrupt checkpoint fails its checksum and cannot
authorize retirement. Append/commit continue normally after successful retirement.
The private-directory/cooperating-process assumptions remain unchanged.

The checkpoint matrix tests publication and deletion interruptions, repeated
cleanup, state restoration after complete retirement, append and torn-write
recovery afterward, pending-log preservation, corrupt/stale checkpoints,
unexpected entries and lock exclusion on all 12 configurations. Image hashes and
inode identity are unchanged by checkpointing, and e2fsck accepts the resulting
images. Process interruption tests do not certify physical power-loss behavior.
Mounted writes, JBD2 integration and real-device commits remain disabled.

## General file-mutation API

`mutation.h` exposes staged write, truncate and create operations taking paths,
caller bytes, offsets and numeric creation metadata. `mutation-producer` applies a
bounded binary batch and emits an overlay only after all operations and the writer
flush succeed. Any error discards the writer/overlay; partial batches are never
sealed. `write-api.py ROOT PRODUCER OPERATIONS.json` connects this API to managed
transaction generations. Generation requests are retained with the undo/redo logs
and are removed by checkpoint retirement.

Example operation list (offset/size are bytes; mode is decimal, 416 means 0640):

```json
[
  {"kind":"write","path":"/existing-file","offset":17,"data_hex":"0001ff"},
  {"kind":"truncate","path":"/existing-file","size":9000},
  {"kind":"create","path":"/directory/new-file","mode":416,"uid":70000,"gid":80000,"data_hex":"68656c6c6f"}
]
```

The Python `apply` entry point accepts the same list directly. Files are regular
files in existing directories; paths must be absolute, with no dot components,
empty components or symlink traversal. Writes may grow files and leave sparse
zero-filled gaps. Truncation supports arbitrary byte lengths and zero-filled
regrowth. Creation refuses existing names, creates empty or populated files, and
supports 32-bit uid/gid fields. Existing inode/xattr metadata is preserved except
for data size/allocation and modification/change timestamps; parent timestamps
are updated for creation. Zero-byte writes do not grow files.

Limits: at most 64 operations, 4 MiB aggregate payload, 4096-byte paths with
255-byte components, 64 MiB write-end and truncate-size ceilings and 2048 staged pages. Immutable
files reject mutation. Append-only files permit only writes at EOF and reject
truncation. Non-regular, encrypted, verity, compressed, inline-data and internal
xattr inodes are rejected. Creation in indexed/casefold directories is rejected
until independently validated. Unindexed directories can expand when full.

The CLI and calls without credentials retain administrative offline behavior.
The optional trusted credential policy below adds access checks, creation
inheritance and a caller umask. Persistent open-handle/namespace semantics and
mounted writes remain disabled; the future frontend must bind authenticated
caller context and implement those lifetime rules.

The API matrix verifies unaligned binary overwrites, EOF growth, sparse gaps,
non-block-aligned shrink/regrow zeroing, nested/empty creation and high uid/gid
metadata against both the native reader and debugfs. It covers failed batches
after an earlier staged write, injected write failures, torn-page recovery,
checkpoint retirement and subsequent writes. Extra tests enforce immutable and
append-only flags, preserve a preexisting xattr, and reject malformed transport
frames. e2fsck verifies committed filesystem consistency. Source images and the
installed reader remain unchanged.

## Coordinated resident-reader session

`session.Session(ROOT, PRODUCER, READER_SERVER)` joins caller-data mutations to a
single long-lived native reader. Recover the managed chain before opening the
reader, hold the chain lock for the whole session, and serialize requests with a
session mutex. Other cooperating sessions, administrative writes, recovery and
checkpoint commands are excluded until it closes. Use the object as a context
manager so reader shutdown precedes releasing the lock.

```python
from session import Session

with Session(root, work / "mutation-producer", work / "reader-server") as fs:
    previous = fs.read("/existing-file", offset=0, length=4096)
    fs.apply([{"kind": "write", "path": "/existing-file", "offset": 17,
               "data_hex": "0001ff"}])
    updated_size = fs.size("/existing-file")
    updated = fs.read("/existing-file", offset=17, length=3)
```

Before preparation the coordinator suspends native reads, including cached size
lookups and allocation counters. It keeps them suspended through recovery and
head publication, then refreshes reader geometry/inode/directory caches before
resuming. Normal failed batches recover the unsealed intent and resume the old
view. An unresolved recovery, refresh or reader transport error makes the session
unusable; close it and start a new session to recover before serving more reads.
A reported error after sealing may still correspond to a committed batch: inspect
the recovered head before retrying a non-idempotent request.

The private binary pipe protocol bounds paths to 4096 bytes and individual reads
to 1 MiB. The Python API accepts canonical absolute UTF-8 paths, explicit bounded
read ranges, sizes and free-block/free-inode counters. The reader resolves each
request afresh; persistent open-file handles are still absent. Requests without
credentials retain administrative behavior; credential-bound sessions enforce
the numeric policy below. The image identity and resident reader process are retained across
successful transactions. Locks protect cooperating processes, not external disk
writers. Full-image hashes and process/pipe transport still make this a correctness
prototype rather than a final low-latency mounted implementation.

The session matrix checks the actual native read gate before and after a commit,
concurrent read/write and write/write requests, competing-session exclusion,
normal failed batches, injected producer/recovery failures, sticky reader death,
restart recovery after a torn page and unchanged image identity. It checks sizes,
bytes and cached counters through the same reader process, compares debugfs and
runs e2fsck on all 12 configurations. Mounted writes, physical devices and the
installed reader remain unchanged.

## Trusted numeric permission and ACL policy

Pass an immutable `Credentials(uid, gid, groups=(), umask=0o022)` to `Session`, or
as the optional `credentials` argument of `write_api.apply`/`encode`. Identities
are 32-bit numeric Linux filesystem IDs, excluding the reserved all-ones value;
at most 64 supplementary groups are accepted and the primary group is implicit.
The reader binds its context once and refuses reconfiguration. This is policy
input from a trusted frontend, not authentication: the caller of this offline API
can select IDs, including root. A mounted frontend must derive the IDs/groups
from authenticated request context and must not expose the administrative path.

```python
from credentials import Credentials
from session import Session

caller = Credentials(uid=70000, gid=80000, groups=(200, 201), umask=0o027)
with Session(root, work / "mutation-producer", work / "reader-server", caller) as fs:
    data = fs.read("/existing-file", offset=0, length=4096)
    fs.apply([{"kind": "create", "path": "/open/new", "mode": 438,
               "data_hex": "68656c6c6f"}])  # 438 decimal is 0666
```

The shared policy checks search permission on each ancestor before lookup, read
permission for content reads, write permission for overwrite/truncate, and a
single write-plus-search request on the creation parent. Metadata lookup requires
ancestor search, not file read permission. Owner and named-user entries take
precedence; matching groups are constrained by the ACL mask and cannot fall
through to other. One matching group must supply the complete request; separate
group grants are not combined. Root bypasses discretionary permissions, but
malformed ACLs, inconsistent inode modes and unsupported rich ACLs still fail.
The model follows the [Linux POSIX ACL access and creation rules](https://man7.org/linux/man-pages/man5/acl.5.html).

ACLs use the existing compact ext4 validation and are limited to 4096 bytes.
Access ACL owner/group-class/other permissions must agree with the inode mode.
The reader uses a fresh read-only libext2fs metadata view for authorization and
retains the native reader for data/size access; it does not depend on macOS UUID
resolution or translating numeric identities into host Apple ACLs. Both views
are serialized by the session and refreshed between generations.

Creation derives the owner from the caller. It uses the parent's group when the
parent has setgid, otherwise the caller's primary group. JSON creation requests
cannot override uid/gid, and raw credential-framed requests cannot override the
derived ownership either. With a default ACL, inherit it as an access ACL and
clip owner, group class/mask and other by the requested mode; do not additionally
apply umask. Without a default ACL, apply the caller umask. The parent default
ACL is unchanged; regular files do not acquire a default ACL or the parent's
setgid mode bit. Initial creation bytes are accepted even with a resulting mode
of zero, while subsequent independent path mutations require write access.

Non-root content changes conservatively clear setuid/setgid bits; zero-byte
writes do not clear them. Credential-bound writes to files carrying
`security.capability` are rejected until killpriv semantics are implemented.
No capability sets, security-module policy, ID mapping, permission-changing APIs,
open-time grants, retained handles or multi-user mounted frontend are introduced.

Credential batches use `E4REQ002`; legacy administrative `E4REQ001` is retained.
Permission/error rejections emit a bounded `E4ER0001` frame with a POSIX errno;
no overlay is emitted and no transaction is sealed. Capture validates the frame
and producer termination before propagating `OSError`. Recovery aborts any
unsealed intent and refreshes the reader, preserving the complete previous head.
The generation request retains the credential context with its logs.

The sanitizer unit suite exercises mode permissions, owner/named/group precedence,
all requested permission combinations, ACL masks, inheritance and malformed
contexts against an independent decision oracle. The image matrix checks numeric
reads/writes, traversal denial, inherited ACL bytes/modes, setgid/high-ID ownership,
umask, privilege-bit clearing, atomic multi-operation denial, malformed/default
ACLs, mode disagreement, rich ACL/capability rejection and forged transport frames
on 12 filesystem configurations. debugfs independently checks committed metadata
and e2fsck verifies all valid committed images. Deliberately invalid ACL fixtures
are separate and must remain byte-for-byte unchanged by rejected mutations.
These tests use explicit logical callers, not host credential changes or mounted
kernel authorization. Physical devices and installed read-only behavior remain
unchanged.
