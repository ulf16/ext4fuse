# Shared reader / libext2fs writer experiment

This experimental backend retains the native reader and uses libext2fs for
filesystem mutations. It includes a private FUSE 3 frontend for managed image copies,
guarded offline device publication, and continuous device write-through via a
private disk-backed shadow or the direct storage mode described at the end.
Production Homebrew packaging and general-purpose
write support remain outside this prototype. See the final continuous-device
sections for commands, storage requirements and recovery limits.

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
loss is not certified. The basic overlay exporter rejects dirty filesystems.
Managed sessions can explicitly recover a supported pending internal journal
before reader admission, as described in the journal-recovery section below.

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
python3 experimental/shared-writer/test-handles.py --work "$work"
python3 experimental/shared-writer/test-namespace.py --work "$work"
python3 experimental/shared-writer/test-directories.py --work "$work"
python3 experimental/shared-writer/test-directory-refs.py --work "$work"
python3 experimental/shared-writer/test-openat.py --work "$work"
python3 experimental/shared-writer/test-directory-streams.py --work "$work"
python3 experimental/shared-writer/test-metadata.py --work "$work"
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

## Required before general-purpose writable mounts

- Incremental durable transactions and in-place crash recovery; the full-image redo
  experiment below is not an ext4 journal commit.
- Feature admission, corruption handling and complete mutation semantics, including
  ownership, ACLs, attributes and full mounted frontend semantics; basic file,
  directory and symlink namespace mutations are now exercised offline.
- Concurrency, reader/writer cache invalidation and stable inode/file-handle lifetime.
- FUSE frontend semantics, device locking, journal interaction and multi-mount protection.
- Resource/error bounds, fault injection at every durability boundary and independent
  native Linux recovery tests before any in-place write support is considered.

These requirements describe the original experiment. Later sections document
incremental image transactions, low-level mounts and guarded device publication.
No production write-support release or installed-reader change is introduced.

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
pages, not physical power loss or failed hardware. Later sections extend this
stage with managed mounts, device publication and opt-in native journal recovery.
New writes still use external redo rather than Linux JBD2 commits. Managed
transaction chaining and log retirement are described below. The installed read-only reader and Homebrew package are unchanged.

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
recovery tests remain supported. Physical devices and production packaging
remain unchanged; the initial managed-image mount is described below.

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
inheritance and a caller umask. Existing-file handles and regular-file namespace
operations are described below. Mounted writes remain disabled; the future
frontend must bind authenticated caller context and implement its lifetime rules.

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
request afresh; the optional inode-bound handles below retain open-time grants. Requests without
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
multi-user mounted frontend are introduced. Existing-file open-time grants
and session-local handles are described below.

Credential batches use `E4REQ002`; legacy administrative `E4REQ001` is retained.
Permission/error rejections emit a bounded `E4ER0001` frame with a POSIX errno;
no overlay is emitted and no transaction is sealed. Missing paths map to
ENOENT, allocation exhaustion to ENOSPC and allocation failures to ENOMEM;
unknown library errors map to EIO. Capture validates the frame
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

## Existing-file handles and open-time grants

Credential-bound sessions can open an existing regular file with access `r`, `w`
or `rw`, optional `append=True`, and optional `truncate=True` requiring write
access. Use the returned `FileHandle` as a context manager or close it explicitly.
Reads/writes take explicit offsets; there is no implicit seek cursor or duplicated
open-file description API. The positional interface is intended for later FUSE
callbacks, not a complete replacement for POSIX file descriptors.

```python
with fs.open("/existing-file", "rw") as file:
    old = file.read(offset=0, length=4096)
    file.write(b"caller bytes", offset=17)
    file.truncate(9000)
with fs.open("/existing-file", "w", append=True) as file:
    file.write(b"tail")  # EOF is selected inside the serialized transaction
```

Open checks ancestor search, the complete requested read/write permission mask,
regular-file type, supported inode features, allocation, link count and inode
generation. Write opens additionally enforce immutable/append-only inode flags
and reject file capabilities. Store the granted access, inode number/generation
and append status in the resident reader's bounded table. Every handle read or
writer-grant request validates the current inode allocation and identity. Native
reads use the opened inode directly; writes use its granted identity, not the
original pathname. Mode or POSIX ACL changes do not revoke a successful open-time
grant. New path opens and path mutations still run current permission checks.
This follows the [open-file description model](https://man7.org/linux/man-pages/man2/open.2.html).

The private writer format `E4REQ003` contains credential context and a trusted
16-byte inode grant instead of a pathname. It is an internal broker privilege:
it is not authenticated, must never be accepted from untrusted callers, and is
not exposed in the JSON operation interface. The session validates its registered
file object and obtains write authority from the resident table before encoding
a request. The C producer independently checks allocation, inode generation,
live regular-file identity, write access, flags and payload bounds before staging.
It deliberately does not rerun path DAC/ACL checks for a granted descriptor.
Current immutable/append-only flags and file-capability restrictions still apply;
non-root data changes still clear privilege bits under the existing policy.

Append status selects the current EOF in the same serialized writer transaction,
ignoring the supplied write offset. This is the prototype's append behavior, not
a claim to implement every POSIX/Linux positional-I/O flag distinction. Truncate
on an append-status handle is allowed for a normal file, but an append-only inode
rejects truncation and requires an append-status handle for writes. A truncating
open obtains a handle slot before touching data; failure releases that slot, and
quota failure cannot truncate an existing file.

At most 128 handles may be active in one session. Released tokens are not reused
within the reader process; Python file objects are bound to their issuing session
and become EBADF after close/session shutdown. A detected stale generation is
sticky for that table entry, even if the generation is later restored. Slots can
still be closed while reads are suspended. No descriptor survives process/session
restart, and failed recovery/reader transport still blocks all operations.

Opening still requires an existing linked regular file. A granted inode can
subsequently have zero links while it belongs to the validated durable orphan
chain described below. Missing/free/retyped/recycled identities fail ESTALE.
Create-and-open, descriptor transfer, shared seek offsets, ID mapping and mounted
writes remain absent. Exclusive chain locking and immutable managed-image
identity remain required; external writers are outside the cooperative-process
model. Identity checks load inode bitmaps through libext2fs; large-filesystem
latency/memory have not been benchmarked.

The handle matrix checks access-mode separation, mode/named-ACL grant retention,
sparse truncate/regrow, live reads after commits, serialized concurrent appends,
truncating-open failure/quota atomicity, dynamic immutable/append-only/capability
restrictions, stale-generation rejection in both reader and writer, token/session
invalidation, paused native handle reads and recovery after an actual torn page.
The same resident reader process and image inode are retained. debugfs compares
contents and e2fsck checks all 12 configurations. `handle-test-producer` is a
separate test-only staged metadata helper, not a user metadata API or installed
target. Physical devices, installed reader behavior and release packaging remain
unchanged.

## Regular-file namespace and durable open-but-unlinked lifetime

`Session.link(source, target)`, `rename(source, target)` and `unlink(path)` are
serialized staged transactions. Batches accept `kind: link/rename` with `path`
and `target`, or `kind: unlink` with `path`. All directory entries, inode link
counts, ctime and affected parent mtime/ctime are published together through the
existing undo/redo recovery chain. Rename replaces an existing regular target;
renaming two names for the same inode is a no-op. Hard links cannot replace an
entry. Directory and symlink extensions are described below.

Source/destination traversal checks search permission; namespace changes check
parent write/search permission and sticky-directory ownership. Hard-link source
traversal only needs search, and the protected-hardlink policy allows an inode
owner/root, or a non-owner with read/write access to a regular file without
setuid or executable-setgid privilege. Immutable and append-only inode flags
block removal/rename; immutable parents block changes and append-only parents
allow addition but forbid removal or replacement. Indexed/casefold directories,
quota/bigalloc/EA-inode filesystems, unsupported regular-file layouts and active
orphan-file recovery (`orphan_present`) are rejected rather than modified.
Casefold directory mutation, rename-exchange/noreplace flags and linking
an unlinked inode through a handle remain unimplemented. Directory creation,
removal, moves and symlink mutation are described below.

Before each namespace transaction the broker obtains a unique snapshot of all
live inode/generation pairs from the resident handle table, under the session
mutex and chain lock. The private `E4REQ004` envelope includes that snapshot;
zero operations are reserved for internal orphan cleanup. These pins are trusted
broker authority, not authenticated input, and must never come from an untrusted
client or the JSON operation interface. The producer validates allocation,
generation and regular-file identity before staging, and rejects stale or
duplicate pins without publishing. The 128-handle limit also bounds orphan-list
length; no live pinned inode can be allocated for another file.

Removing the last filename of a pinned inode sets its link count to zero and
adds it to the legacy ext orphan chain (`s_last_orphan` / `i_dtime`), in the same
recoverable transaction as the directory deletion. Its data, xattrs and allocation
remain live; all existing handles retain their granted access. Replacing a pinned
rename destination uses the same mechanism. Closing a nonfinal handle keeps the
orphan pinned. Final close, normal session shutdown, or a subsequent session after
a coordinator crash reclaims unpinned orphans in a staged transaction, freeing
data/indirect/extent and external attribute storage through libext2fs accounting.
Newly allocated files advance the retained inode generation so recycled identities
cannot satisfy an old grant. If final-close cleanup fails, the handle is still
released and the durable orphan is retried by a later batch/session; close reports
the error. Open handles never survive session/process restart.

A live orphan chain needs recovery and is not a clean export for another reader.
The normal production reader still rejects a nonempty orphan list. Only the
isolated `reader-server` links `super-session.c`, which permits that list after
checking its bounds, allocation, type and cycles on attach and every refresh.
Dirty/journal-recovery checks remain active. Corrupt lists fail closed before any
reclamation. Use a normal close/checkpoint before exporting an image; never mount
or run a repairing tool against an active session image. Independent e2fsck
recovery is tested on disposable copies after the coordinator has exited.

`test-namespace.py` runs the 12 classic/extent, 1/2/4 KiB, checksum on/off fixtures.
It checks cross-parent rename, replacement and same-inode semantics, hard-link
counts, parent/sticky/protected-link permissions, inode flags, multiple orphan
ordering, final-close/session/crash reclamation, external xattrs, generation
reuse, malformed pins, failed batches/producers and actual torn-page recovery.
Native handles compare byte contents; debugfs checks identity/link counts;
e2fsck checks clean post-reclamation images and independently recovers orphan
copies. A test-only next-pointer corruption must poison refresh/attach without
reclamation. This remains an offline managed-image prototype, with physical-device
and mounted writes disabled.

## Directory and symbolic-link mutations

`Session.mkdir(path, mode=0o777)`, `rmdir(path)` and `symlink(target, path)` add
staged directory and link creation/removal. `rename` now moves directories and
renames/replaces symbolic links; `unlink` removes links themselves. `link` can
hard-link a symlink owned by the caller/root, while directory hard links are
forbidden. Operation batches use `kind: mkdir` with `path` and optional `mode`,
`kind: rmdir` with `path`, and `kind: symlink` with `path` and `target`. Bound
credentials determine creation UID/GID; explicit ownership remains available
only in the administrative offline encoder. All final entry operations use
lookup without following a symbolic link, and intermediate symlinks in mutation
paths still return ELOOP. No target file is opened or modified by symlink mutation.

New directories inherit umask, setgid group/bit and default ACLs. Inherited
access ACLs are masked by requested permissions, while the parent's unmodified
default ACL is copied for descendants. Requested mkdir modes support permission
and sticky bits through 01777; callers cannot request setuid/setgid bits (the
inherited setgid bit is applied separately). Symlinks receive mode 0777 regardless
of umask, inherit a setgid parent's group, and receive no inherited access/default
ACL. Targets must be nonempty UTF-8 strings without NUL; their encoded bytes must
be shorter than the filesystem block size. Dangling, relative and absolute
targets are stored verbatim. Both inode-stored fast links (<60 bytes) and
block-backed links are handled; unsupported inline-data creation is rejected.

Directory creation initializes `.` and `..`, accounts for directory allocation,
and increments the parent link count. Removal accepts only an empty directory
with valid dot entries and a consistent two-link count; files/symlinks return
ENOTDIR and nonempty directories return ENOTEMPTY. Cross-parent rename rejects
moves into the directory itself or its descendants, bounds/checks ancestor
traversal, requires source-directory write access to update `..`, and changes
both parent link counts in the same recoverable transaction. Same-parent moves
do not require write access to the moved directory itself. An existing directory
target must be empty; directory/non-directory replacement mismatches fail with
ENOTDIR/EISDIR. The same-inode rename no-op is retained. Parent overflow/underflow
and malformed dot entries fail before publication.

New directory and symlink allocations advance the previous inode generation.
Directory data checksums depend on generation, so the freshly initialized block
is checksummed again after that identity change. Empty-directory deletion frees
its data/xattrs and decrements allocated-directory accounting. Fast-symlink
reclamation skips block punching because `i_block` contains target bytes rather
than block numbers. Symlinks have no file handles in this API and are reclaimed
immediately after their final link is removed. Regular files replaced by a
symlink remain pinned for their existing open handles using the preceding orphan
mechanism. Directory handles, session cwd and removed-but-open directory lifetime are
described below; a full mounted frontend remains absent.

`Session.readlink(path)` returns target **bytes** using the unchanged native
symlink reader. The private pipe command 13 checks the reader pause gate,
ancestor search permissions, symlink type and bounded target size; it does not
follow the target. This makes the prototype usable and lets tests verify native
fast/slow symlink reads after mutations.

`test-directories.py` runs all 12 filesystem configurations with sanitizers.
It checks dot entries and parent counts, subtree moves with a live regular-file
handle, cycles, empty replacement, nonempty removal, type mismatches, source and
parent permissions, sticky/immutable restrictions, generation reuse, inherited
setgid/default ACL policy through a separate numeric caller, fast/slow/Unicode
and dangling symlinks, hard-link and no-follow replacement behavior, block-size
limits, directory/symlink accounting, failed batches/producers, and a real torn
cross-parent rename. debugfs independently inspects topology/metadata, the native
reader compares file/link bytes, and e2fsck checks each successful configuration.
Physical-device writes, FUSE write callbacks and installed reader packaging are
unchanged. Casefold directory mutation remains rejected.

## Directory handles and session cwd lifetime

Credential-bound sessions support `opendir(path)` returning `DirectoryHandle`,
with `stat()` (inode/generation/mode/link count/size), `size()`, `listdir()` (names,
excluding dot entries), `path()`, `dup()` and explicit/context-manager close.
Directory read access is checked at open and retained after mode/ACL changes;
file data reads, writes, truncation and writer grants reject directory tokens.
File and directory tokens share the 128-slot table. Copies and cross-session
objects are rejected before issuing native requests; duplicate directories get
independent tokens and retain the original read grant. Metadata and identity are
checked on every request; detected stale generations remain stale for that slot.

`chdir(path)` and `fchdir(directory_handle)` install an independently owned,
search-only cwd reference after checking current search permission. They never
consume the caller's public handle. A new cwd slot/pin closure is acquired before
releasing the old one; quota/search failures preserve the current cwd. An error
while cleaning up the already released old reference is reported after the new
cwd has been installed, and orphan cleanup is retried by later batches/sessions.
Initial cwd is a virtual immutable `/` without a slot. `getcwd()` reconstructs a
linked path from current inode ancestry, so ancestor rename does not strand a
saved pathname. `cwd_stat()` exposes identity even for a removed cwd. Absolute
chdir ignores a stale/removed current cwd. No host process cwd or credentials are
changed by this API.

Relative session paths now resolve from cwd identity: existing read/write/open,
readlink and mutation helpers use the current parent path, and relative `chdir`
walks dot/dotdot components through retained inodes. Legacy absolute operation paths
retain their existing strict canonical validation; legacy read/write/open/mutation
helpers do not follow symlinks. `chdir` now uses the following resolver described
below.
Administrative sessions without credentials retain absolute operations and may
use simple root-relative canonical paths, but cannot allocate directory/cwd
references. The broker converts relative operation parents to absolute paths
before using the existing writer protocol. These legacy helpers still recheck the reconstructed ancestor path's current
permissions. Use the new `*at` methods below for direct inode-relative operations
and byte-only names.

A removed directory has link count zero and remains on the legacy orphan chain
while a directory/cwd reference exists. Its original dot entries, generation,
data and attributes remain allocated privately so `..` continues to reference
its parent. The public directory listing is empty and logical stat size is zero;
`path()`/`getcwd()` return ENOENT until the cwd leaves that detached node. Creating
entries beneath a removed cwd fails ENOENT, while `chdir("..")` can escape a
removed directory and its removed parents. Rename replacement preserves the old
empty directory for its handles/cwd while the new directory occupies its name.
Closed handles never switch to a replacement inode at the same path.

The live pin snapshot includes the unique ancestors of every directory/cwd
reference through root. This prevents a removed parent from being freed/reused
while a descendant still retains a dotdot pointer. Shared ancestry is deduplicated;
root is never a removable orphan or non-root pin. The union of file/dir/ancestor
identities is limited to 128, independently of the slot limit. Opening a reference
which exceeds either bound fails EMFILE and leaves existing references/cwd intact.
The same validated orphan list is cached within one immutable/staged filesystem
context during snapshot/reap identity checks to avoid repeated ancestry validation.

Orphan admission now permits zero-link regular files and empty directories only.
Removed-directory dot entries, allocated parent types, bounded/cycle-free ancestry
and membership of every zero-link ancestor are checked before reclamation.
Final reference close, cwd departure, session shutdown and crash restart reclaim
unpinned directory data/xattrs/inodes and decrement directory allocation statistics
through the same durable staged transaction engine. File orphan behavior remains
unchanged. Restart drops all session-local cwd/handle references and starts at `/`.
Independent e2fsck recovery of removed-directory orphan trees is tested on copies
after the coordinator has exited.

Private reader commands 14–20 implement directory open, stat, listing, path,
duplication, cwd traversal and relative-parent reconstruction. They use the same
pause gate as file reads; only reference release is allowed while suspended.
Directory namespace/type/bitmap checks remain in libext2fs and production data
reads remain native. `test-directory-refs.py` covers moved cwd identity, public and
private references, read/search distinctions, removed-parent escape, replacement,
failed batches/producers, actual torn rmdir, session/crash release, stale/copy
rejection, slot and 128-ancestor quota boundaries, and checksum-valid corrupt
ancestry which must fail refresh/attach without reclamation. All 12 filesystem
configurations run with sanitizers and independent filesystem checks. Indexed/
casefold directory references and mutation and physical-device writes remain
unimplemented. The initial managed-image FUSE frontend is described below.


## Directory-relative open and namespace operations

`Session.openat(dir, path, access="r", ...)` resolves directly from a live
`DirectoryHandle`; `dir=None` means the session cwd. An absolute path ignores the
supplied handle, including a closed, foreign or non-directory handle. Relative
paths reject invalid handles and validate inode generation before lookup. No
path reconstruction or search check above the starting directory is involved.
Each actually traversed directory needs current search permission, even when
its handle retains a read grant. Final file access is checked once at open;
subsequent handle I/O retains that grant, as with the existing file API.

The shared reader/writer resolver accepts repeated slashes, dot/dotdot, and
trailing slashes which require a directory. Intermediate symbolic links are
followed; relative targets start at the link's containing inode, absolute targets
restart at image root. Dotdot walks after link expansion, rather than cancelling
components lexically. Forty symlinks are allowed over the entire traversal;
cycles/excess return ELOOP. Expanded paths are bounded to 4096 bytes and components
to 255 bytes. Both `str` (filesystem encoding) and raw `bytes` paths/targets are
supported by these private APIs; NUL is rejected. Links are read via libext2fs,
while regular-file data continues through the existing native reader.

Named portable options are `create`, `exclusive`, `mode` (ordinary permission
bits), `append`, `truncate`, `nofollow` and `directory_only`. They correspond to
the relevant [open/openat flags](https://man7.org/linux/man-pages/man2/open.2.html),
not the platform-dependent numeric O_* constants. Opening a directory read-only
returns a `DirectoryHandle` even without `directory_only`; writable directories
fail EISDIR. Nofollow affects only the final component; a trailing slash still
requires directory traversal. Create+exclusive rejects an existing final symlink
without following it, including a dangling one. Ordinary create follows a
dangling final link and creates its target when its parent exists. New files
inherit the existing umask/default-ACL/setgid creation policy. A newly created
mode-zero file still returns the requested open grant; its mode applies to later
opens. Existing files require current mode/ACL permission. Append/immutable and
capability safeguards remain enforced.

Creation, exclusivity, truncation, and open-time permission checks run in one
staged transaction under the session/chain lock. The reader reserves a handle
slot and room for one new inode pin before image changes, so a quota failure does
not create or truncate a file. This conservative reservation may reject a
create/truncate open when all 128 pins are occupied even if the existing inode
is already held. A private, fsynced `operations.result` records the writer's
validated grant before its overlay is sealed; after commit/recovery the reader
validates allocation/generation/type before activating the reserved token.
Producer failures release the reservation and discard the staged mutations.
Reports are checked as owned regular files and retired by normal checkpoints.
An unresolved refresh/transport failure still fails the session closed. These
handles are session-local objects, not host file descriptors.

`statat(dir,path,follow_symlinks=True)`, `readlinkat`, `readat`, and `chdirat`
share the inode resolver; `chdir` follows symlinks as well. Metadata currently
contains inode/generation/mode/links/size, rather than a complete POSIX stat.
`mkdirat`, `unlinkat(remove_directory=True)`, `symlinkat`, `renameat` and `linkat`
perform namespace changes. Rename/link accept independent source and destination
directory handles. Unlink and rename act on the final symlink itself. Link
also defaults to the symlink inode; `follow_symlinks=True` selects its target.
Sticky-bit, protected-link, directory-cycle, ACL and orphan rules still apply.
`applyat(operations,dir,target_directory=...)` resolves each operation sequentially
inside the staged filesystem, so later operations can use directories/links made
or renamed earlier in the batch. An error rolls back the entire batch.

Removed directory references retain dot/dotdot semantics and can escape through
retained ancestors; they cannot receive new names. Cwd and directory handles keep
the same independent ownership, generation and orphan-recovery rules. Absolute
paths remain usable after cwd removal or staleness.

Private commands 21–26 export directory capabilities, admit existing at-opens,
reserve/activate committed opens, and perform statat/readlinkat. They validate
framing, types, generation and the publication pause gate. The private V5 writer
envelope contains separately validated source/destination directory grants per
operation; JSON clients cannot supply inode capabilities or open-result grants.
The tests compare core pathname outcomes against real host openat, exercise all
12 block-size/layout/checksum configurations with sanitizers, verify fsck, and
cover permission revocation, renamed/removed dirfds, symlink budgets, raw names,
quotas, failed producers, actual torn-page recovery and checkpoint retirement.

Production/device writes, complete kernel dentry integration, special-file opens, O_PATH/O_TMPFILE, renameat2 extensions, openat2 containment policies and
casefold directory references/mutation remain outside this image-only
prototype. Host descriptor inheritance/nonblocking/direct-I/O flags do not apply
to its session objects.


## Directory stream offsets and paging

`DirectoryHandle.readdir(max_entries=128,max_bytes=65536,offset=None)` returns
`{"entries": [...], "offset": cookie, "eof": bool}`. Each entry contains `name`
(decoded with the filesystem codec, preserving raw bytes via surrogate escapes),
`inode`, numeric POSIX `type` (DT_*; unknown is allowed), and the opaque offset
immediately after that entry. Linked directory streams include `.` and `..`.
`offset=None` resumes the native cursor; an explicit cookie resumes immediately
after that entry. `tell()` returns the current cookie, and `seek(cookie)` selects
it. Zero denotes the beginning of the current snapshot. Cookies are locators,
not inode capabilities or byte positions; arithmetic or reuse outside the current
handle/snapshot is unsupported. Their nonzero ranges are not reused within a
reader process, so another handle or a rewound snapshot cannot adopt old cookies.
Streams/cookies are session-local and discarded at restart.

The first page request captures a validated immutable listing. Later successful
namespace changes, parent renames, failed batches and recovered commits do not
reset the listing or cursor. Entries deleted or moved since capture may still
appear in that snapshot; they neither pin child inodes nor authorize opening a
historical inode. `openat` resolves the current namespace. `listdir()` retains its
existing live-listing behavior and does not consume the stream cursor.
`rewind()` drops the snapshot, frees its memory, resets the cursor to zero and
invalidates every old nonzero cookie. The next read captures the current listing.
`seek(0)` or `readdir(offset=0)` restarts the existing snapshot without refreshing
it. Independently opened/duplicated directory handles have independent snapshots
and cursors. This is the selected mutation policy; POSIX does not promise which
concurrent directory changes an existing iterator will report.

Pages contain at most 4096 entries and at most 1 MiB of binary reply data. Records
are never split. A byte budget too small for the next entry returns ERANGE without
advancing the cursor. Invalid/foreign cookies return EINVAL without changing the
cursor. EOF is explicit, repeatable and preserves its final cookie. Snapshot
capture can occur on the first undersized-buffer request, but no record is
consumed. One stream may retain up to 4 MiB of entry-vector capacity, and a reader
may retain 32 MiB across all streams. Hitting the individual cap returns EOVERFLOW;
reader-wide pressure returns ENOMEM, without evicting other snapshots/cookies.
Release or rewind makes capacity available. Snapshot assembly additionally uses
at most one 4 MiB candidate vector (allocator reallocation can transiently retain
the previous vector); a page allocates at most 1 MiB. These limits concern stream
buffers, rather than libext2fs's filesystem metadata/bitmap allocations.

Every request validates the directory handle's type, allocation and generation
and observes the publication pause gate. Original read grants survive permission
revocation; search-only cwd references cannot obtain a stream. Detected stale
handles remain stale. Existing snapshots can finish after directory removal;
rewind/fresh capture of a removed directory returns an empty stream, matching
its logical zero size and empty live listing. Directory and ancestor lifetime
pins remain independent of cached entry metadata. Release, session shutdown and
reader EOF free all stream buffers.

Private reader commands 27/28/29 implement page, tell/seek and rewind. Page
requests contain the directory token and an entry limit; the request offset is
an opaque cookie (INT64_MAX is the internal current-cursor sentinel). The reply
size field carries the next cookie, followed by a little-endian EOF/count header
and length-delimited inode/type/name/next-cookie records. The frontend validates
record bounds, types, names, cookies, count and EOF before returning a page. A
future FUSE filler can resume from the cookie of the last entry it accepted even
if a native page contains additional records. These stream primitives are also used by the initial mounted frontend below.

`test-directory-streams.py` checks multiblock classic/extent directories on all
12 block-size/checksum combinations, compares entry identities/types against
independent current metadata, and checks byte/entry limits, random cookie seeks,
EOF, duplicate independence, raw names, rename/mutation snapshots, refresh,
failed/torn commits, removed/stale/copied handles, permission retention, pause
admission, malformed replies and release/restart. The isolated
`reader-server-stream-limits` build links the same stream implementation with
4 KiB per-stream/8 KiB reader-wide limits to exercise both resource errors and
capacity reclamation without creating enormous fixtures. It is a test helper,
not an installed frontend. Owned source images remain byte-identical and resulting
filesystems are checked independently with e2fsck.


## Experimental low-level FUSE 3 mount

`mount-broker.py` now connects a separate native FUSE 3 callback executable to the
managed-image session. The frontend never opens an image or device itself. The
Python broker holds the chain lock throughout the mount, authenticates requests
from its private inherited pipes, serializes callbacks, and delegates reads to
the existing native reader and mutations to the staged transaction engine.
Foreground/single-threaded/private-owner mounts are fixed by the launcher; it
accepts no allow_other, writeback-cache or arbitrary FUSE options.

Build the experiment as above, then create a **pristine** managed copy (the older
`chain.py init` intentionally runs demonstration mutations and is not used here):

```sh
python3 experimental/shared-writer/chain.py clone /path/to/source.img /path/to/private-chain
mkdir /path/to/empty-owned-mountpoint
python3 experimental/shared-writer/mount-broker.py --work "$work" \
  --root /path/to/private-chain --mountpoint /path/to/empty-owned-mountpoint
```

The original source is read-only, hashed during copying, and never mounted or
written. Existing managed directories are never overwritten by clone. The chain
and image must be private/owned and the image must be a regular, single-link file;
physical devices/symlink sources are rejected. The mountpoint must be empty,
unmounted, owned by the launching user, and outside the chain/build programs.
Unmount with `umount MOUNTPOINT` on macOS or `fusermount3 -u MOUNTPOINT` on Linux.
The managed image and transaction logs remain available for inspection and restart.
The chain lock excludes another cooperating controller/mount of that chain; it
cannot prevent an unrelated program from directly editing its files.

Supported callbacks are stat/getattr/statfs/access, open/create/read/write,
truncate, flush/fsync, mkdir/rmdir, hard link, symlink/readlink, rename/unlink, and
directory open/read/release/fsync, chmod/chown/utimens and user/POSIX ACL
xattr get/list/set/remove. Rename extensions, special file creation, privileged
security/trusted attributes remain unsupported. Native macOS access ACL editing
is supported for the representable subset described below.
Unsupported operations return an error rather than pretending success.
Creation accepts ordinary permission bits (mkdir also permits sticky);
setgid inheritance is still derived by the backend. File sizing follows the inode's extent/indirect mapping capacity and signed
64-bit offsets. The 128 open-handle, 4,096 mounted lookup/pin, 4 MiB transaction payload and 32 MiB reader
stream bounds still apply; large files are written in bounded chunks. The mounted helper uses FUSE 3 only; the stable reader's FUSE 2 ABI
is unaffected.

The mount is owner-only and policy is enforced in the broker, including numeric
POSIX ACL access/default inheritance, sticky/protected-link rules and immutable/
append safeguards. Caller uid/gid/umask originate in FUSE context. Where FUSE can
provide supplementary groups, those are supplied for the request; otherwise the
broker uses only the authenticated primary gid, rather than granting the daemon's
potentially broader group list. Linux kernel ACL enforcement is not advertised;
macOS uses default_permissions plus extended_security for native kernel checks
and retains broker authorization. nodev/nosuid are fixed.
Lifecycle-only handle release/flush/fsync and kernel metadata requests can use the
mount owner's context; they grant no new data or namespace access. This is not a
multi-user mount or a replacement for the stable native macOS ACL reader.

File/dir inode handles survive rename and the broker preserves their open-time
rights. Every acknowledged write/namespace mutation is durably committed through
the existing recovery engine; flush does not close a handle shared by dup/fork,
and fsync checks the still-live handle/session after already committed writes.
Regular-file direct I/O, zero attribute/entry/negative timeouts and disabled
writeback/directory caching avoid serving stale kernel data after commits.
Mounted stat reports actual write bits, Linux uid/gid, inode/link counts, logical
size, allocated 512-byte sectors and validated timestamps. Space/inode counts are
reported from current libext2fs metadata without the read-only flag.

The mounted helper now uses `fuse_lowlevel_ops` and opaque inode node IDs.
Lookup, create, mkdir, symlink and link replies add kernel lookup references;
forget and batch-forget consume their exact counts. Node IDs never repeat within
a mount, and hard links share one node. The visible stat/readdir inode number
remains the ext4 inode; kernel node IDs are separate, generation-bound identities.
The kernel resolves symlinks; the broker resolves namespace operations directly
from pinned parent inodes, without reconstructing an absolute path after rename.

The implicit root pin requires identity rather than search permission, allowing
owner getattr/chmod even when the root mode is 000. Ordinary lookup still checks
directory search permission. Lookup pins confer no file-data access. Open/opendir performs fresh mode/ACL and
immutable/append checks before allocating an independent open-time grant. A node
stays pinned while either its lookup count or open count is nonzero; release does
not consume lookups and forget does not revoke a still-open handle. Lookup pins
use a separate 4,096-slot pool; the existing 128 open slots remain separate.
Distinct inode/ancestor pins and durable orphan entries are bounded at 4,096;
ancestry traversal remains bounded to 128 steps. Namespace operations returning
new entries preflight both node slots and pin capacity before mutation. Exceeding
a bound returns an error rather than reusing a live identity.

Unlink, rmdir and rename-over remove names immediately. Referenced zero-link files,
symlinks and empty directories enter the durable legacy orphan chain. Removed cwd
and directory lookup references preserve their allocated `..` ancestry. Inode
getattr/setattr, readlink and xattrs work after name removal; data operations use
independent file grants, and creating an entry in a removed directory fails ENOENT.
There is no high-level `.fuse_hidden` rename policy. Interrupted entry/create replies
balance unaccepted lookup/open references. Unmount implicitly drops all references,
even if the kernel does not send every forget; session teardown then reaps orphans.
An abrupt process loss discards volatile references, and the next session reaps
validated durable orphans before serving requests. No recovery scans or deletes
names merely because they start with `.fuse_hidden`. Existing leftovers from an
older frontend are retained for explicit owner inspection.

Setattr and native ACL editing use atomic inode-grant batches, including combined
truncate/ownership/mode/timestamp changes. Namespace, data and metadata transactions
still commit durably before acknowledgement. Regular-file direct I/O and zero entry/
attribute timeouts remain; there is no writeback cache, NFS export or multi-user mount.
A disconnected macFUSE mount may require explicit `umount -f MOUNTPOINT` before
reusing its mountpoint. This does not replace managed-image transaction recovery.

Mount admission requires a clean Linux-format filesystem. The explicit
`--recover-journal` startup option below can replay a supported internal journal
on a private candidate before admission.
It rejects bigalloc, quota, ea_inode, active modern orphan records, inline data,
encryption, verity, casefold, readonly and largedir feature profiles. An inactive
orphan-file feature is accepted because the existing legacy-orphan backend has
been independently fsck/recovery-tested on those same profiles. Casefold
directory operations still fail EOPNOTSUPP at use; supported non-casefold HTree
mutations are described below. Ongoing writes use managed-image redo
recovery rather than native ext4/JBD2 commits; physical-power-loss certification
remains outstanding.
The Python orchestration uses authenticated chunk updates and periodic full-scan
checkpoints as described below; mounted latency and resource limits remain experimental.

`test-mount-broker.py` checks pristine clone preservation, full inode/geometry
metadata, per-request umask/context, foreign-caller rejection, grant lifetime,
tracked hidden cleanup, rename/size errors and malformed transport across all
12 profiles. `test-mounted-writer.py` requires a real working FUSE 3 installation
and mounts only owned temporary clones. It verifies regular writes, sparse
truncate/growth, allocation, fd metadata, hard-link/rename/unlink-open lifetime,
dup/flush/fsync, append/exclusive creation, kernel buffer pagination of long
names, symlink/directory changes, mode mutation, lock exclusion,
restart, independent e2fsck/debugfs contents and unchanged inputs. Its first
configuration injects a verified one-shot EIO after an actual half-page replay;
the failed syscall is followed by checks that the sealed mutation completed
through recovery and that subsequent mounted operations still succeed.
It never deletes a still-mounted tree; failed fixtures/logs are retained. The new
Linux CI mount job requires /dev/fuse and fusermount3 rather than silently skipping
kernel integration. Native macFUSE is validated separately on this host.


## Transactional metadata mutations

The experimental mount supports chmod/fchmod, chown/fchown/lchown, utimens with
explicit nanoseconds or NOW/OMIT, and user extended attribute get/list/set/remove.
The session exposes `chmod`, `chown`, `utimens`, `setxattr`, `removexattr`,
`getxattr` and `listxattrs`; each accepts a live handle instead of a path where
appropriate. Path mutations also work in atomic `applyat` batches with a held
directory base and explicit `follow_symlinks`. Handle metadata uses a private V6
request with the current caller, generation-checked inode grant and complete live
pin snapshot. A read-only data handle can change metadata when the current caller
has authority; an old write grant never substitutes for ownership or group checks.
Rename/unlink and removed-directory handles retain their inode identity.

Modes accept the full 07777 permission range. Ownership changes preserve 32-bit
numeric IDs; -1 leaves that identity unchanged. An unprivileged caller must own
the inode, cannot give it to another UID, and can choose only a member group.
Unprivileged chmod drops setgid when the caller is outside the inode's group;
regular-file chown clears setuid/setgid. Existing file capabilities continue to
block mode/ownership changes conservatively rather than preserving stale
privileges through an unsupported killpriv transition. Immutable/append-only
inodes reject metadata mutations. A both-OMIT timestamp request leaves inode
metadata unchanged. Explicit timestamps require ownership/root; both-NOW also
allows current write permission. ctime updates on actual metadata operations;
mtime and atime are preserved by unrelated changes. Extended timestamp epochs
and nanoseconds are encoded only where the actual inode contains those fields.
Older 128-byte inodes accept whole-second signed-32-bit timestamps and reject
unrepresentable precision/ranges with EOVERFLOW. Birth time remains unchanged.

User attributes enforce current inode read/write rights, plus sticky-directory
ownership rules. Values are bounded to 64 KiB and names to 255 bytes; the ext4 EA
block/inline storage limit can be smaller and returns ENOSPC. Create-only and
replace-only flags, empty/binary values, missing attributes and short output
buffers have explicit errno semantics. The broker maps native macOS user names
such as `com.apple.FinderInfo` to `user.com.apple.FinderInfo` on disk and reverses
that mapping for listing. Linux uses native `user.*` names. Privileged
`security.*`, `trusted.*` and unknown `system.*` namespaces fail closed.
macOS `com.apple.system.Security` is handled by the bounded native ACL editor
below rather than stored as an opaque user attribute.

Numeric POSIX access/default ACL attributes use Linux xattr v2 at the API boundary
and packed ext4 v1 on disk. Incoming ACLs are validated for entry ordering,
permissions, masks, IDs and undefined fields. Setting an access ACL updates its
mode class bits atomically; an equivalent three-entry ACL is represented by mode
alone. chmod adjusts owner/mask-or-group/other permissions while preserving named
entries. Default ACLs apply only to directories and retain existing creation
inheritance. ACL removal preserves current mode bits. Changes to attributes can
allocate or replace EA blocks; the writer refreshes the inode before updating
ordinary metadata so allocation/checksum fields are preserved. All staged errors
roll back the whole batch, and sealed interrupted replay completes before the
resident reader resumes. This remains managed-image redo recovery and the private
owner mount, without native JBD2 journal or physical-device writing.

`test-metadata.py` covers current authority versus retained data grants, high IDs,
special bits, ACL/mode coherence and default inheritance, binary values/flags,
symlink and removed-inode metadata, immutable/append-only protections, legacy
inode overflow, staged rollback and an observed half-page replay failure.
`test-mounted-metadata.py` uses actual FUSE 3 mounts and native libc xattr APIs
on both platforms. It verifies modes/ownership/nanosecond timestamps, descriptor
metadata after unlink, size/ERANGE/missing-attribute behavior, ACL preservation and
copy tools (`cp -p` on macOS, `shutil.copy2` on Linux), then checks e2fsck, contents
and source hashes after unmount. Both suites run all 12 filesystem profiles in CI.


## Native macOS access ACL editing

The experimental macFUSE mount now supports `acl_set_file`/`acl_get_file`, native
ACL removal (`chmod -N`) and explicit-position edits such as:

```sh
chmod +a# 0 'user:daemon allow read,write,append' MOUNTPOINT/path
ls -le MOUNTPOINT/path
chmod -N MOUNTPOINT/path
```

The projected POSIX selection rules require ordered allow/deny entries. macOS
`chmod +a` can reject this as noncanonical order before calling the filesystem;
`+a#` explicitly specifies the insertion position. Edits normalize the effective
POSIX entries, rather than preserving arbitrary native ACE bytes or inactive
masked permissions. Reading a native ACL returns a projection of current POSIX
permissions. Writing the identical projected payload preserves the existing raw
ACL, including masked bits. Mode-equivalent rules may become mode bits without
an extended ACL. The mode group class reports the POSIX mask; ACL removal retains
those current mode bits. Numeric POSIX access/default attribute APIs remain usable.

`native_acl.py` validates Apple's big-endian filesec header and bounded ACE array.
Access rules with representable read/write/append/execute behavior are accepted. Directory delete-child rights must agree with POSIX write
plus search. Explicit delete-self, generic rights, independent metadata/owner/
security rights, unsupported inheritance flags and owner/group UUID header changes are
rejected with EOPNOTSUPP. This is a POSIX data-access compatibility layer;
attribute authority continues to follow the existing POSIX metadata policy and
cannot become an independent native ACE grant. Native access editing preserves POSIX default ACLs. Native inheritance uses the
separate policy described below; the two inheritance authorities cannot coexist.

UUIDs resolve through Membership's UID/GID APIs and must round-trip to the same
UUID. Reserved principals use their defined owner/owning-group/everybody roles;
unknown, ambiguous and unsupported reserved identities fail closed. The editor
checks every referenced user/owner/other identity class, every combination of
referenced groups, and every combined data-right request against the candidate
POSIX ACL. Mixed group accumulation, UID permissions dependent on group membership,
or independent write versus append behavior have no supported equivalent and
are rejected before mutation. Bounds are 128 ACEs, 32 named users and eight group
classes including the owning group. This check is exhaustive within those bounds,
not random sampling or a union-of-allow-bits conversion.

Native writes require current ownership/root, then use the existing staged POSIX
ACL/mode mutation transaction and recovery engine. `XATTR_NOSECURITY`, supplied
internally by macOS for ACL transport, is accepted only for the native Security
attribute; it never bypasses broker authorization. Rejected changes do not create
AppleDouble fallbacks or alter the image. Native removal clears the POSIX access
ACL and preserves the current modes. ACL read/write and ACL-preserving `cp -p`
use the actual platform APIs.

The mount enables macFUSE `extended_security` and `default_permissions` alongside
broker enforcement. Deferred permission checks permitted macFUSE to reuse a held
read handle for a new open after revocation; native kernel checks now deny that
new open while the original descriptor retains its POSIX open-time data grant.
Supported native projections therefore participate in macOS permission checks;
unprojectable ACLs fail closed rather than falling back to an overly broad mode
mask. The stable production reader and Linux experimental mount options are
unchanged.

`test-native-acl-edit.py` tests 256 deterministic randomized file/directory ACLs,
round-trip data decisions, ordered insertion, combined group requests, UUID and
proof bounds, malformed headers and rejected rights. It runs portably in Linux
CI. `test-mounted-native-acl.py` runs natively on macOS across all 12 profiles:
actual `acl_set_file`/`acl_get_file`, `chmod +a#`/`-N`, ACL-preserving copy, unchanged
images on rejected edits, owner read revocation with a live old descriptor,
foreign-owner rejection, and namespace operations through a foreign-owned parent
with a named-user ACL. Every completed mount is unmounted and fsck-checked and its
source hashes remain unchanged. Existing mounted metadata and writer regressions
are rerun with native kernel permission checks.


## Native macOS ACL inheritance

The experimental writer accepts file-only, directory-only or combined inheritance,
with optional `only_inherit` and `limit_inherit`, through native ACL APIs and explicit-position chmod:

```sh
chmod +a# 0 'user:daemon allow read,file_inherit,directory_inherit,only_inherit' MOUNTPOINT/directory
```

`only_inherit` leaves the directory's access rights alone. Without it, the rule
also changes the directory's access ACL. Child directories retain only directory-inheriting rules that do not carry
`limit_inherit`. File-only entries are not passed through a newly created
directory, matching XNU inheritance. Limited entries apply to the immediate
child but disappear from its propagation template. Existing descendants are unchanged by parent edits or
`chmod -N`; native removal clears that inode's access ACL and native template.
Symlinks do not inherit access ACLs. Native ACE provenance and ordering are
normalized on reads: access is projected from POSIX permissions, and the numeric
template is returned as inherit-only entries. The inherited annotation is
accepted but is not stored as historical provenance.

macOS grants can exceed creation mode bits, so substituting a POSIX default ACL
would lose permissions. The writer instead persists a versioned numeric ordered
policy in the reserved `trusted.ext4fuse.native_inherit` attribute. New templates use
`NACL0002`, including per-entry propagation controls; existing `NACL0001`
templates remain readable with their original combined inheritance semantics. Linux restricts the trusted
namespace to CAP_SYS_ADMIN, so a non-owner with directory write permission cannot
forge the policy through ordinary Linux xattr calls. The mounted xattr
API hides it and rejects direct edits. The transaction backend requires inode
ownership, directory type and bounded valid encoding even for direct Session
operations. Parent access ACL and native template edits share one staged/durable
transaction. The template is copied onto new child directories in the same
creation transaction. On regular-file/directory creation, the producer evaluates
native ordered allow/deny decisions against the requested mode after umask,
then materializes a standard ext4 POSIX access ACL. A named read grant therefore
survives a requested file mode of 0200 with umask 0077. Child UID aliases and
owning-group membership are evaluated using the actual new inode identity.

The producer checks all relevant owner/named-user/other identities, all combinations of owning-group and referenced named-group membership, and every combined read/write/append/execute request
(including directory delete-child). If that child policy cannot be represented
by POSIX class selection, creation fails before allocating an inode. For example,
a named read allow combined with unequal group/other write fallback can depend
on group membership, which a POSIX named-user entry cannot express. Accepted
parent templates consequently do not guarantee that every possible child
creation mode will succeed. Write and append must agree; directory deletion must
match write plus search. There are at most 32 inheritable ACEs and eight distinct
numeric named users and seven distinct numeric named groups (eight group classes
including the owning group). Owner, owning-group and everybody roles are
supported. Independent metadata/security grants and generic rights remain
unsupported. Exact reserved GUID collisions are rejected; ordinary numeric group
GUIDs sharing the well-known prefix are resolved through Membership and are not
treated as special principals.

The numeric policy is an experimental ext4fuse extension, not an ext4 kernel
inheritance feature. Linux and other writers understand the already-created
children's standard access ACLs, but do not inherit this template when creating
new children themselves. Ordinary POSIX default ACL behavior remains unchanged;
attempts to combine a default ACL with a native template fail atomically.

`test-native-inherit.py` compares the Python native ACL evaluator and the C
producer over all 512 BSD modes, files/directories, owner aliases and allow/deny
policies. `test-native-inherit-transactions.py` verifies authority, umask, grants
beyond creation mode, propagation, symlink exclusion, conflict/encoding rejection,
rollback and an observed half-page durable replay across all 12 profiles. CI runs
both suites. `test-mounted-native-acl.py` additionally exercises native chmod,
ACL APIs, removal and grandchild propagation through actual macFUSE mounts,
followed by e2fsck and unchanged source hashes.

The short-lived initial implementation used `user.ext4fuse.native_inherit`.
That legacy key is rejected at mounted getattr/native ACL reads and before child
creation, and cannot be set by the writer. It is not automatically promoted into
trusted policy. An owner can remove it through the offline Session API, then
reapply the desired native ACL through the mounted editor. No released reader or
installed Homebrew formula has used this experimental inheritance format.


## Offline physical-device publication

`device-writer.py` adds an explicit snapshot/edit/publish path for an unmounted
ext4 device. The ordinary FUSE writer still opens only its managed image. The
physical device is never passed to the mutation producer or mounted for writing.
Use the returned `SESSION/chain` with the existing image writer, then explicitly
publish that frozen generation:

```sh
python3 experimental/shared-writer/device-writer.py snapshot DEVICE SESSION
# Edit SESSION/chain with the existing Session API or private mounted writer.
python3 experimental/shared-writer/device-writer.py commit SESSION DEVICE
# After interruption, use the SAME retained recovery directory:
python3 experimental/shared-writer/device-writer.py recover SESSION DEVICE
```

Device access may require administrator privileges. No device is discovered or
selected for writing implicitly, and no mounted filesystem is forcibly unmounted.
Initial physical admission requires a partition with a stable partition UUID and
hardware serial/WWID, supported 512/1024/2048/4096-byte sectors, page-aligned
capacity, an entirely offline drive and an external local journal filesystem.
macOS additionally rejects drives containing APFS/HFS volumes and takes Disk
Arbitration claims on the whole disk and target slice; existing raw-device users
are rejected. Linux rejects holders/layered devices and holds an exclusive whole-drive block
claim throughout publication, plus whole-drive mount checks. Owned disk-image and loop devices are
accepted specifically for disposable native tests. Geometry and identity are
rechecked against the open descriptor. Ambiguous identities, aliases, system or
mounted drives, changed source contents and unsupported geometry fail closed.

The snapshot and staged candidate must pass read-only e2fsck, retain the same
filesystem UUID and match the admitted capacity. Candidate publication holds the
managed chain lock, preventing a mounted writer or another session from changing
the captured generation. The external journal contains old/new changed pages,
full pre/post hashes, a log hash and device identity. It is synced and sealed
before target writes. Publication temporarily clears the primary ext4 magic in
an aligned sector, flushes and verifies it, then writes and flushes all new pages
while retaining that guard. A full-device hash is checked before restoring the
magic. The final sector differs from its already-durable predecessor only in the
two magic bytes, so a torn final write leaves either an unrecognizable device or
the fully updated filesystem. Completion is recorded only after device flush and
readback verification. Recovery accepts torn logged pages but rejects changed
unlogged bytes, wrong devices, changed capacity and corrupted logs/markers.

Keep the recovery directory after interruption: it is the authority needed to
restore the temporarily unrecognizable device. Each directory describes one
publication; further edits require a new snapshot/session. This is external redo
publication, not JBD2 journal integration or continuous direct-device FUSE writes.
OS claims coordinate mounts and cooperating users; simultaneous privileged raw
access or devices that falsely acknowledge cache flushes are unsupported. The
protocol does not automatically rewrite backup superblocks to make a partial
filesystem usable, and no repairing fsck should run before recovery finishes.

`test-device-writer.py` injects interruption at every replay sector and publication
boundary, exercises torn sectors, and checks identity/log/clean-byte rejection
without enabling regular files in production admission. `test-device-native.py`
uses only a freshly generated disposable hdiutil or loop device, interrupts a real
publication after the guard is durable, recovers idempotently, checks resulting
file bytes and runs e2fsck. Linux CI runs whole-loop and partitioned-loop tests with sudo, including
mounted-sibling rejection and preventing sibling mounts during a held claim; macOS tests
use owned disk images. No physical user disk is touched by these tests.


## Indexed-directory mutation

Existing non-casefold HTree directories now support create, mkdir, symlink,
hard-link, rename/replacement, unlink and rmdir through the same staged transaction
engine, including relative directory handles and retained open inodes. Their index
flags and hash policy are retained. libext2fs performs hash-routed insertion,
leaf splitting, internal-node splitting and root growth; indexed errors never
fall back to linear `expand_dir`. Deletion preserves the index rather than
repacking/shrinking it. New directories still start in the ordinary linear format;
automatic conversion of growing linear directories is not part of this change.

A bounded validator runs before indexed traversal/mutation and after insertion or
removal. It checks root/internal layouts, count/limit fields, checksums, hash ranges
and collision continuations, allocated mappings/inodes, full logical-block
coverage, duplicate logical/physical references and duplicate names. Corrupt
indexes fail without publication; mutations and their validation share one
rollback/recovery boundary. Validation is a full-tree scan, so write throughput
on large directories is not yet optimized. Limits are 16,384 logical blocks
(16–64 MiB at supported block sizes) and 65,536 live names. Root depths zero and
one and legacy/half-MD4/TEA policies with signed/unsigned hashing are supported.
`large_dir`/depth-two and casefold feature profiles remain rejected.

Tree growth also exposed a native reader compatibility error: libext2fs can retain
nonzero reserved dx-tail bytes while computing a valid checksum. Linux includes
those bytes in its checksum without requiring zero. The reader now follows that
rule, retaining checksum, structural and reference validation. The stable reader's
indexed tests include a repaired-checksum reserved-tail regression.

`test-indexed-mutations.py` exercises growth and namespace/handle/empty-directory
lifetime across all 12 block-size/checksum/mapping profiles and all six hash
variants. Valid-checksum cycles, duplicate child references and incorrect hash
ranges are rejected with unchanged images and transaction heads.
`test-indexed-collisions.py` uses real same-hash names across leaf/internal-node
boundaries and verifies recovery after actual half-page interruption across
12 configurations. `test-mounted-indexed.py` checks real FUSE create, relative
opens, link, cross-parent file/directory moves and open-unlink cleanup on two
representative profiles. Every accepted output passes independent read-only
e2fsck and source hashes remain unchanged. CI runs these suites with sanitizers.


## Large writable files and transaction costs

The arbitrary 64 MiB file-size ceiling has been removed from path, handle and
mounted APIs. Offsets use signed 64-bit bounds. Before any allocation, the producer
checks the entire write/truncate against the actual inode layout: classic direct,
single/double/triple-indirect capacity at the filesystem block size, or the
32-bit extent logical-block range with its reserved final block excluded.
Format overflow returns EFBIG atomically. Bounded transaction payloads and dirty
page budgets remain independent of logical file size. Sparse files can exceed
the physical image capacity; allocated writes still require filesystem space.

Legacy standalone block-log/in-place transactions retain whole-image SHA256.
Managed sessions now migrate validated version-1 chain state to version 2 with
`algorithm: sha256-merkle-1m-v1`; version-3 page transactions use that same
algorithm. The `sha256`, `base_sha256` and `image_sha256` fields in these new
formats hold domain-separated Merkle roots, **not whole-file SHA256 digests**.
Older writer implementations cannot open a migrated chain. Migration occurs only
after recovering pending legacy work and checking the legacy whole-image hash.

The in-memory tree authenticates 1 MiB chunks, including the partial final chunk;
leaf hashes bind their index and length, node hashes bind child ordering, and the
root binds image size and chunk size. Empty padding leaves are distinct from data
leaves. The tree uses a packed bytearray with a 256 MiB allocation budget: about
64–128 bytes per MiB of image capacity, supporting images up to 4 TiB. Larger
managed images fail closed before allocation; this is separate from sparse file
mapping limits. Only roots and complete page undo/redo logs are persisted. No
on-disk tree or hash-index update needs a separate crash recovery protocol.

A live session holds chain-lock and caches the tree from a full scan. Capture and
replay authenticate every touched chunk (including its clean bytes), update only
changed branches, sync the image, and read back touched chunks before sealing
completion and publishing the new root. Every transaction checks image identity,
size, ownership, links, mode, mtime and ctime against the trusted fingerprint.
Ordinary outside writes, including writes followed by restoring mtime, invalidate
the cache and are rejected before intent publication. This remains a private,
cooperating-process design; timestamps are a cache-validity guard, not a
cryptographic guarantee against concurrent hostile modification.

Opening a session, cold recovery and checkpoints fully scan the image. Cold
recovery substitutes logged preimages while hashing **all** chunks, verifies both
base and prospective roots, then replays a sealed transaction. This detects clean
corruption outside the transaction even after a torn page write. Latent media
corruption in an untouched chunk with no metadata change can remain undetected
during warm transactions until a full scan; ordinary reads are not Merkle-verified.
This explicitly changes verification cadence rather than claiming untouched bytes
can be authenticated without reading them. The default mounted checkpoint every
64 transactions still performs a full scan, so its amortized scan cost remains
proportional to image size. Offline physical-device publication keeps its existing
whole-device SHA256, guard, flush and recovery protocol.

`Session.checkpoint()` retires completed history under the existing session lock
without closing the resident reader, open files, directory handles or cwd.
`Session(..., checkpoint_every=N)` enables automatic retirement; zero disables it.
The mounted broker defaults to `--checkpoint-every 64`. Publication/retirement uses
the existing checksummed checkpoint protocol, and pending generations cannot be
retired. A checkpoint failure fails the session closed; recover in a fresh session.
Each acknowledged mutation still commits durably, including before retirement;
this is not deferred writeback or group commit.

The previous stage reduced Python verification reads from about 12 to 6 image
passes per transaction. The Merkle path removes those full scans from steady
small transactions: a local five-write run read 31,625,216 bytes total on both
32 MiB and 512 MiB containers holding the same filesystem. Byte counts exclude
native producer/reader metadata reads, startup, and checkpoints. Timing is a
single-run observation, not a general throughput promise. CI gates changed-region
read volume and equal bytes on differently sized containers rather than timing.

`test-merkle.py` covers legacy migration, incremental/rebuilt root equivalence,
non-power-of-two and partial chunks, outside edits with restored mtime, bounded
allocation, log/marker/schema/identity corruption, every durability boundary,
torn pages, checkpoint fallback, and cold detection of simulated silent corruption
in an untouched chunk. `test-hash-scaling.py` checks 32/512 MiB scaling. Existing
legacy full-hash fault matrices remain separate regression gates.

`test-large-writes.py` checks sparse multi-gigabyte writes, the 4 GiB boundary,
append, shrink/regrow zeroing, exact mapping bounds, rejected writes and half-page
recovery across all 12 filesystem profiles. `test-session-checkpoints.py` tests
live unlinked files, directory/cwd lifetime, restart, fsck and refusal of changed
untouched bytes. `test-mounted-large.py` exercises actual FUSE large-file I/O,
open-unlink lifetime and automatic history bounds. Existing capture/replay and
checkpoint fault matrices remain the recovery regression gates.

## Low-level mounted lifetime validation

`test-lowlevel-broker.py` checks lookup/open count independence, immediate unlink,
rename/hard-link identity, metadata-only pin authority, forgotten-ID refusal,
combined-setattr rollback, symlink orphans, retained removed ancestry, resource
preflight, and more than 128 simultaneous lookups across all 12 profiles.
`test-mounted-lifetime.py` exercises actual macFUSE/Linux FUSE mounts on classic
1 KiB and checksum-enabled extent 4 KiB profiles: open-unlink data/stat/metadata,
rename-over victims, dup lifetime, cwd removal without an open handle, traversal
through removed ancestors, removed directory fds, and abrupt isolated mount-group
termination followed by orphan recovery and remount. It verifies source hashes,
independent e2fsck results and preservation of a legitimate `.fuse_hidden…` file.
Existing mounted namespace, large-file, indexed and metadata/ACL suites now use
this same low-level frontend. The installed stable read-only reader is unchanged.


## Continuous device writing (experimental)

`live-device.py` keeps the existing native reader/mutator on a private, full-size
**disk-backed shadow** and publishes each committed mutation to the explicitly
selected device before acknowledging it. It holds device admission and the
external journal lock for the entire mount. This is continuous write-through,
not a final offline publish and not a RAM filesystem. It requires enough local
storage on another drive for the shadow plus outstanding undo/redo history.

```
python3 experimental/shared-writer/live-device.py init DEVICE JOURNAL
python3 experimental/shared-writer/live-device.py mount DEVICE JOURNAL \
  --work RUNTIME --mountpoint EMPTY_DIRECTORY --checkpoint-every 64
# After an interrupted mount or an ambiguous device I/O failure:
python3 experimental/shared-writer/live-device.py recover DEVICE JOURNAL --work RUNTIME
```

Select an unmounted ext4 GPT partition with a stable hardware identity. Disposable
hdiutil/loop devices are supported for testing; ordinary files are never admitted
as production device targets. The same whole-drive/sibling, off-device journal,
geometry, exclusive descriptor and macOS Disk Arbitration checks used by the
offline publisher apply. The FUSE mount remains private to its launching owner,
with nodev/nosuid and no writeback caching. Unmount normally to finish publication.

The target's primary ext4 magic stays disabled throughout the active mount.
Durable guard phases cover activation and restoration, and per-generation redo
markers cover interrupted sector writes. Each mutation flushes the target and
verifies its changed chunks before publishing the durable device head or resuming
reads. Device failure fails the session closed: no successful acknowledgement,
continued reads, replacement-device selection or automatic clean publication.
A fresh recovery verifies all device chunks, completes sealed generations and
mirrors orphan reaping before serving the filesystem. Clean shutdown releases
all inode pins, verifies the entire shadow/device, requires read-only e2fsck, then
restores and flushes the primary magic. A checkpoint fully verifies the device
before retiring any corresponding shadow redo history.

**Keep the journal and shadow together until clean shutdown/recovery succeeds.**
This is an external recovery protocol, not native JBD2 journal integration;
Linux cannot automatically replay it. Do not force a backup-superblock mount of
an active or interrupted target. A guarded primary superblock discourages normal
mounting but cannot prevent privileged raw writes or forced backup mounting.
Hardware power-loss behavior and dishonest device flushes are not certified.

Warm publication authenticates the touched 1 MiB chunks using the tree built
under the exclusive device claim. Startup, cold recovery, checkpoints and close
scan the entire device. Latent damage in untouched chunks can remain undetected
until those scans; ordinary reads still use the shadow and are not separately
Merkle-verified. Full-device copy/startup/close costs and the full shadow storage
requirement remain. This stage does not introduce a direct-device native reader
or remove those costs.

`test-live-device.py` uses real C mutation logs on explicitly simulated sector
targets: 512/4096-byte sectors, guard/head/journal/retirement/close interruptions,
torn writes, open-unlink lifetime, checkpoint retirement, bounded warm read volume,
I/O fail-closed behavior and malformed/changed device rejection.
`test-live-device-native.py` checks actual disposable macOS hdiutil/Linux loop
writes through both Session and a real low-level FUSE mount, abrupt mount-group
loss, guarded recovery, orphan reaping, clean remount and independent e2fsck.
No test enumerates or selects a user's physical disk.


## Local file locking and range allocation

The private mount explicitly leaves POSIX record locks and `flock` in the host
kernel by disabling remote-lock capabilities. The kernel owns conflict checks,
F_GETLK replies, range splitting, blocking waiters, interruption and process/open
file-description lifetime. Locks follow inode identity through hard links, rename
and unlink; normal writes remain advisory. POSIX locks disappear on the owning
process's close of any descriptor for that inode; flock follows duplicated open
file descriptions. These are local host semantics, not distributed/NFS locks.
The frontend was already relying on local FUSE locking; this stage makes that
choice explicit and adds actual cross-process regression coverage.

`FileHandle.allocate(offset,length,mode=0)` uses the same atomic mutation, redo,
checkpoint and continuous-device publication path as writes. Modes are allocate
and grow (0), keep logical size (1), punch while keeping size (3), and Darwin
physical-EOF preallocation (4, zero offset only). Allocations preserve existing
data. Extents reserve zero-reading unwritten blocks; classic indirect allocations
zero newly allocated blocks. Partial punched block edges are zeroed only when
mapped and initialized; full blocks are freed, and holes/unwritten blocks are
never allocated just to zero them. Inode flags, write grants, format/overflow
bounds and transaction resource limits still apply. Failed operations publish no
partial allocation. Classic mappings reject keep-size allocations beyond EOF,
which cannot pass independent e2fsck with that representation. Extent conversion,
metadata allocation and the bounded overlay can still fail; this prototype does
not promise unlimited reservations or remove those remaining write limits.

Linux exposes allocation, KEEP_SIZE and PUNCH_HOLE|KEEP_SIZE through native
`fallocate`; other flags (zero/collapse/insert range, etc.) fail EOPNOTSUPP.
macOS exposes F_PREALLOCATE through macFUSE's Darwin allocation flags. Only
noncontiguous physical-EOF allocation is supported; contiguous and absolute-volume
requests fail. Native F_PUNCHHOLE on the tested macFUSE 5.4.0 supplies no copied
argument buffer. The frontend refuses that request safely, without dereferencing
the opaque kernel pointer ([upstream report](https://github.com/macfuse/macfuse/issues/1107)).

For mounted macOS hole punching, explicitly enable the private control socket:

```sh
mkdir -m 700 /private/tmp/ext4-control-EXAMPLE
python3 experimental/shared-writer/mount-broker.py --work RUNTIME --root CHAIN \
  --mountpoint MOUNT --control-socket /private/tmp/ext4-control-EXAMPLE/control.sock
# Path is absolute INSIDE the virtual filesystem, not the host mountpoint path.
python3 experimental/shared-writer/mount-control.py \
  --socket /private/tmp/ext4-control-EXAMPLE/control.sock punch /file 4096 16384
```

`live-device.py mount` accepts the same option. The socket must be outside the
mount and managed chain, in a private owned directory. Peer UID is authenticated;
frames, operations and integer ranges are bounded. The server resolves paths and
obtains fresh write grants under the session mutex; callers cannot supply inode
grants or credentials. A control acknowledgement follows the normal durable
commit/device flush, and existing FUSE reads observe the refreshed image. Socket
cleanup preserves unrelated replacement paths. This is an explicit portable
command interface, not transparent native F_PUNCHHOLE support on macOS.

`test-allocation.py` verifies classic/extent profiles, checksummed metadata,
preallocation states with e2fsck before subsequent edits, overlapping byte edges,
zero preservation, unchanged size, read-only/invalid-range refusal, open-unlink
allocation, injected allocation rollback and interrupted punch replay.
`test-mounted-allocation-locks.py` tests real record/flock conflicts, F_GETLK,
shared/disjoint/split ranges, blocking waits while FUSE writes continue, killed
waiters, any-close POSIX release, dup flock lifetime, hard-link/rename identity,
advisory writes, native allocation, Linux punches and the private macOS command.
Native macOS punch refusal is reported separately in its JSON results.

On the tested macOS mount, native preallocation leaves cached `st_blocks`
unchanged until kernel invalidation. The private command invalidates inode and
file-data caches before acknowledgement, so existing descriptors see the
new bytes. Native macOS `st_blocks` still does not match ext4 allocation counts,
so tests require exact reclamation through independent debugfs accounting. Kernel invalidation runs on a separate
notification thread to avoid blocking the serialized request loop. Native
allocation reporting remains a platform integration gap;
Linux tests require native block counts to change. Space reclamation is also
verified independently with debugfs and e2fsck.

### Opt-in dirty-filesystem journal recovery

The experimental writer can recover an internal JBD2 journal before opening the
native reader. Default admission continues to refuse filesystems needing replay.
For an ordinary image, create a managed copy and recover it with:

```sh
python3 experimental/shared-writer/journal-recover.py image SOURCE.img CHAIN
# Retry an interrupted recovery in the same chain:
python3 experimental/shared-writer/journal-recover.py chain CHAIN
```

The source image remains unchanged. Existing managed chains can also pass
`--recover-journal` to `mount-broker.py`; trusted Python callers can use
`Session(..., recover_journal=True)`. This occurs under the chain lock, before
starting the native reader. Recovery requires e2fsprogs `e2fsck` and `debugfs`.

For an explicitly selected, unmounted physical device, use the existing device
admission and off-device recovery directory:

```sh
python3 experimental/shared-writer/live-device.py init DEVICE JOURNAL --recover-journal
python3 experimental/shared-writer/live-device.py mount DEVICE JOURNAL \
  --work RUNTIME --mountpoint MOUNT --recover-journal
# Or publish/finish recovery without mounting:
python3 experimental/shared-writer/live-device.py recover DEVICE JOURNAL --work RUNTIME --recover-journal
```

Initialization only captures and recovers a private shadow; it never changes the
original device. Mount/recover first installs the device guard and publishes the
sealed recovery generation through the ordinary sector redo protocol, before
exposing files. Interrupted publication uses the same retained generation on a
fresh recovery. If initialization sealed its baseline but journal replay failed,
the retained chain can be retried with the explicit recovery option; a dirty
shadow cannot install the device guard or start the reader.

Recovery runs `e2fsck -p -E journal_only,nodiscard` on a second private candidate,
then requires a complete read-only `e2fsck -fn`. Journal identity, geometry,
supported features and modern superblock checksums are checked before invoking
replay: preen must not silently recreate a damaged journal. If the source had an
unclean state bit, it is marked clean only after the full check succeeds, and
checked again afterward. Tool output and execution time are bounded. The candidate
is diffed into authenticated old/new pages; only a sealed, validated generation
can modify the managed image or device. Failed/unsealed candidates are retained
in aborted generations for inspection and retired by normal checkpoints.

This supports internal journals with legacy, checksum-v2 and checksum-v3 records,
including committed transactions, revokes, escaped blocks and incomplete tails.
External/shared journals, journal error states, unknown journal features,
fast commit, MMP and unsupported writer feature profiles remain refused. Other
filesystem damage requiring general repair is refused; this is not automatic
`e2fsck -y`. Recovery needs temporary space for another full image and performs
full-image scans and filesystem checks at startup.

This adds native journal recovery at import/startup. New writes still use our
external redo generations; they do not create Linux JBD2 transactions. It does
not make this experimental branch a fully journaled production ext4 driver.
`test-journal-recovery.py` exercises real debugfs-generated JBD2 records across
all twelve reader/writer profiles, including coupled inode/bitmap/directory
transactions and crashes before/during generation replay.
`test-journal-native.py` checks actual disposable hdiutil/loop devices, recovered
mounted reads and writes, and interrupted physical publication.

### Physical writing without a full data shadow

The opt-in **direct** storage mode retains the native reader and libext2fs
mutator, but reads unchanged blocks from the exclusively claimed physical device.
It does not copy regular-file data into a persistent shadow. Select it when
initializing a new recovery directory:

```sh
python3 experimental/shared-writer/live-device.py init DEVICE JOURNAL \
  --storage direct --work RUNTIME
python3 experimental/shared-writer/live-device.py mount DEVICE JOURNAL \
  --work RUNTIME --mountpoint MOUNT
# After interruption, with the same device and intact recovery directory:
python3 experimental/shared-writer/live-device.py recover DEVICE JOURNAL --work RUNTIME
```

`direct-device.py init/mount/recover` provides the same direct-only interface.
Existing shadow recovery directories keep their format; mount/recover detects
the direct marker automatically. Shadow mode remains the default for the old
initialization command. Existing histories are not converted or discarded.

The off-device directory stores identity/state files and sealed transaction page
preimages/redo, not a complete data image. `chain/image.img` is an opaque sparse
identity token with the device's logical size and **zero allocated data blocks**.
Its apparent size in `ls -lh` is not occupied shadow storage. It is never a backup,
ordinary image, or source for external filesystem tools; outside the explicit
controller its bytes are holes. The controller validates its identity, ownership,
mode, size and lack of allocated blocks before activating a device. Native
readers/mutators receive a narrowly scoped, inherited **read-only** descriptor
whose identity is checked against that token; they cannot write the physical
source. The FUSE frontend receives no raw device descriptor.

Mutations still stage bounded pages in the C overlay. Before any physical write,
the coordinator seals complete old/new pages and their authenticated roots in the
off-device journal. Replay writes through the held writable device descriptor,
keeps the primary magic guarded, flushes the device, authenticates touched chunks
and publishes the durable chain head before acknowledging. Partial sector/page
writes, lost replies and interrupted head publication recover from those same
retained pages. Sub-sector writes use aligned sector read/modify/write; they never
expose the guarded magic. Cold recovery authenticates the entire normalized device
before replay; warm updates retain the existing touched-chunk verification model.
Device claim/geometry/guard checks also precede reader RPCs. A failure keeps the
device guarded and requires a fresh recovery process.

Clean close releases all live pins/orphans and requires an independent read-only
`e2fsck -fn` on a **temporary sparse metadata-only check image**. The exporter uses
the same metadata selection as e2image: superblock/descriptors, initialized inode
tables and bitmaps, directories, long symlinks, external attributes, mapping-tree
blocks and internal journal/orphan-file storage. Ordinary file payloads are omitted.
Only selected metadata sub-blocks are copied; other bytes in their host pages stay
zero. Sorted page runs and explicit hole punching prevent host write allocation
from densely filling gaps. This scratch image is not a recoverable data backup.
It is deleted after checking and rebuilt after interruption. A full device scan
checks that the exact committed root is unchanged before clean magic restoration.

`--check-bytes BYTES` bounds selected metadata export (default 1 GiB, configurable
from 4 KiB to 1 TiB). Host page rounding and allocation overhead are separate;
the recovery filesystem must support sparse files and hole punching. Too little
scratch space, an exporter/check failure or device mismatch prevents clean close;
retained redo remains available for recovery with a suitable budget. Persistent
redo storage grows with outstanding changes and the checkpoint interval, rather
than filesystem capacity. Checkpointing retires old logs only after full device
verification. Keep the entire recovery directory on another drive until the
device is clean; Linux still cannot replay this external log.

Dirty internal journals require explicit consent during direct initialization:

```sh
python3 experimental/shared-writer/live-device.py init DEVICE JOURNAL \
  --storage direct --work RUNTIME --recover-journal
# Resume staging or complete an interrupted physical replay:
python3 experimental/shared-writer/live-device.py recover DEVICE JOURNAL --work RUNTIME
```

The private `journal-candidate` FUSE service presents a regular file to trusted
e2fsprogs. Reads fall through to the held **read-only** device descriptor; writes
stay in the bounded C page overlay. No full-size candidate is copied or allocated.
The temporary mount requires working native FUSE, including for initialization
and for resuming an interrupted, unsealed import. It is private to the caller,
and has no network service or physical write capability. Its apparent capacity
is virtual; it disappears when the producer seals its stream or closes its
control pipe. Startup replay uses the same strict journal validation,
`e2fsck -p -E journal_only,nodiscard`, and two full read-only consistency audits
as shadow mode. The candidate includes recovered namespace/allocation metadata
and their newly referenced data, rather than a snapshot of pre-replay metadata.

`--journal-bytes BYTES` bounds the candidate's distinct modified 4096-byte pages
(default 256 MiB, page aligned, configurable from 4 KiB to 1 GiB). RAM also holds
old pages and indexing overhead; this is a changed-page budget, not a total RSS
limit. Exhaustion refuses replay without writing the source. A retained import
can retry with a larger budget. Candidate I/O errors signal the supervising
process through a private pipe, so a tool stuck in its own error cleanup is
terminated promptly. Sealed replay no longer needs the volatile candidate.
There is no full-image fallback. Teardown verifies that the private mount has
actually detached, including when the producer disappears mid-stream.

Initialization records durable import consent, then streams complete old/new
pages into the authenticated external transaction log. It **leaves the original
dirty device unchanged**. Before guarding the device, mount/recover validates the
entire sealed log and source root. Interrupted unsealed candidates are discarded
and rebuilt; sealed candidates are reused verbatim. Recovery then installs the
guard and applies the transaction through the usual durable sector-write path.
The native reader starts only after replay and full-root verification succeed.
Changing a device externally after direct initialization remains an error; this
option does not rebase an existing direct history onto an unrelated journal.

Internal legacy/checksum-v2/checksum-v3 journals, committed transactions, revokes,
escaped blocks and incomplete tails use e2fsprogs replay. External journals,
fast-commit, MMP, unsupported features, journal errors and non-journal damage
remain refused. New writes still use our external recovery log, rather than
creating Linux-replayable JBD2 transactions. Full-device scans at admission,
cold recovery, checkpoints and close remain. Existing feature, permission,
handle, transaction and 4 TiB Merkle limits still apply.

`test-journal-candidate.py` compares bounded replay with independent full-copy
test oracles across all twelve profiles and journal formats, and checks budget,
checksum, UUID, feature and metadata failures. `test-journal-candidate-space.py`
proves that replay beside a 128 MiB allocated file on a 256 MiB filesystem needs
only changed-page storage; the macOS fixture used 12 KiB of changed pages and a
24,624-byte old/new stream. `test-direct-journal.py` uses
explicitly disposable native devices to verify unchanged initial sources,
zero-allocation tokens, cold replay, mounted writes, tampered-log refusal, budget
retry, and process loss throughout candidate/staging/guard/physical replay/close.
Linux includes actual 4096-byte logical sectors. These tests do not use or alter
user disks.

`test-direct-device.py` uses only explicitly created hdiutil/loop targets. It
checks all twelve profiles, native Linux 512/4096-byte logical sectors (including
4 KiB sector crash recovery), zero token allocation after writes, read-only child
capabilities, foreign-device/token refusal, regular/sparse/allocation/namespace
and open-unlink operations, actual mounted writes, corrupted sealed logs,
untouched-device corruption, scratch-budget failure, and guard/replay/close
interruption boundaries with fresh-process recovery. `test-metadata-snapshot.py`
requires fsck-clean metadata images while proving allocated user payload blocks
are absent, measures occupied scratch bytes on a 256 MiB filesystem with a
128 MiB allocated file, and tests the export budget. Native checks run with
sanitizers on macOS and Linux CI. Hardware power-loss behavior remains uncertified.
