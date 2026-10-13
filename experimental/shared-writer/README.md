# Shared reader / libext2fs writer experiment

This experimental backend retains the native reader and uses libext2fs for
filesystem mutations. It now includes an initial private FUSE 3 frontend for
managed regular-file image copies. Production read-only reader and Homebrew
behavior are unchanged. Physical-device and general-purpose writable mounts
remain outside this prototype.

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
python3 experimental/shared-writer/test-handles.py --work "$work"
python3 experimental/shared-writer/test-namespace.py --work "$work"
python3 experimental/shared-writer/test-directories.py --work "$work"
python3 experimental/shared-writer/test-directory-refs.py --work "$work"
python3 experimental/shared-writer/test-openat.py --work "$work"
python3 experimental/shared-writer/test-directory-streams.py --work "$work"
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

No production in-place commits, physical-device writes or release change is
introduced. The experimental mounted frontend below applies only to managed copies.

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
Indexed/casefold directory mutation, rename-exchange/noreplace flags and linking
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
unchanged. Indexed/casefold directory mutation remains rejected.

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
indexed/casefold directory references/mutation remain outside this image-only
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


## Initial experimental FUSE 3 mount

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
directory open/read/release/fsync. Rename extensions, chmod/chown/utimens, special
file creation, xattr mutation and native mounted ACL delivery are not implemented.
Unsupported metadata mutation returns ENOTSUP rather than pretending success.
Mounted creation accepts ordinary permission bits (mkdir also permits sticky);
setgid inheritance is still derived by the backend. The backend's 64 MiB mutation
size, 128 handle/pin, 4 MiB stream and 32 MiB reader stream limits still apply.
Larger existing regular files can be read, but writable sizing beyond that limit
returns EFBIG. The mounted helper uses FUSE 3 only; the stable reader's FUSE 2 ABI
is unaffected.

The mount is owner-only and policy is enforced in the broker, including numeric
POSIX ACL access/default inheritance, sticky/protected-link rules and immutable/
append safeguards. Caller uid/gid/umask originate in FUSE context. Where FUSE can
provide supplementary groups, those are supplied for the request; otherwise the
broker uses only the authenticated primary gid, rather than granting the daemon's
potentially broader group list. Linux kernel ACL enforcement is not advertised;
macOS uses defer_permissions for the broker policy. nodev/nosuid are fixed.
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

High-level macFUSE does not always provide an open fh on getattr after immediate
unlink, so this frontend deliberately uses libfuse's standard deferred-removal
policy. It temporarily renames open unlinked files to `.fuse_hidden...`, and
libfuse adjusts the visible link count. Read/write/fstat/truncate/fsync remain
usable until final close; libfuse then unlinks the temporary name. Live generated
names are tracked by exact inode/generation for lifecycle-only cleanup if libfuse
supplies a kernel/teardown context with no caller. This is volatile tracking, not
a destructive prefix scan. **Abrupt frontend/broker termination can leave such
names in the managed image**; recovery preserves them for inspection. Automatic
hidden-name recovery and complete kernel lookup/forget/cwd handling require a
low-level inode frontend. In particular, offline retained-cwd guarantees are not
certified for a kernel cwd after its directory is removed. Directory snapshot
cookies work through the mounted filler; subsequent calls resume from the last
entry the kernel accepted.

Mount admission requires a clean Linux-format filesystem and no journal replay.
It rejects bigalloc, quota, ea_inode, active modern orphan records, inline data,
encryption, verity, casefold, readonly and largedir feature profiles. An inactive
orphan-file feature is accepted because the existing legacy-orphan backend has
been independently fsck/recovery-tested on those same profiles. Indexed/casefold
directory operations still fail EOPNOTSUPP at use. This is managed-image redo
recovery, not native ext4/JBD2 journaling or physical-power-loss certification.
The Python orchestration still hashes images and retains transaction history;
mounted latency and long-running storage consumption are experimental.

`test-mount-broker.py` checks pristine clone preservation, full inode/geometry
metadata, per-request umask/context, foreign-caller rejection, grant lifetime,
tracked hidden cleanup, rename/size errors and malformed transport across all
12 profiles. `test-mounted-writer.py` requires a real working FUSE 3 installation
and mounts only owned temporary clones. It verifies regular writes, sparse
truncate/growth, allocation, fd metadata, hard-link/rename/unlink-open lifetime,
dup/flush/fsync, append/exclusive creation, kernel buffer pagination of long
names, symlink/directory changes, unsupported metadata operations, lock exclusion,
restart, independent e2fsck/debugfs contents and unchanged inputs. Its first
configuration forces half-page replay interruptions during mounted transactions.
It never deletes a still-mounted tree; failed fixtures/logs are retained. The new
Linux CI mount job requires /dev/fuse and fusermount3 rather than silently skipping
kernel integration. Native macFUSE is validated separately on this host.
