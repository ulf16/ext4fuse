# Durability qualification

The write engine remains a beta. Passing software fault campaigns does not certify
physical power-loss behavior. New writes still use the external redo log, not
native JBD2 transactions. Keep the entire recovery directory on durable storage.

## Acceptance rules

The test oracle is separate from the filesystem implementation. It uses seeded
file contents and immutable history entries. For each submitted atomic batch,
recovery must produce the complete state before or after the batch. A batch whose
successful return was durably acknowledged must produce the after state. All
previously acknowledged history must survive. Recovery must be idempotent, leave
correct hardlink identities/counts and attributes, and pass independent `e2fsck -fn`
and `debugfs` content/directory checks. A rejected batch must not partly publish.

Mounted applications use file `fsync`, rename, hardlink and directory `fsync`, then
send an acknowledgement to the parent test process. The parent syncs its external
ledger before killing the mounted writer. Merely seeing a filename is not treated
as an acknowledgement. Unacknowledged files may survive; their presence does not
prove that an application received success.

## Software campaigns

`test-endurance.py` runs a seeded mixed workload on managed disposable images:

- Creation, sparse writes, truncation, mode/xattr changes, hardlink replacement,
  atomic rename and immutable per-transaction history entries.
- An open unlinked inode retained across commits and repeated checkpoints.
- Late invalid operations to verify whole-batch rollback.
- Process termination at 22 transaction/checkpoint publication boundaries.
- Actual page-write and file/directory-sync call sites injected with EIO/ENOSPC,
  including short, zero-progress and partly completed writes. Transient failures
  can recover a sealed transaction while still reporting failure to the caller;
  persistent replay failures must fail the live session closed. Failures before
  sealing may safely abort and leave the reader usable.

`test-device-cache-loss.py` uses only explicitly created hdiutil/loop-backed images.
It copies the physical target to a separate test oracle after each successful
device flush. Following process loss it discards or tears actual changed sectors
written since the last flush, retaining the durable baseline. Another simulated
outage can occur during recovery. It checks acknowledgements, clean publication,
independent filesystem consistency and the absence of a full-size production data
shadow. The full-size oracle is test infrastructure, not a writer requirement.

This cache model assumes an honest target flush, a durable recovery-log filesystem,
and cache loss limited to the target. It does not model lying flush acknowledgements,
arbitrary damage to already durable sectors, simultaneous loss/reordering on the
recovery-log filesystem, or real drive/controller/bridge firmware behavior.

`test-mounted-endurance.py` runs two concurrent application writers through a real
FUSE mount, records received acknowledgements externally, kills the broker/frontend
process group during subsequent writes, detaches the stale mount, recovers and
remounts. All acknowledged content and hardlinks must survive every cycle.

`test-resource-exhaustion.py` fills actual bounded storage, rather than injecting
an error at an I/O call site:

- 1 KiB and 4 KiB ext4 images independently run out of blocks and inodes. Failed
  multi-operation batches must roll back their names, metadata and bytes. Smaller
  writes consume the final fragments; `debugfs` must report zero free blocks or
  zero free inodes at the failure. Deleting
  an acknowledged filler must permit new writes.
- A new 64 MiB HFS+ disk image on macOS, or a size-limited private Linux tmpfs,
  holds the managed chain. A filler consumes its real free space before a request,
  during page logging, after redo sealing, after image application and before head
  publication. No filler is written to the host volume. Sealed transactions must
  recover after space returns; incomplete transactions must not partly publish.
- A separate virtual ext4 device repeats logging, sealing, application and head
  publication failures with its recovery log on a different bounded volume. It
  also fills that volume during clean device publication. The identity token must
  remain sparse, acknowledged bytes must survive, and recovery must restore a
  clean independently checked device. On macOS this uses a 128 MiB APFS log image;
  HFS+ cannot satisfy the sparse-token requirement. No physical disk is used.
- Linux workers exhaust their own address space under hard 96/128 MiB limits,
  before preparation and at sealed/replay stages. Each retained page is touched
  to consume resident memory; the report records the allocation and peak RSS. Independent unrestricted parents
  recover the chain and check acknowledged bytes. These are process-local allocation
  failures, not system-wide swapping or kernel OOM-killer qualification. Darwin's
  unreliable `RLIMIT_AS` implementation is explicitly reported as not run; Linux
  CI is required for this part. Sanitizers reserve large virtual ranges, so this
  campaign deliberately uses an ordinary runtime build.

Every case resumes successful writes and checkpoints, cold-opens twice, and runs
independent `e2fsck` and `debugfs` checks. Disposable sources are preserved. Linux's
bounded log filesystem needs root to mount; no physical disk is selected.

Reproduce from a checkout with the existing development dependencies:

```sh
python3 experimental/shared-writer/build.py --work /tmp/ext4-durability --sanitize
python3 experimental/shared-writer/run-matrix.py --work /tmp/ext4-durability
python3 experimental/shared-writer/test-endurance.py --work /tmp/ext4-durability --rounds 240
python3 experimental/shared-writer/test-device-cache-loss.py --work /tmp/ext4-durability --focused
python3 experimental/shared-writer/test-mounted-endurance.py --work /tmp/ext4-durability \
  --prefix /path/to/installed/prefix --cycles 3 --acks 32
```

Linux disposable loop-device tests require root. macOS hdiutil targets can usually
be tested by the launching owner. The tests never select a physical disk. Seeds,
profile results and retained diagnostic paths are written to JSON reports in the
work directory. Failed fixtures are retained. Remove any stale mount before
manually removing test directories. Production `ext4fuse-writer` strips the test
crash environment hook; the fault campaigns use development APIs/test workers.

For the bounded resource campaign (use a separate unsanitized build directory):

```sh
python3 experimental/shared-writer/build.py --runtime-only --work /tmp/ext4-resources
sudo env PATH="$PATH" python3 experimental/shared-writer/test-resource-exhaustion.py \
  --work /tmp/ext4-resources
```

On macOS omit `sudo`; memory cases run on Linux CI. The JSON report records each
exhaustion stage, observed failure and recovery outcome. Failed diagnostics remain
in the work directory; the bounded recovery volume is detached on exit.

## Dependency regression found by this campaign

The zero-free-block case found that Ubuntu's libext2fs 1.47.0 rejects unlinking a
valid extent occupying the filesystem's final block (`EXT2_ET_BAD_BLOCK_NUM`). The
upstream fix changes the exclusive upper-bound test in `punch_extent_blocks` from
`>=` to `>` ([upstream commit](https://github.com/tytso/e2fsprogs/commit/509da98)).
The transaction overlay rejects the failed deletion without damaging the image,
but a full disk must still permit deleting files to regain space.

Writer builds now require libext2fs 1.47.4 or newer, the fixed release exercised
by this campaign, rather than accepting 1.47.0. CI builds a checksum-pinned upstream
1.47.4 library and tools. It links the library statically so root-launched helper
processes cannot silently load the distribution's older shared library. Homebrew's
current e2fsprogs already meets this requirement. No private filesystem geometry
is changed and no local replacement deallocation algorithm is introduced.

## Still required for production qualification

- Longer multi-hour and higher-volume workloads, including simultaneous writers
  during exhaustion, system-wide memory pressure/OOM termination, and exhaustion
  on representative real devices. The bounded managed-image and virtual-device
  campaigns cover actual block/inode/log-space exhaustion and process-local
  allocation failures; it does not establish those wider guarantees.
- Controlled real power interruption of a disposable target, with several device,
  bridge and sector-size combinations. Repeat loss during recovery.
- Separate testing of host/recovery-log filesystem power interruption and its
  ordering guarantees. Target-only simulated cache loss cannot establish this.
- Repeated disconnect/reconnect with persistent hardware identity verification and
  representative real I/O/flush errors. Devices that lie about durable flushes
  remain outside the guarantee.

Hardware testing needs dedicated expendable storage and a reviewed power-cut plan.
No user disk is used or power-cycled by these software campaigns. Passing them
strengthens the evidence for the supported profiles; it does not add unsupported
ext4 features or remove the documented interface/resource limits.

## Integrity scaling and verification cadence

The beta.4 scaling campaign also requires paged/RAM hash equivalence, bounded
resident hash pages, scratch I/O error handling, >4 TiB node geometry and measured
scan reuse on real disposable images and virtual devices. Hash geometry coverage
is not a full multi-terabyte filesystem qualification. See WORKFLOW.md for storage
requirements and the explicit remaining cold-scan cost.

Live session checkpoints now retire history against the verified in-process tree;
they no longer perform an independent whole-volume audit. Ordinary external edits
still invalidate the fingerprint. Same-metadata latent corruption in a chunk not read through the live verifier
is found by explicit recovery, standalone administrative checkpoint,
an authenticated read of that chunk or an explicit `Session.scrub()`.
A fast packaged close is not a full scrub. Cold replay still reads every chunk. The tests
must distinguish this cadence change from disabling corruption detection.

## Verified live reads

A live Session now verifies base data and metadata before either the resident
native reader or libext2fs mutation overlay consumes them. A private inherited
socket returns exactly the bytes hashed against the admission scan's 1 MiB
Merkle leaves. Native children receive no raw device descriptor in this mode.
Python overlay-preimage comparisons use the same verifier. Transaction replay
keeps its existing independent preimage/redo and readback checks: a partially
published chunk does not yet belong to either completed root.

Each native overlay also retains at most 1024 verified pages (4 MiB payload),
cleared on suspend, publication/refresh and rollback. The broker checks image
identity and fingerprint before and after every reader operation, including
operations entirely served by that native cache. No cache hit rereads raw bytes.

The verifier keeps at most 32 immutable chunks (32 MiB payload), shared by the
serialized reader and producer. It discards that cache when the committed root,
image fingerprint or tree instance changes. Each request also checks the image
identity and fingerprint. Cached bytes remain a previously authenticated snapshot;
silent corruption of cached media is detected on a later cache miss or full scan,
not by rereading unchecked bytes after a successful hash. Corruption anywhere in
an uncached chunk rejects even an undamaged subrange requested from that chunk.
An integrity failure latches the session closed to further operations; the failed
producer path cannot rebuild a tree and silently accept the changed contents.

Each native process has its own framed, bounded channel. Child loss cannot leave
a stale reply for a later process. Reads, response sizes, image identity, short
I/O and socket errors fail closed. This private interface assumes trusted shipped
helpers and an exclusively claimed volume; it is not a hostile-process sandbox.

Verified reads permit the persistent-index fast path described below. Explicit
recovery and scrubs still read the entire volume; filesystem metadata checks
remain mandatory at packaged close.
`test-verified-reads.py` checks hidden-metadata corruption, native reader and
producer refusal, preimage failure latching, generation cache replacement, partial
last chunks, cross-chunk reads, malformed bounds and short image I/O.

## Timed mounted endurance

`test-mounted-endurance.py --work WORK --prefix PREFIX --cycles 3 --acks 32
--duration 1200` runs for at least twenty minutes, completing each crash/recovery
cycle. Two concurrent writers split and overwrite files, fsync, rename and
hardlink, then churn directories, symlinks, permissions, truncation and open-unlink
handles. An off-volume fsynced ledger records acknowledged obligations. After
process loss, cold recovery, independent e2fsck/debugfs checks and remount verify
all outstanding acknowledgements. Verified old obligations are durably retired
before deletion so the volume working set stays bounded during longer runs.
Incomplete unacknowledged work is cleaned only after recovery and verification.

`--duration` accepts up to 86400 seconds; `--stall-timeout` limits time without a
new acknowledgement rather than total time in a busy cycle. The report records
actual elapsed time, completed cycles and total/retained acknowledgements. CI
runs twenty minutes by default and manual dispatch accepts up to one hour. The
same job then exercises process-local 96/128 MiB allocation limits and recovery;
the separate exhaustion job retains actual data-volume and recovery-log ENOSPC
checks. These are complementary tests, not a claim that the mounted soak ran
under global host memory pressure or that USB power loss was tested.

The recovery-log exhaustion oracle allows one filesystem-specific outcome at
final clean publication: APFS may still accept a small metadata marker after
ordinary data allocation reports ENOSPC. That case must reach the injected full
volume boundary, durably seal a clean device state, restore the checked device
magic, and pass the same repeated cold recovery, acknowledged-content and fsck
checks. Earlier redo-allocation stages must still report failure. Successful
use of filesystem metadata reserves is not treated as data loss or a missed fill.


## Persistent authenticated clean-head index

`integrity-index` is a disposable snapshot of the 1 MiB chunk leaf hashes, bound
to the complete clean chain state and file/token fingerprint. The independently
persisted chain root remains authoritative. Load reconstructs all internal nodes,
including canonical padding leaves, and compares the size-bound root before
returning any tree. Stored internal nodes and a self-reported index checksum
cannot authenticate themselves. Memory remains bounded by the existing paged
tree implementation; a 128 GiB synthetic geometry tests forced paged loading.

Packaged mount enables reuse; standalone Session/Controller callers retain their
conservative default unless they explicitly pass `persistent_index=True`.
Standalone recovery/checkpoint and `recover STATE` keep full scans. The first
mount without an index scans. A clean close writes a new snapshot using private
same-directory temporary storage, full file sync, atomic replacement and parent
sync. Root/state publication and durable redo precede index publication; no index
operation acknowledges writes or permits log retirement. Missing, stale, unsafe,
truncated, malformed or hash-corrupt snapshots are cache misses. Index ENOSPC or
sync failure leaves recovery state intact and requires a scan on the next open
if no valid snapshot remains. A process killed before replacement can leave an
unused `.integrity-index-*` file; it never grants trust or participates in replay.

Pending transactions and non-clean direct-device phases never use an index for
cold admission. They retain full-scan authentication of old bytes plus replay
preimage/readback verification. Dirty-journal recovery is unchanged. Clean direct
admission authenticates the superblock before installing the existing guard;
identity, exclusive claims and guard-sector readback are unchanged. Fast close
validates metadata through the verified channel before independent read-only
fsck of its sparse metadata snapshot. Regular-image packaged fast close uses
the same authenticated metadata path. A failed read prevents clean publication.

This deliberately changes audit cadence: invisible corruption in chunks never
read during a fast session can survive fast unmount undetected. They cannot be
consumed by the native reader or mutation helper without verification. Explicit
recovery/scrub retains whole-volume coverage, and externally edited volumes are
never silently accepted as a new baseline. It is not a proof against malicious
same-UID writers, stale-state rollback by the administrator, physical power-loss
faults, or unsupported filesystem profiles.

`test-integrity-index.py` exercises malformed/truncated/corrupted/unsafe indexes,
state binding, index-space failure, eight actual publication process-death cases,
forced paged loading, native successor-root reuse, full-scan torn-write recovery,
zero full scans on virtual-device reopen/close, and invisible raw-device damage
that must latch the native session failed. Tests use disposable virtual media;
physical USB unplug/power-loss qualification remains outstanding.


## Named-volume lifecycle and OS ejection

Profiles are private, atomically replaced metadata, not redo authority. They bind
platform, state directory identity, managed image/token and stable device identity,
and mountpoint identity. Discovery is read-only and must find one exact match;
controller admission remains mandatory. A global private registry lock serializes
profile changes. Mount startup acquires writer-lock before releasing registry-lock,
then passes that same locked open description into the background worker. The child
validates its descriptor against the current private writer-lock inode. Other
writers/forget operations cannot enter the transfer gap; listing remains available
while startup scans run. Native helpers do not inherit the writer lock.

The frontend reports private operation 131 only after mounting its own session
and starting its notification thread; operation 129 remains special-file creation.
The broker replies, then signals the parent's private readiness pipe. The parent
also waits for kernel attachment. It never treats an arbitrary mountpoint, PID
file or lack of stderr output as successful readiness. Loss/cancellation of the
waiting parent closes the pipe without aborting the actual writer. Broker death
retains the established mount intent/device guard and requires ordinary recovery.

Named unmount never forces detachment. Eject waits for checked ready state, holds
writer-lock, rechecks the saved binding and clean guard, audits the whole drive's
mounts and canonical device users, flushes and revalidates the exclusive device,
then releases its own claims before a normal OS eject request. OS-node identity
and stable identity are checked again; physical macOS requests use the partition
UUID, Linux power-off uses the stable partuuid alias. The OS may refuse ejection;
state remains ready/retained and no success is reported on failure. Root can audit
raw users; insufficient permissions fail closed. This retains the trusted-owner,
cooperating-process model; it does not sandbox malicious same-UID/root actors or
certify physical unplug/power-loss behavior.

`test-volume-profiles.py` verifies private/unsafe profiles, wrong identities,
geometry/ambiguity refusal, sibling/raw-user preflight refusal, concurrent startup
status, lock-fd/readiness-fd validation, cancelled waits with a surviving writer,
real background mounts, busy cwd refusal, foreground-API compatibility, broker-loss
recovery, non-destructive forget, and virtual-device eject/reconnect with data
verification after rediscovery. The background package adds no resident service.
