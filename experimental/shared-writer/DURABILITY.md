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
  multi-operation batches must roll back their names, metadata and bytes; deleting
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
