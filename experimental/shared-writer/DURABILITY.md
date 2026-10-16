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

## Still required for production qualification

- Longer multi-hour and higher-volume workloads, including actual volume/journal
  exhaustion, sustained memory pressure and recovery-space pressure.
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
