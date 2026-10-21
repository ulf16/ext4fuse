# Installed read-write workflow

`ext4fuse-writer` packages the writable frontend separately from the read-only
`ext4fuse-maintained`. The write engine remains experimental: packaging does not
certify physical power-loss behavior or add unsupported ext4 features. Use backups.
It supports macFUSE's FUSE 3 API on macOS Sequoia or newer, and libfuse3 on Linux.
Only the launching user's requests are accepted. Linux numeric ownership and ACLs
are preserved; initializing an image does not change its file ownership.

## Install

On macOS, install and approve macFUSE normally, then:

```sh
brew install ulf16/ext4fuse/ext4fuse-writer
brew test ulf16/ext4fuse/ext4fuse-writer
ext4fuse-writer doctor
```

The formula supplies Python and e2fsprogs, pins a source checksum, and builds only
five runtime helpers. It does not change your shell, replace the reader, install
services, or mount anything automatically. Intel Sequoia is the native validation
host; Apple Silicon remains unvalidated. Python is invoked in isolated mode.
`doctor` checks helper/tool paths; a successful result does not prove macFUSE is
approved or that a particular filesystem is supported.

For a source installation on Linux or macOS, install a C compiler, pkg-config,
Python 3.11+, libfuse3 development files (macFUSE on macOS), and libext2fs/e2fsprogs
1.47.4+ (includes fixes for extent deallocation at the end of a full filesystem). Set `PKG_CONFIG_PATH` for keg-only e2fsprogs if needed:

```sh
python3 experimental/shared-writer/build.py --runtime-only --work /tmp/ext4-writer-build
python3 experimental/shared-writer/install.py --prefix "$HOME/.local" \
  --build-dir /tmp/ext4-writer-build --python "$(command -v python3)" \
  --version 0.3.0-beta.9
"$HOME/.local/bin/ext4fuse-writer" doctor
```

On Homebrew, pass `--tools-dir "$(brew --prefix e2fsprogs)/sbin"` to the installer
and select a durable Python path (the formula handles both). `--destdir` supports
package staging; the launcher points to the final prefix. No compiler, checkout,
test tools, or build directory is needed after installation.

## Image workflow

Choose a durable state directory on a local filesystem with adequate free space.
`init --image` copies the source; writes go to `STATE/chain/image.img`. The original
is never the mounted writable image. Do not put state under the mountpoint.

```sh
ext4fuse-writer init --image /path/to/linux.img "$HOME/ext4-state"
mkdir -p "$HOME/ext4-mount"
ext4fuse-writer mount "$HOME/ext4-state" "$HOME/ext4-mount"
```

State paths must fit the local Unix socket limit (keep them under 90 bytes on macOS).
Mount runs in the foreground. In a second terminal:

```sh
ext4fuse-writer status "$HOME/ext4-state"
ext4fuse-writer unmount "$HOME/ext4-state"
```

`unmount` uses normal OS unmounting, then waits for the foreground process to
finish orphan cleanup, read-only e2fsck and checkpoint publication. Close files
and move shells outside the mount first. A busy unmount fails without forcing it.
Do not interrupt the foreground process as the normal shutdown procedure.

For an initially dirty Linux journal, explicitly add `--recover-journal` to `init`.
Only the supported internal JBD2 profiles are replayed; general damage is refused.
The retained image is available for copying or use elsewhere after clean shutdown.
Never edit it with another writer while this state directory remains in use.

The authenticated allocation command also works where macOS cannot forward native
hole-punch arguments. Paths are absolute **within ext4**, not host mount paths:

```sh
ext4fuse-writer allocate "$HOME/ext4-state" /large-file 0 1048576 --mode keep-size
ext4fuse-writer allocate "$HOME/ext4-state" /large-file 4096 4096 --mode punch
```

These operations flush/invalidate the mounted file cache and enforce normal writer
permissions. Recovery removes only an owned stale control socket with no listener;
unknown files at that path are retained and reported.

## Device workflow

Select an **unmounted ext4 partition**, with the entire containing drive offline.
The existing device admission refuses macOS system/container volumes, mounted
siblings, mismatched hardware/partition identity and journals on the target drive.
No device is discovered, selected, unmounted, or formatted automatically.

Keep state on a durable **different drive** and use the same launching user for
init, mount, status, unmount and recovery. Raw device access may require `sudo`;
then the mountpoint and private state must belong to root. Do not switch between
sudo and non-sudo operation of one state directory. Example with explicit paths:

```sh
sudo mkdir -m 700 /path/on/other/drive/ext4-state-parent
sudo mkdir -m 700 /path/to/root-owned-mount
sudo ext4fuse-writer init --device /dev/diskNsM /path/on/other/drive/ext4-state-parent/volume
sudo ext4fuse-writer mount /path/on/other/drive/ext4-state-parent/volume /path/to/root-owned-mount --device /dev/diskNsM
# Second terminal:
sudo ext4fuse-writer unmount /path/on/other/drive/ext4-state-parent/volume
```

Use the actual device node, e.g. `/dev/sdXN` on Linux. Direct mode retains sealed
redo records and a sparse identity token; it does not require a full-size data
shadow. Metadata-check scratch space and startup/close verification still cost
space/time. An active device is guarded against ordinary ext4 mounting until
clean publication. Preserve the **entire state directory** if interrupted: it is
needed to replay writes and restore that guard. Linux cannot replay our external
log. Do not run e2fsck or another filesystem driver directly on a guarded device.

## Recovery and diagnosis

```sh
ext4fuse-writer status /path/to/state --json
ext4fuse-writer recover /path/to/state
# For device state, always explicitly supply its current matching device node:
sudo ext4fuse-writer recover /path/to/device-state --device /dev/diskNsM
```

`status` reads bounded metadata without replaying or opening a device. Its `ready`
phase records the last successful check; `checked: false` means status itself has
not rechecked the data. `busy` means a workflow owns the nonblocking lock; it is
not evidence that the kernel mount is already ready. Recovery verifies identity,
replays sealed transactions, cleans orphans, checks the filesystem and returns to
`ready`. A crash or interrupted foreground process leaves an explicit recovery
requirement; mount refuses it until recovery completes. Mount also performs normal
transaction/integrity checks even when the last workflow phase was `ready`.

If a stale mount remains after a crash, run `unmount STATE` first. It detaches
normally, then reports that recovery is still needed. `recover` refuses an attached
old mount. Never force-delete state to get past an error. Failed initialization
retains partial files for diagnosis; if it stopped before a valid chain/device
manifest was sealed, choose a new state directory and retain the failed one rather
than treating it as a recoverable filesystem. This CLI does not repair arbitrary
metadata damage or silently adopt legacy experimental directories.

Linux admission waits up to 15 seconds for transient udev/device-busy races, retaining
all exclusive-claim and identity checks. A persistently busy target is refused.

Normal failures print a concise error; `--debug` adds a traceback; retain terminal output alongside `doctor`
and `status --json` when reporting a problem. No background daemon or launchd
service is installed. After an upgrade, keep all state and run recovery before
remounting an interrupted volume. Unknown state format versions are refused.
Uninstalling the package leaves your images and recovery directories untouched;
recover and cleanly unmount devices **before** uninstalling their recovery tools.

## Remaining engine and platform limits

See [ENGINE.md](README.md) in source (installed as ENGINE.md) for supported ext4
profiles, resource limits, ACL mappings and transaction guarantees. New writes use
our external redo format, not native JBD2. On the tested macFUSE version, durable
mapped writes require `msync(MS_SYNC)` followed by `fsync()` to observe write errors.
Native macOS hole-punch argument forwarding, contiguous preallocation and FIFO/
device-node I/O remain limited/deferred. The packaged command does not enable host
device-node I/O or multi-user mounts. It exposes no arbitrary FUSE option passthrough.

## Durability qualification

The installed [DURABILITY.md](DURABILITY.md) describes the mixed-workload,
I/O-error, concurrent mounted-writer and simulated device-cache-loss campaigns,
their acceptance rules, reproducible commands and the remaining hardware/host
power-loss qualification. Software test success alone is not power-loss certification.

## Integrity-tree storage and scan costs

The old 4 TiB hash-cache ceiling is removed. Oversized trees use a private,
unlinked temporary node file with a bounded 256 MiB main page cache and small
bounded authentication metadata. Evicted hash pages are checked against recursive
checksum tables anchored in RAM, including checks of the checksum pages themselves. The existing hash
format and recovery logs are unchanged. Hash-node storage is about 64–128 bytes
per MiB of volume capacity (8 TiB needs a 512 MiB node file); temporary storage,
filesystem geometry, transaction and OS limits still apply. Set `TMPDIR` before
launching to select writable temporary storage outside the mounted ext4 target. These files are disposable hashes, not a
persistent recovery index or a full-size data shadow. Preserve the recovery state,
not the temporary hashes. Running out of scratch space must fail the operation;
recovery can rebuild the tree after space returns.

Ordinary managed-image startup builds and validates one tree in one image pass,
including legacy digest migration. Dirty recovery retains its verified replay
tree instead of scanning the image again. Direct-mode clean admission likewise
shares its verified tree with the session. Live checkpoints validate the current
head, identity, fingerprint, root and guarded device publication without rereading
the whole volume. They retire history; they are **not full media scrubs**.

Packaged mounts reuse a persistent authenticated index after a clean close.
If it is absent, stale, damaged or interrupted, admission falls back to a full
integrity scan. Clean unmount reuses the live verified tree, checks filesystem
metadata through authenticated reads, and publishes a replacement index. Direct
mode retains exact readback of the changed guard sector. Metadata checks still
cost time; these changes do not promise constant-time mounting or unmounting.

Initialization, explicit recovery, standalone administrative checkpoints and
interrupted transaction recovery retain full integrity scans. The
`Session.scrub()` development API performs an explicit full audit while open;
for the installed command, unmount then `recover STATE` (with `--device` in direct
mode) performs cold verification. Silent corruption outside chunks read during a
warm session is detected by these full audits, not by every live checkpoint.

The scaling campaign compares complete synthetic paged and RAM trees, tests node
offsets for 8 TiB geometry, and measures real 32 MiB image/virtual-device scans.
It does not claim a complete multi-terabyte filesystem or physical-device test.
The persistent index stores 32 bytes per 1 MiB chunk (about 32 MiB per TiB), plus
a 4 KiB header, in the off-volume state directory. Loading reads the index and
rebuilds its entire tree against the independently recorded committed root;
index checksums or a root claimed by the index itself never grant trust. Old
index formats and recovery state remain readable through the full-scan fallback.
Temporary tree storage remains separate, bounded and disposable.

The index is an optional acceleration, not recovery authority: snapshots are
atomically replaced only at clean heads. A crash during publication leaves an
old complete snapshot, a new complete snapshot, or a cache miss. Pending writes
always follow full-scan redo recovery. Index-space exhaustion preserves recovery
and costs performance; it must not discard redo or accept an incomplete index.

A fast mount/unmount is **not a full media scrub**. Data and metadata consumed by
native helpers are verified against the committed root. Invisible corruption in
untouched chunks is detected when read or by explicit recovery/scrub, rather
than necessarily at every unmount. Run `recover STATE` periodically while
unmounted (add `--device DEVICE` for device mode) for a complete media audit.
Ordinary external image edits invalidate the fingerprint. Device fingerprints
cannot prove no offline edits: authenticated reads enforce the saved root. If
Linux or another writer changed the volume, the old state does not authorize
adopting those bytes; recover detects/refuses that mismatch. Reinitialize into
new off-volume state after a legitimate external change, preserving old state
until any interrupted writes have been resolved.

## USB progress, cancellation and disconnecting

Initialization, recovery and mounts needing a scan show full-volume read progress on stderr,
including percentage, bytes read and read throughput. Hash construction and
metadata checks are separate stages; 100% read does not mean the device is ready
to disconnect. Progress does not change machine-readable `status --json` output.

Use `ext4fuse-writer unmount STATE` from another terminal. It retries a brief busy
mount normally, then waits up to one hour for verification and clean publication.
Close applications and terminals using the mount if it stays busy. `--timeout`
can choose a wait up to 86400 seconds. A timeout does not cancel the writer:
keep the USB connected, check the original mount terminal and retry unmount.

Only a successful device unmount reports “Safe to disconnect this volume”. Other
partitions on the same USB device must also be unused/unmounted before physically
unplugging it; the writer does not eject them or select a whole disk automatically.
Keep the durable recovery directory on the Mac even after clean unmount.

Ctrl-C cancels a foreground check. It does not promise a clean device: retain the
entire state directory, keep the USB attached, detach a remaining mount normally
and run `recover STATE --device DEVICE`. An interrupted initialization may be
incomplete; inspect status and preserve it as described above. Never delete state
or use a second filesystem writer to bypass recovery. Avoid repeatedly interrupting
cleanup. No progress output or cancellation path declares a failed check safe.


## Remembered USB volumes and background mounting

Initialize the explicitly selected offline ext4 partition once using `init` as
above. Then remember its existing recovery state and desired mountpoint:

```sh
ext4fuse-writer volume add linux-usb --state /path/to/usb-state --mountpoint "$HOME/Volumes/linux-usb"
ext4fuse-writer volume mount linux-usb
ext4fuse-writer volume list
ext4fuse-writer volume eject linux-usb
```

`add` creates an empty mountpoint if necessary. It never formats, initializes,
opens or chooses a physical disk. It binds the private state directory, managed
image/token identity and mountpoint identity. A profile cannot silently be
rebound to replacement state or an unrelated device. Names are unique without
case distinctions and contain letters, digits, underscores or hyphens.

`mount` discovers the saved hardware serial plus GPT partition UUID, size and
sector geometry, not a remembered `/dev/diskN` number or a volume label. Owned
disk images/loop test devices use their saved backing-file identity. Disconnected,
ambiguous or changed devices refuse admission. Every discovered device still goes
through the existing system-disk, offline, off-device-state and exclusive-claim
checks. It does not unmount other partitions to make admission succeed.

The writer runs in a background process for this explicit command only; no login
service, automatic drive watcher or privilege helper is installed. The parent
hands its locked writer descriptor directly to the child. Success requires the
child frontend's private successful-mount acknowledgement and visible kernel
attachment, so a competing FUSE mount or a lost startup lock cannot claim
readiness. Progress and diagnostics are in `STATE/volume-mount.log` (private and
append-only). `--timeout` limits the readiness wait, not the lifetime of the
background writer. Cancelling/timing out the wait leaves a starting writer alive;
inspect `volume list` and the log, then `volume unmount NAME` normally.

Use `volume unmount NAME` to leave the device connected. It waits for normal
unmount and checked clean publication, including a mount that is still starting.
Busy open files/cwds refuse unmount; no force-unmount is used. An already clean
unmounted volume is an idempotent success. `volume eject NAME` performs that
unmount, waits for all writer checks, reacquires the writer lock and checks the
saved device binding, clean guard state, all sibling mounts and canonical raw
device users. It then releases its own device claims and requests ordinary OS
ejection/power-off, retaining writer-lock throughout. Identity is rechecked before
the OS request; macOS physical targets use their GPT UUID rather than a cached
BSD number. No force option is used. Another mounted sibling/raw user, insufficient
audit permission, wrong device or OS refusal leaves state retained and prints no
successful-ejection confirmation. Previously clean devices can also be ejected
without mounting them again. Ejection affects the containing drive, so all other
partitions must be unused.

macOS uses normal `diskutil eject` (owned test images use `hdiutil detach`). Linux
physical USB power-off requires `udisksctl` from udisks2 and a matching stable
`/dev/disk/by-partuuid` link; missing tooling/authorization refuses the request.
Disposable loop devices use checked normal detach. These virtual-device tests
are not physical USB unplug or power-loss certification.

After interruption, detach a remaining stale attachment with `volume unmount NAME`
(which may report that recovery is required), then run:

```sh
ext4fuse-writer volume recover linux-usb
ext4fuse-writer volume mount linux-usb
```

Recovery still scans fully and never accepts a changed device as a new baseline.
`volume list --json` is a fast metadata snapshot, not an integrity check or device
open. Add `--connected` for read-only device inventory. `volume forget NAME`
removes only a clean, unmounted profile; it never deletes recovery state or data.
Old explicit `mount STATE MOUNTPOINT --device DEVICE`, `unmount STATE` and recovery
commands remain available.

Profiles live in `~/Library/Application Support/ext4fuse-writer/volumes` on macOS
and `~/.config/ext4fuse-writer/volumes` on Linux, with owner-only permissions. To
choose another private registry, put `--profiles-dir PATH` immediately after
`volume` on every command. Run all commands as the same owner as initialization;
if raw-device permissions required sudo, use that same privileged owner and its
registry (or explicitly select the same private registry). No automatic sudo,
permission changes or cross-user mounting is performed. Keep profiles and recovery
state outside the target mount/drive. Preserve recovery state even after ejection
or forgetting a profile.


## Current progress and watching status

```sh
ext4fuse-writer volume status linux-usb
ext4fuse-writer volume status linux-usb --watch
# Explicit state paths work too:
ext4fuse-writer status /path/to/state --watch
```

Status distinguishes starting, mounted, checking before clean unmount, recovering,
initializing and recovery needed. Named background mount waits now echo the latest
startup stage directly; normal unmount waits show the writer's current check.
Full-volume read stages report percentage and throughput; metadata checks do not
invent a percentage. Progress includes elapsed time at each recorded update.
`--interval` sets the watch refresh period (0.2..60 seconds, default 1). Only changed
snapshots are printed. Ctrl-C stops this observer without stopping the writer.
`--json --watch` emits one complete JSON document per changed snapshot.

The JSON status fields remain available, with additive `status`, `progress` and
`progress_current` fields. Progress records are bounded, private, atomic,
best-effort observations, separate from durable recovery state. Missing, malformed,
old or unwritable progress cannot authorize mounting, recovery or unplugging.
A finished record is historical; `checked` remains false for status itself. A
status snapshot can race with a workflow transition. Use successful checked
unmount/eject, rather than status or a progress percentage, before disconnecting.
The small `writer-progress` file may be lost without losing recovery authority.

## Representative performance measurements

The source benchmark accepts only a work directory and an installed runtime. It
creates disposable 512 MiB regular images, never discovers or opens a physical disk:

```sh
python3 experimental/shared-writer/benchmark-workflows.py \
  --work /private/tmp/ext4-benchmark --prefix "$(brew --prefix ext4fuse-writer)"
```

Defaults are three measured rounds per classic 1 KiB and checksum-enabled extent
4 KiB layout, 32 MiB sequential files, and 128 individually fsynced 4 KiB small
files per round. Results include one initialization and one admission without an integrity
index per layout, plus repeated warm indexed mounts, checked unmounts, sequential write+fsync/read, small-file
creation+fsync, three directory list/stat passes, and rename/read/unlink. Identical
application file calls on the work directory's host filesystem provide context.
Each ext4 run independently checks final e2fsck cleanliness and debugfs file bytes,
and verifies that the seed image was unchanged. Timing has no universal pass bar.

`workflow-benchmarks.json` retains all samples, medians, ranges, stage observations,
configuration and host details. These are host-cache-warm measurements: no OS cache
is evicted, and removing an optional index does not simulate cold USB hardware.
Metadata-check stage times are observations, not a profiler of every engine path.
Use the same arguments and a quiet host when comparing versions; real USB throughput,
large populated filesystems and hardware durability require separate measurements.
CI runs a smaller correctness workload. Failed runs retain state and mounts for
normal inspection/recovery; the benchmark never force-unmounts or deletes them.
