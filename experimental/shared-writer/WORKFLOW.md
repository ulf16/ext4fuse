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
  --version 0.3.0-beta.4
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

Cold recovery, standalone administrative checkpoints, and packaged clean close
still perform a full integrity audit. A direct clean close uses one such pass
plus metadata validation and exact readback of the changed guard sector. The
`Session.scrub()` development API performs an explicit full audit while open;
for the installed command, unmount then `recover STATE` (with `--device` in direct
mode) performs cold verification. Silent corruption outside chunks read during a
warm session is detected by these full audits, not by every live checkpoint.

The scaling campaign compares complete synthetic paged and RAM trees, tests node
offsets for 8 TiB geometry, and measures real 32 MiB image/virtual-device scans.
It does not claim a complete multi-terabyte filesystem or physical-device test.
Cold verification remains proportional to capacity; a durable authenticated index
with verified reads would be a separate integrity design.
