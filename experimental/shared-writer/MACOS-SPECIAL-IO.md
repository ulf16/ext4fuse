# macOS FIFO and device I/O investigation

Tested on Intel macOS Sequoia with macFUSE 5.4.0. No installed kernel software or
system settings were changed; probes used disposable images and were unmounted.

## Observed failure boundaries

| Probe | Result | Boundary established |
| --- | --- | --- |
| FIFO, ordinary private mount | EPERM | No FUSE open request reached the broker. |
| FIFO, uid 0 and explicit dev mount | EPERM | Root and dev did not fix open. |
| Character node copied from host null device, ordinary mount | ENXIO | FUSE OPEN reached LowBroker; our reader command 39 rejected the special inode. |
| Copied host-null node, uid 0 and explicit dev mount | ENXIO | The earlier root probe did not bypass that reader rejection. |
| Isolated character-node stub accepting FUSE OPEN on an ordinary private mount | Open and fstat succeeded; read/write returned EPERM | Neither FUSE READ nor FUSE WRITE reached the stub. A userspace open grant alone did not provide I/O. |

The temporary stub implemented only empty reads and discarded writes. It never
opened a host device and was not installed in production code. Its close syscall
also reported EBADF; it is a boundary experiment, not a valid device-handle
implementation. The accepted-open read/write experiment was unprivileged with
the usual nodev mount; it does not independently establish the post-open result
of a root dev mount. The original root dev probe stopped earlier at our ENXIO.

It was too broad to attribute the original character-device ENXIO entirely to
macFUSE. `handles.c` deliberately rejects special inodes, and the new trace
identified that exact userspace error. Removing it alone is not a demonstrated
fix: kernel-side transport still needs to be established.

## What native FIFO support requires

The [historical kernel open implementation](https://github.com/osxfuse/kext/blob/534773bd3135f04b7f6fb801faa2f8991daf4a6b/osxfuse/fuse_vnops.c)
returns EPERM for FIFO vnodes when M_OSXFUSE_ENABLE_FIFOFS is disabled. Its generic
read path also rejects non-regular, non-directory nodes. Historical
[fuse_node.c](https://github.com/osxfuse/kext/blob/534773bd3135f04b7f6fb801faa2f8991daf4a6b/osxfuse/fuse_node.c)
contains conditional selection of FIFO and special-device vnode operation tables.
These are historical architectural evidence, not proof of the exact flags in
the closed 5.4.0 kernel binary. Current runtime callback traces establish the
failure boundaries above.

A proper FIFO implementation needs the kernel backend to create functioning FIFO
vnodes and route operations through FIFO machinery: blocking/nonblocking opens,
PIPE_BUF atomicity, concurrent readers/writers, EOF and SIGPIPE, interruption,
poll/select/kqueue, and close/reclaim. Metadata, ACL checks, hard-link identity and
open-after-unlink lifetime must stay integrated with the filesystem. Returning a
regular file or a symlink to a temporary host pipe changes those semantics.

There is no userspace init feature flag for this in our installed FUSE 3 headers.
Adding a broker buffer cannot fix an open that the kernel refuses to forward.

## What native device support requires

For normal local-device semantics, the kernel backend must create character and
block special vnodes with a correct host rdev and dispatch to the host device
operations (the historical SPECFS branch). That includes open/close, read/write,
applicable ioctl and readiness operations, and block-device strategy behavior.
The nodev option, private-mount ownership and mode/ACL enforcement must remain
correct. Stored Linux major/minor values are not a portable driver mapping.

Our regular-file grants must continue rejecting device inodes. With genuine
native special-vnode support, data I/O would belong to the host kernel, as on
Linux; ext4 transactions would manage the device inode's metadata only.

An alternative userspace device proxy would be a separate feature: authorized
host-FD selection, a distinct handle type, stream versus seekable behavior,
partial I/O, nonblocking operation/cancellation, supported ioctl translation and
readiness/lifetime handling. It first needs a successful kernel transport spike
on an explicit root dev mount. The present null stub is not such a proxy, and
merely returning success from OPEN is insufficient.

## Practical paths

1. Obtain support in the maintained macFUSE kernel backend. Prepare a minimal
   reproducible vnode test and request FIFO/SPECFS support or clarification from
   its maintainer. No issue or external message was sent by this investigation.
2. A separate native kernel backend is technically another route, but requires
   current macOS integration, testing and kernel-extension distribution. The old
   source is not a current Sequoia build with two switches to enable.
3. FSKit is worth an isolated capability experiment, not an assumed fix.
   [Apple exposes FIFO, character and block item types](https://developer.apple.com/documentation/fskit/fsitem/itemtype?language=objc),
   but the enum does not demonstrate operational IPC or driver dispatch.
   [macFUSE documents FSKit bridge limits](https://github.com/macfuse/macfuse/wiki/FUSE-Backends),
   including missing request context and notifications. Our authenticated caller
   policy and explicit cache invalidation depend on those facilities, so changing
   only the mount backend would require a separate compatibility/security audit.

The maintained [macFUSE kernel extension is closed source](https://github.com/macfuse/macfuse#source-code).
We can adjust our frontend and provide reproducible tests; we cannot rebuild and
patch the installed current kernel backend from this repository.

## Validation needed before claiming support

Native FIFO tests must exercise blocking and nonblocking behavior, interruption,
readiness, permissions/ACLs and retained identities across unlink. Device tests
should start with an explicitly authorized host-null node, verify native syscall
routing and nodev rejection, then test supported ioctl/readiness behavior before
any broader device support claim. Linux device-I/O validation remains separate.
