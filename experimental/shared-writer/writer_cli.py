#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Installable owner-only ext4 writer with explicit mount and recovery state."""
import argparse
import contextlib
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import time

# The installed launcher uses isolated Python; import only the adjacent runtime.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import chain
import inplace
import session
import progress
from mount_state import attached, mounts
from credentials import Credentials
from durable import directory, regular

FORMAT = 1
HELPERS = ('mutation-producer', 'reader-server', 'mount-frontend',
           'journal-candidate', 'metadata-snapshot')
PHASES = ('initializing', 'ready', 'mounting', 'recovering', 'recovery-required')


def load_json(path):
    with regular(path) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('state files must be private, owned and singly linked')
        raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError('oversized writer state')
        return json.loads(raw)


def root_path(path):
    root = inplace.block.canonical(path)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('state directory must be private and owned by this user')
    return root


def manifest(root):
    data = load_json(root / 'writer-state')
    if (not isinstance(data, dict) or set(data) != {'version', 'mode', 'phase', 'mountpoint'}
            or type(data['version']) is not int or data['version'] != FORMAT
            or data['mode'] not in ('image', 'direct') or data['phase'] not in PHASES
            or (data['mountpoint'] is not None and (not isinstance(data['mountpoint'], str)
                or not data['mountpoint'].startswith('/') or '\0' in data['mountpoint']))):
        raise ValueError('unsupported or damaged writer state')
    return data


def seal(root, data, phase, mountpoint=None):
    data = dict(data, phase=phase, mountpoint=str(mountpoint) if mountpoint else None)
    inplace.seal(root, 'writer-state', data)
    return data


@contextlib.contextmanager
def lock(root):
    fd = os.open(root / 'writer-lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError('unsafe writer lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def configuration():
    path = HERE / 'runtime.json'
    if not path.is_file():
        raise ValueError('writer runtime is not installed; run install.py first')
    data = json.loads(path.read_text())
    if data.get('format') != FORMAT:
        raise ValueError('unsupported installed writer runtime')
    tools = data['tools']
    if tools:
        # e2fsprogs is keg-only on macOS. sudo must not change tool selection.
        os.environ['PATH'] = tools + os.pathsep + os.environ.get('PATH', os.defpath)
    return data


def runtime():
    data = configuration()
    work = HERE / 'native'
    for name in HELPERS:
        if not (work / name).is_file() or not os.access(work / name, os.X_OK):
            raise ValueError('installed runtime helper is missing: ' + name)
    for name in ('e2fsck', 'debugfs'):
        if shutil.which(name) is None:
            raise ValueError(name + ' is required; reinstall the writer dependencies')
    return work, data


def broker_module():
    spec = importlib.util.spec_from_file_location('writer_mount_broker', HERE / 'mount-broker.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def credentials():
    mask = os.umask(0)
    os.umask(mask)
    return Credentials(os.getuid(), os.getgid(), tuple(os.getgroups()), mask)


def check_image(root):
    progress.stage('Checking filesystem metadata; keep the device connected...')
    import journal_recovery
    result, output = journal_recovery.command(
        [journal_recovery.tool('e2fsck'), '-fn', root / 'chain' / 'image.img'],
        dict(os.environ, LC_ALL='C', E2FSCK_CONFIG='/dev/null'))
    if result:
        raise ValueError('managed image failed read-only e2fsck: ' + output.decode(errors='replace')[-2048:])


def device_admission(call):
    # udev briefly opens newly attached Linux loop/physical nodes. Keep the same
    # explicit target and retain every existing identity/exclusive-claim check.
    deadline = time.monotonic() + 15
    announced = False
    while True:
        try:
            return call()
        except OSError as error:
            if (sys.platform != 'linux' or error.errno not in (errno.EAGAIN, errno.EBUSY)
                    or time.monotonic() >= deadline):
                raise
            if not announced:
                print('Waiting briefly for exclusive device admission...', file=sys.stderr, flush=True)
                announced = True
            time.sleep(.2)


def run_session(root, data, args, work, broker=None, mountpoint=None):
    chain_root = root / 'chain'
    options = dict(checkpoint_every=args.checkpoint_every if broker else 0, persistent_index=bool(broker))
    with contextlib.ExitStack() as stack:
        target = None
        if data['mode'] == 'direct':
            from direct_device import Controller
            progress.stage('Checking device identity and exclusive access...')
            target = device_admission(lambda: stack.enter_context(Controller(root / 'device', args.device, work,
                check_bytes=args.check_bytes, journal_bytes=args.journal_bytes, persistent_index=bool(broker))))
            chain_root = target.chain
            options['commit_sink'] = target
        else:
            options['recover_journal'] = args.recover_journal
        with session.Session(chain_root, work / 'mutation-producer', work / 'reader-server',
                             credentials(), **options) as opened:
            opened._mount_geometry()
            if broker:
                print('Mounting at ' + str(mountpoint) + '; use ext4fuse-writer unmount ' + str(root),
                      file=sys.stderr, flush=True)
                broker.run_mount(opened, work, mountpoint, root / 'control.sock')
            if opened._failed:
                raise OSError(errno.EIO, 'writer session failed; recovery is required')
        progress.stage('Finishing writes and verifying clean publication; keep the device connected...')
        if target:
            target.finish()
        else:
            # Includes orphan cleanup from Session.close. Authenticate metadata
            # snapshot reads as well as ordinary mounted reads on the fast path.
            import integrity_index
            with chain.locked(chain_root):
                current = chain.read_state(chain_root)
                cache = integrity_index.load(chain_root, current) if broker else None
                if broker and cache is not None:
                    import image_io
                    from direct_device import checked
                    from verified_reads import Reader
                    verifier = Reader(chain_root / 'image.img', lambda: (current, cache))
                    try:
                        with image_io.verified(chain_root / 'image.img', verifier):
                            checked(chain_root / 'image.img', None, work, root, args.check_bytes)
                    finally:
                        verifier.close()
                else:
                    check_image(root)
                chain.checkpoint_locked(chain_root, cache)


def require_device(data, args):
    if (data['mode'] == 'direct') != bool(args.device):
        raise ValueError('device state requires --device DEVICE on every mount/recover; image state forbids it')
    if data['mode'] == 'direct' and args.recover_journal:
        raise ValueError('--recover-journal applies to device initialization only; recover replays its sealed import')


def initialize(args):
    work, config = runtime()
    root = inplace.block.canonical(args.state)
    if root.exists() or root.is_symlink():
        raise FileExistsError('state already exists; choose a new directory or use status/recover')
    if args.image:
        source = args.image.resolve(strict=True)
        if source.is_relative_to(root):
            raise ValueError('source must be outside the state directory')
        # Refuse device nodes even before creating any state directory.
        with regular(source) as stream:
            if os.fstat(stream.fileno()).st_uid != os.getuid():
                raise ValueError('source image must be owned by launching user')
    root.mkdir(mode=0o700)
    directory(root.parent)
    fd = os.open(root / 'writer-lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    directory(root)
    data = dict(version=FORMAT, mode='image' if args.image else 'direct',
                phase='initializing', mountpoint=None)
    with lock(root):
        inplace.seal(root, 'writer-state', data)
        if args.image:
            progress.stage('Copying source image into private state...')
            chain.clone(source, root / 'chain')
            run_session(root, data, args, work)
        else:
            from direct_device import init
            def initialize_device():
                try:
                    return init(args.device, root / 'device', work, check_bytes=args.check_bytes,
                         recover_journal=args.recover_journal, journal_bytes=args.journal_bytes)
                except OSError as error:
                    # Only transient pre-admission failures may restart initialization.
                    if (root / 'device').exists() and error.errno in (errno.EAGAIN, errno.EBUSY):
                        raise ValueError('device initialization started; retain state and run recover') from error
                    raise
            device_admission(initialize_device)
            # A dirty native journal import is sealed but not yet published by init.
            run_session(root, data, argparse.Namespace(**dict(vars(args), recover_journal=False)), work)
        seal(root, data, 'ready')
    print('Ready: ' + str(root))
    if args.image:
        print('Writable image: ' + str(root / 'chain' / 'image.img') + ' (source unchanged)')


def cleanup_socket(root):
    path = root / 'control.sock'
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('control.sock is not an owned socket; retained for inspection')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(.2)
        try:
            probe.connect(str(path))
        except OSError as error:
            if error.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                raise
        else:
            raise OSError(errno.EBUSY, 'control socket still has a live listener')
    current = os.lstat(path)
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise ValueError('control socket changed during stale socket cleanup')
    path.unlink()
    directory(root)


def allocate(args):
    root = root_path(args.state)
    data = manifest(root)
    if data['phase'] != 'mounting' or not data['mountpoint'] or not attached(data['mountpoint']):
        raise ValueError('allocation requires an active writer mount')
    if not args.path.startswith('/') or '\0' in args.path or len(os.fsencode(args.path)) > 4096:
        raise ValueError('path must be absolute inside the mounted filesystem')
    if not 0 <= args.offset < 2**63 or not 0 < args.length <= 2**63 - 1 - args.offset:
        raise ValueError('invalid allocation range')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(120)
        client.connect(str(root / 'control.sock'))
        client.sendall(json.dumps(dict(operation=args.mode, path=args.path,
                        offset=args.offset, length=args.length)).encode() + b'\n')
        with client.makefile('rb') as stream:
            raw = stream.readline(4097)
        if len(raw) > 4096 or not raw.endswith(b'\n'):
            raise ValueError('invalid allocation reply')
        reply = json.loads(raw)
        if not isinstance(reply, dict) or type(reply.get('error')) is not int:
            raise ValueError('invalid allocation result')
        if reply['error']:
            raise OSError(reply['error'], reply.get('message', 'allocation failed'))
        print(json.dumps(reply, sort_keys=True))


def operate(args, mounting):
    work, config = runtime()
    root = root_path(args.state)
    with lock(root):
        data = manifest(root)
        require_device(data, args)
        old_mount = data['mountpoint']
        if old_mount and attached(old_mount):
            raise OSError(errno.EBUSY, 'previous mount is still attached; unmount it before recovery')
        if mounting and data['phase'] != 'ready':
            raise ValueError('unclean or incomplete state; run recover before mounting')
        broker = broker_module() if mounting else None
        mountpoint = None
        if mounting:
            requested = args.mountpoint.parent.resolve() / args.mountpoint.name
            if attached(requested):
                raise OSError(errno.EBUSY, 'mountpoint is already attached')
            _, work, mountpoint = broker.validate_mount(root, work, args.mountpoint)
        cleanup_socket(root)
        if mounting and len(os.fsencode(root / 'control.sock')) >= (104 if sys.platform == 'darwin' else 108):
            raise ValueError('state path is too long for a control socket; use a shorter durable state path')
        data = seal(root, data, 'mounting' if mounting else 'recovering', mountpoint)
        try:
            run_session(root, data, args, work, broker, mountpoint)
        except BaseException:
            # Preserve mount intent: a remaining attachment must be removed before replay.
            seal(root, data, 'recovery-required', mountpoint)
            raise
        seal(root, data, 'ready')
    print('Cleanly unmounted and checked.' if mounting else 'Recovered, checked and ready.')


def status(args):
    root = root_path(args.state)
    # No recovery, image reads, directory creation, or device opens in status.
    try:
        with lock(root):
            data = manifest(root)
            busy = False
    except BlockingIOError:
        data = manifest(root)
        busy = True
    result = dict(data, state=str(root), busy=busy, checked=False,
                  mounted=bool(data['mountpoint'] and attached(data['mountpoint'])))
    result['needs_recovery'] = not busy and (data['phase'] != 'ready' or result['mounted'])
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print('State: ' + str(root))
        print('Mode: ' + data['mode'] + '; phase: ' + data['phase'] + (' (in use)' if busy else ''))
        if data['mountpoint']:
            print('Mountpoint: ' + data['mountpoint'] + (' (attached)' if result['mounted'] else ' (detached)'))
        if result['needs_recovery']:
            print('Recovery required before mounting. Keep this entire state directory.')
        print('Metadata status only; recover performs integrity verification.')


def unmount(args):
    root = root_path(args.state)
    data = manifest(root)
    mountpoint = data['mountpoint']
    if not mountpoint:
        raise ValueError('no recorded mount; use status or recover')
    if attached(mountpoint):
        fstype, source = mounts()[mountpoint]
        if source != 'ext4fuse-experimental':
            raise ValueError('recorded mountpoint contains another filesystem; refusing to unmount it')
        command = ['/sbin/umount', mountpoint] if sys.platform == 'darwin' else [
            shutil.which('fusermount3') or 'fusermount3', '-u', mountpoint]
        # macFUSE may briefly retain the last vnode after an application closes
        # it. Retry normal detach, never force-unmount or bypass an open file.
        detach_deadline = time.monotonic() + min(5, args.timeout)
        while True:
            if not attached(mountpoint):
                break
            if mounts().get(mountpoint, (None, None))[1] != 'ext4fuse-experimental':
                raise ValueError('mountpoint changed filesystems; refusing to unmount it')
            result = subprocess.run(command, capture_output=True, check=False)
            if not result.returncode or not attached(mountpoint):
                break
            if time.monotonic() >= detach_deadline:
                raise OSError(errno.EBUSY, 'volume is still busy. Close files and terminals using it, then retry unmount. Keep the device connected.')
            progress.stage('Volume is busy; waiting briefly for open files to close...')
            time.sleep(.5)
    deadline = time.monotonic() + args.timeout
    last_notice = 0
    while True:
        try:
            with lock(root):
                current = manifest(root)
                if current['mountpoint'] or attached(mountpoint):
                    raise ValueError('attachment still recorded; run status and recover before disconnecting')
                if current['phase'] != 'ready':
                    raise ValueError('mount detached; run recover to verify retained state')
                print('Unmounted; recovery state is ready.')
                if current['mode'] == 'direct':
                    print('Writer finished all checks. Safe to disconnect this volume, provided no other partition on the USB device is in use.')
                return
        except BlockingIOError:
            now = time.monotonic()
            if now - last_notice >= 5:
                progress.stage('Mount detached; waiting for writer checks. Keep the device connected. Progress is shown in the mount terminal.')
                last_notice = now
            if now >= deadline:
                raise TimeoutError('mount detached; writer is still finishing checks; inspect status before unplugging')
            time.sleep(.1)


def parser():
    p = argparse.ArgumentParser(prog='ext4fuse-writer', description=__doc__)
    p.add_argument('--version', action='store_true')
    p.add_argument('--debug', action='store_true', help='include a traceback with failure diagnostics')
    sub = p.add_subparsers(dest='action')
    init = sub.add_parser('init', help='initialize a private image copy or an explicit offline device')
    source = init.add_mutually_exclusive_group(required=True)
    source.add_argument('--image', type=Path)
    source.add_argument('--device')
    init.add_argument('state', type=Path, help='new durable recovery directory; never inside the mounted volume')
    mount = sub.add_parser('mount', help='mount in foreground; use unmount from another terminal')
    recover = sub.add_parser('recover', help='replay retained transactions, check integrity and prepare for mounting')
    for command in (mount, recover):
        command.add_argument('state', type=Path)
        command.add_argument('--device', help='required for device state; identity must match initialization')
    mount.add_argument('mountpoint', type=Path, help='existing empty directory owned by launching user')
    mount.add_argument('--checkpoint-every', type=int, default=64)
    for command in (init, mount, recover):
        command.add_argument('--recover-journal', action='store_true', help='explicitly replay a supported dirty Linux journal')
        command.add_argument('--check-bytes', type=int, default=1024**3, help='device metadata scratch budget (default 1 GiB)')
        command.add_argument('--journal-bytes', type=int, default=256*1024**2, help='native journal import budget (default 256 MiB)')
    inspect = sub.add_parser('status', help='inspect workflow metadata without replay or opening a device')
    inspect.add_argument('state', type=Path)
    inspect.add_argument('--json', action='store_true')
    stop = sub.add_parser('unmount', help='unmount normally and wait for checked clean publication')
    stop.add_argument('state', type=Path)
    stop.add_argument('--timeout', type=float, default=3600)
    allocation = sub.add_parser('allocate', help='allocate or punch a mounted file through authenticated control')
    allocation.add_argument('state', type=Path)
    allocation.add_argument('path', help='absolute path within the ext4 filesystem')
    allocation.add_argument('offset', type=int)
    allocation.add_argument('length', type=int)
    allocation.add_argument('--mode', choices=('allocate', 'keep-size', 'punch'), default='allocate')
    sub.add_parser('doctor', help='report installed runtime and dependency paths')
    return p


def main():
    p = parser()
    args = p.parse_args()
    # Test fault injection and inherited device descriptors never enter installed commands.
    os.environ.pop('EXT4_TEST_CRASH', None)
    os.environ.pop('EXT4_DEVICE_VIEW', None)
    try:
        if args.version:
            print('ext4fuse-writer ' + configuration()['version'])
        elif args.action == 'init':
            initialize(args)
        elif args.action in ('mount', 'recover'):
            if args.action == 'mount' and not 0 <= args.checkpoint_every <= 1_000_000:
                raise ValueError('checkpoint interval must be 0..1000000')
            operate(args, args.action == 'mount')
        elif args.action == 'status':
            status(args)
        elif args.action == 'unmount':
            if not 0 < args.timeout <= 86400:
                raise ValueError('unmount timeout must be greater than 0 and at most 86400 seconds')
            unmount(args)
        elif args.action == 'allocate':
            allocate(args)
        elif args.action == 'doctor':
            work, config = runtime()
            print(json.dumps(dict(version=config['version'], python=sys.executable, runtime=str(work),
                  e2fsck=shutil.which('e2fsck'), debugfs=shutil.which('debugfs'), platform=sys.platform), sort_keys=True))
        else:
            p.print_help()
            return 2
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if args.debug:
            import traceback
            traceback.print_exc()
        print('ext4fuse-writer: ' + str(error), file=sys.stderr)
        if args.action in ('init', 'mount', 'recover'):
            print('State retained. Inspect status; do not delete recovery files or run another writer.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('ext4fuse-writer: cancelled. Keep the device connected and retain the entire state directory. Unmount any remaining attachment, then run recover with the same state (and matching --device for device state).', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    with progress.reporting():
        raise SystemExit(main())
