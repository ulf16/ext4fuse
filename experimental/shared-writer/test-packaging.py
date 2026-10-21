#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Installed runtime workflows on disposable images, including real mounts/recovery."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--prefix', type=Path, help='test an already installed package instead of a temporary installation')
p.add_argument('--mount', action='store_true')
a = p.parse_args()
checks = 0
sys.path.insert(0, str(HERE))
from mount_state import attached


def check(condition, message='check failed'):
    global checks
    assert condition, message
    checks += 1


def run(argv, expected=0, **kw):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=180, **kw)
    check(result.returncode == expected, repr((argv, result.returncode, result.stdout, result.stderr)))
    return result


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


# Never automatically delete this work tree: failed mounts must retain their state.
tmp = Path(tempfile.mkdtemp(prefix='package-workflow-', dir=a.work))
prefix = a.prefix or tmp / 'installed package'
if not a.prefix:
    run([sys.executable, HERE / 'install.py', '--prefix', prefix, '--build-dir', a.work,
         '--python', sys.executable, '--version', '0.3.0-beta.9', '--tools-dir', Path(shutil.which('e2fsck')).parent])
cli = prefix / 'bin' / 'ext4fuse-writer'
lib = prefix / 'libexec' / 'ext4fuse-writer'
check((lib / 'native' / 'reader-server').is_file())
check(not (lib / 'test-mounted-writer.py').exists())
check({p.name for p in (lib / 'native').iterdir()} == {
    'mutation-producer', 'reader-server', 'mount-frontend', 'metadata-snapshot', 'journal-candidate'})
check('ext4fuse-writer ' in run([cli, '--version']).stdout.decode())
check(json.loads(run([cli, 'doctor']).stdout)['runtime'] == str(lib / 'native'))
check('state' in run([cli, 'mount', '--help']).stdout.decode())
# Isolated launch ignores injected Python module paths and current-directory modules.
poison = tmp / 'poison'; poison.mkdir()
(poison / 'session.py').write_text('raise RuntimeError("poisoned import")\n')
run([cli, 'doctor'], cwd=poison, env=dict(os.environ, PYTHONPATH=str(poison)))

seed = tmp / 'source.img'
with seed.open('xb') as stream:
    stream.truncate(32 * 1024**2)
run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', seed])
run(['debugfs', '-w', '-R', f'set_inode_field / uid {os.getuid()}', seed])
run(['debugfs', '-w', '-R', f'set_inode_field / gid {os.getgid()}', seed])
original = digest(seed)
state = tmp / 'state'
run([cli, 'init', '--image', seed, state])
check(digest(seed) == original, 'source edited')
check(digest(state / 'chain' / 'image.img') == original, 'clone edited')
meta = lambda: json.loads(run([cli, 'status', state, '--json']).stdout)
check(meta()['phase'] == 'ready')
# Status is read-only, including its workflow lock.
def snapshot():
    return {str(p.relative_to(state)): (p.stat().st_size, p.stat().st_mtime_ns, digest(p))
            for p in state.rglob('*') if p.is_file()}
before = snapshot(); meta(); check(before == snapshot(), 'status changed state')
verified = run([cli, 'recover', state])
check(b'Checking volume integrity: 0%' in verified.stderr)
check(b'validating hash tree' in verified.stderr)
check(b'Safe to disconnect' not in verified.stdout)
check(meta()['phase'] == 'ready')
# Cancel a real cold scan at its first progress notification. The process is
# observed by the parent before SIGINT; an unexpected successful exit fails.
# Use a larger disposable image so there is ample work after the notification.
cancel_source = tmp / 'cancel-source.img'
with cancel_source.open('xb') as stream:
    stream.truncate(512 * 1024**2)
run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', cancel_source])
cancel_state = tmp / 'cancel-state'
run([cli, 'init', '--image', cancel_source, cancel_state])
with (tmp / 'cancel.stdout').open('wb') as output:
    cancelled = subprocess.Popen([cli, 'recover', cancel_state], stdout=output, stderr=subprocess.PIPE)
    messages = []
    try:
        while True:
            line = cancelled.stderr.readline()
            check(bool(line), 'recovery exited before scan progress')
            messages.append(line)
            if b'Checking volume integrity: 0%' in line:
                cancelled.send_signal(signal.SIGINT)
                break
        tail = cancelled.communicate(timeout=60)[1]
        check(cancelled.returncode == 130, repr((messages, tail)))
        check(b'retain the entire state directory' in tail)
    finally:
        if cancelled.poll() is None:
            cancelled.kill(); cancelled.wait(timeout=30)
check(b'Safe to disconnect' not in (tmp / 'cancel.stdout').read_bytes())
cancel_meta = json.loads(run([cli, 'status', cancel_state, '--json']).stdout)
check(cancel_meta['needs_recovery'] and cancel_meta['phase'] == 'recovery-required')
run([cli, 'recover', cancel_state])
check(json.loads(run([cli, 'status', cancel_state, '--json']).stdout)['phase'] == 'ready')
run(['e2fsck', '-fn', cancel_state / 'chain' / 'image.img'])

run([cli, 'init', '--image', seed, state], expected=1)
run([cli, 'recover', state, '--device', '/dev/not-a-device'], expected=1)
check(meta()['phase'] == 'ready')
# Busy workflows must not replay or overwrite state; status remains available.
with (state / 'writer-lock').open('r+b') as locked:
    fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
    check(meta()['busy'])
    run([cli, 'recover', state], expected=1)
    check(meta()['phase'] == 'ready')

mount = tmp / 'mount'; mount.mkdir()
(mount / 'occupied').write_text('do not hide me')
run([cli, 'mount', state, mount], expected=1)
check(meta()['phase'] == 'ready', 'bad mountpoint changed state')
(mount / 'occupied').unlink()
# Simulate the durable mount intent left by an abruptly killed launcher.
intent = json.loads((state / 'writer-state').read_text())
intent.update(phase='mounting', mountpoint=str(mount))
(state / 'writer-state').write_text(json.dumps(intent))
run([cli, 'mount', state, mount], expected=1)
check(meta()['needs_recovery'])
run([cli, 'recover', state]); check(not meta()['needs_recovery'])

# Crash an installed Session during actual page replay, after its redo is sealed.
crasher = tmp / 'crash.py'
crasher.write_text('import sys\nfrom pathlib import Path\nsys.path.insert(0,' + repr(str(lib)) + ')\n'
    'import session\nfrom credentials import Credentials\n'
    'with session.Session(Path(sys.argv[1])/"chain", Path(sys.argv[2])/"mutation-producer", Path(sys.argv[2])/"reader-server", Credentials(__import__("os").getuid(),__import__("os").getgid())) as s:\n'
    ' s.mkdir("/replayed-after-crash",0o755)\n')
run([sys.executable, crasher, state, lib / 'native'], expected=77,
    env=dict(os.environ, EXT4_TEST_CRASH='half:0:0'))
run([cli, 'recover', state])
check('replayed-after-crash' in run(['debugfs', '-R', 'ls -p /', state / 'chain' / 'image.img']).stdout.decode())
run(['e2fsck', '-fn', state / 'chain' / 'image.img'])
# Refuse replaced locks and unknown state formats before mutation.
lockfile = state / 'writer-lock'
lockfile.rename(state / 'saved-lock'); lockfile.symlink_to(state / 'saved-lock')
run([cli, 'recover', state], expected=1)
lockfile.unlink(); (state / 'saved-lock').rename(lockfile)
(state / 'control.sock').write_text('unrelated file')
run([cli, 'recover', state], expected=1)
check((state / 'control.sock').read_text() == 'unrelated file')
(state / 'control.sock').unlink()
run([cli, 'recover', state])
manifest = (state / 'writer-state').read_text()
wrong = json.loads(manifest); wrong['version'] = 999
(state / 'writer-state').write_text(json.dumps(wrong))
run([cli, 'recover', state], expected=1)
(state / 'writer-state').write_text(manifest)

if a.mount:
    logfile = tmp / 'foreground.log'
    with logfile.open('wb') as log:
        process = subprocess.Popen([cli, 'mount', state, mount], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 30
        while not attached(mount):
            check(process.poll() is None, logfile.read_text())
            if time.monotonic() >= deadline: raise TimeoutError(logfile.read_text())
            time.sleep(.1)
        check(meta()['busy'] and meta()['mounted'])
        run([cli, 'recover', state], expected=1)
        # A process whose cwd is on the volume must prevent normal unmount.
        # Failure must leave the attachment and never print safe-disconnect.
        occupant = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
                                    cwd=mount, stdin=subprocess.PIPE)
        try:
            busy_result = run([cli, 'unmount', state, '--timeout', '.2'], expected=1)
            check(attached(mount), 'busy unmount detached a volume still in use')
            check(b'Safe to disconnect' not in busy_result.stdout)
        finally:
            occupant.communicate(timeout=30)
        (mount / 'written').write_bytes(b'installed writer\0durable\n')
        fd = os.open(mount / 'written', os.O_RDWR)
        try: os.fsync(fd)
        finally: os.close(fd)
        run([cli, 'allocate', state, '/written', '8192', '4096', '--mode', 'keep-size'])
        run([cli, 'allocate', state, '/written', '0', '1', '--mode', 'punch'])
        check((mount / 'written').read_bytes().startswith(b'\0nstalled writer'))
        run([cli, 'allocate', state, '/written', '-1', '1'], expected=1)
        (mount / 'written').write_bytes(b'installed writer\0durable\n')
        (mount / 'directory').mkdir(); (mount / 'directory' / 'nested').write_bytes(b'nested')
        os.rename(mount / 'written', mount / 'renamed')
        os.symlink('renamed', mount / 'link')
        check((mount / 'link').read_bytes() == b'installed writer\0durable\n')
        run([cli, 'unmount', state])
        check(process.wait(timeout=30) == 0, logfile.read_text())
        check(not attached(mount))
        check('Loading authenticated integrity index' in logfile.read_text())
        check('full-volume read' not in logfile.read_text(), 'clean mount/close scanned whole image')
        check(meta()['phase'] == 'ready' and not meta()['busy'])
        run(['e2fsck', '-fn', state / 'chain' / 'image.img'])
        check('installed writer' in run(['debugfs', '-R', 'cat /renamed', state / 'chain' / 'image.img']).stdout.decode())
        # Crash only the broker after mounting. Detach the leftover mount and require recovery.
        with logfile.open('ab') as log:
            process = subprocess.Popen([cli, 'mount', state, mount], stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while not attached(mount):
            check(process.poll() is None, logfile.read_text())
            if time.monotonic() >= deadline: raise TimeoutError(logfile.read_text())
            time.sleep(.1)
        (mount / 'before-kill').write_bytes(b'retained')
        process.kill(); process.wait(timeout=30)
        if sys.platform == 'darwin':
            run([cli, 'recover', state], expected=1)
        run([cli, 'unmount', state], expected=1)
        check(not attached(mount))
        check(meta()['needs_recovery'])
        run([cli, 'mount', state, mount], expected=1)
        run([cli, 'recover', state])
        check(meta()['phase'] == 'ready')
        run(['e2fsck', '-fn', state / 'chain' / 'image.img'])
        check(not (state / 'control.sock').exists(), 'stale control socket survived recovery')
        with logfile.open('ab') as log:
            process = subprocess.Popen([cli, 'mount', state, mount], stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while not attached(mount):
            check(process.poll() is None, logfile.read_text())
            if time.monotonic() >= deadline: raise TimeoutError(logfile.read_text())
            time.sleep(.1)
        check((mount / 'before-kill').read_bytes() == b'retained')
        run([cli, 'unmount', state])
        check(process.wait(timeout=30) == 0, logfile.read_text())
    finally:
        if attached(mount):
            subprocess.run(['/sbin/umount', str(mount)] if sys.platform == 'darwin' else ['fusermount3', '-u', str(mount)], timeout=30)
        if process.poll() is None:
            process.terminate(); process.wait(timeout=30)

check(digest(seed) == original)
report = dict(passed=True, checks=checks, mounted=a.mount, prefix=str(prefix), retained=str(tmp))
(a.work / 'packaging-results.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
