#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Installed direct-device workflow on disposable hdiutil/loop devices only."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import journal_fixtures
from mount_state import attached

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--prefix', type=Path, required=True)
a = p.parse_args()
cli = a.prefix / 'bin' / 'ext4fuse-writer'
checks = 0


def check(condition, detail='device workflow check failed'):
    global checks
    assert condition, detail
    checks += 1


def run(argv, expected=0):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=180)
    check(result.returncode == expected, repr((argv, result.returncode, result.stdout, result.stderr)))
    return result.stdout


def mount_start(state, mount, device, logpath):
    with logpath.open('ab') as log:
        child = subprocess.Popen([cli, 'mount', state, mount, '--device', device], stdout=log, stderr=log)
    deadline = time.monotonic() + 30
    while not attached(mount):
        check(child.poll() is None, logpath.read_text())
        if time.monotonic() >= deadline: raise TimeoutError(logpath.read_text())
        time.sleep(.1)
    return child


tmp = Path(tempfile.mkdtemp(prefix='package-device-', dir=a.work))
seed = tmp / 'source.img'
with seed.open('xb') as stream: stream.truncate(32 * 1024**2)
run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', '-O', '^orphan_file', seed])
run(['debugfs', '-w', '-R', f'set_inode_field / uid {os.getuid()}', seed])
run(['debugfs', '-w', '-R', f'set_inode_field / gid {os.getgid()}', seed])
payload = tmp / 'seed-data'; payload.write_bytes(bytes(range(256)) * 48)
run(['debugfs', '-w', '-R', f'write {payload} /existing-file', seed])
# This also exercises installed executable Python journal producers and their imports.
dirty = tmp / 'dirty.img'
fixture = journal_fixtures.create(seed, dirty)
unchanged = journal_fixtures.sha(dirty)
run([cli, 'init', '--image', dirty, tmp / 'dirty-image', '--recover-journal'])
check(journal_fixtures.sha(dirty) == unchanged)
check(run(['debugfs', '-R', 'cat /existing-file', tmp / 'dirty-image' / 'chain' / 'image.img']) == fixture['new'])
run(['e2fsck', '-fn', tmp / 'dirty-image' / 'chain' / 'image.img'])

device = None
process = None
mount = tmp / 'mount'; mount.mkdir()
state = tmp / 'state'
log = tmp / 'mount.log'
try:
    if sys.platform == 'darwin':
        info = plistlib.loads(run(['hdiutil', 'attach', '-nomount', '-imagekey', 'diskimage-class=CRawDiskImage', '-plist', dirty]))
        device = min((entry['dev-entry'] for entry in info['system-entities'] if 'dev-entry' in entry), key=len)
    else:
        device = run(['losetup', '--find', '--show', dirty]).decode().strip()
        if shutil.which('udevadm'): run(['udevadm', 'settle', '--timeout=15'])
    run([cli, '--debug', 'init', '--device', device, state, '--recover-journal'])
    check(json.loads(run([cli, 'status', state, '--json']))['phase'] == 'ready')
    run(['e2fsck', '-fn', device])
    check(run(['debugfs', '-R', 'cat /existing-file', device]) == fixture['new'])
    run([cli, 'mount', state, mount], expected=1)
    run([cli, 'recover', state], expected=1)
    process = mount_start(state, mount, device, log)
    (mount / 'persisted').write_bytes(b'installed direct writer')
    fd = os.open(mount / 'persisted', os.O_RDWR)
    try: os.fsync(fd)
    finally: os.close(fd)
    check(b'Safe to disconnect this volume' in run([cli, 'unmount', state]))
    check(process.wait(timeout=60) == 0, log.read_text()); process = None
    check(run(['debugfs', '-R', 'cat /persisted', device]) == b'installed direct writer')
    run(['e2fsck', '-fn', device])
    # Kill the launcher after acknowledged physical writes; its persistent guard must survive.
    process = mount_start(state, mount, device, log)
    (mount / 'survived').write_bytes(b'acknowledged before launcher loss')
    process.kill(); process.wait(timeout=30); process = None
    with dirty.open('rb') as stream:
        stream.seek(1080); check(stream.read(2) == bytes(2), 'device was not guarded')
    if sys.platform == 'darwin':
        run([cli, 'recover', state, '--device', device], expected=1)
    check(b'Safe to disconnect' not in run([cli, 'unmount', state], expected=1))
    check(not attached(mount))
    run([cli, 'mount', state, mount, '--device', device], expected=1)
    run([cli, 'recover', state, '--device', device])
    check(json.loads(run([cli, 'status', state, '--json']))['phase'] == 'ready')
    with dirty.open('rb') as stream:
        stream.seek(1080); check(stream.read(2) == b'\x53\xef', 'clean magic not restored')
    check(run(['debugfs', '-R', 'cat /survived', device]) == b'acknowledged before launcher loss')
    run(['e2fsck', '-fn', device])
    check(not (state / 'control.sock').exists(), 'stale device control socket survived')
    process = mount_start(state, mount, device, log)
    check((mount / 'survived').read_bytes() == b'acknowledged before launcher loss')
    check(b'Safe to disconnect this volume' in run([cli, 'unmount', state]))
    check(process.wait(timeout=60) == 0, log.read_text()); process = None
    # Sparse token must not silently become a full data shadow.
    check((state / 'device' / 'chain' / 'image.img').stat().st_blocks == 0)
finally:
    if attached(mount):
        subprocess.run(['/sbin/umount', str(mount)] if sys.platform == 'darwin' else ['fusermount3', '-u', str(mount)], timeout=30)
    if process is not None and process.poll() is None:
        process.terminate(); process.wait(timeout=30)
    if log.exists():
        shutil.copyfile(log, a.work / 'packaging-device-mount.log')
    if device:
        run(['hdiutil', 'detach', device] if sys.platform == 'darwin' else ['losetup', '--detach', device])

report = dict(passed=True, checks=checks, platform=sys.platform, retained=str(tmp))
(a.work / 'packaging-device-results.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
