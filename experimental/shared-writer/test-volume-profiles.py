#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private profiles, background lock/readiness, busy refusal and stable rediscovery."""
import argparse
import errno
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch, Mock

import volume_profiles as profiles
from mount_state import attached

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True)
p.add_argument('--prefix',type=Path,required=True)
p.add_argument('--devices',action='store_true')
a=p.parse_args();checks=0
base=Path(tempfile.mkdtemp(prefix='volumes-',dir=a.work));registry=base/'profiles'
cli=a.prefix/'bin/ext4fuse-writer'
volume=[cli,'volume','--profiles-dir',registry]


def check(value,detail='profile check failed'):
    global checks
    assert value,detail;checks+=1


def run(argv,expected=0,timeout=180):
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout)
    check(result.returncode==expected,repr((argv,result.returncode,result.stdout,result.stderr)))
    return result


def denied(call):
    try:call()
    except (OSError,ValueError):check(True)
    else:raise AssertionError('unsafe profile/device accepted')


def status(state):return json.loads(run([cli,'status',state,'--json']).stdout)


def mount(name):
    result=run(volume+['mount',name])
    match=re.search(rb'background writer (\d+)',result.stdout)
    check(match is not None,result.stdout)
    return int(match[1])


# Resolution never relies on a remembered BSD/loop number or label. Ambiguous,
# missing and geometry-mismatched candidates refuse before any device admission.
identity=dict(kind='physical',serial='test-device',partition='test-partition')
profile=dict(binding=dict(identity=identity,size=32*1024**2,sector=512))
factory='mac_candidates' if sys.platform=='darwin' else 'linux_candidates'
with patch.object(profiles,factory,return_value=['/dev/new-name']),patch.object(profiles,'describe',return_value=(identity,32*1024**2,512)):
    check(profiles.resolve(profile)=='/dev/new-name')
with patch.object(profiles,factory,return_value=['/dev/a','/dev/b']),patch.object(profiles,'describe',return_value=(identity,32*1024**2,512)):
    denied(lambda:profiles.resolve(profile))
with patch.object(profiles,factory,return_value=['/dev/a']),patch.object(profiles,'describe',return_value=(dict(identity,serial='wrong'),32*1024**2,512)):
    denied(lambda:profiles.resolve(profile))
with patch.object(profiles,factory,return_value=['/dev/a']),patch.object(profiles,'describe',return_value=(identity,32*1024**2,4096)):
    denied(lambda:profiles.resolve(profile))
for name in ('','../disk','a/b','.hidden','bad name','x'*65):denied(lambda:profiles.name_check(name))

# Whole-drive audit includes both raw/block paths of siblings and never asks
# the OS to unmount/eject anything when a sibling is already mounted or busy.
def fake_plist(argv,mounted=False):
    if argv[1]=='list':return dict(AllDisksAndPartitions=[dict(DeviceIdentifier='disk99',Partitions=[dict(DeviceIdentifier='disk99s1'),dict(DeviceIdentifier='disk99s2')])])
    return dict(DeviceIdentifier=argv[-1].removeprefix('/dev/'),ParentWholeDisk='disk99',Mounted=mounted and argv[-1].endswith('s2'))
with patch.object(sys,'platform','darwin'),patch.object(profiles.admission,'plist',side_effect=lambda argv:fake_plist(argv,True)),patch.object(profiles.subprocess,'run') as calls:
    denied(lambda:profiles.audit_device_users('/dev/disk99s1'));check(not calls.called)
with patch.object(sys,'platform','darwin'),patch.object(profiles.admission,'plist',side_effect=fake_plist),patch.object(profiles.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'p999999999\n',b'')) as calls:
    denied(lambda:profiles.audit_device_users('/dev/disk99s1'))
    check('/dev/disk99s2' in calls.call_args.args[0] and '/dev/rdisk99s2' in calls.call_args.args[0])
with patch.object(sys,'platform','darwin'),patch.object(profiles.admission,'plist',side_effect=fake_plist),patch.object(profiles.subprocess,'run',return_value=subprocess.CompletedProcess([],0,('p'+str(os.getpid())+'\n').encode(),b'')):
    profiles.audit_device_users('/dev/disk99s1');check(True)

# Empty inventory does not create a registry, state, lock or directory.
check(json.loads(run(volume+['list','--json']).stdout)==[])
check(not registry.exists())
source=base/'seed.img'
with source.open('xb') as f:f.truncate(32*1024**2)
run(['mke2fs','-q','-F','-t','ext4','-b','4096','-O','^orphan_file',source])
run(['debugfs','-w','-R',f'set_inode_field / uid {os.getuid()}',source])
run(['debugfs','-w','-R',f'set_inode_field / gid {os.getgid()}',source])
state=base/'s';point=base/'mount'
run([cli,'init','--image',source,state])
run(volume+['add','image','--state',state,'--mountpoint',point])
check(point.is_dir())
record=registry/'image.json';saved=record.read_bytes()
check(stat.S_IMODE(record.stat().st_mode)==0o600)
check(stat.S_IMODE(registry.stat().st_mode)==0o700)
run(volume+['add','IMAGE','--state',state,'--mountpoint',point],expected=1)
run(volume+['add','../escape','--state',state,'--mountpoint',point],expected=1)
# Listing is a metadata snapshot: no process, file or timestamp mutations.
before={p.name:(p.stat().st_mtime_ns,p.read_bytes()) for p in registry.iterdir()}
rows=json.loads(run(volume+['list','--json']).stdout)
check(rows[0]['name']=='image' and rows[0]['phase']=='ready' and not rows[0]['checked'])
check(before=={p.name:(p.stat().st_mtime_ns,p.read_bytes()) for p in registry.iterdir()})
record.chmod(0o644);run(volume+['mount','image'],expected=1);record.chmod(0o600)
hard=registry/'alias';os.link(record,hard)
run(volume+['mount','image'],expected=1);hard.unlink()
record.rename(registry/'saved');record.symlink_to(registry/'saved')
run(volume+['mount','image'],expected=1);record.unlink();(registry/'saved').rename(record)
changed=json.loads(saved);changed['mount_id'][1]+=1;record.write_text(json.dumps(changed))
run(volume+['mount','image'],expected=1);record.write_bytes(saved)
(point/'occupied').write_text('keep')
run(volume+['mount','image'],expected=1)
check((point/'occupied').read_text()=='keep' and status(state)['phase']=='ready')
(point/'occupied').unlink()
# Already attached/dead mountpoints must be refused before any stat/mkdir into them.
import writer_cli as source_cli
with patch.object(profiles,'attached',return_value=True):
    denied(lambda:profiles.add(argparse.Namespace(profiles_dir=registry,name='occupied',state=state,mountpoint=base/'not-created'),source_cli))
check(not (base/'not-created').exists())
# Listing must remain available during startup while writer-lock is held.
# A bad inherited descriptor cannot bypass the ordinary writer lock binding.
import writer_cli as source_cli
mount_args=argparse.Namespace(volume_action='mount',profiles_dir=registry,name='image',timeout=5,
    check_bytes=1024**3,journal_bytes=256*1024**2,checkpoint_every=64)
def inspect_startup(profile,args,cli_module,fd):
    row=json.loads(run(volume+['list','--json']).stdout)[0]
    check(row['busy'] and not row['mounted'])
with patch.object(profiles,'background',side_effect=inspect_startup):profiles.execute(mount_args,source_cli)
other=base/'unrelated-lock';other.write_bytes(b'');other.chmod(0o600)
fd=os.open(other,os.O_RDWR)
try:
    result=subprocess.run(list(map(str,[cli,'mount',state,point,'--lock-fd',fd])),pass_fds=(fd,),capture_output=True,timeout=30)
    check(result.returncode==1 and status(state)['phase']=='ready')
finally:os.close(fd)
read_fd,write_fd=os.pipe()
try:
    result=subprocess.run(list(map(str,[cli,'mount',state,point,'--ready-fd',read_fd])),pass_fds=(read_fd,),capture_output=True,timeout=30)
    check(result.returncode==1 and status(state)['phase']=='ready')
finally:os.close(read_fd);os.close(write_fd)
run(volume+['mount','image','--check-bytes','-1'],expected=1)
check(status(state)['phase']=='ready')
# Deterministically expired waits must not signal or kill the mount worker.
fake_child=Mock(pid=12345)
with source_cli.lock(state) as fd:
    with patch.object(profiles.subprocess,'Popen',return_value=fake_child),patch.object(profiles.select,'select',return_value=([],[],[])),patch.object(profiles.time,'monotonic',side_effect=[0,10,11]):
        denied(lambda:profiles.background(json.loads(record.read_text()),mount_args,source_cli,fd))
check(not fake_child.kill.called and not fake_child.terminate.called and not fake_child.wait.called)
# Stopping the caller's readiness wait must leave the background mount alive.
wait=subprocess.run(list(map(str,volume+['mount','image','--timeout','0.000001'])),capture_output=True,timeout=30)
check(wait.returncode in (0,1))
if wait.returncode==1:check(b'continues' in wait.stderr)
else:check(attached(point))
run(volume+['unmount','image','--timeout','30'])
check(status(state)['phase']=='ready')
process=None
try:
    process=mount('image')
    check(attached(point) and status(state)['busy'])
    observed=json.loads(run(volume+['status','image','--json']).stdout)
    check(observed['status']=='mounted' and observed['progress_current'] and observed['progress']['lifecycle']=='mounted' and not observed['checked'])
    watcher=subprocess.Popen(list(map(str,volume+['status','image','--json','--watch','--interval','.2'])),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        check(json.loads(watcher.stdout.readline())['mounted'])
        watcher.send_signal(signal.SIGINT);_,diagnostics=watcher.communicate(timeout=10)
        check(watcher.returncode==0 and not diagnostics and attached(point) and status(state)['busy'])
    finally:
        if watcher.poll() is None:watcher.kill();watcher.wait()
    rows=json.loads(run(volume+['list','--json']).stdout)
    check(rows[0]['mounted'] and rows[0]['busy'])
    (point/'persisted').write_bytes(b'background writer')
    os.mkfifo(point/'fifo');check(stat.S_ISFIFO((point/'fifo').stat().st_mode));(point/'fifo').unlink()
    run(volume+['mount','image'],expected=1)
    run(volume+['forget','image'],expected=1)
    holder=subprocess.Popen([sys.executable,'-c','import sys;sys.stdin.read()'],cwd=point,stdin=subprocess.PIPE)
    try:
        failed=run(volume+['unmount','image','--timeout','.2'],expected=1)
        check(attached(point) and b'Safe to disconnect' not in failed.stdout)
    finally:holder.communicate(timeout=30)
    run(volume+['unmount','image']);process=None
    check(not attached(point) and status(state)['phase']=='ready')
    run(volume+['unmount','image'])
    run(volume+['eject','image'],expected=1)
    # Kill the background broker, not an arbitrary PID discovered from a file.
    # Its lock must go away, leaving ordinary retained-state recovery authority.
    process=mount('image');os.kill(process,signal.SIGKILL);process=None
    deadline=time.monotonic()+10
    while status(state)['busy']:
        check(time.monotonic()<deadline);time.sleep(.1)
    run(volume+['mount','image'],expected=1)
    run(volume+['unmount','image'],expected=1)
    check(not attached(point))
    run(volume+['recover','image'])
    process=mount('image');check((point/'persisted').read_bytes()==b'background writer')
    run(volume+['unmount','image']);process=None
finally:
    subprocess.run(list(map(str,volume+['unmount','image','--timeout','10'])),capture_output=True,timeout=20)
check(status(state)['phase']=='ready')
observed=json.loads(run(volume+['status','image','--json']).stdout)
check(not observed['busy'] and not observed['mounted'] and not observed['progress_current'] and not observed['checked'])
run(volume+['forget','image'])
check(not record.exists() and (state/'chain/image.img').exists())
check(json.loads(run(volume+['list','--json']).stdout)==[])


def attach(image):
    if sys.platform=='darwin':
        data=plistlib.loads(run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',str(image).replace('/private/tmp/','/tmp/',1)]).stdout)
        return min((e['dev-entry'] for e in data['system-entities'] if 'dev-entry' in e),key=len)
    device=run(['losetup','--find','--show',image]).stdout.decode().strip()
    if shutil.which('udevadm'):run(['udevadm','settle','--timeout=15'])
    return device


def detach(device):run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])


device_result=None
if a.devices:
    image=base/'usb.img';shutil.copyfile(source,image)
    direct=base/'d';mountpoint=base/'usb-mount'
    current=None;spacer=None
    try:
        current=attach(image);first=current
        run([cli,'init','--device',current,direct])
        run(volume+['add','usb','--state',direct,'--mountpoint',mountpoint])
        check(current.encode() not in (registry/'usb.json').read_bytes())
        row=json.loads(run(volume+['list','--connected','--json']).stdout)[0]
        check(row['connected'] and row['device']==current)
        mount('usb');(mountpoint/'data').write_bytes(b'USB profile identity')
        holder=subprocess.Popen([sys.executable,'-c','import sys;sys.stdin.read()'],cwd=mountpoint,stdin=subprocess.PIPE)
        try:
            failed=run(volume+['eject','usb','--timeout','.2'],expected=1)
            check(attached(mountpoint) and b'Safely ejected' not in failed.stdout)
        finally:holder.communicate(timeout=30)
        result=run(volume+['eject','usb'])
        check(b'Safely ejected usb' in result.stdout);current=None
        check(not attached(mountpoint) and status(direct)['phase']=='ready')
        check(not json.loads(run(volume+['list','--connected','--json']).stdout)[0]['connected'])
        run(volume+['mount','usb'],expected=1)
        check(status(direct)['phase']=='ready')
        # Occupy a device number with another disposable image before reconnect.
        other=base/'spacer.img';shutil.copyfile(source,other);spacer=attach(other)
        current=attach(image);second=current
        row=json.loads(run(volume+['list','--connected','--json']).stdout)[0]
        check(row['connected'] and row['device']==current)
        mount('usb');check((mountpoint/'data').read_bytes()==b'USB profile identity')
        run(volume+['unmount','usb'])
        # Already-clean eject is one command too, without a recorded mount.
        run(volume+['eject','usb']);current=None
        run(['e2fsck','-fn',image])
        check(run(['debugfs','-R','cat /data',image]).stdout==b'USB profile identity')
        check((direct/'device/chain/image.img').stat().st_blocks==0)
        device_result=dict(first=first,reconnected=second,renumbered=first!=second,
                           busy_eject_refused=True,reconnected_data_verified=True)
        run(volume+['forget','usb'])
        check((direct/'device/direct-state').exists())
    finally:
        if attached(mountpoint):subprocess.run(list(map(str,volume+['unmount','usb','--timeout','10'])),capture_output=True,timeout=20)
        if current:detach(current)
        if spacer:detach(spacer)

result=dict(result='passed',checks=checks,background_image=True,device=device_result,prefix=str(a.prefix),diagnostics=str(base))
(a.work/'volume-profiles-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
