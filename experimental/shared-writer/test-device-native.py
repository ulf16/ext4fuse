#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual disposable hdiutil/loop devices; never enumerates/selects physical disks."""
import argparse,errno,hashlib,importlib.util,json,os,plistlib,shutil,subprocess,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
import session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--partition',action='store_true');a=p.parse_args();checks=0
spec=importlib.util.spec_from_file_location('device_writer',Path(__file__).with_name('device-writer.py'));d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
def run(args):return subprocess.check_output(list(map(str,args)),stderr=subprocess.PIPE,timeout=120)
def check(value):
 global checks
 assert value;checks+=1
def snapshot_device(root,device):
 deadline=time.monotonic()+15
 while True:
  try:return d.snapshot(device,root)
  except OSError as e:
   # Retry only before admission/state creation; never discard partial state.
   if (sys.platform!='linux' or e.errno not in (errno.EAGAIN,errno.EBUSY)
       or root.exists() or time.monotonic()>=deadline):raise
   time.sleep(.2)
def recover_device(root,device):
 # udev/blkid may briefly hold a shared flock after a loop-device change.
 # Production admission keeps refusing it; the disposable test retries only
 # before recovery has acquired its lock or made any writes.
 deadline=time.monotonic()+15
 while True:
  try:return d.recover(root,device)
  except OSError as e:
   if sys.platform!='linux' or e.errno not in (errno.EAGAIN,errno.EBUSY) or time.monotonic()>=deadline:raise
   time.sleep(.2)
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
with tempfile.TemporaryDirectory(prefix='device-native-',dir=a.work) as tmp:
 tmp=Path(tmp);image=tmp/'disposable.img'
 with image.open('wb') as f:f.truncate(32*1024**2)
 if a.partition:
  assert sys.platform=='linux'
  subprocess.run(['sfdisk',str(image)],input='label: gpt\nsize=14M,type=L\nsize=14M,type=L\n',text=True,capture_output=True,check=True)
 else:run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',image])
 device=None;attachment=None;offset=0
 try:
  if sys.platform=='darwin':
   info=plistlib.loads(run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]));device=min((n['dev-entry'] for n in info['system-entities'] if 'dev-entry' in n),key=len)
  elif sys.platform=='linux':
   attachment=run(['losetup','--find','--show','--partscan',image]).decode().strip();device=attachment
   if a.partition:
    device=attachment+'p1';sibling=attachment+'p2'
    for unused in range(100):
     if Path(device).exists() and Path(sibling).exists():break
     time.sleep(.1)
    run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',device]);run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',sibling])
    offset=int((Path('/sys/class/block')/Path(device).name/'start').read_text())*512
    # A held whole-drive claim must reject mounting any sibling partition.
    mount=tmp/'sibling-mount';mount.mkdir()
    with d.Device(device,tmp):
     result=subprocess.run(['mount',sibling,str(mount)],capture_output=True)
     if result.returncode==0:
      run(['umount',mount]);raise AssertionError('sibling mounted while whole drive claimed')
     check(result.returncode!=0)
    # Conversely a mounted sibling must reject admission before any writes.
    run(['mount','-o','ro',sibling,mount])
    try:
     before=sha(image)
     try:d.snapshot(device,tmp/'mounted-journal')
     except OSError:check(True)
     else:raise AssertionError('mounted sibling admitted')
     check(sha(image)==before)
    finally:run(['umount',mount])
  else:raise RuntimeError('unsupported native device test platform')
  initial=sha(image)
  if sys.platform=='darwin':
   # An existing raw-device reader must block admission, without changing bytes.
   raw='/dev/r'+Path(device).name.removeprefix('r')
   peer=subprocess.Popen([sys.executable,'-c','import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); print("ready",flush=True); sys.stdin.read(); os.close(fd)',raw],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
   try:
    check(peer.stdout.readline().strip()=='ready')
    try:d.snapshot(device,tmp/'busy-journal')
    except OSError:check(True)
    else:raise AssertionError('busy raw device admitted')
    check(sha(image)==initial)
   finally:peer.communicate('',timeout=30)
  root=tmp/'journal';chain=snapshot_device(root,device);check(sha(image)==initial)
  with session.Session(chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   s.chmod('/',0o777);h=s.openat(None,'/device-test','w',create=True,mode=0o600);h.write(b'actual device publication');h.close()
  # Produce a real interruption after durable guard publication.
  original=d.boundary;hit=[]
  def stop(name):
   if name=='device:guarded':hit.append(name);raise OSError('test interruption')
   return original(name)
  with patch.object(d,'boundary',stop):
   try:d.commit(root,device)
   except OSError:
    if not hit:raise
   else:raise AssertionError('device guard interruption not reached')
  check(bool(hit))
  with image.open('rb') as f:f.seek(offset+d.MAGIC);check(f.read(2)==b'\0\0')
  recover_device(root,device);recover_device(root,device);check(sha(Path(device))==sha(chain/'image.img'))
  run(['e2fsck','-fn',device]);contents=run(['debugfs','-R','cat /device-test',device]);check(contents==b'actual device publication')
  try:
   d.commit(root,'/dev/not-a-real-device')
  except (OSError,subprocess.CalledProcessError):check(True)
  else:raise AssertionError('replacement path accepted')
  check(sha(Path(device))==sha(chain/'image.img'))
 finally:
  if device:run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',attachment])
(a.work/('device-native-partition-results.json' if a.partition else 'device-native-results.json')).write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform),indent=2)+'\n');print('PASS',checks,'actual offline device publication checks')
