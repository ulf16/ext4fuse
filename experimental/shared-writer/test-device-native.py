#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual disposable hdiutil/loop devices; never enumerates/selects physical disks."""
import argparse,errno,hashlib,importlib.util,json,os,plistlib,shutil,subprocess,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
import session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
spec=importlib.util.spec_from_file_location('device_writer',Path(__file__).with_name('device-writer.py'));d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
def run(args):return subprocess.check_output(list(map(str,args)),stderr=subprocess.PIPE,timeout=120)
def check(value):
 global checks
 assert value;checks+=1
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
 run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',image]);initial=sha(image);device=None
 try:
  if sys.platform=='darwin':
   info=plistlib.loads(run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]));device=min((n['dev-entry'] for n in info['system-entities'] if 'dev-entry' in n),key=len)
  elif sys.platform=='linux':device=run(['losetup','--find','--show',image]).decode().strip()
  else:raise RuntimeError('unsupported native device test platform')
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
  root=tmp/'journal';chain=d.snapshot(device,root);check(sha(image)==initial)
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
  with image.open('rb') as f:f.seek(d.MAGIC);check(f.read(2)==b'\0\0')
  recover_device(root,device);recover_device(root,device);check(sha(image)==sha(chain/'image.img'))
  run(['e2fsck','-fn',image]);contents=run(['debugfs','-R','cat /device-test',image]);check(contents==b'actual device publication')
  try:
   d.commit(root,'/dev/not-a-real-device')
  except (OSError,subprocess.CalledProcessError):check(True)
  else:raise AssertionError('replacement path accepted')
  check(sha(image)==sha(chain/'image.img'))
 finally:
  if device:run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])
(a.work/'device-native-results.json').write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform),indent=2)+'\n');print('PASS',checks,'actual offline device publication checks')
