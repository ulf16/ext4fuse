#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Dirty internal journal admission and recovery on disposable native devices."""
import argparse,errno,json,os,plistlib,signal,subprocess,sys,tempfile,time
from pathlib import Path
import chain,journal_fixtures as fixture,live_device as live
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
here=Path(__file__).resolve().parent

def check(value,detail='native journal recovery check failed'):
 global checks
 assert value,detail;checks+=1

def admission(call):
 deadline=time.monotonic()+15
 while True:
  try:return call()
  except OSError as e:
   if sys.platform!='linux' or e.errno not in (errno.EAGAIN,errno.EBUSY) or time.monotonic()>=deadline:raise
   time.sleep(.2)

def unmount(mount,force=False):
 fixture.run((['/sbin/umount']+(['-f'] if force else [])+[mount]) if sys.platform=='darwin' else ['fusermount3','-uz' if force else '-u',mount])

with tempfile.TemporaryDirectory(prefix='journal-native-',dir=a.work) as temp:
 temp=Path(temp);seed=temp/'seed.img'
 source=next(p for p in sorted((a.work/'fixtures').glob('*extents-csum1.img')) if '-output' not in p.name)
 import shutil
 shutil.copyfile(source,seed)
 fixture.debug(seed,f'set_inode_field / uid {os.getuid()}');fixture.debug(seed,'set_inode_field / mode 040777')
 for number,crash in enumerate((None,'live:sector:0:0','live:data-synced','journal:checked')):
  image=temp/f'disposable-{number}.img';detail=fixture.create(seed,image);before=fixture.sha(image)
  device=None;proc=None;active=False;log=None;mount=temp/f'mount-{number}';mount.mkdir()
  try:
   if sys.platform=='darwin':
    info=plistlib.loads(fixture.run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]))
    device=min((n['dev-entry'] for n in info['system-entities'] if 'dev-entry' in n),key=len)
   elif sys.platform=='linux':device=fixture.run(['losetup','--find','--show',image]).decode().strip()
   else:raise RuntimeError('unsupported native device platform')
   root=temp/f'journal-{number}'
   try:admission(lambda:live.init(device,temp/f'default-refusal-{number}'))
   except (OSError,ValueError):check(True)
   else:raise AssertionError('dirty device admitted without opt-in')
   check(fixture.sha(image)==before)
   if crash=='journal:checked':
    result=subprocess.run([sys.executable,here/'live-device.py','init',device,root,'--recover-journal'],env=dict(os.environ,EXT4_TEST_CRASH=crash),capture_output=True,timeout=120)
    check(result.returncode!=0);check(fixture.sha(image)==before)
    fixture.run([sys.executable,here/'live-device.py','recover',device,root,'--work',a.work,'--recover-journal'])
    check(fixture.sha(device)==fixture.sha(root/'chain/image.img'))
    check(fixture.run(['debugfs','-R','cat /existing-file',device])==detail['new'])
    fixture.run(['e2fsck','-fn',device]);continue
   admission(lambda:live.init(device,root,recover_journal=True))
   check(fixture.sha(image)==before,'initialization modified original dirty device')
   check(chain.read_state(root/'chain')['head']==1)
   fixture.run(['e2fsck','-fn',root/'chain/image.img'])
   if crash:
    result=subprocess.run([sys.executable,here/'live-device.py','recover',device,root,'--work',a.work],env=dict(os.environ,EXT4_TEST_CRASH=crash),capture_output=True,timeout=120)
    check(result.returncode!=0,(crash,result.stdout,result.stderr))
    # A fresh process must finish the sealed native recovery generation.
    fixture.run([sys.executable,here/'live-device.py','recover',device,root,'--work',a.work])
    check(fixture.sha(device)==fixture.sha(root/'chain/image.img'))
    check(fixture.run(['debugfs','-R','cat /existing-file',device])==detail['new'])
    fixture.run(['e2fsck','-fn',device]);continue
   logpath=temp/'mount.log';log=logpath.open('wb')
   proc=subprocess.Popen([sys.executable,here/'live-device.py','mount',device,root,'--work',a.work,'--mountpoint',mount,'--recover-journal'],stdout=log,stderr=log,start_new_session=True)
   for unused in range(200):
    if os.path.ismount(mount):active=True;break
    if proc.poll() is not None:break
    time.sleep(.1)
   check(active,'recovered device mount failed: '+logpath.read_text())
   check((mount/'existing-file').read_bytes()==detail['new'])
   with image.open('rb') as f:f.seek(live.MAGIC);check(f.read(2)==bytes(2))
   (mount/'after-replay').write_bytes(b'journal recovered before mounted writer')
   unmount(mount);active=False;check(proc.wait(timeout=30)==0);proc=None
   check(fixture.sha(device)==fixture.sha(root/'chain/image.img'))
   fixture.run(['e2fsck','-fn',device]);check(fixture.run(['debugfs','-R','cat /after-replay',device])==b'journal recovered before mounted writer')
  finally:
   if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=15)
   if active:unmount(mount,True)
   if log:log.close()
   if device:fixture.run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])
(a.work/'journal-native-results.json').write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform),indent=2)+'\n')
print('PASS',checks,'dirty native device and mounted recovery checks')
