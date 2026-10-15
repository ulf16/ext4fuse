#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Dirty-journal no-shadow admission and crash recovery on disposable devices."""
import argparse,contextlib,errno,json,os,plistlib,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
import chain,direct_device as direct,journal_fixtures as fixture
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);a=p.parse_args();here=Path(__file__).resolve().parent;checks=0;sectors=set()
def check(value,detail='direct journal check failed'):
 global checks
 assert value,detail;checks+=1

def admission(call):
 deadline=time.monotonic()+20
 while True:
  try:return call()
  except OSError as e:
   if e.errno not in (errno.EBUSY,errno.EAGAIN) or time.monotonic()>=deadline:raise
   time.sleep(.2)

@contextlib.contextmanager
def attached(image,sector=512):
 if sys.platform=='darwin':
  info=plistlib.loads(fixture.run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]));dev=min((e['dev-entry'] for e in info['system-entities'] if 'dev-entry' in e),key=len)
 else:
  dev=fixture.run(['losetup','--find','--show','--sector-size',str(sector),image]).decode().strip()
  if shutil.which('udevadm'):fixture.run(['udevadm','settle','--timeout=15'])
 try:yield dev
 finally:fixture.run(['hdiutil','detach',dev] if sys.platform=='darwin' else ['losetup','--detach',dev])

def cli(action,dev,root,crash=None,ok=True):
 args=[sys.executable,here/'live-device.py',action,dev,root,'--work',a.work]
 if action=='init':args+=['--storage','direct','--recover-journal']
 result=admission(lambda:subprocess.run(args,env=dict(os.environ,EXT4_TEST_CRASH=crash or ''),capture_output=True,timeout=180))
 # CLI admission errors are reported as exit status; retry only known busy errors.
 deadline=time.monotonic()+20
 while result.returncode and b'Device or resource busy' in result.stderr and time.monotonic()<deadline:
  time.sleep(.2);result=subprocess.run(args,env=dict(os.environ,EXT4_TEST_CRASH=crash or ''),capture_output=True,timeout=180)
 check((result.returncode==0)==ok,(action,crash,result.stdout,result.stderr));return result

def verify(dev,root,expected):
 cli('recover',dev,root);check((root/'chain/image.img').stat().st_blocks==0)
 check(chain.read_state(root/'chain')['head']==1)
 fixture.run(['e2fsck','-fn',dev]);check(fixture.run(['debugfs','-R','cat /journal-created',dev])==expected)

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='direct-journal-native-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for number,source in enumerate(sources):
  image=tmp/f'profile-{number}.img';expected=fixture.metadata(source,image);before=fixture.sha(image)
  sector=4096 if source.name.startswith('4096-') else 512
  with attached(image,sector) as dev:
   try:admission(lambda:direct.init(dev,tmp/f'refused-{number}',a.work))
   except (OSError,ValueError):check(True)
   else:raise AssertionError('dirty device admitted without opt-in')
   check(fixture.sha(image)==before)
   root=tmp/f'profile-{number}';admission(lambda:direct.init(dev,root,a.work,recover_journal=True))
   check(fixture.sha(image)==before);check(chain.read_state(root/'chain')['pending']==1);check((root/'chain/image.img').stat().st_blocks==0)
   sectors.add(direct.old.load(root,'direct-state')['sector']);verify(dev,root,expected)
 # Candidate process death must discard volatile pages and release its raw fd;
 # sealed candidates must resume verbatim, including torn physical publication.
 before_guard=('direct:import-intent','chain-intent','candidate:mounted','journal:replayed','journal:checked','candidate:validated','candidate:streamed','record','undo-log','prepared','chain-prepared','validated','direct:import-arming')
 after_guard=('live:guarded','direct:active','started','direct:sector-written','half:0:0','page:0','direct:flushed','synced','complete','head-ready','head-published','direct:recovered','direct:closing','direct:magic-restored','direct:closed')
 source=next((s for s in sources if s.name.startswith('4096-') and 'extents' in s.name),sources[0])
 for number,phase in enumerate(before_guard+after_guard):
  image=tmp/f'fault-{number}.img';expected=fixture.metadata(source,image);before=fixture.sha(image)
  with attached(image,4096 if source.name.startswith('4096-') else 512) as dev:
   root=tmp/f'fault-{number}'
   if phase in before_guard and phase!='direct:import-arming':cli('init',dev,root,phase,False)
   else:
    cli('init',dev,root);cli('recover',dev,root,phase,False)
   if phase in before_guard:check(fixture.sha(image)==before,'pre-guard replay changed source: '+phase)
   verify(dev,root,expected)
   print('PASS crash',phase,flush=True)
 # Validate sealed logs BEFORE changing the device guard. Retained damage must
 # remain refused on repeated attempts, preserving the original dirty source.
 image=tmp/'tampered.img';fixture.metadata(sources[0],image);before=fixture.sha(image)
 with attached(image) as dev:
  root=tmp/'tampered';cli('init',dev,root)
  pages=root/'chain/g-00000001/pages'
  with pages.open('r+b') as f:f.seek(32);b=f.read(1);f.seek(32);f.write(bytes([b[0]^1]))
  cli('recover',dev,root,ok=False);cli('recover',dev,root,ok=False);check(fixture.sha(image)==before)
 # Budget exhaustion is recoverable by retrying with the normal budget.
 image=tmp/'budget.img';expected=fixture.metadata(sources[0],image);before=fixture.sha(image)
 with attached(image) as dev:
  root=tmp/'budget'
  try:admission(lambda:direct.init(dev,root,a.work,recover_journal=True,journal_bytes=4096))
  except (OSError,ValueError):check(True)
  else:raise AssertionError('unbounded journal overlay')
  check(fixture.sha(image)==before);verify(dev,root,expected)
 # Actual writable mount starts only after native journal replay is durable.
 image=tmp/'mounted.img';seed=tmp/'seed.img';shutil.copyfile(sources[0],seed);fixture.debug(seed,'set_inode_field / mode 040777');expected=fixture.metadata(seed,image)
 with attached(image) as dev:
  root=tmp/'mounted';cli('init',dev,root);mount=tmp/'mount';mount.mkdir();proc=None;active=False
  logpath=tmp/'mount.log'
  try:
   with logpath.open('wb') as log:
    proc=subprocess.Popen([sys.executable,here/'live-device.py','mount',dev,root,'--work',a.work,'--mountpoint',mount],stdout=log,stderr=log,start_new_session=True)
    for unused in range(400):
     if os.path.ismount(mount):active=True;break
     if proc.poll() is not None:break
     time.sleep(.1)
    check(active,logpath.read_text());check((mount/'journal-created').read_bytes()==expected)
    (mount/'after-native-replay').write_bytes(b'bounded direct journal recovery')
    fixture.run(['/sbin/umount',mount] if sys.platform=='darwin' else ['fusermount3','-u',mount]);active=False
    check(proc.wait(timeout=60)==0,logpath.read_text());fixture.run(['e2fsck','-fn',dev]);check(fixture.run(['debugfs','-R','cat /after-native-replay',dev])==b'bounded direct journal recovery');check((root/'chain/image.img').stat().st_blocks==0)
  finally:
   if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=15)
   if active:fixture.run(['/sbin/umount','-f',mount] if sys.platform=='darwin' else ['fusermount3','-uz',mount])
(a.work/'direct-journal-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources),logical_sectors=sorted(sectors),crash_boundaries=len(before_guard+after_guard)),indent=2)+'\n')
print('PASS',checks,'no-shadow native dirty-journal checks',flush=True)
