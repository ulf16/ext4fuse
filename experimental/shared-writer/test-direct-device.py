#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""No-shadow writes and process-loss recovery on disposable hdiutil/loop targets."""
import argparse,contextlib,errno,json,os,plistlib,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
import chain,direct_device as direct,image_io,journal_fixtures as fixture,live_device as live,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);p.add_argument('--worker',nargs=2,metavar=('ROOT','DEVICE'));a=p.parse_args();here=Path(__file__).resolve().parent;checks=0;sectors=set()
if a.worker:
 root,device=a.worker
 with direct.Controller(root,device,a.work) as c:
  with session.Session(c.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=c) as s:
   with s.open('/fault','rw') as h:h.write(b'committed after restart')
  c.finish()
 raise SystemExit(0)

def check(value,detail='direct device check failed'):
 global checks
 assert value,detail;checks+=1

def run(argv):return fixture.run(argv)
def admission(call):
 deadline=time.monotonic()+15
 while True:
  try:return call()
  except OSError as error:
   if sys.platform!='linux' or error.errno not in (errno.EAGAIN,errno.EBUSY) or time.monotonic()>=deadline:raise
   time.sleep(.2)

@contextlib.contextmanager
def controller(root,device):
 c=admission(lambda:direct.Controller(root,device,a.work).__enter__())
 try:yield c
 finally:c.__exit__()

def attach(image,sector=512):
 if sys.platform=='darwin':
  info=plistlib.loads(run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]));return min((n['dev-entry'] for n in info['system-entities'] if 'dev-entry' in n),key=len)
 if sys.platform=='linux':
  device=run(['losetup','--find','--show','--sector-size',str(sector),image]).decode().strip()
  if shutil.which('udevadm'):run(['udevadm','settle','--timeout=15'])
  return device
 raise RuntimeError('native disposable device required')
def detach(device):run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])
def opened(c,checkpoint=0):return session.Session(c.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=c,checkpoint_every=checkpoint)
def recover(device,root,ok=True):
 result=subprocess.run([sys.executable,here/'live-device.py','recover',device,root,'--work',a.work],capture_output=True,timeout=120)
 check((result.returncode==0)==ok,(result.stdout,result.stderr));return result

def rawmagic(image):
 with image.open('rb') as f:f.seek(live.MAGIC);return f.read(2)

def unmount(mount,force=False):run((['/sbin/umount']+(['-f'] if force else [])+[mount]) if sys.platform=='darwin' else ['fusermount3','-uz' if force else '-u',mount])

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='direct-native-',dir=a.work) as tmp:
 tmp=Path(tmp)
 # Busy admission must be retryable without deleting a partially initialized root.
 real_device=direct.Device
 class BusyDevice:
  def __init__(self,*unused):pass
  def __enter__(self):raise OSError(errno.EBUSY,'injected busy device')
  def __exit__(self,*unused):pass
 direct.Device=BusyDevice
 try:
  try:direct.init('/dev/unused',tmp/'busy-admission',a.work)
  except OSError as error:check(error.errno==errno.EBUSY)
  else:raise AssertionError('busy device admitted')
  check(not (tmp/'busy-admission').exists())
 finally:direct.Device=real_device
 for index,source in enumerate(sources):
  image=tmp/f'disposable-{index}.img';shutil.copyfile(source,image);before=fixture.sha(image);requested_sector=4096 if source.name.startswith('4096-') else 512;device=attach(image,requested_sector)
  try:
   root=tmp/f'device-{index}';admission(lambda:direct.init(device,root,a.work));check(fixture.sha(image)==before)
   token=root/'chain/image.img';check(token.stat().st_size==source.stat().st_size and token.stat().st_blocks==0)
   with controller(root,device) as c:
    sectors.add(c.target.sector)
    if sys.platform=='linux':check(c.target.sector==requested_sector)
    if index==0:
     # Native children receive only read capability; no raw write descriptor.
     capability_before=fixture.sha(image)
     probe="import os,sys,errno;fd=int(sys.argv[1]);\ntry:os.pwrite(fd,bytes(512),0)\nexcept OSError as e:assert e.errno==errno.EBADF\nelse:raise AssertionError('writable child device descriptor')"
     result=subprocess.run([sys.executable,'-c',probe,str(c.view.read_fd)],pass_fds=(c.view.read_fd,),capture_output=True)
     check(result.returncode==0,result.stderr);check(fixture.sha(image)==capability_before)
     options=image_io.child(token);parts=options['env']['EXT4_DEVICE_VIEW'].split(',');parts[0]=str(c.target.fd);options['env']['EXT4_DEVICE_VIEW']=','.join(parts)
     result=subprocess.run([str(a.work/'reader-server'),token],input=b'',capture_output=True,env=options['env'],pass_fds=(c.target.fd,),timeout=10)
     check(result.returncode!=0);check(fixture.sha(image)==capability_before)
    with opened(c,3) as s:
     check(rawmagic(image)==bytes(2))
     with s.open('/existing-file') as h:check(h.read()==run(['debugfs','-R','cat /existing-file',source]))
     s.mkdir('/directory');s.symlink('directory','/link')
     h=s.openat(None,'/directory/direct','rw',create=True);h.write(b'no shadow data');check(h.read()==b'no shadow data')
     h.allocate(8192,4096,1 if 'extents' in source.name else 0);h.allocate(2,4,3);check(h.read(2,4)==bytes(4))
     s.rename('/directory/direct','/renamed');s.unlink('/renamed');h.write(b'orphan direct');check(h.read(0,6)==b'orphan');h.close()
     s.checkpoint();check(token.stat().st_blocks==0);check(not list((root/'chain').glob('g-*')))
    c.finish();check(rawmagic(image)==b'\x53\xef')
   run(['e2fsck','-fn',device]);check(fixture.sha(source)==before)
   # A normal file-only tool cannot treat the sparse identity token as data.
   result=subprocess.run([str(a.work/'reader-server'),token],input=b'',capture_output=True,timeout=10,env=image_io.child('/ordinary/image')['env'])
   check(result.returncode!=0)
   if index==0:
    # Malformed local metadata and foreign devices must not install a guard.
    clean_before=fixture.sha(image);capacity=token.stat().st_size
    with token.open('r+b') as file:file.write(b'not a data shadow')
    try:
     with controller(root,device):pass
    except OSError:check(True)
    else:raise AssertionError('allocated identity token admitted')
    check(fixture.sha(image)==clean_before)
    with token.open('r+b') as file:file.truncate(0);file.truncate(capacity)
    other=tmp/'foreign-device.img';shutil.copyfile(source,other);foreign=attach(other);foreign_before=fixture.sha(other)
    try:
     try:
      with controller(root,foreign):pass
     except OSError:check(True)
     else:raise AssertionError('foreign device admitted')
     check(fixture.sha(other)==foreign_before);check(fixture.sha(image)==clean_before)
    finally:detach(foreign)
   print('PASS direct profile',source.name,flush=True)
  finally:detach(device)
 # One native device is reused only through clean, checked sessions. The backing
 # file is never rewritten underneath an attached hdiutil/loop device.
 fault_source=next((p for p in sources if p.name.startswith('4096-extents')),sources[0])
 image=tmp/'fault-device.img';shutil.copyfile(fault_source,image);device=attach(image,4096 if fault_source.name.startswith('4096-') else 512);root=tmp/'fault-device'
 try:
  admission(lambda:direct.init(device,root,a.work))
  with controller(root,device) as c:
   with opened(c) as s:
    h=s.openat(None,'/fault','rw',create=True);h.write(b'original before crash');h.close()
   c.finish()
  phases=('direct:arming','live:guarded','direct:active','record','snapshot','undo-log','prepared','validated','started',
          'direct:sector-written','half:0:0','page:0','applied','direct:flushed','synced','complete','head-ready','head-published',
          'direct:acknowledge-ready','direct:checked','direct:closing','direct:magic-restored','direct:closed')
  before_seal=set(phases[:6])
  for phase in phases:
   with controller(root,device) as c:
    with opened(c) as s:
     with s.open('/fault','rw') as h:h.truncate(len(b'original before crash'));h.write(b'original before crash')
    c.finish()
   result=subprocess.run([sys.executable,Path(__file__).resolve(),'--work',a.work,'--worker',root,device],env=dict(os.environ,EXT4_TEST_CRASH=phase),capture_output=True,timeout=120)
   check(result.returncode==77,(phase,result.returncode,result.stdout,result.stderr))
   recover(device,root);run(['e2fsck','-fn',device])
   expected=b'original before crash' if phase in before_seal else b'committed after restart'
   check(run(['debugfs','-R','cat /fault',device])==expected,phase)
   recover(device,root);check(rawmagic(image)==b'\x53\xef');check((root/'chain/image.img').stat().st_blocks==0)
   print('PASS direct interruption',phase,flush=True)
  # A damaged sealed log must not authorize even the first target sector write.
  with controller(root,device) as c:
   with opened(c) as s:
    with s.open('/fault','rw') as h:h.truncate(len(b'original before crash'));h.write(b'original before crash')
   c.finish()
  result=subprocess.run([sys.executable,Path(__file__).resolve(),'--work',a.work,'--worker',root,device],env=dict(os.environ,EXT4_TEST_CRASH='prepared'),capture_output=True,timeout=120)
  check(result.returncode==77);state=chain.read_state(root/'chain');log=root/'chain'/f"g-{state['pending']:08d}"/'pages';saved=log.read_bytes()
  changed=bytearray(saved);changed[-1]^=1;log.write_bytes(changed);before=fixture.sha(image)
  recover(device,root,False);check(fixture.sha(image)==before);check(rawmagic(image)==bytes(2));log.write_bytes(saved);recover(device,root)
  # Untouched corruption is detected by cold verification before target writes.
  with controller(root,device) as c:
   position=c.target.size-c.target.sector;original=direct.old.read_at(c.target.fd,c.target.sector,position);damaged=bytearray(original);damaged[-1]^=1
   direct.old.write_at(c.target.fd,damaged,position);c.target.flush()
  before=fixture.sha(image);recover(device,root,False);check(fixture.sha(image)==before);check(rawmagic(image)==bytes(2))
  with controller(root,device) as c:direct.old.write_at(c.target.fd,original,position);c.target.flush()
  recover(device,root)
  # Reader RPCs must reject a changed guard before consulting the native reader.
  with controller(root,device) as c:
   with opened(c) as s:
    with s.open('/fault') as h:
     offset=live.MAGIC//c.target.sector*c.target.sector;saved_guard=direct.old.read_at(c.target.fd,c.target.sector,offset);tampered=bytearray(saved_guard);tampered[live.MAGIC-offset]=1
     direct.old.write_at(c.target.fd,tampered,offset);c.target.flush()
     try:
      try:h.read()
      except OSError:check(s._failed)
      else:raise AssertionError('reader accepted a changed device guard')
     finally:direct.old.write_at(c.target.fd,saved_guard,offset);c.target.flush()
   check(c.failed);check(rawmagic(image)==bytes(2))
  recover(device,root)
  # Too little metadata scratch leaves an otherwise committed device guarded.
  with controller(root,device) as c:
   with opened(c) as s:s.checkpoint()
   c.check_bytes=4096
   try:c.finish()
   except OSError:check(True)
   else:raise AssertionError('metadata budget was ignored')
   check(rawmagic(image)==bytes(2))
  recover(device,root);check(rawmagic(image)==b'\x53\xef')
 finally:detach(device)
 # Mounted operations exercise the same private owner context and live inodes.
 image=tmp/'mount-device.img';shutil.copyfile(sources[0],image);fixture.debug(image,f'set_inode_field / uid {os.getuid()}');fixture.debug(image,'set_inode_field / mode 040777')
 device=attach(image);root=tmp/'mount-device';mount=tmp/'mount';mount.mkdir();proc=None;active=False;log=None
 try:
  run([sys.executable,here/'live-device.py','init',device,root,'--storage','direct','--work',a.work]);logpath=tmp/'mount.log';log=logpath.open('wb')
  proc=subprocess.Popen([sys.executable,here/'live-device.py','mount',device,root,'--work',a.work,'--mountpoint',mount,'--checkpoint-every','3'],stdout=log,stderr=log,start_new_session=True)
  for unused in range(200):
   if os.path.ismount(mount):active=True;break
   if proc.poll() is not None:break
   time.sleep(.1)
  check(active,logpath.read_text());check(rawmagic(image)==bytes(2))
  fd=os.open(mount/'mounted',os.O_CREAT|os.O_RDWR,0o600)
  try:
   os.write(fd,b'actual direct device mount');os.fsync(fd);os.unlink(mount/'mounted');os.pwrite(fd,b'!',0);check(os.pread(fd,6,0)==b'!ctual')
  finally:os.close(fd)
  (mount/'survivor').write_bytes(b'no shadow on actual mount');check((root/'chain/image.img').stat().st_blocks==0)
  unmount(mount);active=False;check(proc.wait(timeout=30)==0);proc=None
  run(['e2fsck','-fn',device]);check(run(['debugfs','-R','cat /survivor',device])==b'no shadow on actual mount');check(rawmagic(image)==b'\x53\xef')
 finally:
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=15)
  if active:unmount(mount,True)
  if log:log.close()
  detach(device)
(a.work/'direct-device-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources),platform=sys.platform,logical_sectors=sorted(sectors)),indent=2)+'\n')
print('PASS',checks,'native direct-device checks')
