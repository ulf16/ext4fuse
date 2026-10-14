#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Continuous mounted writes to an explicitly created hdiutil/loop target only."""
import argparse,errno,hashlib,json,os,plistlib,signal,subprocess,sys,tempfile,time
from pathlib import Path
import live_device as live,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
here=Path(__file__).resolve().parent

def check(value,detail='native continuous check failed'):
 global checks
 assert value,detail;checks+=1

def run(args):return subprocess.check_output(list(map(str,args)),stderr=subprocess.PIPE,timeout=120)
def admission(call):
 deadline=time.monotonic()+15
 while True:
  try:return call()
  except OSError as e:
   if sys.platform!='linux' or e.errno not in (errno.EAGAIN,errno.EBUSY) or time.monotonic()>=deadline:raise
   time.sleep(.2)
def digest(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unmount(mount,force=False):
 run((['/sbin/umount']+(['-f'] if force else [])+[mount]) if sys.platform=='darwin' else ['fusermount3','-uz' if force else '-u',mount])

with tempfile.TemporaryDirectory(prefix='continuous-native-',dir=a.work) as temp:
 temp=Path(temp);image=temp/'disposable.img';device=None;proc=None;active=False;log=None;fd=None
 with image.open('wb') as f:f.truncate(32*1024**2)
 run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',image])
 script=temp/'seed.commands';script.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n');run(['debugfs','-w','-f',script,image])
 try:
  if sys.platform=='darwin':
   info=plistlib.loads(run(['hdiutil','attach','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',image]));device=min((n['dev-entry'] for n in info['system-entities'] if 'dev-entry' in n),key=len)
  elif sys.platform=='linux':device=run(['losetup','--find','--show',image]).decode().strip()
  else:raise RuntimeError('unsupported disposable device platform')
  root=temp/'journal';before=digest(image);admission(lambda:live.init(device,root));check(digest(image)==before)
  def controller():return admission(lambda:live.Controller(root,device).__enter__())
  # Direct live Session observes the exact held raw fd after every acknowledgement.
  c=controller()
  try:
   with session.Session(c.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(os.getuid(),os.getgid()),checkpoint_every=3,commit_sink=c) as s:
    check(live.magic(c.target)==b'\0\0')
    h=s.openat(None,'/native','rw',create=True);h.write(b'continuous actual device')
    check(live.scan(c.target).root()==s.state['sha256']);check(c.state['head']==s.state['head'])
    h.allocate(8192,4096,1);check(live.scan(c.target).root()==s.state['sha256'])
    h.allocate(2,7,3);check(h.read(2,7)==bytes(7));check(live.scan(c.target).root()==s.state['sha256'])
    s.unlink('/native');h.write(b'orphan');check(live.scan(c.target).root()==s.state['sha256']);h.close()
    s.mkdir('/directory');s.symlink('directory','/link');check(live.scan(c.target).root()==s.state['sha256'])
   c.finish();check(live.magic(c.target)==b'\x53\xef')
  finally:c.__exit__()
  check(digest(device)==digest(root/'chain/image.img'));run(['e2fsck','-fn',device])
  mount=temp/'mount';mount.mkdir()
  def mirrored():
   with image.open('rb') as physical,(root/'chain/image.img').open('rb') as shadow:
    for off in range(0,os.stat(image).st_size,1024**2):
     data=bytearray(physical.read(1024**2))
     if off==0:data[live.MAGIC:live.MAGIC+2]=b'\x53\xef'
     check(data==shadow.read(1024**2),'mounted acknowledgement preceded device write')
  def start(label):
   logpath=temp/(label+'.log');logfile=logpath.open('wb')
   child=subprocess.Popen([sys.executable,here/'live-device.py','mount',device,root,'--work',a.work,'--mountpoint',mount,'--checkpoint-every','3'],stdout=logfile,stderr=logfile,start_new_session=True)
   for unused in range(200):
    if os.path.ismount(mount):return child,logfile
    if child.poll() is not None:break
    time.sleep(.1)
   logfile.close();raise AssertionError('continuous mount failed: '+logpath.read_text())
  proc,log=start('live');active=True
  path=mount/'mounted';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600);os.write(fd,b'mounted physical');os.fsync(fd)
  # The owned backing of this disposable device reflects the flushed target.
  with image.open('rb') as f:f.seek(live.MAGIC);check(f.read(2)==b'\0\0')
  mirrored();check(run(['debugfs','-R','cat /mounted',root/'chain/image.img'])==b'mounted physical')
  os.unlink(path);os.pwrite(fd,b'!',0);check(os.pread(fd,16,0)==b'!ounted physical');os.close(fd);fd=None
  (mount/'survivor').write_bytes(b'acknowledged before crash');mirrored()
  fd=os.open(mount/'crash-orphan',os.O_CREAT|os.O_RDWR,0o600);os.write(fd,b'orphan');os.unlink(mount/'crash-orphan')
  os.killpg(proc.pid,signal.SIGKILL);check(proc.wait(timeout=15)==-signal.SIGKILL);proc=None
  unmount(mount,True);active=False;log.close();log=None
  try:os.close(fd)
  except OSError:pass
  fd=None
  with image.open('rb') as f:f.seek(live.MAGIC);check(f.read(2)==b'\0\0')
  check(subprocess.run(['e2fsck','-fn',device],capture_output=True).returncode!=0)
  # Explicit recovery reaps the abandoned open inode and mirrors that mutation.
  run([sys.executable,here/'live-device.py','recover',device,root,'--work',a.work])
  check(digest(device)==digest(root/'chain/image.img'));run(['e2fsck','-fn',device])
  check(run(['debugfs','-R','cat /survivor',device])==b'acknowledged before crash')
  proc,log=start('clean');active=True
  check((mount/'survivor').read_bytes()==b'acknowledged before crash')
  (mount/'clean').write_bytes(b'clean shutdown');unmount(mount);active=False
  check(proc.wait(timeout=30)==0);proc=None;log.close();log=None
  check(digest(device)==digest(root/'chain/image.img'));run(['e2fsck','-fn',device]);check(run(['debugfs','-R','cat /clean',device])==b'clean shutdown')
 finally:
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=15)
  if active:unmount(mount,True)
  if log:log.close()
  if fd is not None:
   try:os.close(fd)
   except OSError:pass
  if device:run(['hdiutil','detach',device] if sys.platform=='darwin' else ['losetup','--detach',device])
(a.work/'live-device-native-results.json').write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform),indent=2)+'\n')
print('PASS',checks,'actual continuously written device and mount checks')
