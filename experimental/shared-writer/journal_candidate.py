# SPDX-License-Identifier: GPL-2.0-only
"""Trusted e2fsprogs replay on a bounded, ephemeral FUSE page overlay."""
import contextlib,errno,os,select,shutil,subprocess,sys,tempfile
from pathlib import Path
from durable import boundary
import journal_recovery

def budget(value):
 if type(value) is not int or value%4096 or not 4096<=value<=1024**3:raise ValueError('journal overlay budget must be page aligned, 4 KiB..1 GiB')

def unmount(path):
 args=['/sbin/umount','-f',str(path)] if sys.platform=='darwin' else ['fusermount3','-uz',str(path)]
 subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)

@contextlib.contextmanager
def candidate(source,work,limit,log,output):
 budget(limit);source=Path(source).absolute();work=Path(work).resolve()
 parent=Path(tempfile.mkdtemp(prefix='journal-candidate-',dir=work));mount=parent/'mount';mount.mkdir(mode=0o700)
 read,write=os.pipe();process=None;mounted=False
 try:
  inherited=[];config=os.environ.get('EXT4_DEVICE_VIEW')
  if config is not None:
   fields=config.split(',')
   if len(fields)!=8 or not fields[0].isdigit():raise ValueError('invalid inherited device view')
   inherited.append(int(fields[0]))
  with Path(log).open('xb') as errors:
   process=subprocess.Popen([str(work/'journal-candidate'),str(source),str(mount),str(limit//4096),str(write)],stdin=subprocess.PIPE,stdout=output,stderr=errors,pass_fds=tuple(inherited+[write]))
   os.close(write);write=-1
   if not select.select([read],[],[],30)[0] or os.read(read,1)!=b'\1':raise OSError(errno.EIO,'journal candidate mount failed; diagnostic log retained')
   mounted=True;boundary('candidate:mounted')
   with journal_recovery.abort_on(read):yield mount/'image'
   process.stdin.write(b'S');process.stdin.flush();process.stdin.close()
   if process.wait(timeout=120)!=0:raise OSError(errno.EIO,'journal candidate stream failed')
   if os.path.ismount(mount):unmount(mount)
   if os.path.ismount(mount):raise OSError(errno.EIO,'journal candidate mount did not detach')
   mounted=False;boundary('candidate:streamed')
 finally:
  os.close(read)
  if write!=-1:os.close(write)
  if process is not None:
   if process.stdin is not None and not process.stdin.closed:process.stdin.close()
   try:process.wait(timeout=15)
   except subprocess.TimeoutExpired:
    process.kill();process.wait(timeout=15)
   if mounted:unmount(mount)
  if mount.exists():
   try:mount.rmdir()
   except OSError:pass
  try:parent.rmdir()
  except OSError:pass

def producer(source,work,limit):
 import chain
 source=Path(source).absolute();state=chain.read_state(source.parent)
 if state['pending'] is None:raise ValueError('journal candidate requires a sealed chain intent')
 generation=source.parent/f"g-{state['pending']:08d}"
 with candidate(source,work,limit,generation/'journal-daemon.log',sys.stdout.buffer) as path:
  journal_recovery.replay_candidate(path,generation/'journal-replay.log')
  boundary('candidate:validated')
