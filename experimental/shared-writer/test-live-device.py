#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Continuous publication, real mutation logs, and disposable sector fault targets."""
import argparse,errno,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
import chain,inplace,live_device as live,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
class Simulated:
 sector=512
 def __init__(self,path,journal):
  self.fd=os.open(path,os.O_RDWR);st=os.fstat(self.fd);self.size=st.st_size
  self.identity=dict(kind='simulation',device=st.st_dev,inode=st.st_ino);self.flushed=[]
 def __enter__(self):return self
 def __exit__(self,*args):os.close(self.fd)
 def check(self):
  if os.fstat(self.fd).st_size!=self.size:raise OSError(errno.EIO,'simulated removal')
 def flush(self):
  os.fsync(self.fd);self.flushed.append(live.magic(self))
def check(value,detail='continuous check failed'):
 global checks
 assert value,detail;checks+=1
def open_session(c):return session.Session(c.chain,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),commit_sink=c)
def equal(c):
 with (c.chain/'image.img').open('rb') as f:
  view=live.DeviceView(c.target)
  for off in range(0,c.target.size,1024**2):
   view.seek(off);check(view.read(min(1024**2,c.target.size-off))==f.read(1024**2))
def recover(root,device):
 with live.Controller(root,device) as c:
  with open_session(c) as s:check(s.state['head']==c.state['head']);equal(c)
  c.finish();check(live.magic(c.target)==b'\x53\xef');equal(c)
 subprocess.run(['e2fsck','-fn',str(device)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

with tempfile.TemporaryDirectory(prefix='continuous-',dir=a.work) as temp,patch.object(live,'Device',Simulated):
 temp=Path(temp)
 busy=temp/'busy-admission'
 with patch.object(live,'Device',side_effect=BlockingIOError(errno.EAGAIN,'busy test target')):
  try:live.init('/dev/not-opened',busy)
  except BlockingIOError:check(not busy.exists())
  else:raise AssertionError('busy device admitted')
 source=a.work/'fixtures/1024-classic-csum0.img'
 # A sealed head-one generation is generated once with the real C mutator.
 # Fault cases clone it and rewrite only the sealed image inode identity.
 device=temp/'seed-device';shutil.copyfile(source,device);seed=temp/'seed';live.init(device,seed)
 original=device.read_bytes()
 with session.Session(seed/'chain',a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:s.chmod('/',0o777)
 def setup(name,sector):
  root=temp/name;shutil.copytree(seed,root);target=temp/(name+'.img');target.write_bytes(original)
  Simulated.sector=sector
  with Simulated(target,root) as t:
   state=live.offline.load(root,'live-state');state.update(identity=t.identity,sector=sector);inplace.seal(root,'live-state',state)
  info=os.stat(root/'chain/image.img');state=chain.read_state(root/'chain');state.update(device=info.st_dev,inode=info.st_ino);inplace.seal(root/'chain','chain-state',state)
  meta=live.offline.load(root/'chain/g-00000001','transaction');meta.update(device=info.st_dev,inode=info.st_ino);inplace.seal(root/'chain/g-00000001','transaction',meta)
  return root,target
 phases=['live:arming','live:guarded','live:active','live:prepared','live:validated','live:started',
         'live:data-synced','live:verified','live:head-published','live:retire-marker','live:retired',
         'live:recovered','live:checkpoint-verified','live:closing','live:magic-restored','live:closed',
         'live-pending:pending','live-pending:renamed','live-started:pending','live-started:renamed',
         'live-state:pending','live-state:renamed']
 for sector in (512,4096):
  for index,item in enumerate(phases+[f'live:sector:0:{j}' for j in range(4096//sector)]+[(name,n) for name in ('live-state:pending','live-state:renamed','live:retire-marker') for n in range(2,6 if name.startswith('live-state') else 3)]):
   phase,occurrence=item if isinstance(item,tuple) else (item,1)
   seen=[]
   root,target=setup(f'fault-{sector}-{index}',sector);hit=[]
   def fail(name):
    if name==phase:
     seen.append(name)
     if len(seen)==occurrence:hit.append(name);raise OSError(errno.EIO,'disposable crash at '+name)
   with patch.object(live,'boundary',fail),patch.object(inplace,'boundary',fail):
    try:
     with live.Controller(root,target) as c:
      c.recover(chain.read_state(root/'chain'));c.finish()
    except OSError:check(bool(hit),phase)
    else:raise AssertionError('fault not reached: '+phase)
   recover(root,target)
   shutil.rmtree(root);target.unlink()
 # Abrupt child death skips Python cleanup, unlike the exception fault matrix.
 for sector in (512,4096):
  root,target=setup(f'process-crash-{sector}',sector)
  code="""import os,sys
from pathlib import Path
from unittest.mock import patch
import chain,live_device as live
class Simulated:
 def __init__(self,path,journal):
  self.fd=os.open(path,os.O_RDWR);st=os.fstat(self.fd);self.size=st.st_size;self.sector=int(sys.argv[3]);self.identity=dict(kind='simulation',device=st.st_dev,inode=st.st_ino)
 def __enter__(self):return self
 def __exit__(self,*args):os.close(self.fd)
 def check(self):assert os.fstat(self.fd).st_size==self.size
 def flush(self):os.fsync(self.fd)
with patch.object(live,'Device',Simulated),live.Controller(Path(sys.argv[1]),sys.argv[2]) as c:
 c.recover(chain.read_state(c.chain))
"""
  env=dict(os.environ,EXT4_TEST_CRASH='live:data-synced',PYTHONPATH=str(Path(__file__).resolve().parent))
  result=subprocess.run([sys.executable,'-c',code,str(root),str(target),str(sector)],env=env,capture_output=True,timeout=90)
  check(result.returncode==77,result.stderr);check((root/'live-started').exists());recover(root,target)
 # Real live session: every returned operation has already reached the target.
 root,target=setup('session',512)
 with live.Controller(root,target) as c:
  with open_session(c) as s:
   check(live.magic(c.target)==b'\0\0');equal(c)
   h=s.openat(None,'/continuous','rw',create=True)
   reads=[];read_at=live.offline.read_at
   def measured(fd,n,offset):
    if fd==c.target.fd:reads.append(n)
    return read_at(fd,n,offset)
   with patch.object(live.offline,'read_at',measured):h.write(b'physical write-through')
   check(sum(reads)<c.target.size//2,('unexpected warm full-device scan',sum(reads)));equal(c)
   s.unlink('/continuous');h.write(b'open orphan');check(h.read().startswith(b'open orphan'));equal(c)
   s.checkpoint();check(not list(c.chain.glob('g-*')));equal(c)
   h.close();equal(c)
   s.mkdir('/directory');s.symlink('directory','/link');equal(c)
  c.finish();check(live.magic(c.target)==b'\x53\xef');equal(c)
 recover(root,target)
 # Torn sector writes, including the primary-superblock guard and clean close.
 for sector in (512,4096):
  for number in range(2+4096//sector):
   root,target=setup(f'torn-{sector}-{number}',sector);calls=[];original_write=live.offline.write_at
   def torn(fd,data,offset):
    calls.append(offset)
    if len(calls)==number+1:
     os.pwrite(fd,memoryview(data)[:len(data)//2],offset);raise OSError(errno.EIO,'torn sector')
    original_write(fd,data,offset)
   with patch.object(live.offline,'write_at',torn):
    try:
     with live.Controller(root,target) as c:c.recover(chain.read_state(root/'chain'));c.finish()
    except OSError:check(len(calls)==number+1)
    else:raise AssertionError('torn fault not reached')
   recover(root,target);shutil.rmtree(root);target.unlink()
 # Publication failure must stop fresh reads and preserve recovery material.
 root,target=setup('failed',512)
 with live.Controller(root,target) as c:
  s=open_session(c)
  def failed_flush():raise OSError(errno.EIO,'lost flush')
  with patch.object(c.target,'flush',failed_flush):
   try:s.chmod('/',0o755)
   except OSError:check(True)
   else:raise AssertionError('device failure acknowledged')
  try:s.statat(None,'/')
  except OSError as e:check(e.errno==errno.EIO)
  else:raise AssertionError('served failed device session')
  s.close();check(c.failed);check(live.magic(c.target)==b'\0\0')
  try:c.finish()
  except OSError:check(True)
  else:raise AssertionError('failed session enabled device')
 recover(root,target)
 # Explicit full scrub must detect damage outside warm authenticated chunks
 # and preserve history. Live checkpoint retirement now reuses the trusted tree.
 root,target=setup('scrub-corruption',512)
 with live.Controller(root,target) as c:
  s=open_session(c);s.chmod('/',0o755);history=sorted(c.chain.glob('g-*'))
  os.pwrite(c.target.fd,b'X',c.target.size-1)
  try:s.scrub()
  except OSError:check(True)
  else:raise AssertionError('explicit scrub accepted clean-byte damage')
  check(sorted(c.chain.glob('g-*'))==history);s.close();check(c.failed);check(live.magic(c.target)==b'\0\0')
 # A corrupted pending redo cannot cause any further device writes on recovery.
 root,target=setup('pending-corruption',512)
 def stop(name):
  if name=='live:sector:0:0':raise OSError(errno.EIO,'partial device')
 with patch.object(live,'boundary',stop):
  try:
   with live.Controller(root,target) as c:c.recover(chain.read_state(root/'chain'))
  except OSError:check(True)
  else:raise AssertionError('partial fault not reached')
 with (root/'chain/g-00000001/pages').open('r+b') as f:f.seek(24);f.write(b'BAD')
 before=target.read_bytes()
 try:
  with live.Controller(root,target) as c:c.recover(chain.read_state(root/'chain'))
 except (OSError,ValueError):check(True)
 else:raise AssertionError('corrupt pending redo replayed')
 check(target.read_bytes()==before)
 for problem in ('identity','log','clean-byte','guard','geometry'):
  root,target=setup('bad-'+problem,512)
  if problem=='identity':
   state=live.offline.load(root,'live-state');state['identity']['inode']+=1;inplace.seal(root,'live-state',state)
  if problem=='log':
   with (root/'chain/g-00000001/pages').open('r+b') as f:f.seek(24);f.write(b'BAD')
  if problem=='clean-byte':
   with target.open('r+b') as f:f.seek(-1,2);f.write(b'X')
  if problem=='guard':
   with target.open('r+b') as f:f.seek(live.MAGIC);f.write(b'\0\0')
  if problem=='geometry':
   with target.open('r+b') as f:f.truncate(len(original)-4096)
  before=target.read_bytes()
  try:
   with live.Controller(root,target) as c:c.recover(chain.read_state(root/'chain'))
  except (OSError,ValueError):check(True,problem)
  else:raise AssertionError('unsafe input admitted: '+problem)
  # Log validation may arm the guard, but no filesystem data can change.
  after=bytearray(target.read_bytes());old=bytearray(before)
  after[live.MAGIC:live.MAGIC+2]=old[live.MAGIC:live.MAGIC+2];check(after==old,problem)
(a.work/'live-device-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n')
print('PASS',checks,'continuous device publication checks')
