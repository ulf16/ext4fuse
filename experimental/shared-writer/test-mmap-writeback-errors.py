#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native mapped writeback reports injected I/O/space errors and can retry."""
import argparse,errno,json,mmap,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
import chain,session,journal_fixtures as fixture
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();here=Path(__file__).resolve().parent;checks=0

def check(c,detail='writeback error check failed'):
 global checks
 assert c,detail;checks+=1

def unmount(m):
 for attempt in range(20):
  r=subprocess.run(['/sbin/umount',str(m)] if sys.platform=='darwin' else ['fusermount3','-u',str(m)],capture_output=True,timeout=20)
  if not r.returncode or not os.path.ismount(m):return
  time.sleep(.25)
 raise RuntimeError(r.stderr)
base=Path(tempfile.mkdtemp(prefix='mmap-errors-',dir=a.work));ok=False
try:
 for code in [errno.EIO,errno.ENOSPC]:
  root=base/str(code);source=next(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name);chain.clone(source,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:s.chmod('/',0o777)
  armed=base/f'armed-{code}';failed=base/f'failed-{code}';launcher=base/f'broker-{code}.py'
  launcher.write_text('import sys,runpy,errno\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(here))+')\nimport session\n'+
   'old=session.Session._mount_writeback\nordinary=session.FileHandle.write\n'+
   'def inject():\n if Path('+repr(str(armed))+').exists() and not Path('+repr(str(failed))+').exists():\n  Path('+repr(str(failed))+').write_text("injected")\n  raise OSError('+str(code)+',"injected page writeback error")\n'+
   'def writeback(self,handle,offset,data):\n inject()\n return old(self,handle,offset,data)\n'+
   'def write(self,data,offset=0):\n inject()\n return ordinary(self,data,offset)\n'+
   'session.Session._mount_writeback=writeback\nsession.FileHandle.write=write\nrunpy.run_path('+repr(str(here/'mount-broker.py'))+',run_name="__main__")\n')
  mount=base/f'm{code}';mount.mkdir();logpath=base/f'm{code}.log';proc=None;fd=None;mapping=None;active=False
  try:
   with logpath.open('wb') as log:
    proc=subprocess.Popen([sys.executable,launcher,'--root',root,'--work',a.work,'--mountpoint',mount],stdout=log,stderr=log)
    for unused in range(200):
     if os.path.ismount(mount):active=True;break
     if proc.poll() is not None:break
     time.sleep(.1)
    check(active,logpath.read_text());fd=os.open(mount/'file',os.O_CREAT|os.O_RDWR,0o600);os.write(fd,b'A'*8192);os.fsync(fd)
    mapping=mmap.mmap(fd,8192);armed.write_text('armed');mapping[10:17]=b'FAILURE';reported=[]
    for call in [mapping.flush,lambda:os.fsync(fd)]:
     try:call()
     except OSError as e:reported.append(e.errno)
    check(failed.exists(),'page writeback injection was not reached');check(code in reported,(code,reported))
    mapping[10:17]=b'RETRIED';mapping.flush();os.fsync(fd);check(os.pread(fd,7,10)==b'RETRIED')
    check(fixture.run(['debugfs','-R','cat /file',root/'image.img'])[10:17]==b'RETRIED','retry failed to commit')
    mapping.close();mapping=None;os.close(fd);fd=None;unmount(mount);active=False;check(proc.wait(timeout=30)==0,logpath.read_text())
  finally:
   if mapping is not None:mapping.close()
   if fd is not None:os.close(fd)
   if active and os.path.ismount(mount):unmount(mount)
   if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=20)
  fixture.run(['e2fsck','-fn',root/'image.img']);print('PASS mapped error',code,flush=True)
 (a.work/'mmap-writeback-errors-results.json').write_text(json.dumps(dict(result='passed',checks=checks,platform=sys.platform),indent=2)+'\n');ok=True
 print('PASS',checks,'mapped writeback error checks',flush=True)
finally:
 if ok:shutil.rmtree(base)
 else:print('Fixtures retained:',base,file=sys.stderr)
