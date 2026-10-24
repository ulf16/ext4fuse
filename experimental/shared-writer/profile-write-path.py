#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Profile fixed transactions on an owned regular-image copy; never physical media."""
import argparse
import cProfile
import fcntl
import io
import json
import os
from pathlib import Path
import pstats
import subprocess
import sys
import tempfile
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True,help='built native helper directory')
p.add_argument('--source',type=Path,required=True,help='owned ext4 regular image; left unchanged')
p.add_argument('--output',type=Path,required=True)
p.add_argument('--code',type=Path,help='optional alternate Python source revision for comparisons')
a=p.parse_args();a.work=a.work.resolve();a.source=a.source.resolve()
if a.code:sys.path.insert(0,str(a.code.resolve()))
import chain
import session
from credentials import Credentials
base=Path(tempfile.mkdtemp(prefix='write-profile-',dir=a.work));root=base/'chain'
# clone enforces regular-file ownership and uses an independent target inode.
chain.clone(a.source,root)
metrics={}
def measured(label,call,*args,**kwargs):
 start=time.perf_counter()
 try:return call(*args,**kwargs)
 finally:
  value=metrics.setdefault(label,dict(calls=0,seconds=0));value['calls']+=1;value['seconds']+=time.perf_counter()-start

with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),persistent_index=True) as s:
 original_sync=os.fsync;original_fcntl=fcntl.fcntl;original_popen=subprocess.Popen
 def fsync(fd):return measured('fsync',original_sync,fd)
 def control(fd,cmd,*args):return measured('fullsync' if cmd==getattr(fcntl,'F_FULLFSYNC',-1) else 'other-fcntl',original_fcntl,fd,cmd,*args)
 def popen(*args,**kwargs):return measured('producer-spawn',original_popen,*args,**kwargs)
 os.fsync=fsync;fcntl.fcntl=control;subprocess.Popen=popen
 profile=cProfile.Profile();start=time.perf_counter();profile.enable()
 try:
  s.apply([dict(kind='create',path='/write-profile-large')])
  for n in range(16):s.apply([dict(kind='write',path='/write-profile-large',offset=n*65536,data_hex=(b'P'*65536).hex())])
  for n in range(16):
   path='/write-profile-small-'+str(n);s.apply([dict(kind='create',path=path)]);s.apply([dict(kind='write',path=path,offset=0,data_hex=(b'S'*4096).hex())])
  for n in range(8):s.rename('/write-profile-small-'+str(n),'/write-profile-renamed-'+str(n));s.unlink('/write-profile-renamed-'+str(n))
 finally:
  profile.disable();elapsed=time.perf_counter()-start
  os.fsync=original_sync;fcntl.fcntl=original_fcntl;subprocess.Popen=original_popen
 assert s.read('/write-profile-large',0,16*65536)==b'P'*(16*65536)
 for n in range(8,16):assert s.read('/write-profile-small-'+str(n),0,4096)==b'S'*4096
text=io.StringIO();pstats.Stats(profile,stream=text).sort_stats('cumulative').print_stats(30)
(base/'profile.txt').write_text(text.getvalue())
result=dict(result='passed',source=str(a.source),code=str(a.code) if a.code else str(Path(__file__).resolve().parent),
 seconds=elapsed,metrics=metrics,transactions=65,sequential_write_bytes=16*65536,small_files=16,
 diagnostics=str(base),scope='Owned regular-image copy. Instrumented wall time includes blocking/socket/thread scheduling; cumulative profile times are not CPU-only or additive. Native child fsync calls are outside the Python counters. No physical disk or power-loss qualification.')
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
