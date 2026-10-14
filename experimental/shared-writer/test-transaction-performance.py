#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Measure actual image bytes read and latency for isolated small transactions."""
import argparse,json,os,sys,time
from pathlib import Path
from unittest.mock import patch
p=argparse.ArgumentParser();p.add_argument('--code',type=Path);p.add_argument('--work',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--max-passes',type=float);a=p.parse_args()
if a.code:sys.path.insert(0,str(a.code))
import chain,inplace,session,durable
from credentials import Credentials
chain.clone(a.source,a.root)
counts={'image_bytes_read':0,'image_read_calls':0}
class Counted:
 def __init__(self,f):self.f=f
 def __getattr__(self,name):return getattr(self.f,name)
 def __enter__(self):return self
 def __exit__(self,*args):return self.f.__exit__(*args)
 def read(self,*args):
  data=self.f.read(*args);counts['image_bytes_read']+=len(data);counts['image_read_calls']+=1;return data
 def readinto(self,b):
  n=self.f.readinto(b);counts['image_bytes_read']+=n;counts['image_read_calls']+=1;return n
with session.Session(a.root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
 h=s.openat(None,'/performance','rw',create=True);h.close()
 info=os.stat(a.root/'image.img');identity=(info.st_dev,info.st_ino)
 def wrap(f):
  if isinstance(f,Counted):return f
  st=os.fstat(f.fileno());return Counted(f) if (st.st_dev,st.st_ino)==identity else f
 regular=durable.regular;fdopen=os.fdopen
 def measured_regular(path):return wrap(regular(path))
 def measured_fdopen(*args,**kwargs):return wrap(fdopen(*args,**kwargs))
 with patch.object(chain,'regular',measured_regular),patch.object(inplace,'regular',measured_regular),patch.object(inplace.block,'regular',measured_regular),patch.object(os,'fdopen',measured_fdopen):
  start=time.perf_counter()
  for i in range(5):s.apply([dict(kind='write',path='/performance',offset=i*4096,data_hex=(bytes([i+1])*4096).hex())])
  elapsed=time.perf_counter()-start
 assert s.read('/performance',0,4096)==bytes([1])*4096
counts.update(seconds=elapsed,image_size=info.st_size,transactions=5,read_passes=counts['image_bytes_read']/info.st_size/5)
if a.max_passes is not None:assert counts['read_passes']<=a.max_passes,counts
a.output.write_text(json.dumps(counts,indent=2)+'\n');print(json.dumps(counts),flush=True)
