#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guarded device replay fault matrix on explicitly simulated disposable targets."""
import argparse,errno,hashlib,importlib.util,json,os,random,struct,tempfile
from pathlib import Path
from unittest.mock import patch
import inplace
from device_admission import Device
spec=importlib.util.spec_from_file_location('device_writer',Path(__file__).with_name('device-writer.py'));d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
class Simulated:
 def __init__(self,path,sector):self.fd=os.open(path,os.O_RDWR);self.size=os.fstat(self.fd).st_size;self.sector=sector;self.identity={'kind':'simulation','token':1};self.flushes=[]
 def check(self):
  if os.fstat(self.fd).st_size!=self.size:raise OSError('removed/changed simulated target')
 def flush(self):os.fsync(self.fd);self.flushes.append(d.read_at(self.fd,self.size,0))
 def close(self):os.close(self.fd)
def check(value):
 global checks
 assert value;checks+=1
def setup(root,sector):
 root.mkdir(mode=0o700);old=bytearray(random.Random(41).randbytes(5*4096));old[d.MAGIC:d.MAGIC+2]=b'\x53\xef';old[1128:1144]=bytes(range(16))
 new=bytearray(old);new[4]=91;new[4096:8192]=bytes([57])*4096;new[4*4096:]=bytes([93])*4096
 target=root/'simulation';target.write_bytes(old);t=Simulated(target,sector)
 records=b''.join(d.RECORD.pack(i,bytes(old[i*4096:(i+1)*4096]),bytes(new[i*4096:(i+1)*4096])) for i in (0,1,4))
 (root/'device-pages').write_bytes(records)
 h=lambda b:hashlib.sha256(b).hexdigest()
 state=dict(version=1,identity=t.identity,size=t.size,sector=sector,uuid=bytes(range(16)).hex(),base_sha256=h(old))
 inplace.seal(root,'device-transaction',dict(version=1,count=3,size=t.size,base_sha256=h(old),new_sha256=h(new),log_sha256=h(records)))
 return t,state,bytes(old),bytes(new)
with tempfile.TemporaryDirectory(prefix='device-replay-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for sector in (512,4096):
  phases=['device:guarded','device:data-synced','device:published','device:complete']+[f'device:sector:{i}:{j}' for i in range(3) for j in range(4096//sector)]
  for num,phase in enumerate(phases):
   root=tmp/f'{sector}-{num}';t,state,old,new=setup(root,sector);hit=[]
   def fail_at(name):
    if name==phase and not hit:hit.append(name);raise OSError(errno.EIO,'simulated loss at '+name)
   try:
    with patch.object(d,'boundary',fail_at):
     try:d.replay(root,t,state)
     except OSError as e:check(e.errno==errno.EIO)
     else:raise AssertionError('fault not reached')
    check(bool(hit));current=d.read_at(t.fd,t.size,0)
    check(current[d.MAGIC:d.MAGIC+2]!=b'\x53\xef' or current==old or current==new)
    for synced in t.flushes:check(synced[d.MAGIC:d.MAGIC+2]!=b'\x53\xef' or synced==old or synced==new)
    d.replay(root,t,state);check(d.read_at(t.fd,t.size,0)==new);d.replay(root,t,state);check(d.read_at(t.fd,t.size,0)==new)
   finally:t.close()
  # Partial sector writes: recovery must work even if magic changes only partly.
  for fail_number in range(2+3*(4096//sector)):
   root=tmp/f'torn-{sector}-{fail_number}';t,state,old,new=setup(root,sector);calls=[];original=d.write_at
   def torn(fd,data,offset):
    calls.append(offset)
    if len(calls)==fail_number+1:
     os.pwrite(fd,memoryview(data)[:len(data)//2],offset);raise OSError(errno.EIO,'torn sector')
    return original(fd,data,offset)
   try:
    with patch.object(d,'write_at',torn):
     try:d.replay(root,t,state)
     except OSError as e:check(e.errno==errno.EIO)
     else:raise AssertionError('torn sector not reached')
    current=d.read_at(t.fd,t.size,0);check(current[d.MAGIC:d.MAGIC+2]!=b'\x53\xef' or current==old or current==new)
    d.replay(root,t,state);check(d.read_at(t.fd,t.size,0)==new)
   finally:t.close()
 for problem in ('identity','log','clean','unstarted','size'):
  root=tmp/problem;t,state,old,new=setup(root,512)
  try:
   if problem=='identity':t.identity={'kind':'simulation','token':2}
   if problem=='log':
    with (root/'device-pages').open('r+b') as f:f.seek(20);f.write(b'BAD')
   if problem=='clean':os.pwrite(t.fd,b'BAD',2*4096)
   if problem=='unstarted':os.pwrite(t.fd,b'BAD',4096)
   if problem=='size':os.ftruncate(t.fd,t.size-4096)
   before=os.pread(t.fd,t.size,0)
   try:d.replay(root,t,state)
   except (OSError,ValueError):check(True)
   else:raise AssertionError('unsafe device accepted: '+problem)
   check(os.pread(t.fd,t.size,0)==before)
  finally:t.close()
 # Production admission must never interpret a regular target as a device.
 fake=tmp/'not-a-device';fake.write_bytes(bytes(4096))
 try:
  with Device(fake,tmp):pass
 except OSError:check(True)
 else:raise AssertionError('regular file admitted as physical device')
(a.work/'device-replay-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n');print('PASS',checks,'guarded device replay checks')
