#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual FUSE multi-gigabyte positional I/O with bounded transaction history."""
import argparse,hashlib,json,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
import chain
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);a=p.parse_args();checks=0
here=Path(__file__).resolve().parent

def check(v):
 global checks
 assert v;checks+=1

def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120);assert r.returncode==0,r.stdout+r.stderr;return r.stdout

def unmount(path):run(['/sbin/umount',path] if sys.platform=='darwin' else ['fusermount3','-u',path])

sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name);check(bool(sources))
with tempfile.TemporaryDirectory(prefix='mounted-large-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for n,source in enumerate((sources[0],sources[-1])):
  before=hashlib.sha256(source.read_bytes()).digest();seed=tmp/f'seed{n}.img';shutil.copyfile(source,seed)
  commands=tmp/'commands';commands.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n');run(['debugfs','-w','-f',commands,seed])
  root=tmp/f'chain{n}';chain.clone(seed,root);mount=tmp/f'mount{n}';mount.mkdir();log=tmp/f'mount{n}.log'
  with log.open('wb') as output:
   proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount,'--checkpoint-every','3'],stdout=output,stderr=output)
   try:
    for unused in range(150):
     if proc.poll() is not None:raise AssertionError(log.read_text())
     if os.path.ismount(mount):break
     time.sleep(.1)
    check(os.path.ismount(mount));path=mount/'large';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
    try:
     os.ftruncate(fd,9*1024**3+1)
     for offset in (64*1024**2+1,2**32-3,8*1024**3):
      data=b'mounted large data';check(os.pwrite(fd,data,offset)==len(data));check(os.pread(fd,len(data),offset)==data)
     check(os.fstat(fd).st_size==9*1024**3+1)
     check(os.pread(fd,16,7*1024**3)==bytes(16));path.unlink();check(os.pread(fd,18,8*1024**3)==b'mounted large data')
     os.ftruncate(fd,1);os.ftruncate(fd,9*1024**3);check(os.pread(fd,18,8*1024**3)==bytes(18));os.fsync(fd)
    finally:os.close(fd)
    check(len(list(root.glob('g-*')))<3);check((root/'checkpoint').exists())
    unmount(mount);check(proc.wait(timeout=30)==0)
   finally:
    if os.path.ismount(mount):unmount(mount)
    if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
  run(['e2fsck','-fn',root/'image.img']);check(hashlib.sha256(source.read_bytes()).digest()==before)
  print('PASS mounted large writes',source.name,flush=True)
(a.work/'mounted-large-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n');print('PASS',checks,'mounted large checks',flush=True)
