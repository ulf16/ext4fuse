#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real mounted indexed namespace and live file/directory handles on owned images."""
import argparse,hashlib,json,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
import chain
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
here=Path(__file__).resolve().parent

def check(v):
 global checks
 assert v;checks+=1

def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120);assert r.returncode==0,r.stdout+r.stderr;return r.stdout

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def unmount(path):run(['/sbin/umount',path] if sys.platform=='darwin' else ['fusermount3','-u',path])

with tempfile.TemporaryDirectory(prefix='mounted-indexed-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for number,(block,checksum,extent) in enumerate(((1024,False,False),(4096,True,True))):
  seed=tmp/f'{number}.img'
  with seed.open('wb') as f:f.truncate(32*1024**2)
  options=['dir_index','^orphan_file','extents' if extent else '^extents,^64bit','metadata_csum' if checksum else '^metadata_csum,^uninit_bg']
  run(['mke2fs','-q','-F','-t','ext4','-b',block,'-O',','.join(options),seed])
  payload=tmp/'payload';payload.write_bytes(b'indexed mount seed')
  commands=tmp/'commands';commands.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n'+''.join(f'mkdir /{d}\nset_inode_field /{d} uid {os.getuid()}\nset_inode_field /{d} gid {os.getgid()}\nset_inode_field /{d} mode 040777\n'+''.join(f'write {payload} /{d}/entry{i:04d}'+('x'*180)+'\n' for i in range(200)) for d in ('many','other')))
  run(['debugfs','-w','-f',commands,seed]);r=subprocess.run(['e2fsck','-fyD',str(seed)],capture_output=True);check(r.returncode in (0,1));run(['e2fsck','-fn',seed]);before=sha(seed)
  root=tmp/f'chain{number}';chain.clone(seed,root);mount=tmp/f'mount{number}';mount.mkdir();log=tmp/f'mount{number}.log'
  with log.open('wb') as output:
   proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount],stdout=output,stderr=output)
   try:
    for unused in range(150):
     if proc.poll() is not None:raise AssertionError(log.read_text())
     if os.path.ismount(mount):break
     time.sleep(.1)
    check(os.path.ismount(mount));many=mount/'many';other=mount/'other'
    check(len(os.listdir(many))==200)
    new=many/'new';new.write_bytes(b'mounted indexed data');check(new.read_bytes()==b'mounted indexed data')
    descriptor=os.open(new,os.O_RDWR)
    os.link(new,other/'hard');os.rename(new,other/'moved');check((other/'moved').read_bytes()==b'mounted indexed data');os.unlink(other/'hard');os.unlink(other/'moved')
    check(os.pread(descriptor,20,0)==b'mounted indexed data');os.pwrite(descriptor,b'live',0);os.fsync(descriptor);os.close(descriptor)
    sub=many/'sub';sub.mkdir();os.symlink('../entry0000'+'x'*180,sub/'sym');check((sub/'sym').read_bytes()==b'indexed mount seed')
    os.rename(sub,other/'sub');check(os.readlink(other/'sub'/'sym')=='../entry0000'+'x'*180);(other/'sub'/'sym').unlink();(other/'sub').rmdir()
    dirfd=os.open(many,os.O_RDONLY|os.O_DIRECTORY)
    try:
     fd=os.open('relative',os.O_CREAT|os.O_RDWR,0o600,dir_fd=dirfd);os.write(fd,b'indexed dirfd');os.close(fd)
     check((many/'relative').read_bytes()==b'indexed dirfd')
     os.rename(many,other/'relocated');check((other/'relocated'/'relative').read_bytes()==b'indexed dirfd')
     os.unlink('relative',dir_fd=dirfd);os.rename(other/'relocated',many)
    finally:os.close(dirfd)
    check(len(os.listdir(many))==200);check(not any(n.startswith('.fuse_hidden') for n in os.listdir(other)))
    unmount(mount);check(proc.wait(timeout=30)==0)
   finally:
    if os.path.ismount(mount):unmount(mount)
    if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
  run(['e2fsck','-fn',root/'image.img']);check(sha(seed)==before)
  print('PASS mounted indexed namespace',block,checksum,extent,flush=True)
(a.work/'mounted-indexed-results.json').write_text(json.dumps(dict(result='passed',checks=checks),indent=2)+'\n');print('PASS',checks,'mounted indexed checks',flush=True)
