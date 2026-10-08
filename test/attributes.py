#!/usr/bin/env python3
"""Ownership and upstream path regressions on disposable images."""
import errno, hashlib, os, re, shutil, subprocess, tempfile
from pathlib import Path
mkfs=os.environ.get("MKE2FS") or shutil.which("mke2fs")
debugfs=os.environ.get("DEBUGFS") or shutil.which("debugfs")
assert mkfs and debugfs, "e2fsprogs sbin must be in PATH"
count=0
with tempfile.TemporaryDirectory(prefix="ext4fuse-attributes-") as tmp:
 root=Path(tmp); host=root/"payload"; host.write_bytes(b"ext4 fixture\n")
 image=root/"fixture.img"; image.write_bytes(bytes(32*1024*1024))
 subprocess.run([mkfs,"-q","-F","-t","ext4",str(image)],check=True,capture_output=True)
 def debug(cmd):
  return subprocess.run([debugfs,"-w","-R",cmd,str(image)],capture_output=True,text=True,check=True).stdout
 debug("mkdir /.ssh")
 for path in ["/payload","/.hidden","/.ssh/config","/07:12:35.jpeg","/space name"]:
  debug('write %s "%s"'%(host,path))
 def probe(op,path):
  global count
  before=hashlib.sha256(image.read_bytes()).digest()
  p=subprocess.run(["./test/corruption-probe",str(image),op,path],capture_output=True,text=True,timeout=5)
  assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr)
  assert before==hashlib.sha256(image.read_bytes()).digest()
  count+=1; return p.stdout.splitlines()
 for uid,gid in [(0,0),(65535,65535),(65536,131072),(70001,80002),(4294967294,4294967293)]:
  debug("set_inode_field /payload uid %d"%uid);debug("set_inode_field /payload gid %d"%gid)
  for mode in [0o100000,0o100600,0o100640,0o100755]:
   debug("set_inode_field /payload mode 0%o"%mode)
   lines=probe("stat","/payload");assert lines[0]=="0"
   values=lines[1].split();assert int(values[0])==uid and int(values[1])==gid,values
   assert int(values[2],8)==mode & ~0o222,values
   number=int(re.search(r"Inode:\s*(\d+)",debug("stat /payload")).group(1))
   assert int(values[3])==number,values
 for path in ["/.hidden","/.ssh/config","/07:12:35.jpeg","/space name"]:
  lines=probe("read",path);assert lines==["13",b"ext4 fixture\n".hex()],lines
 for path in ["/missing","/missing/child","/.ssh/missing"]:
  for op in ["stat","list","read"]:
   assert int(probe(op,path)[0])==-errno.ENOENT
 assert probe("list","/.ssh")==["0"]
 assert int(probe("list","/.ssh/config")[0])==-errno.ENOTDIR
print("PASS: %d ownership/mode/inode/path checks"%count)
