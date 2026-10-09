#!/usr/bin/env python3
"""Capacity preflight on disposable read-only Linux loop devices (needs sudo)."""
import hashlib,pathlib,shutil,struct,subprocess,tempfile
assert shutil.which('losetup') and shutil.which('mke2fs')
with tempfile.TemporaryDirectory(prefix='ext4fuse-device-capacity-') as tmp:
 image=pathlib.Path(tmp)/'image'
 with image.open('wb') as f:f.truncate(32*1024**2)
 subprocess.run(['mke2fs','-q','-F','-t','ext4','-O','^metadata_csum,^uninit_bg',str(image)],capture_output=True,check=True)
 payload=pathlib.Path(tmp)/'payload';payload.write_bytes(bytes(range(64)))
 subprocess.run(['debugfs','-w','-R','write %s /payload'%payload,str(image)],capture_output=True,check=True)
 original=image.read_bytes()
 for oversized in [False,True]:
  data=bytearray(original)
  if oversized:struct.pack_into('<I',data,1024+4,struct.unpack_from('<I',data,1024+4)[0]*2)
  image.write_bytes(data);before=hashlib.sha256(data).digest();device=None
  try:
   device=subprocess.check_output(['sudo','-n','losetup','--read-only','--find','--show',str(image)],text=True).strip()
   p=subprocess.run(['sudo','-n','./test/feature-probe',device],capture_output=True,text=True)
   if oversized:assert p.returncode==1 and 'declared filesystem size' in p.stderr,(p.returncode,p.stderr)
   else:
    assert p.returncode==0,(p.returncode,p.stderr)
    read=subprocess.run(['sudo','-n','./test/corruption-probe',device,'read','/payload'],capture_output=True,text=True,check=True)
    assert read.stdout.splitlines()==['64',bytes(range(64)).hex()],read.stdout
   assert before==hashlib.sha256(image.read_bytes()).digest()
  finally:
   if device:subprocess.run(['sudo','-n','losetup','--detach',device],check=True)
 print('PASS: actual Linux loop-device capacity match/oversize rejection, reads and unchanged images')
