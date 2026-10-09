#!/usr/bin/env python3
"""Capacity preflight on disposable read-only macOS disk-image devices."""
import hashlib,pathlib,plistlib,shutil,struct,subprocess,tempfile
assert shutil.which('hdiutil') and shutil.which('mke2fs')
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
   result=subprocess.run(['hdiutil','attach','-readonly','-nomount','-imagekey','diskimage-class=CRawDiskImage','-plist',str(image)],capture_output=True,check=True)
   entries=plistlib.loads(result.stdout)['system-entities'];device=min([e['dev-entry'] for e in entries if 'dev-entry' in e],key=len)
   for path in [device,device.replace('/dev/disk','/dev/rdisk')]:
    p=subprocess.run(['./test/feature-probe',path],capture_output=True,text=True)
    if oversized:assert p.returncode==1 and 'declared filesystem size' in p.stderr,(path,p.returncode,p.stderr)
    else:
     assert p.returncode==0,(path,p.returncode,p.stderr)
     read=subprocess.run(['./test/corruption-probe',path,'read','/payload'],capture_output=True,text=True,check=True)
     assert read.stdout.splitlines()==['64',bytes(range(64)).hex()],read.stdout
   assert before==hashlib.sha256(image.read_bytes()).digest()
  finally:
   if device:subprocess.run(['hdiutil','detach',device],check=True,capture_output=True)
 print('PASS: actual macOS block/raw devices, capacity match/oversize rejection, unchanged disposable images')
