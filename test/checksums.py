#!/usr/bin/env python3
"""Real e2fsprogs checksums, individual byte flips, and read-only probes."""
import errno, hashlib, os, re, shutil, struct, subprocess, tempfile
from pathlib import Path
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
fsck=shutil.which('e2fsck')
assert mkfs and debugfs and fsck, 'e2fsprogs sbin must be in PATH'
checks=0
with tempfile.TemporaryDirectory(prefix='ext4fuse-checksums-') as tmp:
 root=Path(tmp); host=root/'payload'; host.write_bytes(bytes(range(256))*300)
 def debug(image,cmd):
  return subprocess.run([debugfs,'-w','-R',cmd,str(image)],capture_output=True,text=True,check=True).stdout
 def check(image,operation='list',path='/',expected=0,reason=None):
  global checks
  before=hashlib.sha256(image.read_bytes()).digest()
  p=subprocess.run(['./test/corruption-probe',str(image),operation,path],capture_output=True,text=True,timeout=10)
  if reason:
   assert p.returncode==2 and reason in p.stderr,(p.returncode,p.stderr)
  else:
   assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr)
   assert int(p.stdout.splitlines()[0])==expected,(operation,path,p.stdout)
   if operation=='read' and expected==64: assert bytes.fromhex(p.stdout.splitlines()[1])==host.read_bytes()[:64]
  assert before==hashlib.sha256(image.read_bytes()).digest()
  checks+=1
 for label,opts in [('default',[]),('seed',['-O','metadata_csum_seed']),('32bit',['-O','^64bit']),('inode128',['-I','128']),('legacy',['-O','^metadata_csum,uninit_bg']),('plain',['-O','^metadata_csum,^uninit_bg'])]:
  image=root/(label+'.img'); image.write_bytes(bytes(32*1024*1024))
  subprocess.run([mkfs,'-q','-F','-t','ext4','-b','4096',*opts,str(image)],check=True,capture_output=True)
  debug(image,'write %s /payload'%host)
  # Fragmentation forces an external extent leaf with a checksum tail.
  for i in range(1,16,2): debug(image,'punch /payload %d %d'%(i,i))
  check(image); check(image,'read','/payload',64)
  original=image.read_bytes(); sb=1024; block=4096
  inode_size=struct.unpack_from('<H',original,sb+0x58)[0]
  table=struct.unpack_from('<I',original,block+8)[0]*block
  def inode(path): return int(re.search(r'Inode:\s*(\d+)',debug(image,'stat '+path)).group(1))
  number=inode('/payload'); ino=table+(number-1)*inode_size
  rootino=table+inode_size
  directory=struct.unpack_from('<I',original,rootino+60)[0]*block
  child=struct.unpack_from('<I',original,ino+56)[0]*block
  metadata=bool(struct.unpack_from('<I',original,sb+0x64)[0]&0x400)
  def flip(offset,op='list',path='/',expected=-errno.EIO,reason=None):
   data=bytearray(original); data[offset]^=1; image.write_bytes(data)
   try: check(image,op,path,expected,reason)
   finally: image.write_bytes(original)
  if metadata:
   for off in [sb+0x78,sb+0x3fc]: flip(off,reason='superblock checksum mismatch')
   flip(sb+0x175,reason='unsupported metadata checksum algorithm')
  if label!='plain':
   for off in [block+12,block+30]: flip(off,reason='group descriptor checksum mismatch')
  if metadata:
   for off in [ino+8,ino+124,ino+inode_size-1]: flip(off,'read','/payload')
   if inode_size>128: flip(ino+130,'read','/payload')
   for off in [directory+8,directory+block-4,directory+block-12]: flip(off)
   assert struct.unpack_from('<H',original,ino+46)[0]>0, 'fixture needs external extent tree'
   maximum=struct.unpack_from('<H',original,child+4)[0]; tail=child+12+maximum*12
   for off in [child+20,tail]: flip(off,'read','/payload')
 # Create a real htree root and interior nodes using e2fsck directory indexing.
 image=root/'indexed.img'; image.write_bytes(bytes(64*1024*1024))
 subprocess.run([mkfs,'-q','-F','-t','ext4','-b','1024',str(image)],check=True,capture_output=True)
 tiny=root/'tiny'; tiny.write_bytes(host.read_bytes()[:256])
 commands=root/'commands'; commands.write_text('mkdir /many\n'+''.join('write %s /many/file%04d%s\n'%(tiny,i,'x'*100) for i in range(1100)))
 subprocess.run([debugfs,'-w','-f',str(commands),str(image)],check=True,capture_output=True)
 result=subprocess.run([fsck,'-fyD',str(image)],capture_output=True,text=True)
 assert result.returncode in (0,1,2),result.stderr
 check(image); check(image,'list','/many'); check(image,'read','/many/file1099'+'x'*100,64)
 baseline=image.read_bytes()
 stat=debug(image,'stat /many'); number=int(re.search(r'Inode:\s*(\d+)',stat).group(1))
 # bmap handles the directory's own extent layout independently.
 blocks=int(re.search(r'Size:\s*(\d+)',stat).group(1))//1024
 mappings=[int(debug(image,'bmap /many %d'%i).strip()) for i in range(blocks)]
 rootblock=mappings[0]*1024
 assert baseline[rootblock+30]==1, 'fixture needs an internal htree level'
 internal=next(i for i in range(1,blocks) if struct.unpack_from('<I',baseline,mappings[i]*1024)[0]==0 and struct.unpack_from('<H',baseline,mappings[i]*1024+4)[0]==1024)
 for logical in [0,1,internal]:
  physical=mappings[logical]
  start=physical*1024
  data=bytearray(baseline)
  # Flip hash index/leaf payload while keeping record lengths intact.
  data[start+40]^=1; image.write_bytes(data)
  try: check(image,'list','/many',-errno.EIO)
  finally: image.write_bytes(baseline)
print('PASS: %d checksum checks (valid variants, byte flips, indexed directories)'%checks)
