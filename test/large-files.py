#!/usr/bin/env python3
"""Large logical files in small images; compare mapping and allocation with debugfs."""
import errno, hashlib, os, re, shutil, struct, subprocess, tempfile
from pathlib import Path
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs, 'e2fsprogs sbin must be in PATH'
checks=0
# Optional fixture destination lets the separate mounted test reuse the ext4 file.
with tempfile.TemporaryDirectory(prefix='ext4fuse-large-') as tmp:
 root=Path(tmp); host=root/'payload'; marker=b'large fixture payload\n'; host.write_bytes(marker)
 def debug(image,cmd):
  p=subprocess.run([debugfs,'-w','-R',cmd,str(image)],capture_output=True,text=True,check=True)
  assert not any(x in p.stderr for x in ['Could not','not found','allocating block','Usage:']),p.stderr
  return p.stdout
 def probe(image,op,path,offset=0):
  global checks
  p=subprocess.run(['./test/corruption-probe',str(image),op,path,str(offset)],capture_output=True,text=True,timeout=10)
  assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr)
  checks+=1;return p.stdout.splitlines()
 def allocation(image,path):
  lines=probe(image,'allocation',path);assert lines[0]=='0',lines
  size,blocks,blksize=map(int,lines[1].split())
  stat=debug(image,'stat '+path)
  assert size==int(re.search(r'Size:\s*(\d+)',stat).group(1)),stat
  assert blocks==int(re.search(r'Blockcount:\s*(\d+)',stat).group(1)),(blocks,stat)
  return size,blocks,blksize
 for kind in ['ext4','ext2']:
  block=4096;image=root/(kind+'.img');image.write_bytes(bytes(32*1024*1024))
  subprocess.run([mkfs,'-q','-F','-t',kind,'-b',str(block),str(image)],check=True,capture_output=True)
  debug(image,'write %s /large'%host)
  per=block//4;double=12+per;triple=double+per*per
  logicals=sorted({0,11,12,double-1,double,triple-1,triple,(4*1024**3)//block, (5*1024**3)//block})
  markers={}
  for logical in logicals:
   physical=int(debug(image,'bmap -a /large %d'%logical).strip())
   content=(b'block %d\n'%logical).ljust(64,b'!');markers[logical]=content
   with image.open('r+b') as f:f.seek(physical*block);f.write(content)
  size=5*1024**3+13;debug(image,'set_inode_field /large size %d'%size)
  before=hashlib.sha256(image.read_bytes()).digest()
  for logical in logicals:
   for offset in [logical*block,logical*block+5,logical*block+block-8]:
    length=min(64,max(0,size-offset));expected=bytearray(length)
    for pos in range(length):
     l=(offset+pos)//block;within=(offset+pos)%block
     if l in markers and within<64:expected[pos]=markers[l][within]
    lines=probe(image,'read','/large',offset)
    assert int(lines[0])==length,(kind,offset,lines)
    assert (bytes.fromhex(lines[1]) if length else b'')==expected,(kind,offset,lines,expected)
  for offset in [size-8,size,size+1,2**32-8,2**32+5]:
   length=min(64,max(0,size-offset));expected=bytearray(length)
   for pos in range(length):
    l=(offset+pos)//block;within=(offset+pos)%block
    if l in markers and within<64:expected[pos]=markers[l][within]
   lines=probe(image,'read','/large',offset);assert int(lines[0])==length
   assert (bytes.fromhex(lines[1]) if length else b'')==expected,(offset,lines)
  for offset,length in [(8*1024**2,8*1024**2),(2**32-16,1024**2),(size-32,1024**2)]:
   result=subprocess.run(['./test/corruption-probe',str(image),'bulk','/large',str(offset),str(length)],capture_output=True,timeout=15)
   assert result.returncode==0 and not result.stderr,(result.returncode,result.stderr)
   header,contents=result.stdout.split(b'\n',1)
   expected=bytearray(min(length,size-offset))
   for logical,content in markers.items():
    first=max(offset,logical*block);last=min(offset+len(expected),logical*block+len(content))
    if last>first:expected[first-offset:last-offset]=content[first-logical*block:last-logical*block]
   assert int(header)==len(expected) and contents==expected,(kind,offset,header)
   checks+=1
  assert allocation(image,'/large')[2]==block
  assert before==hashlib.sha256(image.read_bytes()).digest()
  if kind=='ext4' and os.environ.get('LARGE_FIXTURE'):
   shutil.copyfile(image,os.environ['LARGE_FIXTURE'])
  if kind=='ext4':
   # Metadata-only accounting variants are synthetic, not claims of real allocation.
   original=image.read_bytes()
   for high,low,huge in [(0,16,False),(1,17,False),(2,19,True),(65535,0xffffffff,True)]:
    debug(image,'set_inode_field /large blocks_hi %d'%high)
    debug(image,'set_inode_field /large blocks_lo %d'%low)
    debug(image,'set_inode_field /large flags %d'%(0x80000|(0x40000 if huge else 0)))
    lines=probe(image,'allocation','/large');assert lines[0]=='0'
    values=list(map(int,lines[1].split()));expected=(high*2**32+low)*(block//512 if huge else 1)
    assert values==[size,expected,block],values
    image.write_bytes(original)
   debug(image,'set_inode_field /large size 18446744073709551615')
   assert probe(image,'allocation','/large')==[str(-errno.EOVERFLOW)]
 # A real depth-two extent tree: >4 leaves of 84 entries at 1KiB block size.
 image=root/'deep.img';image.write_bytes(bytes(32*1024*1024));block=1024
 subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),str(image)],check=True,capture_output=True)
 data=bytes((i%251)+1 for i in range(block*1200));host.write_bytes(data)
 debug(image,'write %s /deep'%host)
 commands=root/'punch';commands.write_text(''.join('punch /deep %d %d\n'%(i,i) for i in range(1,1200,2)))
 subprocess.run([debugfs,'-w','-f',str(commands),str(image)],check=True,capture_output=True)
 stat=debug(image,'stat /deep');number=int(re.search(r'Inode:\s*(\d+)',stat).group(1));raw=image.read_bytes()
 table=struct.unpack_from('<I',raw,2*block+8)[0]*block;inode_size=struct.unpack_from('<H',raw,1024+0x58)[0]
 assert struct.unpack_from('<H',raw,table+(number-1)*inode_size+46)[0]>=2,stat
 dump=root/'dump';debug(image,'dump /deep %s'%dump)
 expected=bytearray(data)
 for i in range(1,1200,2):expected[i*block:(i+1)*block]=bytes(block)
 assert dump.read_bytes()==expected
 before=hashlib.sha256(image.read_bytes()).digest()
 for offset in [0,block-8,block,2*block,168*block-8,672*block,1198*block,len(data)-8,len(data)]:
  content=expected[offset:offset+64];lines=probe(image,'read','/deep',offset)
  assert int(lines[0])==len(content) and (bytes.fromhex(lines[1]) if content else b'')==content,(offset,lines)
 allocation(image,'/deep');assert before==hashlib.sha256(image.read_bytes()).digest()
 # Exercise huge-file unit conversion for the other supported block sizes.
 host.write_bytes(marker)
 for block in [1024,2048]:
  image=root/('units-%d.img'%block);image.write_bytes(bytes(16*1024*1024))
  subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),str(image)],check=True,capture_output=True)
  debug(image,'write %s /units'%host)
  debug(image,'set_inode_field /units blocks_hi 3')
  debug(image,'set_inode_field /units blocks_lo 7')
  debug(image,'set_inode_field /units flags %d'%(0x80000|0x40000))
  lines=probe(image,'allocation','/units');assert lines[0]=='0'
  assert list(map(int,lines[1].split()))==[len(marker),(3*2**32+7)*(block//512),block]
print('PASS: %d large-file/allocation/deep-extent checks'%checks)
