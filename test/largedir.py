#!/usr/bin/env python3
"""Fsck-certified three-level htrees; repaired-CRC structural mutations."""
import errno,hashlib,os,pathlib,re,shlex,shutil,struct,subprocess,tempfile,time
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');fsck=shutil.which('e2fsck')
assert mkfs and debugfs and fsck
checks=0

def crc(seed,data):
 for b in data:
  seed^=b
  for _ in range(8):seed=(seed>>1)^(0x82f63b78 if seed&1 else 0)
 return seed

with tempfile.TemporaryDirectory(prefix='ext4fuse-largedir-') as tmp:
 r=pathlib.Path(tmp);host=r/'payload';host.write_bytes(b'large-directory payload')
 env=os.environ.copy();prefix=pathlib.Path(mkfs).resolve().parent.parent
 env['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')+os.pathsep+env.get('PKG_CONFIG_PATH','')
 flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','--static','ext2fs'],env=env,text=True))
 subprocess.run(['cc','test/largedir-set.c',*flags,'-o',str(r/'deepen')],check=True)
 def debug(image,command):return subprocess.run([debugfs,'-w','-R',command,str(image)],capture_output=True,text=True,check=True).stdout
 def probe(image,op,path='/many',offset=None,limit=None):
  global checks
  args=['./test/corruption-probe',str(image),op,path]+([] if offset is None else [str(offset)])
  if limit is not None:args.append(str(limit))
  p=subprocess.run(args,capture_output=True,text=True,timeout=30)
  assert p.returncode==0 and not p.stderr,(args,p.returncode,p.stderr)
  checks+=1
  return int(p.stdout.splitlines()[0]),p.stdout.splitlines()[1:]
 for block in [1024,2048,4096]:
  for mode in ['plain','checksum','seed']:
   image=r/'image';image.write_bytes(bytes(64*1024**2))
   opts='large_dir'+{'plain':',^metadata_csum,^uninit_bg','checksum':'','seed':',metadata_csum_seed'}[mode]
   subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-O',opts,str(image)],capture_output=True,check=True)
   names=['file%04d'%i+'x'*100 for i in range(1100)]
   commands=r/'commands';commands.write_text('mkdir /high\nmkdir /many\n'+''.join('write %s /many/%s\n'%(host,name) for name in names))
   subprocess.run([debugfs,'-w','-f',str(commands),str(image)],capture_output=True,check=True)
   p=subprocess.run([fsck,'-fyD',str(image)],capture_output=True);assert p.returncode in [0,1],p.stdout+p.stderr
   stat=debug(image,'stat /many');number=int(re.search(r'Inode:\s*(\d+)',stat).group(1))
   subprocess.run([str(r/'deepen'),str(image),str(number)],capture_output=True,check=True)
   clean=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert clean.returncode==0,clean.stdout+clean.stderr
   baseline=image.read_bytes();before=hashlib.sha256(baseline).digest()
   stat=debug(image,'stat /many');blocks=int(re.search(r'Size:\s*(\d+)',stat).group(1))//block
   mappings=[int(debug(image,'bmap /many %d'%i).strip()) for i in range(blocks)]
   root=mappings[0]*block;assert baseline[root+30]==2
   first=struct.unpack_from('<I',baseline,root+36)[0];middle=mappings[first]*block
   second=struct.unpack_from('<I',baseline,middle+12)[0];bottom=mappings[second]*block
   started=time.monotonic();ret,summary=probe(image,'listnames');assert ret==0
   expected=0
   for name in names+['.','..']:expected^=crc(0xffffffff,name.encode())
   count,digest,_=map(int,summary[0].split());assert (count,digest)==(1102,expected)
   offset=0;count=0;digest=0
   while True:
    ret,page=probe(image,'listpage',offset=offset,limit=137);assert ret==0
    n,h,nextoff=map(int,page[0].split())
    if not n:break
    assert nextoff>offset;offset=nextoff;count+=n;digest^=h
   assert (count,digest)==(1102,expected)
   for i in [0,549,1099]:
    ret,data=probe(image,'read','/many/'+names[i]);assert ret==len(host.read_bytes()) and bytes.fromhex(data[0])==host.read_bytes()
   assert probe(image,'lookup','/many/missing')[0]==-errno.ENOENT
   assert probe(image,'list',offset=blocks*block)[0]==0
   assert before==hashlib.sha256(image.read_bytes()).digest()
   print('valid %s/%s: %d blocks, 1100 names, listing + lookups %.3fs'%(block,mode,blocks,time.monotonic()-started),flush=True)
   metadata=mode!='plain';seed=struct.unpack_from('<I',baseline,1024+0x270)[0] if mode=='seed' else crc(0xffffffff,baseline[1024+0x68:1024+0x78])
   # Generation and inode number form the per-directory checksum seed.
   generation=int(re.search(r'Generation:\s*(\d+)',stat).group(1));seed=crc(crc(seed,struct.pack('<I',number)),struct.pack('<I',generation))
   def repair(data,start):
    if not metadata:return
    off=32 if start==root else 8;limit,count=struct.unpack_from('<HH',data,start+off)
    if not count or count>limit or start+off+limit*8+8>start+block:return
    tail=start+off+limit*8;used=start+off+count*8
    h=crc(crc(seed,data[start:used]),data[tail:tail+4]);h=crc(h,bytes(4));struct.pack_into('<I',data,tail+4,h)
   mutations=[(root+30,'B',3),(root+29,'B',7),(root+28,'B',6),(root+31,'B',1),
              (root+24,'I',1),(root+34,'H',0),(root+32,'H',1),(root+8,'B',ord('X')),(bottom+24,'I',0)]
   for start,off in [(root,32),(middle,8),(bottom,8)]:
    mutations += [(start+off+4,'I',0),(start+off+4,'I',blocks),(start+off+4,'I',mappings.index(start//block)),(start+off+2,'H',0),(start+off,'H',0)]
    if metadata:mutations += [(start+off+struct.unpack_from('<H',baseline,start+off)[0]*8+4,'I',0)]
   for off,fmt,value in mutations:
    data=bytearray(baseline);struct.pack_into('<'+fmt,data,off,value)
    start=(off//block)*block
    # A checksum mutation deliberately stays unrepaired; structural ones do not.
    if not (metadata and off%block==((32 if start==root else 8)+struct.unpack_from('<H',baseline,start+(32 if start==root else 8))[0]*8+4)):repair(data,start)
    image.write_bytes(data);assert probe(image,'list')[0]==-errno.EIO,(block,mode,off,fmt,value)
   # Kernel index entries reserve the high four block-number bits.
   data=bytearray(baseline);child=struct.unpack_from('<I',data,root+36)[0]
   struct.pack_into('<I',data,root+36,child|0xf0000000);repair(data,root)
   image.write_bytes(data);assert probe(image,'list')[0]==0
   # Depth two requires the feature even with a correct directory checksum.
   data=bytearray(baseline);bits=struct.unpack_from('<I',data,1024+0x60)[0];struct.pack_into('<I',data,1024+0x60,bits&~0x4000)
   if metadata:struct.pack_into('<I',data,1024+0x3fc,crc(0xffffffff,data[1024:1024+0x3fc]))
   image.write_bytes(data);assert probe(image,'list')[0]==-errno.EIO
   image.write_bytes(baseline)
   # Isolated 64-bit cursor fixture: relocate a one-block directory beyond
   # 4 GiB, deliberately leaving holes. This is a boundary test, not a
   # fsck-certified sparse directory (full enumeration must reject its hole).
   highstat=debug(image,'stat /high');highnum=int(re.search(r'Inode:\s*(\d+)',highstat).group(1))
   assert highnum<=struct.unpack_from('<I',baseline,1024+0x28)[0]
   table=struct.unpack_from('<I',baseline,(2 if block==1024 else 1)*block+8)[0]*block
   isize=struct.unpack_from('<H',baseline,1024+0x58)[0];ino=table+(highnum-1)*isize
   assert struct.unpack_from('<H',baseline,ino+42)[0]==1 and struct.unpack_from('<H',baseline,ino+46)[0]==0
   logical=2**32//block+1;length=(logical+1)*block
   data=bytearray(baseline);struct.pack_into('<I',data,ino+52,logical)
   struct.pack_into('<I',data,ino+4,length&0xffffffff);struct.pack_into('<I',data,ino+108,length>>32)
   if metadata:
    struct.pack_into('<H',data,ino+124,0);struct.pack_into('<H',data,ino+130,0)
    fsseed=struct.unpack_from('<I',baseline,1024+0x270)[0] if mode=='seed' else crc(0xffffffff,baseline[1024+0x68:1024+0x78])
    ih=crc(crc(crc(fsseed,struct.pack('<I',highnum)),data[ino+100:ino+104]),data[ino:ino+isize])
    struct.pack_into('<H',data,ino+124,ih&65535);struct.pack_into('<H',data,ino+130,ih>>16)
   image.write_bytes(data)
   ret,stats=probe(image,'allocation','/high');assert ret==0 and int(stats[0].split()[0])==length
   ret,summary=probe(image,'listnames','/high',logical*block);assert ret==0 and int(summary[0].split()[0])==2
   assert probe(image,'list','/high',length)[0]==0
   assert probe(image,'list','/high',0)[0]==-errno.EIO
   assert probe(image,'list','/high',length+4)[0]==-errno.EIO
   image.write_bytes(baseline)
 print('PASS: %d largedir checks'%checks)
