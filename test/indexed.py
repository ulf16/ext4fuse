#!/usr/bin/env python3
"""Indexed lookup against debugfs: all hash variants, depth, collisions, I/O cost."""
import errno,hashlib,os,pathlib,re,shlex,shutil,struct,subprocess,tempfile
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');fsck=shutil.which('e2fsck');assert mkfs and debugfs and fsck
checks=0
with tempfile.TemporaryDirectory(prefix='ext4fuse-indexed-') as tmp:
 r=pathlib.Path(tmp);host=r/'payload';host.write_bytes(b'indexed directory payload')
 prefix=pathlib.Path(mkfs).resolve().parent.parent;env=os.environ.copy();env['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')+os.pathsep+env.get('PKG_CONFIG_PATH','')
 flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','--static','ext2fs'],env=env,text=True))
 subprocess.run(['cc','-I.','test/dirhash-reference.c','dirhash.c',*flags,'-o',str(r/'hash-reference')],check=True)
 subprocess.run([str(r/'hash-reference')],check=True)
 subprocess.run(['cc','test/largedir-set.c',*flags,'-o',str(r/'deepen')],check=True)
 def debug(image,cmd):return subprocess.run([debugfs,'-w','-R',cmd,str(image)],capture_output=True,text=True,check=True).stdout
 def probe(image,op,path):
  global checks
  p=subprocess.run(['./test/corruption-probe',str(image),op,path],capture_output=True,text=True,timeout=10)
  assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr);checks+=1
  return int(p.stdout.splitlines()[0])
 def batch(image,dirname,names,expected):
  global checks
  namesfile=r/'names';namesfile.write_text('\n'.join(names)+'\n')
  p=subprocess.run(['./test/lookup-batch',str(image),dirname,str(namesfile)],capture_output=True,text=True,check=True,timeout=30)
  assert not p.stderr,p.stderr
  actual=[tuple(map(int,line.split())) for line in p.stdout.splitlines()]
  assert actual==expected,(actual[:4],expected[:4]);checks+=len(names)
 def crc(seed,data):
  for b in data:
   seed^=b
   for _ in range(8):seed=(seed>>1)^(0x82f63b78 if seed&1 else 0)
  return seed
 for kind in ['legacy','half_md4','tea']:
  for unsigned in [False,True]:
   image=r/'image';image.write_bytes(bytes(64*1024**2))
   subprocess.run([mkfs,'-q','-F','-t','ext4','-b','1024','-O','large_dir,metadata_csum_seed',str(image)],capture_output=True,check=True)
   debug(image,'set_super_value def_hash_version '+kind)
   debug(image,'set_super_value flags '+('2' if unsigned else '1'))
   names=['file%04d'%i+'é'+'x'*100 for i in range(1100)]
   commands=r/'commands';commands.write_text('mkdir /many\n'+''.join('write %s /many/%s\n'%(host,n) for n in names))
   subprocess.run([debugfs,'-w','-f',str(commands),str(image)],capture_output=True,check=True)
   p=subprocess.run([fsck,'-fyD',str(image)],capture_output=True);assert p.returncode in [0,1],p.stdout+p.stderr
   number=int(re.search(r'Inode:\s*(\d+)',debug(image,'stat /many')).group(1))
   if unsigned:subprocess.run([str(r/'deepen'),str(image),str(number)],check=True)
   p=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert p.returncode==0,p.stdout+p.stderr
   baseline=image.read_bytes();before=hashlib.sha256(baseline).digest()
   reference={parts[5]:int(parts[1]) for line in debug(image,'ls -p /many').splitlines() if len(parts:=line.split('/'))>=7}
   batch(image,'/many',names+['missing'],[(0,reference[n]) for n in names]+[(-errno.ENOENT,0)])
   assert probe(image,'lookup','/many/.')==0 and probe(image,'lookup','/many/..')==0
   p=subprocess.run(['./test/index-probe',str(image),'/many','missing'],capture_output=True,text=True,check=True)
   a,n,fast,b,m,slow=map(int,p.stdout.split());assert a==b==-errno.ENOENT and fast<=4 and slow>fast*10,p.stdout;checks+=1
   print('%s %s: all 1100 names; missing lookup loads %d indexed vs %d linear directory blocks'%(kind,'unsigned' if unsigned else 'signed',fast,slow),flush=True)
   # Damage a node on the selected path while repairing its checksum.
   block=1024;rootblock=int(debug(image,'bmap /many 0').strip());root=rootblock*block
   depth=baseline[root+30];assert depth==(2 if unsigned else 1)
   first=struct.unpack_from('<I',baseline,root+36)[0];middle=int(debug(image,'bmap /many %d'%first).strip())*block
   seed=struct.unpack_from('<I',baseline,1024+0x270)[0]
   generation=int(re.search(r'Generation:\s*(\d+)',debug(image,'stat /many')).group(1))
   seed=crc(crc(seed,struct.pack('<I',number)),struct.pack('<I',generation))
   def repair(data,start):
    off=32 if start==root else 8;limit,count=struct.unpack_from('<HH',data,start+off);tail=start+off+limit*8
    h=crc(crc(seed,data[start:start+off+count*8]),data[tail:tail+4]);struct.pack_into('<I',data,tail+4,crc(h,bytes(4)))
   # Every root child pointing to root is a cycle regardless of the chosen hash.
   data=bytearray(baseline);count=struct.unpack_from('<H',data,root+34)[0]
   for i in range(count):struct.pack_into('<I',data,root+32+i*8+4,0)
   repair(data,root);image.write_bytes(data);assert probe(image,'lookup','/many/'+names[0])==-errno.EIO
   # A depth-two root->middle->root cycle requires traversal checking beyond bounds.
   if unsigned:
    bottomlogical=struct.unpack_from('<I',baseline,middle+12)[0];bottom=int(debug(image,'bmap /many %d'%bottomlogical).strip())*block
    data=bytearray(baseline);count=struct.unpack_from('<H',data,bottom+10)[0]
    for i in range(count):struct.pack_into('<I',data,bottom+8+i*8+4,first)
    repair(data,bottom)
    count=struct.unpack_from('<H',data,middle+10)[0]
    for i in range(count):struct.pack_into('<I',data,middle+8+i*8+4,bottomlogical)
    repair(data,middle);image.write_bytes(data);assert probe(image,'lookup','/many/'+names[0])==-errno.EIO
   image.write_bytes(baseline);assert before==hashlib.sha256(image.read_bytes()).digest()
 print('PASS: %d indexed lookup/reference/performance checks'%checks)
