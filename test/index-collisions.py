#!/usr/bin/env python3
"""Real legacy hash collisions across fsck-certified leaf/index boundaries."""
import errno,hashlib,os,pathlib,re,shlex,shutil,subprocess,tempfile
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');fsck=shutil.which('e2fsck');assert mkfs and debugfs and fsck
state=0x835689ac;seen={}
def legacy(name):
 a=0x12a3fe2d;b=0x37abe8f9
 for c in name.encode():
  h=(b+(a^(c*7152373)))&0xffffffff
  if h&0x80000000:h=(h-0x7fffffff)&0xffffffff
  b=a;a=h
 return (a<<1)&0xffffffff
for trial in range(200000):
 chars=[]
 for i in range(40):state=(state*1664525+1013904223)&0xffffffff;chars.append(chr(97+((state>>16)%26)))
 name=''.join(chars);h=legacy(name)
 if h in seen and seen[h]!=name:pair=[seen[h],name];break
 seen[h]=name
else:raise AssertionError('no fixture collision found')
checks=0
with tempfile.TemporaryDirectory(prefix='ext4fuse-collisions-') as tmp:
 r=pathlib.Path(tmp);prefix=pathlib.Path(mkfs).resolve().parent.parent;env=os.environ.copy();env['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')+os.pathsep+env.get('PKG_CONFIG_PATH','')
 flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','--static','ext2fs'],env=env,text=True))
 for source,target in [('test/collision-set.c','split'),('test/largedir-set.c','deepen')]:subprocess.run(['cc',source,*flags,'-o',str(r/target)],check=True)
 def debug(image,cmd):return subprocess.run([debugfs,'-w','-R',cmd,str(image)],capture_output=True,text=True,check=True).stdout
 for block in [1024,2048,4096]:
  for checksum in [False,True]:
   for depth in [0,1,2]:
    image=r/'image';image.write_bytes(bytes(16*1024**2))
    subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-O','large_dir,'+('metadata_csum_seed' if checksum else '^metadata_csum,^uninit_bg'),str(image)],check=True,capture_output=True)
    debug(image,'mkdir /collision')
    for i,n in enumerate(pair):
     payload=r/('payload'+str(i));payload.write_bytes(('collision value '+str(i)).encode());debug(image,'write %s /collision/%s'%(payload,n))
    number=re.search(r'Inode:\s*(\d+)',debug(image,'stat /collision')).group(1)
    subprocess.run([str(r/'split'),str(image),number,*pair,str(int(depth>0))],check=True,capture_output=True)
    if depth==2:subprocess.run([str(r/'deepen'),str(image),number],check=True,capture_output=True)
    p=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert p.returncode==0,p.stdout+p.stderr
    before=hashlib.sha256(image.read_bytes()).digest()
    for i,n in enumerate(pair):
     p=subprocess.run(['./test/corruption-probe',str(image),'read','/collision/'+n],capture_output=True,text=True,check=True)
     expected=('collision value '+str(i)).encode();lines=p.stdout.splitlines();assert int(lines[0])==len(expected) and bytes.fromhex(lines[1])==expected,(depth,p.stdout);checks+=1
    # Absent name and enumeration must still agree with the complete tree.
    p=subprocess.run(['./test/corruption-probe',str(image),'lookup','/collision/missing'],capture_output=True,text=True,check=True);assert int(p.stdout.splitlines()[0])==-errno.ENOENT;checks+=1
    p=subprocess.run(['./test/corruption-probe',str(image),'listnames','/collision'],capture_output=True,text=True,check=True);assert p.stdout.splitlines()[0]=='0' and int(p.stdout.splitlines()[1].split()[0])==4;checks+=1
    assert before==hashlib.sha256(image.read_bytes()).digest()
 print('PASS: %d real hash-collision leaf/index-boundary checks'%checks)
