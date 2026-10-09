#!/usr/bin/env python3
"""Real ea_inode values, internal-inode isolation, hashes and malformed references."""
import errno,hashlib,os,pathlib,re,shlex,shutil,struct,subprocess,tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs');debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs');fsck=shutil.which('e2fsck')
assert mkfs and debugfs and fsck,'e2fsprogs sbin must be in PATH'
checks=0

def compile_writer(root):
    env=os.environ.copy();prefix=pathlib.Path(mkfs).resolve().parent.parent
    env['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')+os.pathsep+env.get('PKG_CONFIG_PATH','')
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','--static','ext2fs'],env=env,text=True)
    writer=root/'ea-set'
    subprocess.run([os.environ.get('CC','cc'),'test/ea-set.c',*shlex.split(flags),'-o',str(writer)],check=True)
    return writer

def debug(image,command):
    p=subprocess.run([debugfs,'-w','-R',command,str(image)],capture_output=True,check=True)
    assert b'while ' not in p.stderr,(command,p.stderr)
    return p.stdout

def probe(image,op,path,name=None,size=None,truncate=None):
    global checks
    args=['./test/corruption-probe',str(image),op,path]
    if name is not None:args.append(name)
    if size is not None:args.append(str(size))
    if truncate is not None:args.append(str(truncate))
    p=subprocess.run(args,capture_output=True,text=True,timeout=10)
    assert p.returncode==0 and not p.stderr,(args,p.returncode,p.stderr)
    checks+=1;lines=p.stdout.splitlines()
    return int(lines[0]),bytes.fromhex(lines[1]) if len(lines)>1 else b''

def crc(seed,data):
    for b in data:
        seed^=b
        for _ in range(8):seed=(seed>>1)^(0x82f63b78 if seed&1 else 0)
    return seed

def namehash(name,value,signed=False):
    h=0
    for b in name:
        if signed and b>=128:b-=256
        h=((h<<5)^(h>>27)^b)&0xffffffff
    return ((h<<16)^(h>>16)^value)&0xffffffff

with tempfile.TemporaryDirectory(prefix='ext4fuse-ea-inode-') as temp:
    root=pathlib.Path(temp);writer=compile_writer(root);tree=root/'tree';tree.mkdir()
    values={size:bytes((i*37+size)%256 for i in range(size)) for size in [1024,4097,65535,65536]}
    for size,value in values.items():(tree/('f'+str(size))).write_bytes(b'payload');(root/('v'+str(size))).write_bytes(value)
    (tree/'link').symlink_to('f65536')
    variants=[(b,256,mode,inline) for b in [1024,2048,4096] for mode in ['plain','checksum','seed'] for inline in [False,True]]+[(4096,128,'checksum',False),(4096,512,'seed',True)]+[(b,128,'indirect',False) for b in [1024,2048,4096]]
    seen=set();longname='user.'+'n'*200;linkname='user.'+'m'*200
    for block,isize,mode,inline in variants:
        image=root/'image'
        with image.open('wb') as f:f.truncate(32*1024**2)
        opts='ea_inode'+(',inline_data' if inline else '')+{'plain':',^metadata_csum,^uninit_bg','checksum':'','seed':',metadata_csum_seed','indirect':',^extent,^64bit,^metadata_csum,^uninit_bg'}[mode]
        subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-I',str(isize),'-O',opts,'-d',str(tree),str(image)],capture_output=True,check=True)
        numbers={name:int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /'+name)).group(1)) for name in ['f'+str(s) for s in values]+['link']}
        args=[str(writer),str(image)]
        for name,number in numbers.items():
            size=65536 if name=='link' else int(name[1:]);args += [str(number),'user.big',str(root/('v'+str(size)))]
            args += [str(number),longname,str(root/'v4097')]
            # e2fsck 1.47.0 misreads EA-charged fast symlinks without an external
            # xattr block as block pointers. Force that block while keeping the
            # fast symlink and its large EA value in every fixture.
            if name=='link':args += [str(number),linkname,str(root/'v4097')]
        subprocess.run(args,capture_output=True,check=True)
        # libext2fs/debugfs may leave parent EA-block charging for fsck to reconcile.
        fixed=subprocess.run([fsck,'-fy',str(image)],capture_output=True)
        assert fixed.returncode in [0,1],fixed.stdout+fixed.stderr
        clean=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert clean.returncode==0,clean.stdout+clean.stderr
        original=image.read_bytes();before=hashlib.sha256(original).digest()
        table=struct.unpack_from('<I',original,(2 if block==1024 else 1)*block+8)[0]*block
        def inodeoff(n):return table+(n-1)*isize
        def entries(number):
            ino=inodeoff(number);regions=[]
            if isize>128:
                first=ino+128+struct.unpack_from('<H',original,ino+128)[0]+4
                if first+4<=ino+isize and struct.unpack_from('<I',original,first-4)[0]==0xea020000:regions.append((first,'body'))
            external=struct.unpack_from('<I',original,ino+104)[0]
            if external:regions.append((external*block+32,'block'))
            out=[]
            for cursor,kind in regions:
                while struct.unpack_from('<I',original,cursor)[0]:
                    n,index=original[cursor:cursor+2];name=original[cursor+16:cursor+16+n];ea=struct.unpack_from('<I',original,cursor+4)[0]
                    out.append((cursor,index,name,ea,kind));cursor+=(16+n+3)&~3
            return out
        for name,number in numbers.items():
            size=65536 if name=='link' else int(name[1:]);path='/'+name
            attrs=[('user.big',values[size]),(longname,values[4097])]
            if name=='link':
                attrs.append((linkname,values[4097]))
                assert struct.unpack_from('<I',original,inodeoff(number)+104)[0]
            n,names=probe(image,'xlist',path);assert set(names.rstrip(b'\0').split(b'\0'))=={attr.encode() for attr,_ in attrs},(opts,name,names)
            for attr,value in attrs:
                assert probe(image,'xget',path,attr,0)==(len(value),b'')
                assert probe(image,'xget',path,attr,len(value))==(len(value),value)
                assert probe(image,'xget',path,attr,len(value)-1)[0]==-errno.ERANGE
                reference=root/'reference';debug(image,'ea_get -f %s %s %s'%(reference,path,attr));assert reference.read_bytes()==value
            if name!='link':assert probe(image,'read',path)==(7,b'payload')
            for cursor,index,bare,ea,kind in entries(number):
                if ea:seen.add(kind);assert original[inodeoff(ea)+32:inodeoff(ea)+36]!=bytes(4)
        assert before==hashlib.sha256(image.read_bytes()).digest()
        if (block,isize,mode,inline)!=(4096,256,'seed',True):continue
        parent=numbers['f65536'];ino=inodeoff(parent)
        entry=next(e for e in entries(parent) if e[2]==b'big');cursor,_,bare,ea,kind=entry;assert ea
        eoff=inodeoff(ea);physical=struct.unpack_from('<I',original,eoff+60)[0]
        seed=struct.unpack_from('<I',original,1024+0x270)[0]
        def repair(changed,inodes=None,parents=None):
            for number in ([parent,ea] if inodes is None else inodes):
                off=inodeoff(number);struct.pack_into('<H',changed,off+124,0);struct.pack_into('<H',changed,off+130,0)
                h=crc(crc(seed,struct.pack('<I',number)),changed[off+100:off+104]);h=crc(h,changed[off:off+isize])
                struct.pack_into('<H',changed,off+124,h&65535);struct.pack_into('<H',changed,off+130,h>>16)
            for number in ([parent] if parents is None else parents):
                b=struct.unpack_from('<I',changed,inodeoff(number)+104)[0]
                if b:
                    struct.pack_into('<I',changed,b*block+16,0);h=crc(crc(seed,struct.pack('<Q',b)),changed[b*block:(b+1)*block]);struct.pack_into('<I',changed,b*block+16,h)
        # Metadata corruption must fail even when every covering CRC is repaired.
        cases=[(cursor+4,'I',2),(cursor+4,'I',3),(cursor+4,'I',parent),(cursor+4,'I',0xffffffff),
               (cursor+8,'I',0),(cursor+8,'I',65535),(cursor+12,'I',0),
               (eoff+32,'I',0x80000),(eoff,'H',0o040600),(eoff+26,'H',0),(eoff+26,'H',2),
               (eoff+36,'I',0),(eoff+4,'I',65535),(eoff+20,'I',1),(eoff+104,'I',1),(eoff+160,'I',0xea020000)]
        for off,fmt,v in cases:
            changed=bytearray(original);struct.pack_into('<'+fmt,changed,off,v);repair(changed);image.write_bytes(changed)
            assert probe(image,'xlist','/f65536')[0]==-errno.EIO,(off,fmt,v)
            assert probe(image,'xget','/f65536','user.big',0)[0]==-errno.EIO
        # Explicit resource limit is distinct from malformed metadata.
        changed=bytearray(original);struct.pack_into('<I',changed,cursor+8,65537);repair(changed);image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.big',0)[0]==-errno.E2BIG
        # Legitimate high reference-count word (ctime is not an ordinary timestamp).
        changed=bytearray(original);struct.pack_into('<I',changed,eoff+36,0);struct.pack_into('<I',changed,eoff+12,1);repair(changed);image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.big',65536)==(65536,values[65536])
        # Linux also accepts the historical signed-byte name-hash variant.
        changed=bytearray(original);changed[cursor+16:cursor+19]=b'\xc3\xa9g'
        stored_hash=struct.unpack_from('<I',original,eoff+8)[0]
        struct.pack_into('<I',changed,cursor+12,namehash(b'\xc3\xa9g',stored_hash,True));repair(changed);image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.ég',65536)==(65536,values[65536])
        # Value-inode checksum damage is detected even during listing.
        changed=bytearray(original);changed[eoff+124]^=1;image.write_bytes(changed)
        assert probe(image,'xlist','/f65536')[0]==-errno.EIO
        # Payload corruption is detected independently of metadata checksums.
        data_block=struct.unpack_from('<I',original,eoff+60)[0]
        # extents header is 12 bytes, first extent starts at i_block+12;
        # physical low address is at i_block+20 (inode offset 60).
        changed=bytearray(original);changed[data_block*block+123]^=1;image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.big',0)[0]==-errno.EIO
        assert probe(image,'xlist','/f65536')[0]>0
        # No holes: an empty extent tree must not turn into a zero-filled EA value.
        changed=bytearray(original);struct.pack_into('<H',changed,eoff+42,0);repair(changed);image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.big',65536)[0]==-errno.EIO
        changed=bytearray(original);struct.pack_into('<H',changed,eoff+56,32784);repair(changed);image.write_bytes(changed)
        assert probe(image,'xget','/f65536','user.big',65536)[0]==-errno.EIO
        image.write_bytes(original)
        assert probe(image,'xtruncate','/f65536','user.big',65536,data_block*block+10)[0]==-errno.EIO
        image.write_bytes(original)
        # Two attributes share one active EA inode; retire the unused old value
        # inode, then reconcile its allocation bitmaps with e2fsck.
        shared_parent=numbers['f4097'];refs=[e for e in entries(shared_parent) if e[3]]
        a=next(e for e in refs if e[2]==b'big');b=next(e for e in refs if e[2]!=b'big')
        if a[3]!=b[3]:
            # Some libext2fs versions already deduplicate equal values. Otherwise
            # rewire the reference and adjust counters, including shared blocks.
            changed=bytearray(original);struct.pack_into('<I',changed,b[0]+4,a[3])
            external=struct.unpack_from('<I',original,inodeoff(shared_parent)+104)[0]
            delta=struct.unpack_from('<I',original,external*block+4)[0] if b[4]=='block' else 1
            for number,change in [(a[3],delta),(b[3],-delta)]:
                off=inodeoff(number);refs=(struct.unpack_from('<I',original,off+12)[0]<<32)|struct.unpack_from('<I',original,off+36)[0]
                refs+=change;assert refs>=0
                struct.pack_into('<I',changed,off+36,refs&0xffffffff);struct.pack_into('<I',changed,off+12,refs>>32)
                if not refs:struct.pack_into('<H',changed,off+26,0);struct.pack_into('<I',changed,off+20,1)
            repair(changed,[shared_parent,a[3],b[3]],[shared_parent]);image.write_bytes(changed)
            fixed=subprocess.run([fsck,'-fy',str(image)],capture_output=True);assert fixed.returncode in [0,1],fixed.stdout+fixed.stderr
        clean=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert clean.returncode==0,clean.stdout+clean.stderr
        assert probe(image,'xget','/f4097','user.big',4097)==(4097,values[4097])
        assert probe(image,'xget','/f4097',longname,4097)==(4097,values[4097])
        image.write_bytes(original)
        # A corrupt directory reference must not expose an internal value as a file.
        debug(image,'link <'+str(ea)+'> /internal-ea')
        assert probe(image,'lookup','/internal-ea')[0]==-errno.EIO
        assert probe(image,'read','/internal-ea')[0]==-errno.EIO
        assert probe(image,'xlist','/internal-ea')[0]==-errno.EIO
        image.write_bytes(original)
    assert seen=={'body','block'},seen
print('PASS: %d ea_inode value/reference/hash/isolation checks'%checks)
