#!/usr/bin/env python3
"""Binary inode/block xattrs, ACL encoding, API sizes and malformed metadata."""
import errno, hashlib, os, pathlib, re, shutil, struct, subprocess, tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs, 'e2fsprogs sbin must be in PATH'
checks=0
missing=getattr(errno,'ENOATTR',errno.ENODATA)
def probe(image,op,path='/file',name=None,size=None):
    global checks
    args=['./test/corruption-probe',str(image),op,path]
    if name is not None: args.append(name)
    if size is not None: args.append(str(size))
    p=subprocess.run(args,capture_output=True,text=True,timeout=10)
    assert p.returncode==0 and not p.stderr,(args,p.returncode,p.stderr)
    lines=p.stdout.splitlines();checks+=1
    return int(lines[0]),bytes.fromhex(lines[1]) if len(lines)>1 else b''
def debug(image,command):
    p=subprocess.run([debugfs,'-w','-R',command,str(image)],capture_output=True,check=True)
    assert b'while ' not in p.stderr,(command,p.stderr)
    return p.stdout

def crc(seed,data):
    for byte in data:
        seed^=byte
        for _ in range(8): seed=(seed>>1)^ (0x82f63b78 if seed&1 else 0)
    return seed

with tempfile.TemporaryDirectory(prefix='ext4fuse-xattrs-') as temp:
    root=pathlib.Path(temp);tree=root/'tree';tree.mkdir();(tree/'file').write_bytes(b'payload');(tree/'empty').touch();(tree/'folder').mkdir();(tree/'link').symlink_to('file')
    # Disk ACL v1 short/full entries, compared with Linux userspace v2 bytes.
    acl=struct.pack('<I',1)+struct.pack('<HH',1,7)+struct.pack('<HHI',2,4,70001)+struct.pack('<HH',4,5)+struct.pack('<HHI',8,6,80002)+struct.pack('<HH',16,7)+struct.pack('<HH',32,0)
    acl_user=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(2,4,70001),(4,5,0xffffffff),(8,6,80002),(16,7,0xffffffff),(32,0,0xffffffff)])
    for block in [1024,2048,4096]:
      for inode_size in [128,256,512]:
       for mode in ['plain','checksum','seed']:
        image=root/'image'
        with image.open('wb') as f:f.truncate(32*1024**2)
        opts={'plain':'^metadata_csum,^uninit_bg','checksum':'metadata_csum','seed':'metadata_csum,metadata_csum_seed'}[mode]
        subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-I',str(inode_size),'-O',opts,'-d',str(tree),str(image)],capture_output=True,check=True)
        values={'user.note':b'hello','user.empty':b'','user.binary':bytes(range(256)),'security.selinux':b'unconfined_u:object_r:default_t:s0\0','trusted.archive':b'yes','user.com.apple.FinderInfo':bytes(32),'user.'+'n'*200:b'long-name','system.posix_acl_access':acl_user}
        for n,(name,value) in enumerate(values.items()):
            host=root/('value'+str(n));host.write_bytes(value);debug(image,'ea_set -f %s /file %s'%(host,name))
        debug(image,'ea_set -f %s /folder system.posix_acl_default'%(root/'value7'))
        debug(image,'ea_set /link user.note link-metadata')
        before=hashlib.sha256(image.read_bytes()).digest()
        n,listed=probe(image,'xlist');names=listed.rstrip(b'\0').split(b'\0');assert set(names)=={x.encode() for x in values},(block,inode_size,mode,names)
        assert n==len(listed) and probe(image,'xlist',size=0)==(n,b'')
        assert probe(image,'xlist',size=n-1)[0]==-errno.ERANGE
        assert probe(image,'xlist',size=n)==(n,listed)
        for name,value in values.items():
            expected=value
            reference=root/'reference';debug(image,'ea_get -f %s /file %s'%(reference,name));reference_bytes=bytearray(reference.read_bytes())
            if name=="system.posix_acl_access":
                # debugfs returns v2 with zero IDs for unnamed principals;
                # Linux's xattr ABI uses ACL_UNDEFINED_ID for those fields.
                for offset in range(4,len(reference_bytes),8):
                    if struct.unpack_from('<H',reference_bytes,offset)[0] not in [2,8]: struct.pack_into('<I',reference_bytes,offset+4,0xffffffff)
            assert reference_bytes==expected,(name,reference_bytes.hex(),expected.hex())
            assert probe(image,'xget',name=name)==(len(expected),expected),(block,inode_size,mode,name)
            assert probe(image,'xget',name=name,size=0)==(len(expected),b'')
            assert probe(image,'xget',name=name,size=len(expected))==(len(expected),expected)
            if len(expected)>1: assert probe(image,'xget',name=name,size=len(expected)-1)[0]==-errno.ERANGE
        assert probe(image,'xget','/folder','system.posix_acl_default')==(len(acl_user),acl_user)
        assert probe(image,'xget','/link','user.note')==(13,b'link-metadata')
        assert probe(image,'xlist','/empty')==(0,b'')
        assert probe(image,'xget',name='user.missing')[0]==-missing
        assert probe(image,'xget',name='com.apple.FinderInfo')[0]==-missing
        assert probe(image,'xget',name='')[0]==-errno.EINVAL
        assert probe(image,'xlist','/missing')[0]==-errno.ENOENT
        assert probe(image,'xget','/missing','user.note')[0]==-errno.ENOENT
        assert before==hashlib.sha256(image.read_bytes()).digest()
        if inode_size!=256 or block!=4096: continue
        original=image.read_bytes();inum=int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /file')).group(1))
        table=struct.unpack_from('<I',original,block+8)[0]*block;ino=table+(inum-1)*inode_size
        external=struct.unpack_from('<I',original,ino+104)[0]*block
        first=ino+128+struct.unpack_from('<H',original,ino+128)[0]+4
        seed=struct.unpack_from('<I',original,1024+0x270)[0] if mode=='seed' else crc(0xffffffff,original[1024+0x68:1024+0x78])
        def repair(changed):
            if mode=='plain': return
            struct.pack_into('<H',changed,ino+124,0);struct.pack_into('<H',changed,ino+130,0)
            inode_seed=crc(crc(seed,struct.pack('<I',inum)),changed[ino+100:ino+104])
            c=crc(inode_seed,changed[ino:ino+inode_size]);struct.pack_into('<H',changed,ino+124,c&65535);struct.pack_into('<H',changed,ino+130,c>>16)
            struct.pack_into('<I',changed,external+16,0)
            c=crc(crc(seed,struct.pack('<Q',external//block)),changed[external:external+block]);struct.pack_into('<I',changed,external+16,c)
        # Repair checksums so structural failures cannot hide behind CRC failures.
        cases=[(external,'I',0),(external+4,'I',0),(external+4,'I',1025),(external+8,'I',2),(external+20,'I',1),
               (external+32,'B',255),(external+34,'H',65532),(external+34,'H',32),(external+34,'H',4093),
               (external+36,'I',1),(external+40,'I',0xffffffff),(external+48,'B',0),
               (first-4,'I',0x12345678),(first+2,'H',65532),(first+2,'H',4),(first+4,'I',1),(first+8,'I',0xffffffff),
               (ino+104,'I',0xffffffff),(ino+118,'H',1)]
        for off,fmt,val in cases:
            changed=bytearray(original);struct.pack_into('<'+fmt,changed,off,val);repair(changed);image.write_bytes(changed)
            assert probe(image,'xlist')[0]==-errno.EIO,(mode,off,fmt,val)
            assert probe(image,'xget',name='user.note')[0]==-errno.EIO
        if mode!='plain':
            for off in [first+16,external+16,external+4095]:
                changed=bytearray(original);changed[off]^=1;image.write_bytes(changed)
                assert probe(image,'xlist')[0]==-errno.EIO,(mode,off)
        image.write_bytes(original)
    # Inline system.data must remain private, while user metadata is visible.
    image=root/'inline';image.write_bytes(bytes(32*1024**2))
    subprocess.run([mkfs,'-q','-F','-t','ext4','-O','inline_data','-d',str(tree),str(image)],capture_output=True,check=True)
    debug(image,'ea_set /file user.note inline-note')
    assert probe(image,'xlist')==(10,b'user.note\0')
    assert probe(image,'xget',name='user.note')==(11,b'inline-note')
    assert probe(image,'xget',name='system.data')[0]==-missing
    assert probe(image,'read')[0]==7
print('PASS: %d extended-attribute, ACL encoding, size and corruption checks'%checks)
