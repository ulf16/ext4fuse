#!/usr/bin/env python3
"""Real e2fsprogs inline files/directories and bounded malformed inode records."""
import errno, hashlib, os, pathlib, re, shutil, struct, subprocess, tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs, 'e2fsprogs sbin must be in PATH'
checks=0

def probe(image, operation, path, offset=0, length=1024):
    global checks
    p=subprocess.run(['./test/corruption-probe',str(image),operation,path,str(offset),str(length)],capture_output=True,timeout=10)
    assert p.returncode==0,(p.returncode,p.stderr)
    checks+=1
    status,_,data=p.stdout.partition(b'\n')
    return int(status),data

def debug(image, command):
    return subprocess.run([debugfs,'-R',command,str(image)],capture_output=True,check=True).stdout

with tempfile.TemporaryDirectory(prefix='ext4fuse-inline-') as temp:
    root=pathlib.Path(temp);tree=root/'tree';tree.mkdir()
    contents={}
    for size in [0,1,59,60,61,100,156,157,200,400,500]:
        contents['file'+str(size)]=bytes((i*19+size)%256 for i in range(size))
        (tree/('file'+str(size))).write_bytes(contents['file'+str(size)])
    (tree/'folder').mkdir()
    for i in range(3): (tree/('folder/f'+str(i))).write_bytes(b'child'+bytes([i]))
    (tree/'link').symlink_to('file100')
    for block in [1024,2048,4096]:
        for inode_size in [256,512]:
            for csum in [False,True]:
                image=root/'image'
                with image.open('wb') as f:f.truncate(32*1024**2)
                opts='inline_data' + ('' if csum else ',^metadata_csum,^uninit_bg')
                subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-I',str(inode_size),'-O',opts,'-d',str(tree),str(image)],capture_output=True,check=True)
                # Extend an inline directory into its second, separate dirent region.
                target=int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /file100')).group(1))
                extra=root/'dir-extra';extra.write_bytes(struct.pack('<IHBB',target,40,7,1)+b'outside'+bytes(25))
                commands=root/'commands';commands.write_text('ea_set -f '+str(extra)+' /folder system.data\nset_inode_field /folder size 100\n')
                subprocess.run([debugfs,'-w','-f',str(commands),str(image)],capture_output=True,check=True)
                before=hashlib.sha256(image.read_bytes()).digest()
                for name,data in contents.items():
                    reference=debug(image,'cat /'+name)
                    # debugfs cat may pad inline output to a block; logical bytes must match.
                    assert reference[:len(data)]==data and not any(reference[len(data):]),(block,inode_size,csum,name,len(reference))
                    for offset in sorted({0,59,60,61,len(data),len(data)+1}):
                        n,got=probe(image,'bulk','/'+name,offset)
                        assert n==len(data[offset:offset+1024]) and got==data[offset:offset+1024],(block,inode_size,csum,name,offset,n)
                assert probe(image,'list','/folder')[0]==0
                n,got=probe(image,'bulk','/folder/outside',60);assert n==40 and got==contents['file100'][60:]
                assert probe(image,'lookup','/folder/f2')[0]==0
                assert probe(image,'lookup','/folder/../file100')[0]==0
                assert probe(image,'lookup','/folder/.')[0]==0
                assert probe(image,'lookup','/folder/missing')[0]==-errno.ENOENT
                assert probe(image,'link','/link',64)[1]==b'file100\n'
                assert before==hashlib.sha256(image.read_bytes()).digest()
                if block==4096 and inode_size==256 and not csum:
                    base=image.read_bytes()
                    number=int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /file100')).group(1))
                    table=struct.unpack_from('<I',base,block+8)[0]*block
                    off=table+(number-1)*inode_size
                    raw=base[off:off+inode_size]
                    first=128+struct.unpack_from('<H',raw,128)[0]+4
                    assert raw[first:first+2]==bytes([4,7])
                    cases=[(32,'I',0x10080000),(128,'H',255),
                           (first-4,'I',0),(first,'B',255),(first+1,'B',1),
                           (first+2,'H',65532),(first+4,'I',1),(first+8,'I',4096),
                           (first+2,'H',4),(4,'I',1000)]
                    for relative,fmt,value in cases:
                        changed=bytearray(base);struct.pack_into('<'+fmt,changed,off+relative,value);image.write_bytes(changed)
                        assert probe(image,'lookup','/file100')[0]==-errno.EIO,(relative,fmt,value)
                    image.write_bytes(base)
                    directory=int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /folder')).group(1))
                    doff=table+(directory-1)*inode_size
                    # Parent ID, first record length and forbidden slash in a name.
                    for relative,fmt,value in [(40,'I',0),(48,'H',60),(52,'B',ord('/'))]:
                        changed=bytearray(base);struct.pack_into('<'+fmt,changed,doff+relative,value);image.write_bytes(changed)
                        assert probe(image,'list','/folder')[0]==-errno.EIO,(relative,value)
                    image.write_bytes(base)
print('PASS: %d inline and converted-file checks, offsets, directories, symlinks and malformed xattrs'%checks)
