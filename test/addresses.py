#!/usr/bin/env python3
"""Optional large sparse fixture: 16 TiB logical, about 1.6 GiB host allocation.
Real mke2fs geometry; explicit data/tree/inode-table relocations test high bits.
Relocations are reader fixtures, not an e2fsck certification of bitmap accounting.
"""
import errno, os, pathlib, re, shutil, struct, subprocess, tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs')
debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs
checks=0

def probe(image,operation,path='/payload'):
    global checks
    p=subprocess.run(['./test/corruption-probe',str(image),operation,path],capture_output=True,timeout=30)
    assert p.returncode==0,(p.returncode,p.stderr)
    checks+=1
    line,_,data=p.stdout.partition(b'\n');return int(line),data

def debug(image,command):
    return subprocess.run([debugfs,'-c','-R',command,str(image)],capture_output=True,check=True,timeout=30).stdout

with tempfile.TemporaryDirectory(prefix='ext4fuse-addresses-') as temp:
    root=pathlib.Path(temp);image=root/'image';block=4096;count=(1<<32)+2048
    reuse=os.environ.get('ADDRESS_FIXTURE')
    if reuse: image=pathlib.Path(reuse)
    else:
        with image.open('wb') as f:f.truncate(count*block)
        subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-N','1024','-O','64bit,^meta_bg,^has_journal,^resize_inode,^metadata_csum,sparse_super2','-E','lazy_itable_init=1,num_backup_sb=0',str(image)],capture_output=True,check=True)
        payload=root/'payload';payload.write_bytes(b'physical-address-above-32-bits\n')
        subprocess.run([debugfs,'-w','-R','write '+str(payload)+' /payload',str(image)],capture_output=True,check=True)
    data=debug(image,'cat /payload');assert data
    number=int(re.search(rb'Inode:\s*(\d+)',debug(image,'stat /payload')).group(1))
    with image.open('r+b') as f:
        f.seek(1024);superblock=f.read(1024)
        inode_size=struct.unpack_from('<H',superblock,88)[0];inodes_per_group=struct.unpack_from('<I',superblock,40)[0]
        f.seek(block);desc=bytearray(f.read(64))
        table=(struct.unpack_from('<I',desc,8)[0]|struct.unpack_from('<I',desc,40)[0]<<32)*block
        table_size=inodes_per_group*inode_size;f.seek(table);inodes=bytearray(f.read(table_size))
        off=(number-1)*inode_size;extent=off+40
        high=(1<<32)+1024;leaf=high+1;itable=high+2
        f.seek(high*block);f.write(data.ljust(block,b'\0'))
        # Direct root extent with high physical data address.
        struct.pack_into('<HHHHI',inodes,extent,0xf30a,1,4,0,0)
        struct.pack_into('<IHHI',inodes,extent+12,0,1,high>>32,high&0xffffffff)
        f.seek(table);f.write(inodes)
    assert probe(image,'read')[0]==len(data)
    assert debug(image,'cat /payload')==data
    # High extent index points to a high leaf, which points to high file data.
    with image.open('r+b') as f:
        node=bytearray(block);struct.pack_into('<HHHHI',node,0,0xf30a,1,(block-12)//12,0,0)
        struct.pack_into('<IHHI',node,12,0,1,high>>32,high&0xffffffff)
        f.seek(leaf*block);f.write(node)
        struct.pack_into('<HHHHI',inodes,extent,0xf30a,1,4,1,0)
        struct.pack_into('<IIHH',inodes,extent+12,0,leaf&0xffffffff,leaf>>32,0)
        f.seek(table);f.write(inodes)
    n,got=probe(image,'read');assert n==len(data) and bytes.fromhex(got.decode())==data
    assert debug(image,'cat /payload')==data
    # Relocate the complete group-zero inode table above 2**32 blocks.
    with image.open('r+b') as f:
        f.seek(itable*block);f.write(inodes)
        struct.pack_into('<I',desc,8,itable&0xffffffff);struct.pack_into('<I',desc,40,itable>>32)
        f.seek(block);f.write(desc)
    assert probe(image,'lookup','/')[0]==0
    n,got=probe(image,'read');assert n==len(data) and bytes.fromhex(got.decode())==data
    assert debug(image,'cat /payload')==data
    # Out-of-range high extent leaf and data must fail with EIO, never truncate.
    for depth in [0,1]:
        bad=bytearray(inodes);struct.pack_into('<HHHHI',bad,extent,0xf30a,1,4,depth,0)
        if depth: struct.pack_into('<IIHH',bad,extent+12,0,2048,1,0)
        else: struct.pack_into('<IHHI',bad,extent+12,0,1,1,2048)
        with image.open('r+b') as f:f.seek(itable*block);f.write(bad)
        assert probe(image,'read')[0]==-errno.EIO
    with image.open('r+b') as f:f.seek(itable*block);f.write(inodes)
print('PASS: %d high-address reads/rejections; extent data, external tree and inode table match debugfs'%checks)
