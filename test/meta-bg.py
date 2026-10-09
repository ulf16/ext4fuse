#!/usr/bin/env python3
"""Real distributed meta_bg descriptors, sparse-super variants and mixed placement."""
import hashlib, os, pathlib, re, shutil, struct, subprocess, tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs');debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs
checks=0

def check(image,expected=None):
    global checks
    p=subprocess.run(['./test/feature-probe',str(image)],capture_output=True,timeout=10)
    assert p.returncode==int(bool(expected)),(p.returncode,p.stderr,expected)
    if expected:assert expected.encode() in p.stderr,(expected,p.stderr)
    else:
        p=subprocess.run(['./test/corruption-probe',str(image),'bulk','/file','0','4096'],capture_output=True,timeout=10)
        assert p.returncode==0 and p.stdout==b'15\nmeta_bg content',p.stdout
        ref=subprocess.run([debugfs,'-c','-R','cat /file',str(image)],capture_output=True,check=True).stdout
        assert ref==b'meta_bg content'
    checks+=1

with tempfile.TemporaryDirectory(prefix='ext4fuse-meta-bg-') as temp:
    root=pathlib.Path(temp);tree=root/'tree';tree.mkdir();(tree/'file').write_bytes(b'meta_bg content')
    for block in [1024,2048,4096]:
        for wide in [False,True]:
            per_block=block//(64 if wide else 32);groups=2*per_block+1
            for sparse in ['sparse_super','^sparse_super,^sparse_super2','sparse_super2']:
                for csum in [False,True]:
                    image=root/'image';size=groups*256*block
                    # 1KiB layouts have a first-data-block offset of one.
                    if block==1024:size+=block
                    with image.open('wb') as f:f.truncate(size)
                    opts='meta_bg,^resize_inode,^has_journal,'+('64bit' if wide else '^64bit')+','+sparse+(','+('metadata_csum' if csum else '^metadata_csum,^uninit_bg'))
                    subprocess.run([mkfs,'-q','-F','-t','ext4','-b',str(block),'-g','256','-N','1024','-O',opts,'-d',str(tree),str(image)],capture_output=True,check=True)
                    base=image.read_bytes();before=hashlib.sha256(base).digest();check(image)
                    assert before==hashlib.sha256(image.read_bytes()).digest()
                    # Compare actual primary descriptor-block locations with dumpe2fs.
                    dump=subprocess.run([shutil.which('dumpe2fs'),str(image)],capture_output=True,check=True).stdout.decode()
                    section=dump.split('Group '+str(per_block)+':',1)[1].split('\nGroup ',1)[0]
                    match=re.search(r'Group descriptor(?:s)? at (\d+)',section)
                    assert match,(block,wide,sparse,dump[:2000])
                    second=int(match.group(1));assert second>per_block*256-1
                    if csum:
                        with image.open('r+b') as f:f.seek(second*block+8);byte=f.read(1);f.seek(second*block+8);f.write(bytes([byte[0]^1]))
                        check(image,'group descriptor checksum mismatch');image.write_bytes(base)
                    else:
                        # A mixed layout keeps its first two descriptor blocks together.
                        changed=bytearray(base);first=1 if block==1024 else 0
                        old=(first+2)*block
                        changed[old:old+block]=base[second*block:(second+1)*block]
                        struct.pack_into('<I',changed,1024+0x104,2);image.write_bytes(changed);check(image)
                        image.write_bytes(base)
                        for field,value,reason in [(0x104,4,'first meta block group'),(0x20,0xffffffff,'per group')]:
                            changed=bytearray(base);struct.pack_into('<I',changed,1024+field,value);image.write_bytes(changed);check(image,reason)
                        image.write_bytes(base)
print('PASS: %d meta_bg layout/content/corruption checks; distributed and mixed descriptors'%checks)
