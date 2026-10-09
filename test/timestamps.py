#!/usr/bin/env python3
"""Signed ext4 epoch/nanosecond timestamps, field presence and corrupt encodings."""
import datetime, errno, hashlib, os, pathlib, re, shutil, struct, subprocess, tempfile
mkfs=os.environ.get('MKE2FS') or shutil.which('mke2fs');debugfs=os.environ.get('DEBUGFS') or shutil.which('debugfs')
assert mkfs and debugfs
checks=0

def crc(seed,data):
    for byte in data:
        seed ^= byte
        for _ in range(8):seed=(seed>>1)^(0x82f63b78 if seed&1 else 0)
    return seed

def encoded(seconds,nanos):
    base=seconds&0xffffffff;signed=base if base<0x80000000 else base-(1<<32)
    return base,(((seconds-signed)>>32)&3)|(nanos<<2)

def probe(image):
    global checks
    p=subprocess.run(['./test/corruption-probe',str(image),'times','/file'],capture_output=True,timeout=10)
    assert p.returncode==0,(p.returncode,p.stderr)
    checks+=1;lines=p.stdout.decode().splitlines()
    return int(lines[0]),list(map(int,lines[1].split())) if len(lines)>1 else []

with tempfile.TemporaryDirectory(prefix='ext4fuse-times-') as temp:
    root=pathlib.Path(temp);tree=root/'tree';tree.mkdir();(tree/'file').write_bytes(b'timestamp fixture')
    for length,csum in [(128,False),(256,False),(256,True)]:
        image=root/'image'
        with image.open('wb') as f:f.truncate(16*1024**2)
        opts='^metadata_csum,^uninit_bg' if not csum else 'metadata_csum'
        subprocess.run([mkfs,'-q','-F','-t','ext4','-b','4096','-I',str(length),'-O',opts,'-d',str(tree),str(image)],capture_output=True,check=True)
        base=bytearray(image.read_bytes());number=int(re.search(rb'Inode:\s*(\d+)',subprocess.run([debugfs,'-R','stat /file',str(image)],capture_output=True,check=True).stdout).group(1))
        table=struct.unpack_from('<I',base,4096+8)[0]*4096;off=table+(number-1)*length
        original=bytes(base[off:off+length]);seed=crc(crc(crc(0xffffffff,base[1024+104:1024+120]),struct.pack('<I',number)),original[100:104])
        def write(raw):
            if csum:
                raw[124:126]=b'\0\0';high=struct.unpack_from('<H',raw,128)[0]>=4
                if high:raw[130:132]=b'\0\0'
                digest=crc(seed,raw);struct.pack_into('<H',raw,124,digest&65535)
                if high:struct.pack_into('<H',raw,130,digest>>16)
            with image.open('r+b') as f:f.seek(off);f.write(raw)
        dates=[-2147483648,-1,0,2147483647]
        if length>128:dates += [2147483648,4294967295,4294967296,8589934592,12884901888,15032385535]
        for seconds in dates:
            raw=bytearray(original);values=[]
            for index,(field,extra) in enumerate([(8,140),(16,136),(12,132),(144,148)]):
                if field>=length:continue
                nanos=[1,123456789,999999999,987654321][index] if length>128 else 0
                lo,hi=encoded(seconds,nanos);struct.pack_into('<I',raw,field,lo)
                if extra<length:struct.pack_into('<I',raw,extra,hi)
                values.extend([seconds,nanos])
            if length==128:values.extend([0,0])
            values.append(int(length>128));write(raw)
            assert probe(image)==(0,values),(length,csum,seconds,probe(image),values)
            # debugfs independently decodes signed epoch seconds into UTC dates.
            result=subprocess.run([debugfs,'-R','stat /file',str(image)],capture_output=True,check=True,env={**os.environ,'TZ':'UTC'}).stdout.decode()
            for name in ['atime','mtime','ctime']:
                date=re.search(r'\b'+name+r':.*?-- (.+)',result).group(1).strip()
                decoded=datetime.datetime.strptime(date,'%a %b %d %H:%M:%S %Y').replace(tzinfo=datetime.timezone.utc)
                shown=int(decoded.timestamp())
                # Some debugfs builds widen the unsigned base before decoding.
                # Linux uses s32; accept that known formatter quirk only for high-bit bases.
                assert shown==seconds or (seconds&0x80000000 and shown==seconds+(1<<32)),(name,result,seconds)
        if length>128:
            # Tail bytes outside i_extra_isize are xattrs/padding, never timestamps.
            for extra_size in [0,4,8,12,16,20,24]:
                raw=bytearray(original);struct.pack_into('<H',raw,128,extra_size)
                for field in [8,12,16,144]:struct.pack_into('<I',raw,field,0xffffffff)
                for extra in [132,136,140,148]:struct.pack_into('<I',raw,extra,encoded(4294967295,123)[1])
                write(raw);expected=[]
                for extra in [140,136,132]:expected.extend([4294967295,123] if extra+4<=128+extra_size else [-1,0])
                expected.extend(([4294967295,123] if extra_size>=24 else [-1,0]) if extra_size>=20 else [0,0]);expected.append(int(extra_size>=20))
                assert probe(image)==(0,expected),(length,csum,extra_size,probe(image),expected)
            for extra in [132,136,140,148]:
                raw=bytearray(original);struct.pack_into('<I',raw,extra,1000000000<<2);write(raw)
                assert probe(image)[0]==-errno.EIO
            for bad in [3,length]:
                raw=bytearray(original);struct.pack_into('<H',raw,128,bad);write(raw)
                assert probe(image)[0]==-errno.EIO
        write(bytearray(original))
        before=hashlib.sha256(image.read_bytes()).digest();probe(image);assert before==hashlib.sha256(image.read_bytes()).digest()
print('PASS: %d timestamp checks, UTC debugfs comparison, 2038/epoch boundaries, nanos and field presence'%checks)
