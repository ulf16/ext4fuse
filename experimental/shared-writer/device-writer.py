#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline ext4 device snapshot/edit/publish with an external durable redo log."""
import argparse,contextlib,fcntl,hashlib,json,os,stat,struct,subprocess
from pathlib import Path
import chain,inplace
from durable import regular,sync,directory,boundary,digest
from device_admission import Device,PAGE,refuse
MAGIC=1024+56
RECORD=inplace.RECORD

def private(root):
    root=inplace.block.canonical(root);info=os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:refuse('recovery directory must be private and owned')
    return root

def read_at(fd,n,offset):
    result=bytearray()
    while len(result)<n:
        data=os.pread(fd,n-len(result),offset+len(result))
        if not data:raise OSError('short device read')
        result+=data
    return bytes(result)

def write_at(fd,data,offset):
    data=memoryview(data)
    while data:
        written=os.pwrite(fd,data,offset)
        if written<=0:raise OSError('short device write')
        data=data[written:];offset+=written

def fd_hash(fd,size):
    h=hashlib.sha256()
    for pos in range(0,size,1024*1024):h.update(read_at(fd,min(1024*1024,size-pos),pos))
    return h.hexdigest()

def clean_image(path,size):
    with regular(path) as f:
        if os.fstat(f.fileno()).st_size!=size:refuse('candidate capacity mismatch')
        sb=read_at(f.fileno(),1024,1024)
        if sb[56:58]!=b'\x53\xef' or not struct.unpack_from('<H',sb,58)[0]&1 or struct.unpack_from('<I',sb,96)[0]&4:refuse('filesystem must be clean ext4 without journal recovery')
        incompat=struct.unpack_from('<I',sb,96)[0]
        blocks=struct.unpack_from('<I',sb,4)[0]|((struct.unpack_from('<I',sb,336)[0]<<32) if incompat&0x80 else 0)
        exponent=struct.unpack_from('<I',sb,24)[0]
        if exponent>2 or blocks*(1024<<exponent)>size:refuse('unsupported filesystem/device geometry')
        uuid=sb[104:120].hex()
        if not any(sb[104:120]):refuse('filesystem UUID required')
    run=subprocess.run(['e2fsck','-fn',str(path)],capture_output=True,timeout=600)
    if run.returncode:raise OSError('candidate did not pass read-only e2fsck: '+run.stderr.decode(errors='replace')[-1024:])
    return uuid

def load(root,name):
    with regular(root/name) as f:
        st=os.fstat(f.fileno())
        if st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_size>65536:refuse('unsafe journal metadata')
        return json.load(f)

@contextlib.contextmanager
def locked(root):
    root=private(root);fd=os.open(root/'device-lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1:refuse('unsafe device lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield root
    finally:os.close(fd)

def snapshot(device,root):
    root=inplace.block.canonical(root);root.mkdir(mode=0o700);directory(root.parent)
    with locked(root),Device(device,root) as target:
        target.check();before=fd_hash(target.fd,target.size)
        fd=os.open(root/'base.img',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:
            for pos in range(0,target.size,1024*1024):output.write(read_at(target.fd,min(1024*1024,target.size-pos),pos))
            output.flush();sync(output.fileno())
        uuid=clean_image(root/'base.img',target.size)
        target.check()
        if fd_hash(target.fd,target.size)!=before:refuse('device changed during snapshot')
        with regular(root/'base.img') as base:
            if digest(base)!=before:refuse('snapshot differs from admitted device')
        chain.clone(root/'base.img',root/'chain')
        inplace.seal(root,'device-state',dict(version=1,identity=target.identity,size=target.size,sector=target.sector,uuid=uuid,base_sha256=before))
    return root/'chain'

def validate_state(state,target):
    if set(state)!={'version','identity','size','sector','uuid','base_sha256'} or type(state['version']) is not int or state['version']!=1:refuse('invalid device snapshot state')
    if (state['identity'],state['size'],state['sector'])!=(target.identity,target.size,target.sector):refuse('target is not the snapshotted device')
    if type(state['size']) is not int or type(state['sector']) is not int or state['size']<=0 or state['size']%PAGE:refuse('invalid device bounds')
    if not isinstance(state['uuid'],str) or len(state['uuid'])!=32 or any(c not in '0123456789abcdef' for c in state['uuid']):refuse('invalid filesystem identity')
    for value in [state['base_sha256']]:
        if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):refuse('invalid device digest')


def prepare(root,target,state,current):
    """No target writes occur here. Freeze/recover the managed chain first."""
    validate_state(state,target)
    if (root/'device-transaction').exists():return
    if (root/'device-started').exists():refuse('started transaction is missing its sealed manifest')
    uuid=clean_image(root/'chain/image.img',target.size)
    if uuid!=state['uuid']:refuse('candidate changes filesystem UUID')
    if fd_hash(target.fd,target.size)!=state['base_sha256']:refuse('device changed since snapshot')
    with regular(root/'base.img') as base,regular(root/'chain/image.img') as new:
        if digest(base)!=state['base_sha256'] or digest(new)!=current['sha256']:refuse('managed inputs changed')
        base.seek(0);new.seek(0)
        # Include page zero even for a no-op transaction: it contains the
        # temporarily disabled magic and is restored only after data flush.
        fd=os.open(root/'device-pages',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:
            os.close(fd);refuse('unsafe partial device log')
        os.ftruncate(fd,0)
        count=0
        with os.fdopen(fd,'wb') as log:
            for index in range(target.size//PAGE):
                old=base.read(PAGE);after=new.read(PAGE)
                if index==0 or old!=after:
                    count+=1
                    if count>inplace.block.MAX_RECORDS:refuse('device transaction page bound exceeded')
                    log.write(RECORD.pack(index,old,after))
            log.flush();sync(log.fileno())
        with regular(root/'device-pages') as log:log_hash=digest(log)
        inplace.seal(root,'device-transaction',dict(version=1,count=count,size=target.size,base_sha256=state['base_sha256'],new_sha256=current['sha256'],log_sha256=log_hash))
        boundary('device:prepared')


def validate_log(root,target,state):
    meta=load(root,'device-transaction')
    if set(meta)!={'version','count','size','base_sha256','new_sha256','log_sha256'} or type(meta['version']) is not int or meta['version']!=1:refuse('invalid device redo manifest')
    count=meta['count']
    if type(count) is not int or not 1<=count<=min(in_place_limit(),target.size//PAGE) or meta['size']!=target.size or meta['base_sha256']!=state['base_sha256']:refuse('invalid device redo bounds')
    for key in ('base_sha256','new_sha256','log_sha256'):
        value=meta[key]
        if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):refuse('invalid redo hash')
    base=hashlib.sha256();new=hashlib.sha256();cursor=0;first=None;previous=-1
    with regular(root/'device-pages') as log:
        st=os.fstat(log.fileno())
        if st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_size!=count*RECORD.size or digest(log)!=meta['log_sha256']:refuse('redo log integrity mismatch')
        log.seek(0)
        for number in range(count):
            index,old,after=RECORD.unpack(log.read(RECORD.size))
            if not previous<index<target.size//PAGE or number==0 and index!=0:refuse('invalid redo page order')
            end=index*PAGE
            while cursor<end:
                data=read_at(target.fd,min(1024*1024,end-cursor),cursor);base.update(data);new.update(data);cursor+=len(data)
            base.update(old);new.update(after);cursor+=PAGE;previous=index
            if number==0:first=after
        while cursor<target.size:
            data=read_at(target.fd,min(1024*1024,target.size-cursor),cursor);base.update(data);new.update(data);cursor+=len(data)
    if base.hexdigest()!=meta['base_sha256'] or new.hexdigest()!=meta['new_sha256']:refuse('clean device bytes or logged pages changed')
    if first[MAGIC:MAGIC+2]!=b'\x53\xef' or first[1128:1144].hex()!=state['uuid']:refuse('redo filesystem identity changed')
    return meta,first

def in_place_limit():return inplace.block.MAX_RECORDS

def replay(root,target,state):
    validate_state(state,target);meta,first=validate_log(root,target,state)
    marker=dict(log_sha256=meta['log_sha256'],identity=state['identity'])
    for name in ('device-started','device-complete'):
        if (root/name).exists() or (root/name).is_symlink():
            if load(root,name)!=marker:refuse('invalid device commit marker')
    if (root/'device-complete').exists():
        if not (root/'device-started').exists() or fd_hash(target.fd,target.size)!=meta['new_sha256']:refuse('completed device changed')
        return
    if not (root/'device-started').exists():
        if fd_hash(target.fd,target.size)!=meta['base_sha256']:refuse('device changed before commit')
        inplace.seal(root,'device-started',marker)
    # Before touching any other page, disable the primary superblock using an
    # aligned full-sector write differing in only its two magic bytes. A crash
    # here leaves either the old intact filesystem or an unrecognizable one.
    target.check();start=MAGIC//target.sector*target.sector
    sector=bytearray(read_at(target.fd,target.sector,start));sector[MAGIC-start:MAGIC-start+2]=b'\0\0'
    write_at(target.fd,sector,start);target.flush()
    if read_at(target.fd,target.sector,start)[MAGIC-start:MAGIC-start+2]!=b'\0\0':refuse('device guard did not persist')
    boundary('device:guarded')
    with regular(root/'device-pages') as log:
        for number in range(meta['count']):
            index,old,after=RECORD.unpack(log.read(RECORD.size));data=bytearray(after)
            if index==0:data[MAGIC:MAGIC+2]=b'\0\0'
            for at in range(0,PAGE,target.sector):
                target.check();write_at(target.fd,data[at:at+target.sector],index*PAGE+at)
                boundary(f'device:sector:{number}:{at//target.sector}')
    target.flush();boundary('device:data-synced')
    # Verify every byte while substituting only the intentionally disabled magic.
    h=hashlib.sha256()
    for pos in range(0,target.size,1024*1024):
        data=bytearray(read_at(target.fd,min(1024*1024,target.size-pos),pos))
        if pos<=MAGIC<pos+len(data):data[MAGIC-pos:MAGIC-pos+2]=b'\x53\xef'
        h.update(data)
    if h.hexdigest()!=meta['new_sha256']:refuse('guarded device verification failed')
    target.check();write_at(target.fd,first[start:start+target.sector],start);target.flush()
    boundary('device:published')
    if fd_hash(target.fd,target.size)!=meta['new_sha256']:refuse('published device verification failed')
    inplace.seal(root,'device-complete',marker)
    boundary('device:complete')


def commit(root,device):
    with locked(root) as root,chain.locked(root/'chain'):
        current=chain.recover_locked(root/'chain')
        with Device(device,root) as target:
            state=load(root,'device-state')
            if (root/'device-transaction').exists() and current['sha256']!=load(root,'device-transaction')['new_sha256']:refuse('managed image changed after device transaction was sealed')
            prepare(root,target,state,current);replay(root,target,state)
    return root

def recover(root,device):
    with locked(root) as root,Device(device,root) as target:replay(root,target,load(root,'device-state'))
    return root

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);subs=p.add_subparsers(dest='action',required=True)
    sub=subs.add_parser('snapshot');sub.add_argument('device');sub.add_argument('root')
    for name in ('commit','recover'):
        sub=subs.add_parser(name);sub.add_argument('root');sub.add_argument('device')
    args=vars(p.parse_args());action=args.pop('action');print(globals()[action](**args))
