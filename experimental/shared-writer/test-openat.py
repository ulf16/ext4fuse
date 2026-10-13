#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inode-relative path traversal, atomic open flags, namespace and recovery."""
import argparse
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch
import session
from fault_injection import torn_replay
from credentials import Credentials
here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--fixtures',type=Path)
parser.add_argument('--limit',type=int)
args=parser.parse_args();fixtures=args.fixtures or args.work/'fixtures'
checks,rows=0,[]
def check(condition,detail='check failed'):
    global checks
    assert condition,detail;checks+=1

def run(argv):
    r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
    check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def denied(call,error):
    try:call()
    except Exception as e:check(isinstance(e,error) if isinstance(error,type) else getattr(e,'errno',None)==error,repr(e))
    else:raise AssertionError('unexpected success')

def atomic(s,call,error):
    digest,head=sha(s.root/'image.img'),s.state['head']
    denied(call,error);check(sha(s.root/'image.img')==digest and s.state['head']==head and s.state['pending'] is None)

def clean(s):run(['e2fsck','-fn',s.root/'image.img'])

def metadata(s,path,**fields):
    env={'EXT4_TEST_HANDLE_'+k.upper():str(v) for k,v in fields.items()};env['EXT4_TEST_HANDLE_PATH']=path
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])

def oracle(s,temp):
    """Compare common POSIX pathname results with real host openat, not our resolver."""
    host=temp/'host-oracle';host.mkdir(parents=True)
    (host/'dir').mkdir();(host/'dir'/'child').mkdir();(host/'dir'/'file').write_bytes(b'oracle data')
    os.symlink('dir/child',host/'portal');os.symlink('file',host/'dir'/'link');os.symlink('absent',host/'dir'/'dangling')
    s.mkdirat(None,'/oracle')
    with s.openat(None,'/oracle',directory_only=True) as root:
        s.applyat([dict(kind='mkdir',path='dir'),dict(kind='mkdir',path='dir/child'),
                   dict(kind='create',path='dir/file',data_hex=b'oracle data'.hex()),
                   dict(kind='symlink',path='portal',target='dir/child'),
                   dict(kind='symlink',path='dir/link',target='file'),
                   dict(kind='symlink',path='dir/dangling',target='absent')],root)
        fd=os.open(host,os.O_RDONLY)
        try:
            for path,nofollow in [('dir/file',False),('./dir//./file',False),('portal/../file',False),
                                  ('dir/link',False),('dir/link',True),('dir/dangling',False),
                                  ('dir/missing/../file',False),('dir/file/../file',False),('dir/file/',False)]:
                def host_open():
                    f=os.open(path,os.O_RDONLY | (os.O_NOFOLLOW if nofollow else 0),dir_fd=fd)
                    try:return os.read(f,100)
                    finally:os.close(f)
                def image_open():
                    with s.openat(root,path,nofollow=nofollow) as f:return f.read(length=100)
                def outcome(call):
                    try:return ('data',call())
                    except OSError as e:return ('error',e.errno)
                check(outcome(host_open)==outcome(image_open),(path,nofollow))
            # Exclusive create and grant-on-create with mode zero match the OS.
            f=os.open('created',os.O_RDWR|os.O_CREAT|os.O_EXCL,0,dir_fd=fd)
            try:os.write(f,b'zero mode')
            finally:os.close(f)
            with s.openat(root,'created','rw',create=True,exclusive=True,mode=0) as f:
                f.write(b'zero mode');check(f.read()==b'zero mode')
            denied(lambda:os.open('created',os.O_WRONLY|os.O_CREAT|os.O_EXCL,dir_fd=fd),errno.EEXIST)
            atomic(s,lambda:s.openat(root,'created','w',create=True,exclusive=True),errno.EEXIST)
        finally:os.close(fd)

with tempfile.TemporaryDirectory(prefix='openat-',dir=args.work) as temp:
    temp=Path(temp);sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source);seed=temp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        script=temp/'seed.commands';script.write_text('set_inode_field / mode 040777\nset_inode_field / uid 100\nset_inode_field /existing-file uid 100\nset_inode_field /existing-file gid 200\nset_inode_field /existing-file mode 0100660\n')
        run(['debugfs','-w','-f',script,seed]);run(['e2fsck','-fn',seed]);root=temp/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            pid=s._process.pid
            oracle(s,temp/source.stem.replace(".img",""))
            s.mkdirat(None,'/a');s.mkdirat(None,'/a/b');d=s.openat(None,'/a/b',directory_only=True)
            s.mkdirat(None,'/dest');dest=s.openat(None,'/dest',directory_only=True)
            with s.openat(d,'zero','rw',create=True,mode=0) as f:
                check(f.write(b'created grant')==13);check(f.read()==b'created grant')
            atomic(s,lambda:s.openat(d,'zero'),errno.EACCES)
            check(s.statat(d,'zero')['mode']&0o777==0)
            metadata(s,'/a/b/zero',mode=0o100660)
            with s.openat(d,'zero','rw',create=True) as f:check(f.read()==b'created grant')
            atomic(s,lambda:s.openat(d,'zero','rw',create=True,exclusive=True,truncate=True),errno.EEXIST)
            check(s.readat(d,'zero')==b'created grant')
            with s.openat(d,'zero','rw',truncate=True) as f:check(f.size()==0);f.write(b'after truncation')
            with s.openat(d,'zero','w',append=True) as f:f.write(b'+',0)
            check(s.readat(d,'zero')==b'after truncation+')
            # Relative and absolute symlink targets restart from the right inode.
            s.symlinkat('zero',d,'link');s.symlinkat('/a/b/zero',d,'absolute-link')
            check(s.readat(d,'link')==s.readat(d,'absolute-link'))
            check(s.readlinkat(d,'link')==b'zero')
            check(s.statat(d,'link',follow_symlinks=False)['mode']&0o170000==0o120000)
            check(s.statat(d,'link')['inode']==s.statat(d,'zero')['inode'])
            atomic(s,lambda:s.openat(d,'link',nofollow=True),errno.ELOOP)
            atomic(s,lambda:s.openat(d,'link',create=True,exclusive=True),errno.EEXIST)
            atomic(s,lambda:s.openat(d,'zero',directory_only=True),errno.ENOTDIR)
            atomic(s,lambda:s.openat(d,'link',directory_only=True,nofollow=True),errno.ENOTDIR)
            atomic(s,lambda:s.openat(d,'zero/'),errno.ENOTDIR)
            s.symlinkat('dangling-target',d,'dangling')
            atomic(s,lambda:s.openat(d,'dangling',create=True,exclusive=True),errno.EEXIST)
            with s.openat(d,'dangling','rw',create=True) as f:f.write(b'followed create')
            check(s.readat(d,'dangling-target')==b'followed create')
            # Unlink/rename/link default to the final link itself; explicit linkat
            # following links the target inode instead.
            s.linkat(d,'link',dest,'link-copy');check(s.readlinkat(dest,'link-copy')==b'zero')
            s.linkat(d,'link',dest,'file-copy',follow_symlinks=True)
            check(s.statat(dest,'file-copy')['inode']==s.statat(d,'zero')['inode'])
            s.renameat(d,'link',dest,'moved-link');check(s.readlinkat(dest,'moved-link')==b'zero')
            check(s.readat(d,'zero')==b'after truncation+')
            s.unlinkat(dest,'moved-link');s.unlinkat(dest,'link-copy');s.unlinkat(dest,'file-copy')
            # Dot-dot must walk after following a symlink, not lexically cancel.
            s.mkdirat(d,'inside');s.symlinkat('b/inside',None,'/a/portal')
            check(s.readat(None,'/a/portal/../zero')==b'after truncation+')
            s.symlinkat('/a/b',None,'/portal')
            with s.openat(None,'//portal///./',directory_only=True) as same:check(same.stat()['inode']==d.stat()['inode'])
            s.chdirat(None,'/portal');check(s.getcwd()=='/a/b');check(s.readat(None,'zero')==b'after truncation+')
            # Rename and ancestor DAC revocation do not invalidate dirfd. Only
            # directories actually traversed from dirfd are searched.
            s.rename('/a','/renamed');metadata(s,'/renamed',mode=0o040000)
            check(s.readat(d,'zero')==b'after truncation+')
            with s.openat(d,'new','rw',create=True) as f:f.write(b'dirfd create')
            s.renameat(d,'new',dest,'new');check(s.readat(dest,'new')==b'dirfd create');s.unlinkat(dest,'new')
            atomic(s,lambda:s.openat(None,'/renamed/b/zero'),errno.EACCES)
            metadata(s,'/renamed',mode=0o040777)
            metadata(s,'/renamed/b',mode=0o040600)
            atomic(s,lambda:s.openat(d,'zero'),errno.EACCES)
            check('zero' in d.listdir())
            metadata(s,'/renamed/b',mode=0o040777)
            # Absolute paths ignore invalid dirfds; relative paths do not.
            fake=copy.copy(d)
            atomic(s,lambda:s.openat(fake,'zero'),errno.EBADF)
            with s.openat(fake,'/existing-file') as f:check(f.size()>0)
            with s.openat(None,'/existing-file') as f:
                atomic(s,lambda:s.openat(f,'zero'),errno.ENOTDIR)
                check(s.statat(f,'/existing-file')['size']>0)
            closed=s.openat(None,'/');closed.close()
            atomic(s,lambda:s.openat(closed,'zero'),errno.EBADF)
            with s.openat(closed,'/existing-file') as f:check(f.size()>0)
            # Staged batches resolve later names after preceding changes.
            s.applyat([dict(kind='mkdir',path='batch'),dict(kind='symlink',path='batch-link',target='batch'),
                       dict(kind='create',path='batch-link/file',data_hex='616263'),
                       dict(kind='write',path='batch-link/./file',data_hex='5a',offset=1)],d)
            check(s.readat(d,'batch/file')==b'aZc')
            atomic(s,lambda:s.applyat([dict(kind='rename',path='batch/file',target='rollback'),dict(kind='unlink',path='missing')],d,target_directory=d),errno.ENOENT)
            check(s.readat(d,'batch/file')==b'aZc')
            s.unlinkat(d,'batch/file');s.unlinkat(d,'batch-link');s.unlinkat(d,'batch',remove_directory=True)
            # Link count, directory topology and fsck remain valid across at rename.
            s.mkdirat(d,'moved-dir');s.renameat(d,'moved-dir',dest,'moved-dir')
            check(s.statat(dest,'moved-dir/..')['inode']==dest.stat()['inode'])
            s.unlinkat(dest,'moved-dir/',remove_directory=True)
            s.mkdirat(d,'trailing///');s.unlinkat(d,'trailing/',remove_directory=True)
            for call,error in [(lambda:s.mkdirat(d,'.'),errno.EEXIST),(lambda:s.unlinkat(d,'.'),errno.EISDIR),
                               (lambda:s.unlinkat(d,'.',remove_directory=True),errno.EINVAL),
                               (lambda:s.renameat(d,'.',dest,'bad'),errno.EBUSY),
                               (lambda:s.mkdirat(None,'/'),errno.EEXIST),
                               (lambda:s.unlinkat(None,'/',remove_directory=True),errno.EBUSY),
                               (lambda:s.unlinkat(None,'.',remove_directory=True),errno.EINVAL),
                               (lambda:s.unlinkat(None,'..',remove_directory=True),errno.ENOTEMPTY)]:
                atomic(s,call,error)
            # Slow symlinks use block data, relative targets start at the link's
            # own parent, and absolute targets ignore an inaccessible ancestor.
            slow='./'*40+'zero';s.symlinkat(slow,d,'slow-link')
            check(s.readlinkat(d,'slow-link')==slow.encode());check(s.readat(d,'slow-link')==b'after truncation+')
            s.unlinkat(d,'slow-link')
            # The symlink budget is per whole pathname and shared with expansion.
            s.applyat([dict(kind='symlink',path='loop-a',target='loop-b'),dict(kind='symlink',path='loop-b',target='loop-a')],d)
            atomic(s,lambda:s.openat(d,'loop-a'),errno.ELOOP)
            atomic(s,lambda:s.openat(d,'loop-a','rw',create=True),errno.ELOOP)
            ops=[dict(kind='symlink',path=f'chain-{i}',target=f'chain-{i+1}' if i<39 else 'zero') for i in range(40)]
            s.applyat(ops,d)
            check(s.readat(d,'chain-0')==b'after truncation+')
            s.symlinkat('chain-0',d,'chain-overflow');atomic(s,lambda:s.openat(d,'chain-overflow'),errno.ELOOP)
            s.applyat([dict(kind='unlink',path=f'chain-{i}') for i in range(40)]+[dict(kind='unlink',path='chain-overflow'),dict(kind='unlink',path='loop-a'),dict(kind='unlink',path='loop-b')],d)
            for path,error in [('',errno.ENOENT),('x'*256,errno.ENAMETOOLONG),('x'*4097,errno.ENAMETOOLONG),('missing/../zero',errno.ENOENT),('zero/../zero',errno.ENOTDIR)]:
                atomic(s,lambda path=path:s.openat(d,path),error)
            # Failed producer leaves neither a new file nor a leaked reservation.
            slots=len(s._files)
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:s.openat(d,'failed','rw',create=True),errno.ENOSPC)
                atomic(s,lambda:s.openat(d,'zero','rw',truncate=True),errno.ENOSPC)
            check(len(s._files)==slots);check(s.readat(d,'zero')==b'after truncation+')
            atomic(s,lambda:s.statat(d,'failed'),errno.ENOENT)
            # A real torn-page commit recovers the open grant before activation.
            with torn_replay() as fault:
                denied(lambda:s.openat(d,'recovered','rw',create=True),errno.EIO)
            check(fault['hit']);check(s.readat(d,'recovered')==b'')
            with s.openat(d,'recovered','rw') as f:f.write(b'recovered grant')
            check(s.readat(d,'recovered')==b'recovered grant');s.unlinkat(d,'recovered')
            clean(s)
            if not rows:
                roots=[s.openat(None,'/') for _ in range(128-len(s._files))]
                atomic(s,lambda:s.openat(d,'quota','rw',create=True),errno.EMFILE)
                atomic(s,lambda:s.openat(d,'zero','rw',truncate=True),errno.EMFILE)
                for h in roots:h.close()
                check(s.readat(d,'zero')==b'after truncation+')
            rawname=b'byte-\xff-name'
            with s.openat(d,rawname,'rw',create=True) as f:f.write(b'raw name')
            s.symlinkat(rawname,d,b'raw-link');check(s.readat(d,b'raw-link')==b'raw name')
            check(s.readlinkat(d,b'raw-link')==rawname)
            s.unlinkat(d,b'raw-link');s.unlinkat(d,rawname)
            # Detached directories retain dot-dot but cannot receive new entries.
            s.chdir('/');s.mkdirat(None,'/detached');det=s.openat(None,'/detached',directory_only=True)
            s.unlinkat(None,'/detached',remove_directory=True)
            with s.openat(det,'.',directory_only=True) as same:check(same.stat()['links']==0)
            atomic(s,lambda:s.openat(det,'new','rw',create=True),errno.ENOENT)
            with s.openat(det,'../existing-file') as f:check(f.size()>0)
            s.chdirat(det,'.');denied(s.getcwd,errno.ENOENT);s.chdirat(det,'..');check(s.getcwd()=='/')
            det.close();check(s._rpc(12)[0]==0)
            writer=s.openat(None,'/existing-file','rw');grant=s._rpc(11,s._file(writer))[1]
            reservation=s._rpc(23)[1]
            s._rpc(3)
            denied(lambda:s._rpc(24,reservation+grant),errno.EBUSY)
            s._rpc(10,reservation)
            for command,payload,offset in [(21,session.struct.pack('<Q',d._token),0),(22,session.struct.pack('<Q',d._token)+b'zero',1),(23,b'',0),(25,session.struct.pack('<Q',d._token)+b'zero',1),(26,session.struct.pack('<Q',d._token)+b'dangling',0)]:
                denied(lambda command=command,payload=payload,offset=offset:s._rpc(command,payload,offset),errno.EBUSY)
            s._rpc(4);writer.close();check(s._process.pid==pid)
            s.mkdirat(None,'/stale-at');stale=s.openat(None,'/stale-at',directory_only=True)
            generation=stale.stat()['generation'];metadata(s,'/stale-at',generation=generation+1)
            atomic(s,lambda:s.openat(stale,'.',directory_only=True),errno.ESTALE)
            atomic(s,lambda:s.mkdirat(stale,'child'),errno.ESTALE)
            metadata(s,'/stale-at',generation=generation);atomic(s,lambda:s.statat(stale,'.'),errno.ESTALE)
            stale.close();s.unlinkat(None,'/stale-at',remove_directory=True)
            # New capabilities cannot alter immutable/append-only data policy.
            metadata(s,'/renamed/b/zero',flags=16)
            atomic(s,lambda:s.openat(d,'zero','w',truncate=True),errno.EPERM)
            metadata(s,'/renamed/b/zero',flags=32)
            atomic(s,lambda:s.openat(d,'zero','w'),errno.EPERM)
            atomic(s,lambda:s.openat(d,'zero','w',append=True,truncate=True),errno.EPERM)
            with s.openat(d,'zero','w',append=True) as f:f.write(b'!')
            metadata(s,'/renamed/b/zero',flags=0)
            check(s.readat(d,'zero')==b'after truncation+!')
            dest.close();d.close();clean(s)
            if not rows:
                # A malformed result may never transfer an unchecked grant. The
                # already committed image is valid; the session fails closed.
                original_apply=s._apply_request
                def corrupt_result(request):
                    state=original_apply(request)
                    report=s.root/f"g-{state['head']:08d}"/'operations.result'
                    raw=bytearray(report.read_bytes());raw[8:12]=bytes(4);report.write_bytes(raw)
                    return state
                with patch.object(s,'_apply_request',corrupt_result):
                    denied(lambda:s.openat(None,'/bad-result','rw',create=True),errno.EIO)
                check(s._failed)
                denied(lambda:s.openat(None,'/existing-file'),errno.EIO)
        if not rows:
            with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as recovered:
                with recovered.openat(None,'/bad-result','rw') as f:check(f.size()==0)
                recovered.unlinkat(None,'/bad-result');clean(recovered)

        __import__('chain').checkpoint(root)
        run(['e2fsck','-fn',root/'image.img'])
        check(sha(source)==original,'source image changed');rows.append(dict(fixture=source.name,result='passed'))
        print('PASS',source.name,flush=True)
(args.work/'openat-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows,scope='offline dirfd path traversal and atomic open admission'),indent=2)+'\n')
print(f'PASS {checks} openat checks across {len(rows)} configurations',flush=True)
