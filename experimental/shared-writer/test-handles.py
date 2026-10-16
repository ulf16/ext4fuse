#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Open-time grants, inode identity, append serialization and handle recovery."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from unittest.mock import patch
import session
from credentials import Credentials

here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--fixtures',type=Path)
parser.add_argument('--limit',type=int)
args=parser.parse_args()
fixtures=args.fixtures or args.work/'fixtures'
checks,rows=0,[]


def check(value,detail='check failed'):
    global checks
    assert value,detail
    checks+=1


def run(argv):
    p=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
    check(p.returncode==0,p.stdout+p.stderr)
    return p.stdout


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def denied(call,error):
    try:call()
    except Exception as e:check(isinstance(e,error) if isinstance(error,type) else getattr(e,'errno',None)==error,repr(e))
    else:raise AssertionError('operation unexpectedly accepted')


def atomic(s,call,error):
    before,head=sha(s.root/'image.img'),s.state['head']
    denied(call,error)
    check(sha(s.root/'image.img')==before and s.state['head']==head and s.state['pending'] is None)


def metadata(s,**fields):
    env={'EXT4_TEST_HANDLE_'+key.upper():str(value) for key,value in fields.items()}
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])


def verify(s,f,model,path='/existing-file'):
    check(f.size()==len(model))
    check(f.read(0,len(model))==bytes(model),'native handle content')
    check(f.read(len(model)+1,1)==b'')
    check(f.read(0,0)==b'')
    dump=s.root/'handle-dump'
    run(['debugfs','-R',f'dump {path} {dump}',s.root/'image.img'])
    check(dump.read_bytes()==bytes(model),'independent dump mismatch')
    dump.unlink()
    run(['e2fsck','-fn',s.root/'image.img'])


with tempfile.TemporaryDirectory(prefix='handles-',dir=args.work) as directory:
    directory=Path(directory)
    sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    for source in sources:
        original=sha(source)
        seed=directory/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        payload=directory/'payload';payload.write_bytes(b'ACL granted content')
        acl=directory/'acl';acl.write_bytes(struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in
            [(1,6,2**32-1),(2,6,101),(4,0,2**32-1),(16,6,2**32-1),(32,0,2**32-1)]))
        script=directory/'seed.commands'
        script.write_text('\n'.join(['set_inode_field /existing-file uid 100','set_inode_field /existing-file gid 200',
            'set_inode_field /existing-file mode 0100660',f'write {payload} /acl-grant',
            f'ea_set -f {acl} /acl-grant system.posix_acl_access','set_inode_field /acl-grant uid 100',
            'set_inode_field /acl-grant gid 200','set_inode_field /acl-grant mode 0100660',
            'symlink /sym existing-file','mknod fifo p','set_inode_field /fifo uid 100',
            'set_inode_field /fifo gid 200','set_inode_field /fifo mode 010660'])+'\n')
        run(['debugfs','-w','-f',script,seed]);run(['e2fsck','-fn',seed])
        root=directory/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        image=root/'image.img';identity=(image.stat().st_dev,image.stat().st_ino)
        model=bytearray((i*19+13)&255 for i in range(32768))
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server-handle-limits',Credentials(100,200)) as s:
            pid=s._process.pid
            r=s.open('/existing-file','r');rw=s.open('/existing-file','rw');w=s.open('/existing-file','w')
            denied(lambda:w.read(),errno.EBADF)
            atomic(s,lambda:r.write(b'denied'),errno.EBADF)
            atomic(s,lambda:r.truncate(0),errno.EBADF)
            denied(lambda:s.open('/'),errno.EISDIR)
            denied(lambda:s.open('/missing'),errno.ENOENT)
            denied(lambda:s.open('/sym'),errno.ELOOP)
            denied(lambda:s.open('/fifo'),errno.EOPNOTSUPP)
            for options in ({'access':'bad'},{'access':'r','append':True},{'access':'r','truncate':True},{'append':1}):
                denied(lambda options=options:s.open('/existing-file',**options),ValueError)
            check(rw.write(b'\0\xffunaligned',77)==11)
            model[77:88]=b'\0\xffunaligned'
            verify(s,r,model)
            rw.truncate(31);del model[31:];verify(s,r,model)
            rw.truncate(4097);model.extend(b'\0'*(4097-len(model)));verify(s,r,model)
            before=sha(image);check(rw.write(b'',4097)==0);check(sha(image)==before)
            atomic(s,lambda:rw.write(b'x',-1),ValueError)
            atomic(s,lambda:rw.truncate(2**63),ValueError)
            denied(lambda:rw.read(-1,1),ValueError)
            denied(lambda:rw.read(0,session.LIMIT+1),ValueError)
            # Revoke path DAC through a test-only, staged metadata transaction.
            metadata(s,mode='0')
            denied(lambda:s.read('/existing-file'),errno.EACCES)
            denied(lambda:s.open('/existing-file','rw'),errno.EACCES)
            atomic(s,lambda:s.apply([dict(kind='write',path='/existing-file',data_hex='00')]),errno.EACCES)
            check(rw.write(b'open grant',9)==10);model[9:19]=b'open grant';verify(s,r,model)
            metadata(s,mode='0660')
            # Error before sealing retains all active grants and the same reader.
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:rw.write(b'not committed'),errno.ENOSPC)
                atomic(s,lambda:s.open('/existing-file','w',truncate=True),errno.ENOSPC)
            verify(s,r,model)
            # Real torn-page write, then automatic recovery before handles resume.
            boundary=session.write_api.inplace.boundary
            injected=[False]
            def interrupt(name):
                if name=='half:0:0' and not injected[0]:
                    injected[0]=True
                    raise OSError(errno.EIO,'injected torn commit')
                boundary(name)
            previous=s.state['head']
            with patch.object(session.write_api.inplace,'boundary',interrupt):
                denied(lambda:rw.write(b'recovered handle',1),errno.EIO)
            check(injected[0] and s.state['head']==previous+1)
            model[1:17]=b'recovered handle';verify(s,r,model)
            # Reader pipe gate rejects inode-based reads/grant issuance too.
            apply_locked=session.write_api.apply_encoded_locked
            def gated(*arguments):
                denied(lambda:s._rpc(8,struct.pack('<Q',r._token),0,16),errno.EBUSY)
                denied(lambda:s._rpc(11,struct.pack('<Q',rw._token)),errno.EBUSY)
                value=apply_locked(*arguments)
                denied(lambda:s._rpc(9,struct.pack('<Q',r._token)),errno.EBUSY)
                return value
            with patch.object(session.write_api,'apply_encoded_locked',gated):
                rw.write(b'gate',33)
            model[33:37]=b'gate';verify(s,r,model)
            # EOF selection belongs to the serialized writer transaction.
            a=s.open('/existing-file','w',append=True);b=s.open('/existing-file','w',append=True)
            with ThreadPoolExecutor(max_workers=2) as pool:
                fa=pool.submit(a.write,b'first\0',5);fb=pool.submit(b.write,b'second\xff',0)
                check(fa.result(timeout=60)==6 and fb.result(timeout=60)==7)
            tail=r.read(len(model),13);check(tail in (b'first\0second\xff',b'second\xfffirst\0'))
            model.extend(tail);verify(s,r,model)
            a.truncate(53);del model[53:];verify(s,r,model) # status append is not append-only inode
            metadata(s,flags='16')
            atomic(s,lambda:rw.write(b'immutable'),errno.EPERM)
            denied(lambda:s.open('/existing-file','w'),errno.EPERM)
            check(r.read(0,len(model))==model)
            metadata(s,flags='32')
            atomic(s,lambda:rw.write(b'not O_APPEND',len(model)),errno.EPERM)
            atomic(s,lambda:a.truncate(0),errno.EPERM)
            denied(lambda:s.open('/existing-file','w'),errno.EPERM)
            check(a.write(b'append-only',1)==11);model.extend(b'append-only');verify(s,r,model)
            metadata(s,flags='0',cap='1')
            atomic(s,lambda:rw.write(b'capability'),errno.EOPNOTSUPP)
            denied(lambda:s.open('/existing-file','w'),errno.EOPNOTSUPP)
            check(r.read(0,len(model))==model)
            metadata(s,cap='0')
            # Truncating open is atomic under the session lock, and returns a grant.
            with s.open('/existing-file','rw',truncate=True) as t:
                check(t.size()==0);check(t.write(b'new contents')==12)
            model=bytearray(b'new contents');verify(s,r,model)
            check(t.closed);denied(lambda:t.read(),errno.EBADF)
            # Closed identifiers are never recycled within the reader process.
            duplicate=copy.copy(r)
            denied(lambda:duplicate.read(),errno.EBADF)
            denied(lambda:duplicate.close(),errno.EBADF)
            check(r.read(0,len(model))==model, 'copied object released original handle')
            old=r._token;r.close();r.close()
            denied(lambda:r.read(),errno.EBADF)
            denied(lambda:s._rpc(8,struct.pack('<Q',old),0,1),errno.EBADF)
            r=s.open('/existing-file');check(r._token>old)
            denied(lambda:session.FileHandle(s,old,object()),ValueError)
            # The C writer independently rejects a captured grant once identity changes.
            _,grant=s._rpc(11,struct.pack('<Q',rw._token))
            ino,generation,access,flags=struct.unpack('<IIII',grant)
            metadata(s,generation=str((generation+1)&0xffffffff))
            atomic(s,lambda:s._apply_request(session.write_api.encode_grant(s.credentials,grant,'write',0,b'stale')),errno.ESTALE)
            denied(lambda:rw.size(),errno.ESTALE)
            metadata(s,generation=str(generation))
            denied(lambda:rw.read(),errno.ESTALE) # stale slot never resurrects on ABA
            rw.close();w.close();a.close();b.close();r.close()
            with s.open('/existing-file','rw') as fresh:verify(s,fresh,model)
            if not rows:
                handles=[s.open('/existing-file') for _ in range(128)]
                atomic(s,lambda:s.open('/existing-file','w',truncate=True),errno.EMFILE)
                handles[0].close();replacement=s.open('/existing-file');check(replacement._token>handles[-1]._token)
                for handle in handles:handle.close()
                replacement.close()
                # Raw V3 frames must carry write access and zero reserved inode fields.
                context=s.credentials.encode()
                malformed=bytearray(session.write_api.encode_grant(s.credentials,grant,'write',0,b'raw'))
                record=16+len(context)
                struct.pack_into('<I',malformed,record+40+8,1) # read-only grant
                atomic(s,lambda:s._apply_request(malformed),errno.EBADF)
                malformed=bytearray(session.write_api.encode_grant(s.credentials,grant,'write',0,b'raw'))
                struct.pack_into('<I',malformed,record+8,1) # reserved inode operation mode
                atomic(s,lambda:s._apply_request(malformed),errno.EINVAL)
            check(s._process.pid==pid and s._process.poll() is None)
            surviving=s.open('/existing-file')
        check(surviving.closed);denied(lambda:surviving.read(),errno.EBADF)
        # ACL grants persist just like mode grants; fresh path opens must fail.
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(101,9000)) as s:
            denied(lambda:s._file(surviving),errno.EBADF)
            with s.open('/acl-grant','rw') as f:
                check(f.read()==payload.read_bytes())
                metadata(s,path='/acl-grant',mode='0',drop_acl='1')
                denied(lambda:s.read('/acl-grant'),errno.EACCES)
                denied(lambda:s.open('/acl-grant','r'),errno.EACCES)
                check(f.write(b'named fd')==8)
                expected=bytearray(payload.read_bytes());expected[:8]=b'named fd'
                verify(s,f,expected,'/acl-grant')
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server') as admin:
            denied(lambda:admin.open('/existing-file'),errno.EOPNOTSUPP)
        run(['python3',here/'chain.py','checkpoint',root])
        check((image.stat().st_dev,image.stat().st_ino)==identity)
        check(sha(source)==original)
        rows.append(dict(fixture=source.stem,retained_open_grants=True,serialized_append=True,
            inode_identity_checked=True,stale_closed=True,recovery_refreshed=True,fsck_clean=True))
        print('PASS handles',source.stem,flush=True)
    check(len(rows)==(args.limit or 12))
report=dict(checks=checks,result='passed',configurations=rows,
    scope='existing linked regular files; trusted session-local grants; no namespace mutations or mounted writes')
(args.work/('handles-smoke-results.json' if args.limit else 'handles-results.json')).write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'handle checks')
