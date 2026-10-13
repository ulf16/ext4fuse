#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Regular-file namespace atomicity, durable orphan pins and crash reclamation."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from unittest.mock import patch
import session
import inplace
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
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
    check(result.returncode==0,result.stdout+result.stderr)
    return result.stdout

def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()

def denied(call,error):
    try: call()
    except Exception as e: check(isinstance(e,error) if isinstance(error,type) else getattr(e,'errno',None)==error,repr(e))
    else: raise AssertionError('unexpected success')

def atomic(s,call,error):
    digest,head=sha(s.root/'image.img'),s.state['head']
    denied(call,error)
    check(sha(s.root/'image.img')==digest and s.state['head']==head and s.state['pending'] is None)

def stat(s,path):
    text=run(['debugfs','-R','stat '+path,s.root/'image.img']).decode()
    return tuple(int(re.search(pattern,text).group(1)) for pattern in (r'Inode:\s+(\d+)',r'Generation:\s+(\d+)',r'Links:\s+(\d+)'))

def clean(s): run(['e2fsck','-fn',s.root/'image.img'])

def metadata(s,**fields):
    env={'EXT4_TEST_HANDLE_'+key.upper():str(value) for key,value in fields.items()}
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])

def create(s,path,data=b'content'):
    s.apply([dict(kind='create',path=path,data_hex=data.hex(),mode=0o660)])

def content(s,f,expected):
    check(f.size()==len(expected));check(f.read(0,len(expected)+1)==expected)

with tempfile.TemporaryDirectory(prefix='namespace-',dir=args.work) as directory:
    directory=Path(directory)
    sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit: sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source)
        seed=directory/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        payload=directory/'payload';payload.write_bytes(b'foreign file')
        attr=directory/'attribute';attr.write_bytes(bytes(700))
        commands=directory/'seed.commands'
        commands.write_text('\n'.join([
            'set_inode_field / mode 040777','set_inode_field / uid 100',
            'set_inode_field /existing-file uid 100','set_inode_field /existing-file gid 200',
            'set_inode_field /existing-file mode 0100660','mkdir /destination',
            'set_inode_field /destination mode 040777','set_inode_field /destination uid 100',
            'mkdir /sticky','set_inode_field /sticky mode 041777','set_inode_field /sticky uid 200',
            'mkdir /readonly','set_inode_field /readonly mode 040555',
            'symlink /symdir destination','mknod fifo p',
            f'write {payload} /sticky/foreign','set_inode_field /sticky/foreign uid 101',
            'set_inode_field /sticky/foreign mode 0100000',f'write {payload} /foreign',
            'set_inode_field /foreign uid 101','set_inode_field /foreign mode 0100000',
            f'write {payload} /attr-file','set_inode_field /attr-file uid 100',
            'set_inode_field /attr-file gid 200', 'set_inode_field /attr-file mode 0100660',
            f'ea_set -f {attr} /attr-file user.fixture',
            f'write {payload} /readonly/owned','set_inode_field /readonly/owned uid 100',
            'set_inode_field /readonly/owned mode 0100660',
            f'write {payload} /foreign-rw','set_inode_field /foreign-rw uid 101',
            'set_inode_field /foreign-rw gid 200','set_inode_field /foreign-rw mode 0100660',
            f'write {payload} /foreign-priv','set_inode_field /foreign-priv uid 101',
            'set_inode_field /foreign-priv gid 200','set_inode_field /foreign-priv mode 0104660'])+'\n')
        run(['debugfs','-w','-f',commands,seed]);run(['e2fsck','-fn',seed])
        root=directory/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        image=root/'image.img';identity=(image.stat().st_dev,image.stat().st_ino)
        model=bytes((i*19+13)&255 for i in range(32768))
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            pid=s._process.pid
            baseline=s.counters()
            a=s.open('/existing-file','rw');b=s.open('/existing-file')
            ino,generation,links=stat(s,'/existing-file');check(links==1)
            s.link('/existing-file','/alias');check(stat(s,'/alias')==(ino,generation,2))
            clean(s)
            s.rename('/existing-file','/destination/moved')
            denied(lambda:s.size('/existing-file'),errno.ENOENT)
            content(s,a,model);check(s.read('/destination/moved',0,len(model))==model)
            s.rename('/alias','/destination/moved')  # Two names for same inode: POSIX no-op.
            check(stat(s,'/alias')[2]==2);clean(s)
            s.unlink('/alias');check(stat(s,'/destination/moved')[2]==1)
            counters=s.counters()
            s.unlink('/destination/moved')
            denied(lambda:s.open('/destination/moved'),errno.ENOENT)
            s._rpc(3);denied(lambda:s._rpc(12),errno.EBUSY);s._rpc(4)
            check(s._rpc(12)[0]==ino);check(stat(s,f'<{ino}>')[2]==0)
            ordinary=subprocess.run([str(args.work/'reader-watch'),str(image)],input=b'',capture_output=True,timeout=30)
            check(ordinary.returncode==2,'ordinary reader admitted a live orphan list')
            check(s.counters()==counters,'pinned inode/block reuse')
            content(s,a,model);content(s,b,model)
            a.write(b'after unlink',7);model=model[:7]+b'after unlink'+model[19:]
            content(s,b,model)
            a.truncate(31);a.truncate(4097);model=model[:31]+bytes(4097-31)
            content(s,b,model)
            b.close();check(s._rpc(12)[0]==ino)
            before=s.counters();a.close()
            check(s._rpc(12)[0]==0);check(s.counters()[1]==before[1]+1)
            check(s.counters()[0]>before[0]);clean(s)
            # Replaced destination is pinned separately from the source.
            create(s,'/source',b'SOURCE');create(s,'/target',b'TARGET')
            source_handle=s.open('/source','rw');old1=s.open('/target','rw');old2=s.open('/target')
            old_inode,old_generation,_=stat(s,'/target')
            s.rename('/source','/target')
            denied(lambda:s.size('/source'),errno.ENOENT)
            check(s.read('/target')==b'SOURCE');content(s,source_handle,b'SOURCE')
            content(s,old1,b'TARGET');old1.write(b'OLD');content(s,old2,b'OLDGET')
            old1.close();check(s._rpc(12)[0]==old_inode)
            old2.close();check(s._rpc(12)[0]==0);source_handle.close();clean(s)
            # Delete external EA storage through the libext2fs accounting path.
            free=s.counters();s.unlink('/attr-file')
            check(s.counters()[1]==free[1]+1);check(s.counters()[0]>free[0]);clean(s)
            # Three simultaneous orphan entries; release the middle, then tail, then head.
            orphan_handles=[];orphan_inodes=[]
            for number in range(3):
                name=f'/orphan-{number}';create(s,name,b'orphan')
                orphan_handles.append(s.open(name,'rw'));orphan_inodes.append(stat(s,name)[0]);s.unlink(name)
            check(s._rpc(12)[0]==orphan_inodes[2])
            create(s,'/fresh');check(stat(s,'/fresh')[0] not in orphan_inodes,'allocated pinned inode reused')
            orphan_handles[1].close();check(s._rpc(12)[0]==orphan_inodes[2])
            content(s,orphan_handles[0],b'orphan');content(s,orphan_handles[2],b'orphan')
            orphan_handles[0].close();orphan_handles[2].close();check(s._rpc(12)[0]==0);clean(s)
            s.unlink('/fresh')
            # Reusing a freed inode must change generation; an old writer grant is stale.
            create(s,'/reuse');reuse=s.open('/reuse','rw')
            _,old_grant=s._rpc(11,s._file(reuse));old_number,old_gen,_=stat(s,'/reuse')
            reuse.close();s.unlink('/reuse');create(s,'/reuse-new')
            new_number,new_gen,_=stat(s,'/reuse-new')
            if new_number==old_number:check(new_gen!=old_gen,'recycled inode generation unchanged')
            atomic(s,lambda:s._apply_request(session.write_api.encode_grant(s.credentials,old_grant,'write',0,b'bad')),errno.ESTALE)
            s.unlink('/reuse-new');clean(s)
            # Unpinned deletion reclaims immediately.
            create(s,'/large',bytes(20000));metadata(s,path='/large',drop_acl=1)
            free=s.counters();s.unlink('/large');check(s.counters()[1]==free[1]+1)
            check(s.counters()[0]>free[0]);clean(s)
            for op,error in [(lambda:s.link('/missing','/x'),errno.ENOENT),
                             (lambda:s.link('/target','/target'),errno.EEXIST),
                             (lambda:s.unlink('/destination'),errno.EISDIR),
                             (lambda:s.rename('/target','/destination'),errno.EISDIR),
                             (lambda:s.unlink('/fifo'),errno.EOPNOTSUPP),
                             (lambda:s.link('/target','/readonly/x'),errno.EACCES),
                             (lambda:s.link('/target','/symdir/x'),errno.ELOOP)]:
                atomic(s,op,error)
            for target in ('relative','/a/../b','/','/a//b'):
                atomic(s,lambda target=target:s.rename('/target',target),ValueError)
            # Source search, rather than write, permits a hardlink from a read-only parent.
            s.link('/readonly/owned','/readonly-source-link');s.unlink('/readonly-source-link')
            s.link('/foreign-rw','/group-link');check(stat(s,'/group-link')[2]==2)
            s.unlink('/group-link')
            atomic(s,lambda:s.link('/foreign-priv','/priv-link'),errno.EPERM)
            # Sticky deletion/replacement and protected hardlink ownership.
            create(s,'/sticky/own')
            metadata(s,path='/sticky/own',mode=0o600)  # Owner remains 100: permitted.
            s.unlink('/sticky/own')
            atomic(s,lambda:s.unlink('/sticky/foreign'),errno.EPERM)
            atomic(s,lambda:s.rename('/target','/sticky/foreign'),errno.EPERM)
            atomic(s,lambda:s.rename('/sticky/foreign','/stolen'),errno.EPERM)
            atomic(s,lambda:s.link('/foreign','/foreign-link'),errno.EACCES)
            # Immutable and append-only parents/files cannot lose namespace entries.
            metadata(s,path='/target',flags=16)
            atomic(s,lambda:s.unlink('/target'),errno.EPERM)
            atomic(s,lambda:s.rename('/target','/immutable-move'),errno.EPERM)
            metadata(s,path='/target',flags=32)
            atomic(s,lambda:s.unlink('/target'),errno.EPERM)
            metadata(s,path='/target',flags=0)
            metadata(s,path='/destination',flags=32)
            create(s,'/destination/append-child')
            atomic(s,lambda:s.unlink('/destination/append-child'),errno.EPERM)
            atomic(s,lambda:s.rename('/destination/append-child','/out'),errno.EPERM)
            metadata(s,path='/destination',flags=0)
            s.unlink('/destination/append-child')
            metadata(s,path='/destination',flags=16)
            atomic(s,lambda:s.link('/target','/destination/new'),errno.EPERM)
            metadata(s,path='/destination',flags=0)
            # Atomic batch failure after staged last-link removal leaves handle/name intact.
            f=s.open('/target','rw');payload=f.read()
            atomic(s,lambda:s.apply([dict(kind='unlink',path='/target'),dict(kind='unlink',path='/missing')]),errno.ENOENT)
            check(s.read('/target')==payload);content(s,f,payload);check(s._rpc(12)[0]==0)
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:s.unlink('/target'),errno.ENOSPC)
            content(s,f,payload);check(s.read('/target')==payload)
            # Recovery must finish a sealed last-link deletion after an actual half-page write.
            boundary=inplace.boundary;once=[False]
            def interrupt(name):
                if name=='half:0:0' and not once[0]:
                    once[0]=True;raise OSError(errno.EIO,'injected torn namespace page')
                return boundary(name)
            with patch.object(inplace,'boundary',interrupt):
                denied(lambda:s.unlink('/target'),errno.EIO)
            check(once[0]);denied(lambda:s.size('/target'),errno.ENOENT)
            content(s,f,payload);f.write(b'RECOVERED');content(s,f,b'RECOVERED')
            f.close();check(s._rpc(12)[0]==0);clean(s)
            # Duplicate/stale pin snapshots cannot be used to change the namespace.
            create(s,'/snapshot');f=s.open('/snapshot','rw')
            _,pins=s._rpc(12)
            atomic(s,lambda:s._apply_request(session.write_api.encode_broker([dict(kind='unlink',path='/snapshot')],s.credentials,pins+pins)),errno.EINVAL)
            stale=struct.pack('<II',*[(stat(s,'/snapshot')[0]),(stat(s,'/snapshot')[1]+1)])
            atomic(s,lambda:s._apply_request(session.write_api.encode_broker([],s.credentials,stale)),errno.ESTALE)
            s.unlink('/snapshot')
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,f.close,errno.ENOSPC)
            check(f.closed and s._rpc(12)[0]!=0)
            create(s,'/after-close-failure');check(s._rpc(12)[0]==0);clean(s)
            s.unlink('/after-close-failure')
            # Closing a session with live orphans must reclaim them, too.
            create(s,'/snapshot');f=s.open('/snapshot','rw')
            s.unlink('/snapshot');check(s._rpc(12)[0]!=0)
            check(s._process.pid==pid);check((image.stat().st_dev,image.stat().st_ino)==identity)
        run(['e2fsck','-fn',image])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            check(s._rpc(12)[0]==0);create(s,'/crash',b'crash content')
        # Crash the coordinator without a release/close; pipe EOF also ends the reader.
        child='''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import session
from credentials import Credentials
s=session.Session(sys.argv[2],sys.argv[3],sys.argv[4],Credentials(100,200))
f=s.open('/crash','rw');s.unlink('/crash');f.write(b'left orphan')
os._exit(0)
'''
        run(['python3','-c',child,here,root,args.work/'mutation-producer',args.work/'reader-server'])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            check(s._rpc(12)[0]==0,'abandoned orphan not reclaimed')
            denied(lambda:s.size('/crash'),errno.ENOENT);clean(s)
        # Independent tools must also be able to reclaim our legacy orphan chain.
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            create(s,'/crash',b'fsck orphan')
        run(['python3','-c',child,here,root,args.work/'mutation-producer',args.work/'reader-server'])
        copy=directory/(source.stem+'-fsck.img');shutil.copyfile(image,copy)
        result=subprocess.run(['e2fsck','-fy',str(copy)],capture_output=True,timeout=60)
        check(result.returncode in (0,1),result.stdout+result.stderr)
        run(['e2fsck','-fn',copy])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server') as s:
            check(s._rpc(12)[0]==0);clean(s)
        if not rows:
            # Corrupt a private orphan next-pointer in a test-only staged producer.
            # Both refresh and a subsequent attach must reject the entire list;
            # neither may follow a cycle or reclaim arbitrary allocations.
            bad=directory/'bad-orphans'
            run(['python3',here/'chain.py','init',seed,bad,args.work/'prototype'])
            s=session.Session(bad,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200))
            # A directory entry with a zero-link inode cannot issue a new grant.
            old=s.open('/existing-file','rw')
            metadata(s,links=0)
            denied(lambda:s.open('/existing-file','rw'),errno.ESTALE)
            denied(lambda:old.read(),errno.ESTALE)
            metadata(s,links=1);old.close();clean(s)
            f=s.open('/existing-file','rw');bad_inode=stat(s,'/existing-file')[0]
            s.unlink('/existing-file')
            denied(lambda:metadata(s,inode=bad_inode,orphan_next=bad_inode),errno.EIO)
            denied(lambda:f.read(),errno.EIO)
            corrupt_hash=sha(bad/'image.img');s.close()
            denied(lambda:session.Session(bad,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)),OSError)
            check(sha(bad/'image.img')==corrupt_hash,'failed attach changed corrupt image')
        check(sha(source)==original,'source image changed')
        rows.append(dict(fixture=source.name,result='passed'))
        print('PASS',source.name,flush=True)
report=dict(result='passed',checks=checks,configurations=rows,
            scope='offline regular-file link/rename/unlink, session-local pins and durable legacy orphan reclamation')
(args.work/'namespace-results.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'namespace/orphan checks')
