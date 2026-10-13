#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Directory cookie paging, stable snapshots, mutation, bounds and resource lifetime."""
import argparse
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
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

def unchanged(s,call,error):
    digest,head=sha(s.root/'image.img'),s.state['head']
    denied(call,error);check(sha(s.root/'image.img')==digest and s.state['head']==head and s.state['pending'] is None)

def clean(s):run(['e2fsck','-fn',s.root/'image.img'])

def metadata(s,path,**fields):
    env={'EXT4_TEST_HANDLE_'+k.upper():str(v) for k,v in fields.items()};env['EXT4_TEST_HANDLE_PATH']=path
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])

def drain(d,count=7,budget=1024):
    entries=[]
    while True:
        page=d.readdir(count,max_bytes=budget);entries+=page['entries']
        check(len(page['entries'])<=count)
        check(8+sum(16+len(os.fsencode(e['name'])) for e in page['entries'])<=budget)
        check(d.tell()==page['offset'])
        if page['eof']:return entries
        check(bool(page['entries']))

with tempfile.TemporaryDirectory(prefix='dirstream-',dir=args.work) as temp:
    temp=Path(temp);sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source);seed=temp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        script=temp/'seed.commands';script.write_text('set_inode_field / mode 040777\nset_inode_field / uid 100\nset_inode_field /existing-file uid 100\nset_inode_field /existing-file gid 200\nset_inode_field /existing-file mode 0100660\n')
        run(['debugfs','-w','-f',script,seed]);run(['e2fsck','-fn',seed]);root=temp/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            pid=s._process.pid;s.mkdirat(None,'/stream');d=s.openat(None,'/stream',directory_only=True)
            names=[f'entry-{i:03d}-'+'n'*40 for i in range(300)]+['long-'+'x'*240]
            for start in range(0,len(names),64):
                s.applyat([dict(kind='create',path=name,data_hex='61') for name in names[start:start+64]],d)
            rawname=b'raw-\xff-name'
            s.applyat([dict(kind='create',path=rawname,data_hex='62'),dict(kind='mkdir',path='child'),dict(kind='symlink',path='link',target=names[0])],d)
            check(d.tell()==0)
            denied(lambda:d.seek(123456789),errno.EINVAL);check(d.tell()==0)
            denied(lambda:d.readdir(offset=123456789),errno.EINVAL);check(d.tell()==0)
            page=d.readdir(2);first=page['entries'];check([e['name'] for e in first]==['.','..'])
            check(first[0]['inode']==d.stat()['inode'] and first[1]['inode']==2)
            check(all(e['type']==4 for e in first));check(not page['eof'])
            first_cookie=first[0]['offset'];saved=page['offset'];check(d.tell()==saved)
            d.seek(first_cookie);check(d.readdir(1)['entries']==[first[1]])
            d.seek(saved);rest=drain(d);whole=first+rest
            check(len(whole)==len(names)+5);check(len({e['name'] for e in whole})==len(whole))
            check({e['name'] for e in rest}==set(names)|{os.fsdecode(rawname),'child','link'})
            for e in whole:
                current=s.statat(d,e['name'],follow_symlinks=False)
                check(e['inode']==current['inode'])
                expected={0o100000:8,0o040000:4,0o120000:10}[current['mode']&0o170000]
                check(e['type'] in (0,expected))
            eof_cookie=d.tell();check(d.readdir(1)==dict(entries=[],offset=eof_cookie,eof=True))
            # Explicit FUSE-style offsets and seek resume exactly after each
            # previously accepted entry, regardless of byte/page boundaries.
            random.seed(12345)
            for unused in range(20):
                index=random.randrange(len(whole)+1)
                offset=whole[index-1]['offset'] if index else 0
                page=d.readdir(3,max_bytes=300,offset=offset)
                check(page['entries']==whole[index:index+len(page['entries'])]);check(d.tell()==page['offset'])
            d.seek(0);check(d.tell()==0);check(d.readdir(2)['entries']==first)
            d.seek(saved);denied(lambda:d.readdir(1,max_bytes=8),errno.ERANGE);check(d.tell()==saved)
            # An insufficient buffer never consumes the long filename.
            long_index=next(i for i,e in enumerate(whole) if e['name']==names[-1])
            before_long=whole[long_index-1]['offset'];d.seek(before_long)
            denied(lambda:d.readdir(1,max_bytes=32),errno.ERANGE);check(d.tell()==before_long)
            exact=8+16+len(names[-1].encode());check(d.readdir(1,max_bytes=exact)['entries']==[whole[long_index]])
            # Independent duplicate/open streams cannot consume each other's
            # cursor or accept each other's nonzero cookies.
            duplicate=d.dup();check(duplicate.tell()==0)
            duplicate_first=duplicate.readdir(1);other=duplicate_first['offset']
            denied(lambda:d.seek(other),errno.EINVAL);denied(lambda:duplicate.seek(saved),errno.EINVAL)
            check(duplicate.tell()==other);check(d.tell()==whole[long_index]['offset'])
            duplicate.close()
            # A snapshot survives successful mutations; listdir remains live.
            d.seek(saved)
            s.applyat([dict(kind='unlink',path=names[0]),dict(kind='rename',path=names[1],target='renamed'),
                       dict(kind='create',path='added',data_hex='63')],d,target_directory=d)
            s.renameat(None,'/stream',None,'/moved-stream')
            check(d.path()=='/moved-stream');check(d.readdir(4096)['entries']==rest)
            check(names[0] not in d.listdir() and 'added' in d.listdir())
            d.rewind();check(d.tell()==0);denied(lambda:d.seek(saved),errno.EINVAL)
            fresh=drain(d);fresh_names={e['name'] for e in fresh}
            check(names[0] not in fresh_names and names[1] not in fresh_names and {'renamed','added'}<=fresh_names)
            denied(lambda:d.seek(saved),errno.EINVAL)
            # A failed mutation, producer or recovery boundary leaves the stream
            # snapshot/cursor intact; writes never reset directory iteration.
            d.seek(fresh[1]['offset']);snapshot_position=d.tell()
            unchanged(s,lambda:s.applyat([dict(kind='unlink',path='added'),dict(kind='unlink',path='missing')],d),errno.ENOENT)
            check(d.tell()==snapshot_position)
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                unchanged(s,lambda:s.mkdirat(d,'failed'),errno.ENOSPC)
            check(d.tell()==snapshot_position)
            with torn_replay() as fault:
                denied(lambda:s.mkdirat(d,'recovered'),errno.EIO)
            check(fault['hit'])
            check(d.tell()==snapshot_position);check(d.readdir(4096)['entries']==fresh[2:])
            d.rewind();check('recovered' in {e['name'] for e in drain(d)})
            # Read permission is an open-time grant; copied, search-only, file,
            # suspended and stale handles cannot bypass stream admission.
            metadata(s,'/moved-stream',mode=0o040000);d.rewind();check(bool(d.readdir()['entries']))
            unchanged(s,lambda:s.openat(None,'/moved-stream',directory_only=True),errno.EACCES)
            metadata(s,'/moved-stream',mode=0o040777)
            s.chdir('/moved-stream');denied(lambda:s._cwd.readdir(),errno.EBADF);s.chdir('/')
            copied=copy.copy(d);denied(copied.tell,errno.EBADF);denied(copied.rewind,errno.EBADF)
            f=s.open('/existing-file');denied(lambda:s._rpc(27,s._file(f)+struct.pack('<I',1),0,128),errno.ENOTDIR);f.close()
            location=d.tell();s._rpc(3)
            for call in (d.tell,d.rewind,lambda:d.seek(0),lambda:d.readdir()):denied(call,errno.EBUSY)
            s._rpc(4);check(d.tell()==location and s._process.pid==pid)
            for call in (lambda:d.readdir(0),lambda:d.readdir(4097),lambda:d.readdir(max_bytes=7),
                         lambda:d.readdir(max_bytes=session.LIMIT+1),lambda:d.seek(-1),lambda:d.seek(True),
                         lambda:d.seek(2**63-1),lambda:d.readdir(offset=2**63-1)):
                denied(call,ValueError);check(d.tell()==location)
            # A removed-but-held directory can finish its existing snapshot.
            s.mkdirat(None,'/removed');removed=s.openat(None,'/removed',directory_only=True)
            s.applyat([dict(kind='create',path='past',data_hex='61')],removed)
            prior=removed.readdir(2);s.unlinkat(removed,'past');s.unlinkat(None,'/removed',remove_directory=True)
            tail=removed.readdir(1);check([e['name'] for e in tail['entries']]==['past'] and tail['eof'])
            removed.rewind();check(removed.readdir(max_bytes=8)==dict(entries=[],offset=0,eof=True))
            denied(lambda:removed.seek(prior['offset']),errno.EINVAL);removed.close();check(s._rpc(12)[0]==0)
            # Detected generation changes remain stale and do not donate cached
            # entries to a replacement inode. Close still releases their memory.
            s.mkdirat(None,'/stale-stream');stale=s.openat(None,'/stale-stream',directory_only=True)
            stale.readdir(1);generation=stale.stat()['generation']
            metadata(s,'/stale-stream',generation=generation+1)
            denied(stale.readdir,errno.ESTALE);denied(stale.tell,errno.ESTALE);denied(stale.rewind,errno.ESTALE)
            metadata(s,'/stale-stream',generation=generation);denied(stale.readdir,errno.ESTALE)
            stale.close();s.unlinkat(None,'/stale-stream',remove_directory=True)
            # Release/reuse of a table slot cannot inherit a previous snapshot.
            old_cookie=d.tell();d.close();denied(d.readdir,errno.EBADF)
            reopened=s.openat(None,'/moved-stream',directory_only=True);check(reopened.tell()==0)
            denied(lambda:reopened.seek(old_cookie),errno.EINVAL);reopened.close();clean(s)
        if not rows:
            # The alternate reader links the same stream code with smaller fixed
            # budgets, making both production limit paths practical to test.
            with session.Session(root,args.work/'mutation-producer',args.work/'reader-server-stream-limits',Credentials(100,200)) as s:
                large=s.openat(None,'/moved-stream',directory_only=True)
                denied(large.readdir,errno.EOVERFLOW);check(large.tell()==0);large.close()
                s.mkdirat(None,'/small');streams=[]
                for unused in range(3):
                    h=s.openat(None,'/small',directory_only=True);check(h.readdir()['eof']);streams.append(h)
                fourth=s.openat(None,'/small',directory_only=True);denied(fourth.readdir,errno.ENOMEM);check(fourth.tell()==0)
                first_cookie=streams[0].tell();streams[0].rewind();check(fourth.readdir()['eof'])
                denied(streams[0].readdir,errno.ENOMEM);fourth.close();check(streams[0].readdir()['eof'])
                denied(lambda:streams[0].seek(first_cookie),errno.EINVAL)
                for h in streams:h.close()
                # Repeated close frees all reader-wide capacity for future calls.
                for unused in range(20):
                    with s.openat(None,'/small',directory_only=True) as h:check(h.readdir()['eof'])
                clean(s)
            with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
                with s.openat(None,'/small',directory_only=True) as h:check(h.tell()==0);check(h.readdir()['eof'])
                clean(s)
            with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
                d=s.openat(None,'/small',directory_only=True)
                with patch.object(s,'_rpc',return_value=(0,struct.pack('<II',0,0))):
                    denied(d.readdir,errno.EIO)
                check(s._failed)
                denied(d.tell,errno.EIO)
        check(sha(source)==original,'source image changed');rows.append(dict(fixture=source.name,result='passed'))
        print('PASS',source.name,flush=True)
(args.work/'directory-streams-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows,scope='offline opaque directory cookies, bounded snapshots and cursor lifetime'),indent=2)+'\n')
print(f'PASS {checks} directory stream checks across {len(rows)} configurations',flush=True)
