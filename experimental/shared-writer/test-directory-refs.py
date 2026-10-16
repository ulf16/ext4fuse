#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Directory/cwd identity, removed ancestry, bounded pins and crash reclamation."""
import argparse
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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

def create(s,path,data=b'content'):
    s.apply([dict(kind='create',path=path,mode=0o660,data_hex=data.hex())])

def metadata(s,path,**fields):
    env={'EXT4_TEST_HANDLE_'+k.upper():str(v) for k,v in fields.items()};env['EXT4_TEST_HANDLE_PATH']=path
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])

with tempfile.TemporaryDirectory(prefix='dirrefs-',dir=args.work) as temp:
    temp=Path(temp);sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source);seed=temp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        script=temp/'seed.commands';script.write_text('\n'.join([
            'set_inode_field / mode 040777','set_inode_field / uid 100',
            'set_inode_field /existing-file uid 100','set_inode_field /existing-file gid 200','set_inode_field /existing-file mode 0100660',
            'symlink /sym existing-file'])+'\n')
        run(['debugfs','-w','-f',script,seed]);clean_image=seed
        run(['e2fsck','-fn',clean_image]);root=temp/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server-handle-limits',Credentials(100,200)) as s:
            pid=s._process.pid;check(s.getcwd()=='/');check(s.cwd_stat()['inode']==2)
            r=s.opendir('/');check('existing-file' in r.listdir());check(r.path()=='/');r.close()
            atomic(s,lambda:s.opendir('/missing'),errno.ENOENT)
            atomic(s,lambda:s.opendir('/existing-file'),errno.ENOTDIR)
            atomic(s,lambda:s.opendir('/sym'),errno.ELOOP)
            f=s.open('/existing-file');atomic(s,lambda:s.fchdir(f),errno.ENOTDIR);f.close()
            s.mkdir('/a');s.mkdir('/a/b');create(s,'/a/b/leaf')
            d=s.opendir('/a/b');dup=d.dup();identity=d.stat()['inode']
            check(d.listdir()==['leaf']);check(d.path()=='/a/b');check(dup.stat()['inode']==identity)
            for call in (lambda:d.read(),lambda:d.write(b'data'),lambda:d.truncate(0)):
                atomic(s,call,errno.EISDIR)
            s.fchdir(d);check(s.getcwd()=='/a/b');check(s.cwd_stat()['inode']==identity)
            d.close();check(s.getcwd()=='/a/b');check(s.read('leaf')==b'content')
            create(s,'relative',b'cwd child');check(s.read('relative')==b'cwd child')
            s.rename('/a','/moved');check(s.getcwd()=='/moved/b');check(dup.path()=='/moved/b')
            check(s.read('leaf')==b'content');s.symlink('../b/leaf','relative-link');check(s.readlink('relative-link')==b'../b/leaf')
            s.unlink('relative-link');s.unlink('relative');s.unlink('leaf')
            before=s.counters();s.rmdir('/moved/b');s.rmdir('/moved')
            check(s.counters()==before,'removed referenced directory allocations changed')
            check(dup.listdir()==[]);check(dup.stat()['links']==0 and dup.stat()['size']==0)
            denied(s.getcwd,errno.ENOENT);denied(dup.path,errno.ENOENT)
            check(s.cwd_stat()['links']==0);atomic(s,lambda:create(s,'child'),errno.ENOENT)
            # Both child and removed parent survive; '..' can escape the detached tree.
            dup.close();check(s._rpc(12)[0]!=0)
            s.chdir('..');check(s.cwd_stat()['links']==0);denied(s.getcwd,errno.ENOENT)
            s.chdir('..');check(s.getcwd()=='/');check(s._rpc(12)[0]==0)
            check(s.counters()[1]==before[1]+2 and s.counters()[0]>before[0]);clean(s)
            # Directory overwrite keeps the old empty destination identity alive.
            s.mkdir('/source');s.mkdir('/destination');old=s.opendir('/destination');oldino=old.stat()['inode']
            s.fchdir(old);s.rename('/source','/destination')
            check(old.stat()['inode']==oldino and old.stat()['links']==0);denied(s.getcwd,errno.ENOENT)
            new=s.opendir('/destination');check(new.stat()['inode']!=oldino);check(new.path()=='/destination')
            s.fchdir(new);old.close();check(s.getcwd()=='/destination');check(s._rpc(12)[0]==0)
            new.close();s.chdir('/');s.rmdir('/destination');clean(s)
            # Reading is an open-time grant; fchdir and path lookups recheck search.
            s.mkdir('/permissions');create(s,'/permissions/item');d=s.opendir('/permissions')
            metadata(s,'/permissions',mode=0)
            check(d.listdir()==['item']);check(d.path()=='/permissions')
            atomic(s,lambda:s.fchdir(d),errno.EACCES);atomic(s,lambda:s.opendir('/permissions'),errno.EACCES)
            metadata(s,'/permissions',mode=0o111);s.fchdir(d);check(s.getcwd()=='/permissions')
            atomic(s,lambda:s.opendir('.'),errno.EACCES)
            create(s,'/absolute-from-cwd',b'absolute')
            s.chdir('/');metadata(s,'/permissions',mode=0o777);d.close()
            s.unlink('/permissions/item');s.rmdir('/permissions');s.unlink('/absolute-from-cwd');clean(s)
            # Search-only cwd does not acquire a read grant. Permission loss does
            # not discard cwd identity, but relative traversal is denied.
            s.mkdir('/search');metadata(s,'/search',mode=0o111);s.chdir('/search')
            denied(lambda:s._rpc(16,s._cwd_token()),errno.EBADF)
            metadata(s,'/search',mode=0);check(s.getcwd()=='/search')
            atomic(s,lambda:s.read('missing'),errno.EACCES)
            s.chdir('/');metadata(s,'/search',mode=0o777);s.rmdir('/search')
            # Failed batches/producers cannot detach a live directory reference.
            s.mkdir('/rollback');d=s.opendir('/rollback');s.fchdir(d)
            atomic(s,lambda:s.apply([dict(kind='rmdir',path='/rollback'),dict(kind='unlink',path='/missing')]),errno.ENOENT)
            check(d.path()=='/rollback' and s.getcwd()=='/rollback')
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:s.rmdir('/rollback'),errno.ENOSPC)
            boundary=inplace.boundary;once=[False]
            def interrupt(name):
                if name=='half:0:0' and not once[0]:once[0]=True;raise OSError(errno.EIO,'torn held-directory removal')
                return boundary(name)
            with patch.object(inplace,'boundary',interrupt):denied(lambda:s.rmdir('/rollback'),errno.EIO)
            check(once[0]);check(d.stat()['links']==0);check(d.listdir()==[]);denied(s.getcwd,errno.ENOENT)
            s.chdir('..');d.close();check(s._rpc(12)[0]==0);clean(s)
            # Native pending gate also covers directory listing/path/cwd traversal.
            d=s.opendir('/');s._rpc(3)
            for op,payload in ((15,s._file(d)),(16,s._file(d)),(17,s._file(d)),(20,s._cwd_token()+b'.')):
                denied(lambda op=op,payload=payload:s._rpc(op,payload),errno.EBUSY)
            s._rpc(4)
            fake=copy.copy(d);denied(fake.listdir,errno.EBADF);denied(fake.close,errno.EBADF)
            check(d.path()=='/');d.close();denied(d.stat,errno.EBADF)
            check(s._process.pid==pid)
            # Final cwd release failure keeps a recoverable orphan, but does not
            # undo the successfully installed new cwd reference.
            s.mkdir('/release-failure');s.chdir('/release-failure');s.rmdir('/release-failure')
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:s.chdir('/'),errno.ENOSPC)
            check(s.getcwd()=='/' and s._rpc(12)[0]!=0)
            create(s,'/reap-trigger');check(s._rpc(12)[0]==0);s.unlink('/reap-trigger');clean(s)
            # Cross-session and stale/copy identities cannot transfer cwd authority.
            s.mkdir('/stale');d=s.opendir('/stale');old_gen=d.stat()['generation']
            metadata(s,'/stale',generation=old_gen+1)
            denied(d.stat,errno.ESTALE);atomic(s,lambda:s.fchdir(d),errno.ESTALE)
            metadata(s,'/stale',generation=old_gen);denied(d.listdir,errno.ESTALE)
            d.close();fresh=s.opendir('/stale');fresh.close();s.rmdir('/stale');clean(s)
            if not rows:
                # A full handle table cannot silently discard the current cwd.
                s.mkdir('/quota')
                roots=[s.opendir('/') for _ in range(128-len(s._files))]
                atomic(s,lambda:s.opendir('/'),errno.EMFILE)
                atomic(s,lambda:s.chdir('/quota'),errno.EMFILE)
                atomic(s,roots[0].dup,errno.EMFILE)
                check(s.getcwd()=='/')
                roots.pop().close();s.chdir('/quota');check(s.getcwd()=='/quota')
                for handle in roots:handle.close()
                s.rmdir('/quota');s.chdir('/');check(s._rpc(12)[0]==0);clean(s)
                # The ancestry-depth bound is independent of the enlarged pin budget.
                paths=['/deep']
                for _ in range(127):paths.append(paths[-1]+'/d')
                for start in range(0,128,64):s.apply([dict(kind='mkdir',path=p) for p in paths[start:start+64]])
                deep=s.opendir(paths[-1]);check(deep.path()==paths[-1])
                s.mkdir(paths[-1]+'/extra')
                atomic(s,lambda:s.opendir(paths[-1]+'/extra'),errno.EMFILE)
                with s.open('/existing-file') as independent:check(independent.size()>=0)
                atomic(s,lambda:s.chdir(paths[-1]+'/extra'),errno.EMFILE)
                check(s.getcwd()=='/');s.rmdir(paths[-1]+'/extra')
                # All 128 retained ancestors may become unlinked together.
                reversed_paths=list(reversed(paths))
                for start in range(0,128,64):s.apply([dict(kind='rmdir',path=p) for p in reversed_paths[start:start+64]])
                check(deep.stat()['links']==0 and deep.listdir()==[])
                denied(deep.path,errno.ENOENT);deep.close();check(s._rpc(12)[0]==0);clean(s)
            # Session close drops both a public directory handle and private cwd.
            s.mkdir('/shutdown');d=s.opendir('/shutdown');s.fchdir(d);s.rmdir('/shutdown')
        run(['e2fsck','-fn',root/'image.img']);check(d.closed)
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            check(s.getcwd()=='/' and s._rpc(12)[0]==0);s.mkdir('/crash');s.mkdir('/crash/child')
        child='''import os,sys
sys.path.insert(0,sys.argv[1])
import session
from credentials import Credentials
s=session.Session(sys.argv[2],sys.argv[3],sys.argv[4],Credentials(100,200))
d=s.opendir('/crash/child');s.fchdir(d);d.close()
s.rmdir('/crash/child');s.rmdir('/crash')
os._exit(0)
'''
        run(['python3','-c',child,here,root,args.work/'mutation-producer',args.work/'reader-server'])
        # Independently recover the directory orphan chain on a dead-session copy.
        fsck_copy=temp/(source.stem+'-orphans.img');shutil.copyfile(root/'image.img',fsck_copy)
        result=subprocess.run(['e2fsck','-fy',str(fsck_copy)],capture_output=True,timeout=90)
        check(result.returncode in (0,1),result.stdout+result.stderr);run(['e2fsck','-fn',fsck_copy])
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)) as s:
            check(s.getcwd()=='/' and s._rpc(12)[0]==0);clean(s)
        if not rows:
            # A checksum-valid but cyclic removed-directory ancestry poisons
            # refresh/attach, and cannot be used to free arbitrary inodes.
            bad=temp/'bad-ancestry'
            run(['python3',here/'chain.py','init',seed,bad,args.work/'prototype'])
            s=session.Session(bad,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200))
            s.mkdir('/bad');d=s.opendir('/bad');ino=d.stat()['inode'];s.rmdir('/bad')
            denied(lambda:metadata(s,'/unused',inode=ino,parent=ino),errno.EIO)
            denied(d.stat,errno.EIO);digest=sha(bad/'image.img');s.close()
            denied(lambda:session.Session(bad,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200)),OSError)
            check(sha(bad/'image.img')==digest,'failed attach changed corrupt ancestry')
        check(sha(source)==original,'source image changed')
        rows.append(dict(fixture=source.name,result='passed'));print('PASS',source.name,flush=True)
report=dict(result='passed',checks=checks,configurations=rows,scope='offline directory handles, identity-based cwd and detached ancestry lifetime')
(args.work/'directory-refs-results.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'directory/cwd reference checks')
