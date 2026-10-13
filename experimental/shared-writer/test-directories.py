#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Directory topology, inherited policy and no-follow symlink mutation matrix."""
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

def check(condition,detail='check failed'):
    global checks
    assert condition,detail
    checks+=1

def run(argv):
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
    check(result.returncode==0,result.stdout+result.stderr)
    return result.stdout

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def denied(call,error):
    try:call()
    except Exception as e:check(isinstance(e,error) if isinstance(error,type) else getattr(e,'errno',None)==error,repr(e))
    else:raise AssertionError('unexpected success')

def atomic(s,call,error):
    digest,head=sha(s.root/'image.img'),s.state['head']
    denied(call,error)
    check(sha(s.root/'image.img')==digest and s.state['head']==head and s.state['pending'] is None)

def stat(s,path):
    text=run(['debugfs','-R','stat '+path,s.root/'image.img']).decode()
    patterns=[r'Inode:\s+(\d+)',r'Generation:\s+(\d+)',r'Links:\s+(\d+)',r'User:\s+(\d+)',r'Group:\s+(\d+)']
    values=[int(re.search(p,text).group(1)) for p in patterns]
    return dict(zip(['inode','generation','links','uid','gid'],values),mode=int(re.search(r'Mode:\s+([0-7]+)',text).group(1),8))

def clean(s):run(['e2fsck','-fn',s.root/'image.img'])

def create(s,path,data=b'payload'):
    s.apply([dict(kind='create',path=path,mode=0o640,data_hex=data.hex())])

def metadata(s,path,**fields):
    env={'EXT4_TEST_HANDLE_'+key.upper():str(value) for key,value in fields.items()};env['EXT4_TEST_HANDLE_PATH']=path
    with patch.object(s,'producer',args.work/'handle-test-producer'),patch.dict(os.environ,env):
        s.apply([dict(kind='write',path='/existing-file',data_hex='')])

with tempfile.TemporaryDirectory(prefix='directories-',dir=args.work) as directory:
    directory=Path(directory)
    sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source);seed=directory/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        acl=directory/'acl';acl.write_bytes(struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in
            [(1,7,2**32-1),(2,7,101),(4,5,2**32-1),(16,7,2**32-1),(32,1,2**32-1)]))
        commands=directory/'seed.commands';commands.write_text('\n'.join([
            'set_inode_field / mode 040777','set_inode_field / uid 100',
            'set_inode_field /existing-file uid 100','set_inode_field /existing-file gid 200',
            'set_inode_field /existing-file mode 0100660','mkdir /group',
            'set_inode_field /group mode 042777','set_inode_field /group uid 100','set_inode_field /group gid 300',
            'mkdir /acl','set_inode_field /acl mode 042777','set_inode_field /acl uid 100','set_inode_field /acl gid 300',
            f'ea_set -f {acl} /acl system.posix_acl_default','mkdir /readonly','set_inode_field /readonly mode 040555',
            'mkdir /sticky','set_inode_field /sticky mode 041777','set_inode_field /sticky uid 200',
            'mkdir /sticky/foreign','set_inode_field /sticky/foreign uid 101',
            'symlink /sticky/foreign-link ../existing-file','set_inode_field /sticky/foreign-link uid 101',
            'symlink /parent-link group'])+'\n')
        run(['debugfs','-w','-f',commands,seed]);run(['e2fsck','-fn',seed])
        root=directory/source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        image=root/'image.img';identity=(image.stat().st_dev,image.stat().st_ino)
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(100,200,umask=0o027)) as s:
            pid=s._process.pid;initial=stat(s,'/')['links'];free=s.counters()
            s.mkdir('/normal');n=stat(s,'/normal')
            check((n['mode'],n['uid'],n['gid'],n['links'])==(0o750,100,200,2))
            check(stat(s,'/')['links']==initial+1);check(stat(s,'/normal/.')['inode']==n['inode'])
            check(stat(s,'/normal/..')['inode']==stat(s,'/')['inode']);clean(s)
            s.rmdir('/normal');check(s.counters()==free);check(stat(s,'/')['links']==initial);clean(s)
            s.mkdir('/normal');replacement=stat(s,'/normal')
            if replacement['inode']==n['inode']:check(replacement['generation']!=n['generation'])
            s.mkdir('/group/inherited');g=stat(s,'/group/inherited')
            check((g['mode'],g['uid'],g['gid'])==(0o2750,100,300));clean(s)
            s.mkdir('/acl/inherited',0o770);a=stat(s,'/acl/inherited')
            check((a['mode'],a['uid'],a['gid'])==(0o2770,100,300))
            create(s,'/acl/inherited/child',b'ACL descendant')
            child=stat(s,'/acl/inherited/child');check((child['uid'],child['gid'],child['mode'])==(100,300,0o640));clean(s)
            s.mkdir('/own-sticky',0o1777);check(stat(s,'/own-sticky')['mode']==0o1750)
            # Cross-parent subtree rename updates '..' and both parent link counts.
            s.apply([dict(kind='mkdir',path='/tree'),dict(kind='mkdir',path='/tree/a'),dict(kind='mkdir',path='/tree/a/b'),
                     dict(kind='mkdir',path='/newparent')])
            create(s,'/tree/a/b/leaf',b'moved subtree');f=s.open('/tree/a/b/leaf','rw')
            before=stat(s,'/tree/a');from_links=stat(s,'/tree')['links'];to_links=stat(s,'/newparent')['links']
            atomic(s,lambda:s.rename('/tree/a','/tree/a/b/cycle'),errno.EINVAL)
            atomic(s,lambda:s.rename('/tree/a','/tree/a/new'),errno.EINVAL)
            s.rename('/tree/a','/newparent/moved')
            check(stat(s,'/newparent/moved')['inode']==before['inode'])
            check(stat(s,'/newparent/moved')['links']==before['links'])
            check(stat(s,'/newparent/moved/..')['inode']==stat(s,'/newparent')['inode'])
            check(stat(s,'/newparent/moved/b/..')['inode']==before['inode'])
            check(stat(s,'/tree')['links']==from_links-1);check(stat(s,'/newparent')['links']==to_links+1)
            denied(lambda:s.size('/tree/a/b/leaf'),errno.ENOENT)
            check(f.read()==b'moved subtree');f.write(b'LIVE');check(s.read('/newparent/moved/b/leaf')==b'LIVEd subtree');f.close();clean(s)
            s.rename('/newparent/moved','/newparent/moved');clean(s)
            atomic(s,lambda:s.rmdir('/newparent/moved'),errno.ENOTEMPTY)
            atomic(s,lambda:s.unlink('/newparent/moved'),errno.EISDIR)
            atomic(s,lambda:s.link('/newparent/moved','/hard-directory'),errno.EPERM)
            # Directory replacement reclaims the empty target and balances counts.
            s.mkdir('/other');s.mkdir('/other/empty');s.mkdir('/replacement')
            moving=stat(s,'/other/empty');root_links=stat(s,'/')['links'];other_links=stat(s,'/other')['links'];free=s.counters()
            s.rename('/other/empty','/replacement')
            check(stat(s,'/replacement')['inode']==moving['inode']);check(stat(s,'/replacement/..')['inode']==stat(s,'/')['inode'])
            check(stat(s,'/')['links']==root_links);check(stat(s,'/other')['links']==other_links-1)
            check(s.counters()[1]==free[1]+1);clean(s)
            atomic(s,lambda:s.rename('/replacement','/newparent/moved'),errno.ENOTEMPTY)
            atomic(s,lambda:s.rename('/replacement','/existing-file'),errno.ENOTDIR)
            atomic(s,lambda:s.rename('/existing-file','/replacement'),errno.EISDIR)
            atomic(s,lambda:s.rmdir('/existing-file'),errno.ENOTDIR)
            atomic(s,lambda:s.mkdir('/replacement'),errno.EEXIST)
            atomic(s,lambda:s.mkdir('/readonly/new'),errno.EACCES)
            atomic(s,lambda:s.mkdir('/missing/child'),errno.ENOENT)
            atomic(s,lambda:s.symlink('target','/missing/child'),errno.ENOENT)
            atomic(s,lambda:s.mkdir('/existing-file/child'),errno.ENOTDIR)
            atomic(s,lambda:s.symlink('target','/existing-file/child'),errno.ENOTDIR)
            atomic(s,lambda:s.mkdir('/parent-link/new'),errno.ELOOP)
            atomic(s,lambda:s.rmdir('/sticky/foreign'),errno.EPERM)
            atomic(s,lambda:s.rename('/sticky/foreign','/foreign-moved'),errno.EPERM)
            atomic(s,lambda:s.unlink('/sticky/foreign-link'),errno.EPERM)
            # Cross-parent rename needs write permission on the directory itself.
            metadata(s,'/replacement',mode=0o555)
            atomic(s,lambda:s.rename('/replacement','/other/no-write'),errno.EACCES)
            s.rename('/replacement','/same-parent-readonly');s.rmdir('/same-parent-readonly');clean(s)
            metadata(s,'/normal',flags=16);atomic(s,lambda:s.rmdir('/normal'),errno.EPERM);metadata(s,'/normal',flags=0)
            # Fast and slow links, target byte preservation, no-follow hardlink/rename/unlink.
            block=int(source.name.split('-')[0])
            targets=['../existing-file','x'*59,'x'*60,'y'*(block-1),'../caf\u00e9/\u2603']
            for index,target in enumerate(targets):
                name=f'/sym-{index}';free=s.counters();s.symlink(target,name)
                check(s.readlink(name)==target.encode('utf-8'));link=stat(s,name)
                check((link['mode'],link['uid'],link['gid'],link['links'])==(0o777,100,200,1))
                check(s.counters()[1]==free[1]-1)
                denied(lambda:s.open(name),errno.ELOOP);atomic(s,lambda:s.rmdir(name),errno.ENOTDIR)
                s.link(name,name+'-alias');check(stat(s,name+'-alias')['inode']==link['inode'])
                s.rename(name,name+'-moved');check(s.readlink(name+'-moved')==target.encode('utf-8'))
                s.unlink(name+'-alias');check(stat(s,name+'-moved')['links']==1)
                s.unlink(name+'-moved');check(s.counters()==free);clean(s)
            # Zero-length corrupt symlinks cannot make target bytes into block pointers.
            s.symlink('temporary-target','/damaged-link');metadata(s,'/damaged-link',size=0)
            atomic(s,lambda:s.unlink('/damaged-link'),errno.EIO)
            metadata(s,'/damaged-link',size=len('temporary-target'))
            check(s.readlink('/damaged-link')==b'temporary-target');s.unlink('/damaged-link');clean(s)
            s.symlink('does-not-exist','/dangling');check(s.readlink('/dangling')==b'does-not-exist')
            s.symlink('/newparent','/directory-link');atomic(s,lambda:s.rmdir('/directory-link'),errno.ENOTDIR)
            s.unlink('/directory-link');check(stat(s,'/newparent')['links']>=2)
            s.symlink('target','/acl/link');sy=stat(s,'/acl/link');check((sy['mode'],sy['gid'])==(0o777,300))
            # Symbolic-link replacement pins a regular target; replacing the link never changes its target.
            create(s,'/victim',b'original victim');old=s.open('/victim','rw')
            s.symlink('existing-file','/replace-link');s.rename('/replace-link','/victim')
            check(s.readlink('/victim')==b'existing-file');check(old.read()==b'original victim');old.write(b'old')
            old.close();check(s._rpc(12)[0]==0);clean(s)
            create(s,'/replace-file',b'regular replaces link');s.rename('/replace-file','/victim')
            check(s.read('/victim')==b'regular replaces link');clean(s)
            atomic(s,lambda:s.symlink('x'*block,'/too-long'),errno.ENAMETOOLONG)
            for target in ('','x\0y'):
                atomic(s,lambda target=target:s.symlink(target,'/invalid'),ValueError)
            atomic(s,lambda:s.symlink('x','/victim'),errno.EEXIST)
            atomic(s,lambda:s.readlink('/victim'),errno.EINVAL)
            s._rpc(3);denied(lambda:s._rpc(13,b'/dangling'),errno.EBUSY);s._rpc(4)
            # Whole-batch rollback includes directory accounting and link payload blocks.
            atomic(s,lambda:s.apply([dict(kind='mkdir',path='/rollback'),dict(kind='symlink',path='/rollback/link',target='x'*60),
                                   dict(kind='rmdir',path='/missing')]),errno.ENOENT)
            with patch.dict(os.environ,{'EXT4_TEST_MUTATION_FAIL_WRITES':'0'}):
                atomic(s,lambda:s.mkdir('/failed-directory'),errno.ENOSPC)
                atomic(s,lambda:s.symlink('x'*60,'/failed-link'),errno.ENOSPC)
                atomic(s,lambda:s.rename('/normal','/other/failed-move'),errno.ENOSPC)
            # Complete a sealed cross-parent rename after a real half-page write failure.
            boundary=inplace.boundary;once=[False]
            def interrupt(name):
                if name=='half:0:0' and not once[0]:once[0]=True;raise OSError(errno.EIO,'torn directory update')
                return boundary(name)
            with patch.object(inplace,'boundary',interrupt):denied(lambda:s.rename('/normal','/other/recovered'),errno.EIO)
            check(once[0]);denied(lambda:s.size('/normal'),errno.ENOENT)
            check(stat(s,'/other/recovered/..')['inode']==stat(s,'/other')['inode']);clean(s)
            # Batch teardown validates empty removal and parent/accounting restoration.
            s.apply([dict(kind='unlink',path='/newparent/moved/b/leaf'),dict(kind='rmdir',path='/newparent/moved/b'),
                     dict(kind='rmdir',path='/newparent/moved'),dict(kind='rmdir',path='/newparent'),dict(kind='rmdir',path='/tree')])
            clean(s);check(s._process.pid==pid);check((image.stat().st_dev,image.stat().st_ino)==identity)
        # Independent caller checks inherited default ACL semantics through the new directory.
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(101,201)) as s:
            check(s.read('/acl/inherited/child')==b'ACL descendant')
            denied(lambda:s.open('/acl/inherited/child','rw'),errno.EACCES)
            create(s,'/acl/inherited/peer',b'peer creation')
            p=stat(s,'/acl/inherited/peer');check((p['uid'],p['gid'])==(101,300));clean(s)
            atomic(s,lambda:s.link('/acl/link','/unowned-link'),errno.EPERM)
        check(sha(source)==original,'source changed')
        rows.append(dict(fixture=source.name,result='passed'));print('PASS',source.name,flush=True)
report=dict(result='passed',checks=checks,configurations=rows,scope='offline mkdir/rmdir/directory rename, symlink create/link/rename/unlink and native readlink')
(args.work/'directories-results.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'directory/symlink checks')
