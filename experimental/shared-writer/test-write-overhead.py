#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Direct producer dispatch and read-only orphan eligibility preserve inode lifetime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import chain
import session
from credentials import Credentials

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True)
a=p.parse_args();a.work.mkdir(parents=True,exist_ok=True);a.work=a.work.resolve()
base=Path(tempfile.mkdtemp(prefix='write-overhead-',dir=a.work));checks=0;rows=[]
def check(value):
 global checks
 assert value;checks+=1
def command(argv):
 result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=120)
 check(result.returncode==0);return result

def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

for name,block,features in [('classic','1024','^extent,^64bit,^metadata_csum,^orphan_file'),('extents','4096','extent,64bit,metadata_csum,^orphan_file')]:
 source=base/(name+'.img')
 with source.open('xb') as f:f.truncate(32*1024**2)
 command(['mke2fs','-q','-F','-t','ext4','-b',block,'-O',features,source])
 original=digest(source);root=base/name;chain.clone(source,root)
 # This interpreter is already running. A per-request Python adapter would
 # import this sitecustomize, while the native children must ignore it.
 custom=base/(name+'-site');custom.mkdir();sentinel=custom/'executed'
 (custom/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').write_text("unexpected adapter")\n')
 poison=base/(name+'-poison');poison.write_bytes(b'invalid inherited request')
 native=subprocess.Popen
 with patch.dict(os.environ,dict(PYTHONPATH=str(custom),EXT4_MUTATION_REQUEST=str(poison))):
  with patch.object(subprocess,'Popen',wraps=native) as launches:
   with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
    s._mount_nodes()
    s.apply([dict(kind='create',path=path) for path in ['/held','/lookup-only','/unrelated']])
    h=s.openat(None,'/held','rw');h.write(b'held data',0)
    second=s.openat(None,'/held','r')
    lookup,_,_=s._mount_lookup(None,'lookup-only')
    s.mkdir('/parent');s.mkdir('/parent/child');s.chdir('/parent/child')
    s.unlink('/held');s.unlink('/lookup-only')
    s.unlinkat(None,'/parent/child',remove_directory=True);s.unlinkat(None,'/parent',remove_directory=True)
    check(s._rpc(12)[0]!=0);check(s._rpc(44)[0]==0)
    head=s.state['head'];root_hash=s.state['sha256']
    check(h.read(0,9)==b'held data')
    for _ in range(12):
     other=s.openat(None,'/unrelated','r');other.close()
     check(s.state['head']==head and s.state['sha256']==root_hash)
    second.close();check(s.state['head']==head)
    before=s.state['head'];h.close();check(s.state['head']==before+1)
    check(s._rpc(12)[0]!=0 and s._rpc(44)[0]==0)
    before=s.state['head'];lookup.close();check(s.state['head']==before+1)
    # The removed parent stays pinned by its child's cwd until chdir releases it.
    check(s.statat(None,'.')['links']==0)
    before=s.state['head'];s.chdir('/');check(s.state['head']==before+1)
    check(s._rpc(12)[0]==0 and s._rpc(44)[0]==0)
    check(not list(root.glob('g-*/request-producer')))
    # Older states may still contain their generated adapters. They remain
    # allowable retirement entries and are never needed for redo recovery.
    legacy=next(root.glob('g-*'))/'request-producer';legacy.write_text('legacy adapter retained for compatibility');legacy.chmod(0o700)
    s.checkpoint();check(not list(root.glob('g-*')))
   producers=[call for call in launches.call_args_list if '--stream' in list(map(str,call.args[0]))]
   check(bool(producers))
   for call in producers:
    check(Path(call.args[0][0])==a.work/'mutation-producer')
    request=Path(call.kwargs['env']['EXT4_MUTATION_REQUEST'])
    check(request.name=='operations' and request.parent.parent==root)
    check('EXT4_VERIFIED_READ' in call.kwargs['env'])
    check(bool(call.kwargs['pass_fds']))
 check(not sentinel.exists() and poison.read_bytes()==b'invalid inherited request')
 command(['e2fsck','-fn',root/'image.img']);check(digest(source)==original)
 rows.append(dict(profile=name,result='passed',unrelated_closes_without_commit=12,orphan_head_cleared=True))
result=dict(result='passed',checks=checks,profiles=rows,diagnostics=str(base))
(a.work/'write-overhead-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
