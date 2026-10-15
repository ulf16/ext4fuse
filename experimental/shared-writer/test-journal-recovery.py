#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Committed/revoked/incomplete JBD2 replay and atomic external recovery faults."""
import argparse,errno,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
import chain,session
from credentials import Credentials
import journal_fixtures as fixture,journal_recovery as journal
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);a=p.parse_args();checks=0;here=Path(__file__).resolve().parent

def check(value,detail='journal recovery check failed'):
 global checks
 assert value,detail;checks+=1
def opened(root,**kwargs):return session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0),**kwargs)
def verify(root,expected):
 with opened(root) as s:
  with s.open('/existing-file') as h:check(h.read()==expected)
 fixture.run(['e2fsck','-fn',root/'image.img'])

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='journal-recovery-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sources):
  source_hash=fixture.sha(source)
  for kind in ('committed','uncommitted','revoke','escaped','tail'):
   image=tmp/f'{index}-{kind}.img';detail=fixture.create(source,image,kind=kind);original=fixture.sha(image)
   check(journal.inspect(image)['needed']);root=tmp/f'{index}-{kind}'
   chain.clone(image,root)
   # Default refusal remains; explicit recovery must precede the native reader.
   try:
    with opened(root):pass
   except OSError:check(True)
   else:raise AssertionError('dirty filesystem mounted without recovery opt-in')
   with opened(root,recover_journal=True) as s:
    with s.open('/existing-file') as h:check(h.read()==detail['new'])
    head=s.state['head'];check(head==1)
    h=s.openat(None,'/after-replay','rw',create=True);h.write(b'writer after native replay');h.close()
   check(not journal.inspect(root/'image.img')['needed']);check(fixture.sha(image)==original)
   fixture.run(['e2fsck','-fn',root/'image.img']);check(not list(root.glob('g-*/journal-candidate')))
   with opened(root,recover_journal=True) as s:check(s.state['head']>head)
   # Journal generations and their bounded logs must retire normally.
   with opened(root) as s:s.checkpoint()
   check(not list(root.glob('g-*')));check(fixture.sha(source)==source_hash)
 # Explicitly exercise checksum-v2 as well as the modern default v3.
 modern=next((p for p in sources if 'csum1' in p.name),None)
 if modern:
  for kind in ('committed','uncommitted','revoke','escaped','tail'):
   image=tmp/f'v2-{kind}.img';detail=fixture.create(modern,image,version=2,kind=kind)
   root=tmp/f'v2-{kind}';chain.clone(image,root);journal.managed(root);verify(root,detail['new'])
 # Trusted-tool failures must remain bounded and terminate their subprocess.
 for program,timeout in (("import time;time.sleep(5)",.05),("import sys;sys.stdout.write('x'*300000)",5)):
  try:journal.command([sys.executable,'-c',program],dict(os.environ),timeout=timeout)
  except OSError as error:check(error.errno in (errno.ETIMEDOUT,errno.EFBIG))
  else:raise AssertionError('unbounded recovery subprocess accepted')
 # Failure points before sealing must preserve dirty bytes; sealed replay must
 # complete idempotently after a fresh process starts, including torn pages.
 image=tmp/'fault.img';detail=fixture.create(sources[0],image);original=fixture.sha(image)
 for number,phase in enumerate(('journal:copied','journal:replayed','journal:checked','journal:stream-ready','journal:streamed',
       'chain-intent','record','undo-log','prepared','chain-prepared','validated','started','half:0:0','page:0','synced','head-ready','head-published')):
  root=tmp/f'fault-{number}';chain.clone(image,root)
  result=subprocess.run([sys.executable,here/'journal-recover.py','chain',root],env=dict(os.environ,EXT4_TEST_CRASH=phase),capture_output=True,timeout=120)
  check(result.returncode!=0,(phase,result.stdout,result.stderr))
  if phase.startswith('journal:'):check(fixture.sha(root/'image.img')==original,'candidate replay escaped before sealing')
  journal.managed(root);verify(root,detail['new']);head=chain.read_state(root)['head'];journal.managed(root);check(chain.read_state(root)['head']==head)
  check(fixture.sha(image)==original)
 # Non-journal damage must not be fixed by journal recovery, and no device is
 # ever handed to e2fsck. Unknown/external journal geometry is refused early.
 for problem in ('no-journal','external','errors','capacity','journal-corrupt','journal-uuid','journal-size','journal-feature','journal-error','journal-checksum','super-checksum','journal-length','metadata-corrupt'):
  if problem in ('journal-checksum','super-checksum') and modern is None:continue
  image=tmp/(problem+'.img');detail=fixture.create(modern if problem in ('journal-checksum','super-checksum') and modern else sources[0],image)
  if problem=='no-journal':
   with image.open('rb') as f:f.seek(1120);features=struct.unpack('<I',f.read(4))[0]
   fixture.debug(image,f'set_super_value feature_incompat {features&~4}')
  elif problem=='external':fixture.debug(image,'set_super_value journal_dev 1')
  elif problem=='errors':fixture.debug(image,'set_super_value state 2')
  elif problem=='capacity':
   with image.open('r+b') as f:f.truncate(image.stat().st_size-4096)
  elif problem=='super-checksum':
   with image.open('r+b') as f:f.seek(2044);f.write(b'BAD!')
  elif problem=='metadata-corrupt':fixture.debug(image,'set_inode_field /existing-file links_count 0')
  else:
   journal_blocks=list(map(int,fixture.debug(image,'blocks <8>').split()))
   with image.open('r+b') as f:
    offset,data={'journal-corrupt':(0,b'BAD!'),'journal-uuid':(48,bytes(16)),'journal-size':(12,struct.pack('>I',8192)),'journal-length':(16,struct.pack('>I',2)),'journal-feature':(40,struct.pack('>I',0x80000000)),'journal-error':(32,struct.pack('>I',5)),'journal-checksum':(252,b'BAD!')}[problem]
    f.seek(journal_blocks[0]*detail['block']+offset);f.write(data)
  original=fixture.sha(image);root=tmp/(problem+'-chain');chain.clone(image,root);before=fixture.sha(root/'image.img')
  try:journal.managed(root)
  except (OSError,ValueError):check(True,problem)
  else:raise AssertionError('unsafe recovery accepted: '+problem)
  check(fixture.sha(image)==original);check(fixture.sha(root/'image.img')==before)
(a.work/'journal-recovery-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources)),indent=2)+'\n')
print('PASS',checks,'native journal recovery checks')
