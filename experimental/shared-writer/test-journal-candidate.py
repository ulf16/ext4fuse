#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded private replay views: formats, namespace recovery and refusal safety."""
import argparse,json,shutil,struct,tempfile
from pathlib import Path
import journal_candidate as candidate,journal_fixtures as fixture,journal_recovery as journal
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--limit',type=int);a=p.parse_args();checks=0;maximum=0

def check(value,detail='candidate replay check failed'):
 global checks
 assert value,detail;checks+=1

def replay(image,expected,path='/existing-file',budget=256*1024**2):
 global maximum
 before=fixture.sha(image);stream=image.with_suffix('.stream')
 with stream.open('wb') as output:
  with candidate.candidate(image,a.work,budget,image.with_suffix('.daemon.log'),output) as view:
   journal.replay_candidate(view,image.with_suffix('.replay.log'))
 result=image.with_suffix('.result');shutil.copyfile(image,result)
 with stream.open('rb') as src,result.open('r+b') as dst:
  magic,size,count=struct.unpack('<8sQQ',src.read(24));check(magic==b'E4OVL001' and size==image.stat().st_size);check(count*4096<=budget)
  previous=-1
  for unused in range(count):
   page,old,new=struct.unpack('<Q4096s4096s',src.read(8200));check(previous<page<size//4096);previous=page
   dst.seek(page*4096);check(dst.read(4096)==old);dst.seek(page*4096);dst.write(new)
  check(not src.read(1));maximum=max(maximum,count*4096)
 fixture.run(['e2fsck','-fn',result]);check(fixture.run(['debugfs','-R','cat '+path,result])==expected);check(fixture.sha(image)==before)
 # Independent full-copy recovery oracle is test-only, never production storage.
 oracle=image.with_suffix('.oracle');shutil.copyfile(image,oracle);journal.replay_candidate(oracle,image.with_suffix('.oracle.log'))
 # e2fsprogs updates the primary superblock write time and its checksum.
 with oracle.open('rb') as left,result.open('rb') as right:
  x=bytearray(left.read());y=bytearray(right.read())
  for offset,length in ((1072,4),(2044,4)):
   x[offset:offset+length]=y[offset:offset+length]
  check(x==y,('oracle differences',[i for i,(u,v) in enumerate(zip(x,y)) if u!=v][:32]))

sources=sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)
if a.limit:sources=sources[:a.limit]
check(bool(sources))
with tempfile.TemporaryDirectory(prefix='candidate-test-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for number,source in enumerate(sources):
  for kind in ('committed','uncommitted','revoke','escaped','tail'):
   image=tmp/f'{number}-{kind}.img';detail=fixture.create(source,image,kind=kind);replay(image,detail['new'])
  image=tmp/f'{number}-metadata.img';expected=fixture.metadata(source,image);replay(image,expected,'/journal-created')
 modern=next((s for s in sources if 'csum1' in s.name),None)
 if modern:
  for kind in ('committed','uncommitted','revoke','escaped','tail'):
   image=tmp/f'v2-{kind}.img';detail=fixture.create(modern,image,version=2,kind=kind);replay(image,detail['new'])
 for problem in ('budget','metadata','checksum','uuid','feature'):
  image=tmp/(problem+'.img');fixture.metadata(modern or sources[0],image)
  if problem=='metadata':fixture.debug(image,'set_inode_field /existing-file links_count 0')
  elif problem not in ('budget',):
   blocks=list(map(int,fixture.debug(image,'blocks <8>').split()))
   with image.open('rb') as f:f.seek(1048);block=1024<<struct.unpack('<I',f.read(4))[0]
   offset,data={'checksum':(252,b'BAD!'),'uuid':(48,bytes(16)),'feature':(40,struct.pack('>I',0x80000000))}[problem]
   with image.open('r+b') as f:f.seek(blocks[0]*block+offset);f.write(data)
  before=fixture.sha(image)
  try:
   with image.with_suffix('.stream').open('wb') as output:
    with candidate.candidate(image,a.work,4096 if problem=='budget' else 256*1024**2,image.with_suffix('.daemon.log'),output) as view:journal.replay_candidate(view,image.with_suffix('.replay.log'))
  except (OSError,ValueError):check(True,problem)
  else:raise AssertionError('unsafe candidate accepted: '+problem)
  check(fixture.sha(image)==before)
(a.work/'journal-candidate-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=len(sources),maximum_overlay_bytes=maximum),indent=2)+'\n')
print('PASS',checks,'bounded journal candidate checks',flush=True)
