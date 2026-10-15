#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Replay a small journal beside a large allocated file without a data copy."""
import argparse,json,struct,tempfile
from pathlib import Path
import journal_candidate as candidate,journal_fixtures as fixture,journal_recovery as journal
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='candidate-space-',dir=a.work) as tmp:
 tmp=Path(tmp);image=tmp/'large.img';payload=tmp/'payload'
 with image.open('wb') as f:f.truncate(256*1024**2)
 fixture.run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',image])
 pattern=(bytes(range(251))*4178)[:1024**2]
 with payload.open('wb') as f:
  for unused in range(128):f.write(pattern)
 small=tmp/'small';small.write_bytes(pattern[:16384])
 fixture.debug(image,f'write {payload} /large');fixture.debug(image,f'write {small} /existing-file');fixture.run(['e2fsck','-fn',image])
 dirty=tmp/'dirty.img';detail=fixture.create(image,dirty);before=fixture.sha(dirty);stream=tmp/'stream'
 with stream.open('wb') as output:
  with candidate.candidate(dirty,a.work,1024**2,tmp/'daemon.log',output) as view:
   journal.replay_candidate(view,tmp/'replay.log')
   # macFUSE may synthesize st_blocks from apparent size; the stream
   # counts actual overlay pages, and this mount has no backing image file.
   info=view.stat();assert info.st_size==256*1024**2
   assert fixture.run(['debugfs','-R','cat /existing-file',view])==detail['new']
   # Newly created private mount directories contain no hidden image/backup.
   host_files=[f for f in view.parent.parent.iterdir() if f.is_file()]
   assert not host_files
 with stream.open('rb') as src:magic,size,count=struct.unpack('<8sQQ',src.read(24))
 assert magic==b'E4OVL001' and size==256*1024**2 and count*4096<=1024**2
 assert stream.stat().st_size==24+count*8200
 assert fixture.sha(dirty)==before
 result=dict(result='passed',checks=8,filesystem_bytes=size,allocated_payload_bytes=128*1024**2,changed_page_bytes=count*4096,sealed_stream_bytes=stream.stat().st_size)
(a.work/'journal-candidate-space-results.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS bounded large-file replay space:',result,flush=True)
