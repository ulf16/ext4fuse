#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent metadata-only fsck images omit fully allocated user payloads."""
import argparse,json,subprocess,tempfile
from pathlib import Path
import journal_fixtures as fixture
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0

def check(value,detail='metadata snapshot check failed'):
 global checks
 assert value,detail;checks+=1
with tempfile.TemporaryDirectory(prefix='metadata-snapshot-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for index,source in enumerate(sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)):
  snapshot=tmp/f'profile-{index}.img';fixture.run([a.work/'metadata-snapshot',source,snapshot,64*1024**2]);fixture.run(['e2fsck','-fn',snapshot])
  check(snapshot.stat().st_blocks*512<source.stat().st_size//2)
  block=int(fixture.run(['debugfs','-R','bmap /existing-file 0',source]).strip())
  with source.open('rb') as f:f.seek(1048);blocksize=1024<<int.from_bytes(f.read(4),'little')
  with snapshot.open('rb') as f:f.seek(block*blocksize);check(f.read(blocksize)==bytes(blocksize))
 # Large allocated file: exported space depends on metadata, not file contents.
 image=tmp/'large.img'
 with image.open('wb') as f:f.truncate(256*1024**2)
 fixture.run(['mke2fs','-q','-F','-t','ext4','-O','^orphan_file',image])
 payload=tmp/'payload';pattern=(bytes(range(251))*4178)[:1024**2]
 with payload.open('wb') as f:
  for number in range(128):f.write(pattern)
 fixture.debug(image,f'write {payload} /large');fixture.run(['e2fsck','-fn',image])
 snapshot=tmp/'large-check.img';output=fixture.run([a.work/'metadata-snapshot',image,snapshot,32*1024**2]);fixture.run(['e2fsck','-fn',snapshot])
 used=snapshot.stat().st_blocks*512;check(used<image.stat().st_size//8);check(int(output)<32*1024**2)
 block=int(fixture.run(['debugfs','-R','bmap /large 0',image]).strip())
 with image.open('rb') as f:f.seek(1048);blocksize=1024<<int.from_bytes(f.read(4),'little')
 with snapshot.open('rb') as f:f.seek(block*blocksize);check(f.read(blocksize)==bytes(blocksize))
 # Limits refuse output safely; a partial scratch file never authorizes a close.
 result=subprocess.run([str(a.work/'metadata-snapshot'),str(image),str(tmp/'limited.img'),'4096'],capture_output=True)
 check(result.returncode!=0)
(a.work/'metadata-snapshot-results.json').write_text(json.dumps(dict(result='passed',checks=checks,large_image_bytes=image.stat().st_size if image.exists() else 256*1024**2,scratch_allocated_bytes=used),indent=2)+'\n')
print('PASS',checks,'metadata-only snapshot checks; allocated scratch',used)
