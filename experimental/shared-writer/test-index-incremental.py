#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Large-directory changed-leaf validation, corruption and bounded-cache fallback."""
import argparse,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args()
def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=180)
 assert r.returncode==0,(argv,r.stdout,r.stderr)
 return r.stdout
with tempfile.TemporaryDirectory(prefix='index-incremental-',dir=a.work) as tmp:
 tmp=Path(tmp);image=tmp/'seed.img'
 with image.open('wb') as f:f.truncate(128*1024**2)
 run(['mke2fs','-q','-F','-t','ext4','-b','1024','-N','85000','-O','dir_index,metadata_csum,^orphan_file',image])
 empty=tmp/'empty';empty.write_bytes(b'');script=tmp/'commands';script.write_text('mkdir /many\n'+''.join(f'write {empty} /many/seed-{i:04d}\n' for i in range(200)))
 run(['debugfs','-w','-f',script,image]);r=subprocess.run(['e2fsck','-fyD',str(image)],capture_output=True);assert r.returncode in (0,1),r.stdout+r.stderr
 run([a.work/'index-scale-fixture',image,'70000']);run(['e2fsck','-fn',image])
 rows=[]
 for binary,options in [('index-incremental-unit',[]),('index-incremental-limits',['bounded'])]:
  result=json.loads(run([a.work/binary,image,*options]));rows.append(result);print('PASS incremental index',result,flush=True)
 run(['e2fsck','-fn',image])
 (a.work/'index-incremental-results.json').write_text(json.dumps(dict(result='passed',profiles=rows),indent=2)+'\n')
