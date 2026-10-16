#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Indexed names and metadata-only checks must preserve opaque device numbers."""
import argparse,json,shutil,stat,subprocess,tempfile
from pathlib import Path
import chain,session,journal_fixtures as fixture
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
with tempfile.TemporaryDirectory(prefix='namespace-storage-',dir=a.work) as tmp:
 tmp=Path(tmp)
 for number,source in enumerate(sorted(p for p in (a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name)):
  image=tmp/f'seed-{number}.img';shutil.copyfile(source,image)
  # Force independent e2fsprogs HTree conversion, including checksum tails.
  script=tmp/'commands';names=['indexed-%03d-'%i+'x'*90 for i in range(150)]
  script.write_text('expand_dir /\n'*24+'\n'.join('ln /existing-file /'+name for name in names)+f'\nset_inode_field /existing-file links_count {len(names)+1}\n')
  fixture.run(['debugfs','-w','-f',script,image])
  result=subprocess.run(['e2fsck','-fyD',image],capture_output=True);assert result.returncode in (0,1),result.stderr
  fixture.run(['e2fsck','-fn',image]);assert b'0x81000' in fixture.run(['debugfs','-R','stat /',image]) or b'0x1000' in fixture.run(['debugfs','-R','stat /',image])
  root=tmp/f'chain-{number}';chain.clone(image,root)
  with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
   s.mknod('/opaque-device',stat.S_IFCHR|0o640,major=4095,minor=1048575)
   s.setxattr('/opaque-device','user.external',b'x'*600)
   s.mknod('/fifo',stat.S_IFIFO|0o640);s.rename('/opaque-device','/fifo',flags=2)
   assert stat.S_ISCHR(s.statat(None,'/fifo')['mode']);checks+=1
   s.rename('/opaque-device','/new-name',flags=1);s.link('/fifo','/device-link');s.unlink('/device-link')
   s.rename('/new-name','/whiteout-fifo',flags=4);assert stat.S_ISFIFO(s.statat(None,'/whiteout-fifo')['mode']);checks+=1
   assert stat.S_ISCHR(s.statat(None,'/new-name')['mode']);checks+=1
  fixture.run(['e2fsck','-fn',root/'image.img']);checks+=1
  snapshot=tmp/f'check-{number}.img'
  fixture.run([a.work/'metadata-snapshot',root/'image.img',snapshot,32*1024**2]);fixture.run(['e2fsck','-fn',snapshot]);checks+=1
  # The all-ones rdev encoding must never be treated as a physical block number.
  assert b'Device major/minor number: 4095:1048575' in fixture.run(['debugfs','-R','stat /fifo',snapshot]);checks+=1
  assert b'Device major/minor number: 00:00' in fixture.run(['debugfs','-R','stat /new-name',snapshot]);checks+=1
  print('PASS indexed special storage',source.name,flush=True)
(a.work/'namespace-extension-storage-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=number+1),indent=2)+'\n')
print('PASS',checks,'indexed namespace and special metadata snapshot checks',flush=True)
