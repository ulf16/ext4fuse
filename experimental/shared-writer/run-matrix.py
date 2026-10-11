import argparse,hashlib,json,subprocess,itertools
from pathlib import Path
import shutil
parser=argparse.ArgumentParser(description="Run disposable shared-writer fixtures; outputs must be new files.")
parser.add_argument('--work',type=Path,required=True)
a=parser.parse_args();r=a.work.resolve();fixtures=r/'fixtures';fixtures.mkdir(exist_ok=True)
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');fsck=shutil.which('e2fsck')
if not all((mkfs,debugfs,fsck)):raise SystemExit('e2fsprogs utilities are required in PATH')
def run(command,log):
 p=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=60)
 (r/log).write_text(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError((command,p.returncode,(p.stdout+p.stderr)[-1500:]))
 return p.stdout

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
seed=r/'seed-data';seed.write_bytes(bytes((i*19+13)&255 for i in range(32768)));expected=bytes(((i*131+(i>>8))^0x5a)&255 for i in range(160*1024))
rows=[]
for block,layout,checksum in itertools.product((1024,2048,4096),('extents','classic'),(True,False)):
 key=f'{block}-{layout}-csum{int(checksum)}';image=fixtures/(key+'.img');output=fixtures/(key+'-output.img')
 if output.exists():raise RuntimeError('refusing existing export '+str(output))
 with image.open('xb') as f:f.truncate(32*1024**2)
 features=[]
 if layout=='classic':features+=['^extent','^64bit','^flex_bg']
 if not checksum:features+=['^metadata_csum','^metadata_csum_seed']
 args=[mkfs,'-q','-F','-t','ext4','-b',block]
 if features:args+=['-O',','.join(features)]
 run(args+[image],key+'-mkfs.log')
 run([debugfs,'-w','-R',f'write {seed} /existing-file',image],key+'-seed.log')
 run([fsck,'-f','-n',image],key+'-source-fsck.log')
 before=sha(image)
 result=run([r/'prototype',image,output],key+'-prototype.log')
 assert sha(image)==before,'base image changed'
 assert not Path(str(output)+'.failed').exists(),'failed export leaked'
 assert not list(fixtures.glob(key+'-output.img*.stage.*')),'staging export leaked'
 run([fsck,'-f','-n',output],key+'-export-fsck.log')
 extracted=r/'extracted'
 run([debugfs,'-R',f'dump /renamed-file {extracted}',output],key+'-dump.log')
 assert extracted.read_bytes()==expected;extracted.unlink()
 run([debugfs,'-R',f'dump /existing-file {extracted}',output],key+'-original-dump.log')
 assert sha(extracted)==sha(seed);extracted.unlink()
 rows.append({'block_size':block,'layout':layout,'metadata_checksum':checksum,'base_unchanged':True,'fsck_clean':True,'new_file_verified':True,'existing_file_preserved':True,'result':result.strip()})
 print('PASS',key,result.strip(),flush=True)
report={'platform':__import__('platform').platform(),'libext2fs':subprocess.check_output(['pkg-config','--modversion','ext2fs'],text=True).strip(),'reader':'ulf16/ext4fuse v0.2.14 unchanged; test-only pread interception','scope':'serialized offline in-memory overlay; atomic new-image export, no in-place writes or journal integration','configurations':rows}
(r/'matrix-results.json').write_text(json.dumps(report,indent=2)+'\n')
