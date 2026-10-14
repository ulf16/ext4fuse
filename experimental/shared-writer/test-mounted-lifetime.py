#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real kernel lookup/cwd/open lifetimes, immediate unlink and abrupt restart."""
import argparse,errno,hashlib,json,os,shutil,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
import chain,session
from credentials import Credentials
here=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--fixtures',type=Path);a=p.parse_args();checks=0

def check(v,detail='mounted lifetime check failed'):
 global checks
 assert v,detail;checks+=1

def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90);check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def unmount(path,force=False):
 run((['/sbin/umount']+(['-f'] if force else [])+[path]) if sys.platform=='darwin' else ['fusermount3','-uz' if force else '-u',path])

sources=sorted(p for p in (a.fixtures or a.work/'fixtures').glob('*-csum*.img') if '-output' not in p.name);check(bool(sources))
root_tmp=Path(tempfile.mkdtemp(prefix='mounted-lifetime-',dir=a.work));succeeded=False
try:
 for index,source in enumerate((sources[0],sources[-1])):
  original=sha(source);seed=root_tmp/f'seed-{index}.img';shutil.copyfile(source,seed)
  script=root_tmp/'seed.commands';script.write_text(f'set_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field / mode 040777\n');run(['debugfs','-w','-f',script,seed])
  root=root_tmp/f'chain-{index}';chain.clone(seed,root);mount=root_tmp/f'mount-{index}';mount.mkdir()
  def start(label):
   log=(root_tmp/f'{index}-{label}.log').open('wb')
   proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--work',a.work,'--root',root,'--mountpoint',mount,'--checkpoint-every','3'],stdout=log,stderr=log,start_new_session=True)
   for unused in range(150):
    if os.path.ismount(mount):return proc,log
    if proc.poll() is not None:break
    time.sleep(.1)
   log.close();raise AssertionError('low-level mount failed: '+(root_tmp/f'{index}-{label}.log').read_text())
  proc,log=start('live');active=True;fd=None;child=None
  try:
   path=mount/'unlinked';fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
   os.write(fd,b'alive');ino=os.fstat(fd).st_ino;os.unlink(path)
   check(not path.exists());check(os.fstat(fd).st_nlink==0 and os.fstat(fd).st_ino==ino)
   check(not any(n.startswith('.fuse_hidden') for n in os.listdir(mount)))
   os.pwrite(fd,b'!',4);check(os.pread(fd,5,0)==b'aliv!');os.ftruncate(fd,10000)
   os.fchmod(fd,0o640);os.utime(fd,ns=(1000000002,3000000004));os.fsync(fd)
   st=os.fstat(fd);check(st.st_size==10000 and stat.S_IMODE(st.st_mode)==0o640 and st.st_nlink==0)
   check((st.st_atime_ns,st.st_mtime_ns)==(1000000002,3000000004))
   other=os.dup(fd);os.close(fd);fd=other;check(os.pread(fd,5,0)==b'aliv!');os.close(fd);fd=None
   (mount/'victim').write_bytes(b'old');(mount/'replacement').write_bytes(b'new')
   fd=os.open(mount/'victim',os.O_RDWR);oldino=os.fstat(fd).st_ino
   os.replace(mount/'replacement',mount/'victim')
   check((mount/'victim').read_bytes()==b'new');check(os.fstat(fd).st_nlink==0 and os.fstat(fd).st_ino==oldino)
   check(os.pread(fd,3,0)==b'old');os.pwrite(fd,b'OLD',0);check((mount/'victim').read_bytes()==b'new');os.close(fd);fd=None
   # The cwd holds a kernel lookup reference without a file handle in the broker.
   (mount/'ancestor').mkdir();(mount/'ancestor'/'cwd').mkdir()
   code='''import errno,json,os,sys
os.chdir(sys.argv[1]);print("ready",flush=True);sys.stdin.readline()
assert os.stat('.').st_nlink==0
try:os.getcwd()
except OSError as e:assert e.errno==errno.ENOENT
else:raise AssertionError('removed cwd remained named')
assert os.listdir('.')==[]
try:os.open('new',os.O_CREAT|os.O_WRONLY,0o600)
except OSError as e:assert e.errno==errno.ENOENT
else:raise AssertionError('created inside removed directory')
f=os.open('.',os.O_RDONLY|os.O_DIRECTORY)
assert os.fstat(f).st_nlink==0
os.fchdir(f);os.close(f)
os.chdir('..');assert os.stat('.').st_nlink==0
os.chdir('..');assert os.path.samefile('.',sys.argv[2])
print('passed',flush=True)
'''
   child=subprocess.Popen([sys.executable,'-c',code,str(mount/'ancestor'/'cwd'),str(mount)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   check(child.stdout.readline().strip()=='ready')
   os.rmdir(mount/'ancestor'/'cwd');os.rmdir(mount/'ancestor')
   output,error=child.communicate('continue\n',timeout=30)
   check(child.returncode==0,(output,error));check(output.strip()=='passed');child=None
   # An open directory retains its inode too, with an empty removed snapshot.
   directory=mount/'opened-dir';directory.mkdir();fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.rmdir(directory)
   check(os.fstat(fd).st_nlink==0);check(os.listdir(fd)==[]);os.close(fd);fd=None
   (mount/'.fuse_hidden0000000100000001').write_bytes(b'legitimate user file')
   # Leave two durable orphans, kill ONLY the isolated disposable mount group.
   crashfile=mount/'crash-file';fd=os.open(crashfile,os.O_CREAT|os.O_RDWR,0o600);os.write(fd,b'crash orphan');os.unlink(crashfile)
   crashdir=mount/'crash-dir';crashdir.mkdir();dirfd=os.open(crashdir,os.O_RDONLY|os.O_DIRECTORY);os.rmdir(crashdir)
   check(os.fstat(fd).st_nlink==0 and os.fstat(dirfd).st_nlink==0)
   os.killpg(proc.pid,signal.SIGKILL);check(proc.wait(timeout=15)==-signal.SIGKILL)
   # A disconnected macFUSE mount makes ismount() return False (stat fails).
   # Track the known test mount explicitly and unmount it unconditionally.
   unmount(mount,True);active=False
   for orphan_fd in (fd,dirfd):
    try:os.close(orphan_fd)
    except OSError:pass
   fd=None
   with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(os.getuid(),os.getgid())) as recovered:
    check(recovered._rpc(12)[0]==0)
    check(recovered.readat(None,'/.fuse_hidden0000000100000001')==b'legitimate user file')
    check(recovered.readat(None,'/victim')==b'new')
   run(['e2fsck','-fn',root/'image.img'])
   # A fresh mount must not reuse dead session node IDs or resurrect names.
   log.close();proc,log=start('restart');active=True
   check(not (mount/'crash-file').exists() and not (mount/'crash-dir').exists())
   check((mount/'.fuse_hidden0000000100000001').read_bytes()==b'legitimate user file')
   (mount/'after-restart').write_bytes(b'restarted');check((mount/'after-restart').read_bytes()==b'restarted')
   unmount(mount);active=False;check(proc.wait(timeout=30)==0)
  finally:
   if child is not None:
    child.kill();child.communicate(timeout=10)
   if fd is not None:
    try:os.close(fd)
    except OSError:pass
   if active:unmount(mount,True)
   if proc.poll() is None:
    proc.terminate()
    try:proc.wait(timeout=15)
    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
   log.close()
  run(['e2fsck','-fn',root/'image.img']);check(sha(source)==original)
  print('PASS mounted inode lifetimes',source.name,flush=True)
 (a.work/'mounted-lifetime-results.json').write_text(json.dumps(dict(result='passed',checks=checks,profiles=2,platform=sys.platform),indent=2)+'\n')
 print('PASS',checks,'mounted inode-lifetime checks',flush=True);succeeded=True
finally:
 if succeeded:shutil.rmtree(root_tmp)
 else:print('Retained lifetime fixtures/logs:',root_tmp,file=sys.stderr)
