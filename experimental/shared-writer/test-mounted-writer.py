#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real FUSE 3 writes on private cloned images; never a user image/device."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import chain
import session
from credentials import Credentials
here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--fixtures',type=Path)
parser.add_argument('--limit',type=int)
args=parser.parse_args();fixtures=args.fixtures or args.work/'fixtures'
checks,rows=0,[]
def check(condition,detail='check failed'):
    global checks
    assert condition,detail;checks+=1

def run(argv):
    r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
    check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def denied(call,error):
    try:call()
    except Exception as e:check(getattr(e,'errno',None)==error,repr(e))
    else:raise AssertionError('unexpected success')

def unmount(mount):
    command=['/sbin/umount',str(mount)] if sys.platform=='darwin' else [shutil.which('fusermount3') or 'fusermount3','-u',str(mount)]
    r=subprocess.run(command,capture_output=True,timeout=20)
    if r.returncode and os.path.ismount(mount):raise AssertionError('unmount failed; retained fixtures: '+str(mount)+' '+repr(r.stderr))
    check(not os.path.ismount(mount),'still mounted; fixtures retained')

# Never delete a mounted tree on any failure.
temp=Path(tempfile.mkdtemp(prefix='mounted-writer-',dir=args.work));succeeded=False
try:
    sources=[p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit:sources=sources[:args.limit]
    check(bool(sources),'no fixtures')
    for source in sources:
        original=sha(source);seed=temp/(source.stem+'-seed.img');shutil.copyfile(source,seed)
        command=temp/'seed.commands';command.write_text(f'set_inode_field / mode 040777\nset_inode_field / uid {os.getuid()}\nset_inode_field / gid {os.getgid()}\nset_inode_field /existing-file uid {os.getuid()}\nset_inode_field /existing-file gid {os.getgid()}\nset_inode_field /existing-file mode 0100660\n')
        run(['debugfs','-w','-f',command,seed])
        long_names=[f'listed-{i:03d}-'+'x'*180 for i in range(180)]
        command.write_text('mkdir /listed\n'+f'set_inode_field /listed uid {os.getuid()}\nset_inode_field /listed gid {os.getgid()}\nset_inode_field /listed mode 040777\n'+
                           'expand_dir /listed\n'*60+'\n'.join(f'ln /existing-file /listed/{name}' for name in long_names)+
                           f'\nset_inode_field /existing-file links_count {len(long_names)+1}\n')
        run(['debugfs','-w','-f',command,seed]);run(['e2fsck','-fn',seed]);seed_sha=sha(seed)
        root=temp/source.stem;chain.clone(seed,root);check(sha(root/'image.img')==seed_sha,'clone changed contents')
        mount=temp/(source.stem+'-mount');mount.mkdir()
        logpath=temp/(source.stem+'-mount.log');log=logpath.open('wb')
        launcher=here/'mount-broker.py'
        marker=temp/'torn-replay-observed'
        if not rows:
            launcher=temp/'fault-broker.py'
            launcher.write_text('import sys,runpy\n'+'sys.path.insert(0,'+repr(str(here))+')\n'+
                'from fault_injection import torn_replay\n'+
                'with torn_replay('+repr(str(marker))+'):\n    runpy.run_path('+repr(str(here/'mount-broker.py'))+',run_name="__main__")\n')
        process=subprocess.Popen([sys.executable,launcher,'--work',args.work,'--root',root,'--mountpoint',mount],stdout=log,stderr=log)
        mounted=False
        try:
            for unused in range(120):
                if process.poll() is not None:raise AssertionError('mount exited: '+logpath.read_text(errors='replace'))
                if os.path.ismount(mount):mounted=True;break
                time.sleep(.1)
            check(mounted,'mount timeout: '+logpath.read_text(errors='replace'))
            existing=mount/'existing-file';check(existing.read_bytes()!=b'')
            check(set(os.listdir(mount/'listed'))==set(long_names))
            check(set(os.listdir(mount/'listed'))==set(long_names))
            before=os.statvfs(mount);check(not before.f_flag&os.ST_RDONLY)
            check(before.f_frsize==int(source.name.split('-')[0]));check(before.f_namemax==255)
            if not rows:
                denied(lambda:(mount/'recovery-probe').mkdir(),errno.EIO)
                check(marker.read_text()=='half:0:0\n','partial replay was not injected')
                check((mount/'recovery-probe').is_dir(),'sealed mutation was not recovered')
                (mount/'recovery-probe').rmdir()
            path=mount/'created'
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o660)
            try:
                check(os.write(fd,b'abcdef')==6);check(os.pread(fd,6,0)==b'abcdef')
                check(os.fstat(fd).st_size==6);check(os.fstat(fd).st_uid==os.getuid())
                os.ftruncate(fd,3);check(os.pread(fd,10,0)==b'abc')
                os.ftruncate(fd,8193);check(os.pread(fd,8190,3)==bytes(8190))
                check(os.pwrite(fd,b'Z',8192)==1);check(os.pread(fd,2,8191)==b'\0Z')
                os.fsync(fd)
                os.rename(path,mount/'renamed');check(os.pread(fd,3,0)==b'abc')
                os.link(mount/'renamed',mount/'hard-link')
                check(os.stat(mount/'hard-link').st_ino==os.stat(mount/'renamed').st_ino)
                os.unlink(mount/'renamed');check(os.fstat(fd).st_nlink==1)
                os.unlink(mount/'hard-link');check(os.fstat(fd).st_nlink==0)
                check(os.pwrite(fd,b'!',2)==1);check(os.pread(fd,3,0)==b'ab!')
                duplicated=os.dup(fd)
                try:
                    os.fsync(duplicated);check(os.pread(duplicated,3,0)==b'ab!')
                finally:os.close(duplicated)
            finally:os.close(fd)
            check(not path.exists() and not (mount/'renamed').exists() and not (mount/'hard-link').exists())
            append=mount/'append';append.write_bytes(b'first')
            afd=os.open(append,os.O_WRONLY|os.O_APPEND)
            try:os.write(afd,b'+last');os.fsync(afd)
            finally:os.close(afd)
            check(append.read_bytes()==b'first+last')
            denied(lambda:os.open(append,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),errno.EEXIST)
            directory=mount/'directory';directory.mkdir()
            for i in range(40):(directory/f'item-{i:03d}').write_bytes(str(i).encode())
            with os.scandir(directory) as entries:
                listed={e.name:e.inode() for e in entries}
            check(set(listed)=={f'item-{i:03d}' for i in range(40)})
            check(all(listed[name]==os.lstat(directory/name).st_ino for name in listed))
            os.symlink('append',mount/'relative-link');check(os.readlink(mount/'relative-link')=='append')
            check((mount/'relative-link').read_bytes()==b'first+last')
            os.link(mount/'relative-link',mount/'symlink-copy',follow_symlinks=False)
            check(stat.S_ISLNK(os.lstat(mount/'symlink-copy').st_mode));os.unlink(mount/'symlink-copy')
            os.rename(directory,mount/'moved-directory');directory=mount/'moved-directory'
            check((directory/'item-039').read_bytes()==b'39')
            for child in directory.iterdir():child.unlink()
            directory.rmdir();check(not directory.exists())
            # Invalid/unsupported mutations must not turn into success.
            denied(lambda:os.chmod(append,0o600),errno.ENOTSUP)
            check(append.read_bytes()==b'first+last')
            check(not any(name.startswith('.fuse_hidden') for name in os.listdir(mount)),'deferred-removal name leaked after final close')
            # The chain lock excludes another controller/mount while mounted.
            try:
                with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(os.getuid(),os.getgid())):pass
            except BlockingIOError:check(True)
            else:raise AssertionError('second image controller accepted')
            after=os.statvfs(mount);check(after.f_bfree<=before.f_bfree and after.f_ffree<before.f_ffree)
            unmount(mount);mounted=False
            check(process.wait(timeout=30)==0,'broker exit: '+logpath.read_text(errors='replace'))
        except BaseException:
            log.flush();print(logpath.read_text(errors='replace'),file=sys.stderr);raise
        finally:
            if os.path.ismount(mount):unmount(mount)
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            log.close()
        run(['e2fsck','-fn',root/'image.img'])
        out=run(['debugfs','-R','cat /append',root/'image.img']);check(out==b'first+last')
        check(sha(seed)==seed_sha and sha(source)==original,'input changed')
        with session.Session(root,args.work/'mutation-producer',args.work/'reader-server',Credentials(os.getuid(),os.getgid())) as resumed:
            check(resumed._rpc(12)[0]==0,'unreleased mounted orphan')
            check(resumed.readat(None,'/append')==b'first+last')
        rows.append(dict(fixture=source.name,result='passed'));print('PASS mounted',source.name,flush=True)
    (args.work/'mounted-writer-results.json').write_text(json.dumps(dict(result='passed',checks=checks,configurations=rows,scope='private managed-image FUSE 3 mounted mutations'),indent=2)+'\n')
    print(f'PASS {checks} mounted checks across {len(rows)} configurations',flush=True);succeeded=True
finally:
    if succeeded and not any(os.path.ismount(p) for p in temp.iterdir() if p.is_dir()):shutil.rmtree(temp)
    elif not succeeded:print('Fixtures retained:',temp,file=sys.stderr)
