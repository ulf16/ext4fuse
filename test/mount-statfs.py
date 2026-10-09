#!/usr/bin/env python3
"""Native macFUSE statvfs/df check on a disposable, read-only image."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

assert sys.platform == 'darwin', 'requires macOS/macFUSE'
def main():
    # Keep fixtures on an unmount failure rather than deleting through a mount.
    root = Path(tempfile.mkdtemp(prefix='ext4fuse-mount-statfs-'))
    image = root / 'image'
    mount = root / 'mount'
    mount.mkdir()
    with image.open('wb') as file:
        file.truncate(32 * 1024**2)
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', '-m', '5', str(image)],
                   capture_output=True, check=True)
    payload = root / 'payload'
    payload.write_bytes(b'statfs mount fixture\n')
    subprocess.run(['debugfs', '-w', '-R', f'write {payload} /payload', str(image)],
                   capture_output=True, check=True)
    before = hashlib.sha256(image.read_bytes()).digest()
    header = subprocess.run(['dumpe2fs', '-h', str(image)], capture_output=True,
                            text=True, check=True, env=dict(os.environ, LC_ALL='C')).stdout
    def field(name):
        return int(re.search(r'^' + re.escape(name) + r':\s+(\d+)', header, re.M)[1])
    block, total, free = field('Block size'), field('Block count'), field('Free blocks')
    available = max(0, free - field('Reserved block count'))
    log = (root / 'reader.log').open('w+')
    process = subprocess.Popen([os.environ.get('READER', './ext4fuse'), str(image), str(mount),
                                '-f', '-s', '-o', 'ro,defer_permissions'], stdout=log, stderr=log)
    try:
        for attempt in range(40):
            if (mount / 'payload').exists():
                break
            if process.poll() is not None:
                raise AssertionError('reader exited before mount')
            time.sleep(.25)
        else:
            raise AssertionError('mount timeout')
        assert (mount / 'payload').read_bytes() == payload.read_bytes()
        for path in [mount, mount / 'payload']:
            st = os.statvfs(path)
            assert st.f_frsize == block, st
            assert (st.f_blocks, st.f_bfree, st.f_bavail) == (total, free, available), st
            assert (st.f_files, st.f_ffree, st.f_favail) == (field('Inode count'),
                field('Free inodes'), field('Free inodes')), st
            assert st.f_flag & os.ST_RDONLY, st
            assert st.f_namemax == 255, st
        # macOS df converts block counts to 1024-byte units.
        df = subprocess.run(['/bin/df', '-k', str(mount)], text=True, capture_output=True, check=True)
        print(df.stdout.strip())
        values = df.stdout.splitlines()[-1].split()
        assert tuple(map(int, values[1:4])) == (total * block // 1024,
            (total - free) * block // 1024, available * block // 1024), df.stdout
        try:
            (mount / 'write-attempt').write_bytes(b'no')
        except OSError:
            pass
        else:
            raise AssertionError('read-only mount accepted write')
    except BaseException:
        log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
        raise
    finally:
        # Stop before fixture deletion or relinking the reader.
        unmount = subprocess.run(['/sbin/umount', str(mount)], capture_output=True)
        if unmount.returncode and process.poll() is None:
            subprocess.run(['/sbin/umount', '-f', str(mount)], check=True)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
        log.close()
    assert before == hashlib.sha256(image.read_bytes()).digest(), 'reader changed image'
    shutil.rmtree(root)
    print('PASS: mounted statvfs, df, inode counts and read-only state; image unchanged')

if __name__ == '__main__':
    main()
