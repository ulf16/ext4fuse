#!/usr/bin/env python3
"""Disposable mounted permission matrix; sudo enables child-only cross-user probes."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import struct
import subprocess
import sys
import tempfile
import time

# The helper lives inside the public disposable fixture directory so another
# user never needs access to the checkout (which may be in a private home).
PROBE = r'''
import ctypes, errno, json, os, sys
def xattr(path):
    if hasattr(os, 'getxattr'): return os.getxattr(path, 'system.posix_acl_access')
    libc = ctypes.CDLL(None, use_errno=True)
    get = libc.getxattr
    get.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    get.restype = ctypes.c_ssize_t
    buf = ctypes.create_string_buffer(256)
    n = get(os.fsencode(path), b'system.posix_acl_access', buf, len(buf), 0, 0)
    if n < 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return buf.raw[:n]
def kernel_groups():
    if sys.platform != 'darwin': return os.getgroups()
    libc = ctypes.CDLL(None, use_errno=True)
    get = libc.getgroups
    get.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    get.restype = ctypes.c_int
    n = get(0, None)
    if n < 0: raise OSError(ctypes.get_errno(), 'getgroups')
    groups = (ctypes.c_uint32 * n)()
    if get(n, groups) < 0: raise OSError(ctypes.get_errno(), 'getgroups')
    return list(groups)
root, cases, identity = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
assert os.getuid() == identity['uid'] != 0, (os.getuid(), identity)
assert os.getgid() == identity['gid'], (os.getgid(), identity)
actual_groups = kernel_groups()
assert set(identity['groups']).issubset(actual_groups), (actual_groups, identity)
count = 0
acl_absent = 0
for repeat in range(2):
    for case in cases:
        path = root + '/' + case['path']
        try:
            if case['op'] == 'read':
                with open(path, 'rb') as file: assert file.read() == b'permission fixture\n'
            elif case['op'] == 'list':
                assert 'payload' in os.listdir(path)
            elif case['op'] == 'stat':
                st = os.stat(path)
                assert st.st_uid == case['uid'] and st.st_gid == case['gid']
                assert st.st_mode & 0o777 == case['mode'] & ~0o222
            elif case['op'] == 'xattr':
                assert xattr(path).hex() == case['value']
            elif case['op'] == 'write':
                fd = os.open(path, os.O_WRONLY | os.O_APPEND)
                os.close(fd)  # Do not write even if the read-only check fails.
            else: raise AssertionError(case)
        except OSError as error:
            if case.get('allow_absent') and error.errno == errno.ENODATA:
                acl_absent += 1
                count += 1
                continue
            assert not case['allow'], (case, error)
            expected = (errno.EACCES, errno.EPERM, errno.EROFS) if case['op']=='write' else (errno.EACCES, errno.EPERM)
            assert error.errno in expected, (case, error)
        else:
            assert case['allow'], ('unexpected permission grant', case, identity)
        count += 1
print(json.dumps(dict(checks=count, uid=os.getuid(), gid=os.getgid(), groups=actual_groups, acl_absent=acl_absent)))
'''


def credentials(identity):
    # Popen's POSIX credential parameters report errors in the parent instead
    # of hiding them behind a generic preexec_fn failure.
    return dict(user=identity['uid'], group=identity['gid'], extra_groups=identity['groups'])


def subprocess_groups():
    if sys.platform != 'darwin': return os.getgroups()
    import ctypes
    get = ctypes.CDLL(None, use_errno=True).getgroups
    get.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    n = get(0, None)
    assert n >= 0
    groups = (ctypes.c_uint32 * n)()
    assert get(n, groups) == n
    return list(groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reader', default=os.environ.get('READER', './ext4fuse'))
    parser.add_argument('--require-cross-user', action='store_true',
                        help='fail rather than skip peer probes when not run via sudo')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assert sys.platform in ('darwin', 'linux'), 'requires macFUSE or Linux FUSE'
    privileged = os.geteuid() == 0
    assert not args.require_cross_user or privileged, 'cross-user probes require sudo (only child credentials change)'
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    gid = int(os.environ.get('SUDO_GID', os.getgid()))
    assert uid != 0, 'run sudo as a normal user so mount/probes retain that user as owner'
    groups = os.getgrouplist(pwd.getpwuid(uid).pw_name, gid) if privileged else subprocess_groups()
    groups = [gid] + sorted(set(groups) - {gid})
    if privileged:
        # Darwin accepts at most NGROUPS_MAX groups in setgroups(), even when
        # account lookup reports a larger membership list. Only child creds
        # are bounded; persistent account membership stays untouched.
        groups = groups[:os.sysconf('SC_NGROUPS_MAX')]
    supplementary = next((g for g in groups if g not in (gid, 12) and g < 1000000), None)
    assert supplementary is not None, 'mount owner needs a supplementary group for this test'
    owner = dict(uid=uid, gid=gid, groups=groups)
    foreign_uid, foreign_gid, peer_gid = uid + 65536, 1000002, 1000001
    peer_uid = pwd.getpwnam('nobody').pw_uid
    assert peer_uid not in (uid, foreign_uid, 0)
    identities = {'owner': owner}
    if privileged:
        identities['peer-group'] = dict(uid=peer_uid, gid=peer_gid, groups=[supplementary])
        identities['peer-other'] = dict(uid=peer_uid, gid=peer_gid, groups=[])
    mkfs, debugfs = shutil.which('mke2fs'), shutil.which('debugfs')
    assert mkfs and debugfs, 'e2fsprogs sbin must be in PATH'
    reader = str(Path(args.reader).resolve())
    root = Path(tempfile.mkdtemp(prefix='ext4fuse-permissions-', dir='/private/tmp' if sys.platform=='darwin' else '/tmp'))
    root.chmod(0o755)
    image, mount = root/'image', root/'mount'
    mount.mkdir(mode=0o755)
    if privileged: os.chown(mount, uid, gid)
    helper = root/'probe.py'; helper.write_text(PROBE); helper.chmod(0o644)
    payload = root/'payload'; payload.write_bytes(b'permission fixture\n')
    with image.open('wb') as file: file.truncate(32*1024**2)
    subprocess.run([mkfs, '-q', '-F', '-t', 'ext4', '-b', '4096', str(image)], check=True, capture_output=True)
    image.chmod(0o644)
    def debug(command):
        result = subprocess.run([debugfs, '-w', '-R', command, str(image)], check=True, capture_output=True, text=True)
        assert not any(s in result.stderr for s in ('not found', 'Usage:', 'Could not')), result.stderr
    entries = {
        'owner': (uid, foreign_gid, 0o600),
        'primary': (foreign_uid, gid, 0o040),
        'supplementary': (foreign_uid, supplementary, 0o040),
        'public': (foreign_uid, foreign_gid, 0o004),
        'none': (foreign_uid, foreign_gid, 0o000),
        'owner-precedence': (uid, foreign_gid, 0o004),
        'group-precedence': (foreign_uid, gid, 0o004),
        'acl-grant': (uid, foreign_gid, 0o440),
        'acl-deny': (foreign_uid, foreign_gid, 0o004),
    }
    for name in entries: debug(f'write {payload} /{name}')
    acls = {}
    for name, perms in [('acl-grant', (4,4,0,4,0)), ('acl-deny', (0,0,0,0,4))]:
        acls[name] = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, ident) for tag, perm, ident in
            zip((1,2,4,16,32), perms, (0xffffffff,peer_uid,0xffffffff,0xffffffff,0xffffffff)))
        host = root/(name+'.acl'); host.write_bytes(acls[name])
        debug(f'ea_set -f {host} /{name} system.posix_acl_access')
    for name, (owner_uid, owner_gid, mode) in entries.items():
        for field, value in [('uid',owner_uid), ('gid',owner_gid), ('mode',0o100000|mode)]:
            debug(f'set_inode_field /{name} {field} {value}')
    for name, mode in [('traverse',0o050), ('list-only',0o040), ('search-only',0o010)]:
        debug(f'mkdir /{name}')
        debug(f'write {payload} /{name}/payload')
        for field, value in [('uid',foreign_uid), ('gid',supplementary), ('mode',0o040000|mode)]:
            debug(f'set_inode_field /{name} {field} {value}')
        debug(f'set_inode_field /{name}/payload mode {0o100004}')
    debug('symlink /link owner')
    # Mount-owner isolation may deny even root stat() access. Inspect the mount
    # inventory instead of using ismount(), which stats the protected root.
    def mounted():
        if sys.platform == 'linux':
            return any(line.split()[4] == str(mount) for line in Path('/proc/self/mountinfo').read_text().splitlines())
        return ' on ' + str(mount) + ' (' in subprocess.check_output(['/sbin/mount'], text=True)
    before = hashlib.sha256(image.read_bytes()).digest()
    results = []
    modes = [('private', 'ro,default_permissions', False, False)]
    if privileged: modes.append(('shared', 'ro,default_permissions,allow_other', True, False))
    if sys.platform == 'darwin':
        modes.append(('recovery-private', 'ro,defer_permissions', False, True))
        if privileged: modes.append(('recovery-shared', 'ro,defer_permissions,allow_other', True, True))
    try:
        for label, options, shared, recovery in modes:
            log = (root/(label+'.log')).open('w+')
            process = subprocess.Popen([reader,str(image),str(mount),'-f','-s','-o',options], stdout=log, stderr=log,
                                       **(credentials(owner) if privileged else {}))
            try:
                for attempt in range(80):
                    if mounted(): break
                    if process.poll() is not None: raise AssertionError('daemon exited before mounting')
                    time.sleep(.1)
                else: raise AssertionError('mount timeout')
                # Return to the owner after peer probes to catch permission-cache leakage.
                for position,role in enumerate(list(identities) + ['owner']):
                    identity = identities[role]
                    visible = role=='owner' or shared
                    def permitted(owner_uid, owner_gid, mode, bit):
                        if not visible: return False
                        if recovery: return True
                        shift = 6 if identity['uid']==owner_uid else 3 if owner_gid in identity['groups']+[identity['gid']] else 0
                        return bool(mode & (bit << shift))
                    cases = []
                    for name,(owner_uid,owner_gid,mode) in entries.items():
                        cases.append(dict(op='read', path=name, allow=permitted(owner_uid,owner_gid,mode,4)))
                        cases.append(dict(op='stat', path=name, allow=visible, uid=owner_uid, gid=owner_gid, mode=mode))
                    for name,mode in [('traverse',0o050),('list-only',0o040),('search-only',0o010)]:
                        cases.append(dict(op='list',path=name,allow=permitted(foreign_uid,supplementary,mode,4)))
                        cases.append(dict(op='read',path=name+'/payload',allow=permitted(foreign_uid,supplementary,mode,1)))
                    cases.append(dict(op='read',path='link',allow=permitted(uid,foreign_gid,0o600,4)))
                    cases.append(dict(op='write',path='public',allow=False))
                    # ACL retrieval is checked as owner, independently of named-rule enforcement.
                    if role=='owner':
                        for name,value in acls.items():
                            cases.append(dict(op='xattr',path=name,allow=True,value=value.hex(),
                                              allow_absent=sys.platform=='linux' and position>0))
                    command = [sys.executable,str(helper),str(mount),json.dumps(cases),json.dumps(identity)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                            **(credentials(identity) if privileged else {}))
                    assert result.returncode==0, (label,role,result.stdout,result.stderr)
                    row = dict(mode=label,role=role,**json.loads(result.stdout));results.append(row)
                    print(f'PASS: {label} {role}: {row["checks"]} permission checks',flush=True)
                    if row['acl_absent']: print('NOTE: Linux FUSE cached ACL absence after permission probes',flush=True)
            except BaseException:
                log.flush();log.seek(0);print(log.read(),file=sys.stderr)
                raise
            finally:
                if mounted():
                    unmount = ['/sbin/umount',str(mount)] if sys.platform=='darwin' else ['umount',str(mount)]
                    if sys.platform=='linux' and not privileged:
                        helper_unmount = shutil.which('fusermount3') or shutil.which('fusermount')
                        assert helper_unmount, 'fusermount needed for non-root cleanup'
                        unmount = [helper_unmount, '-u', str(mount)]
                    subprocess.run(unmount,check=True)
                if process.poll() is None: process.terminate()
                process.wait(timeout=10);log.close()
            assert hashlib.sha256(image.read_bytes()).digest()==before, 'source image changed'
        if not privileged: print('SKIP: cross-user/allow_other probes require sudo; owner/group checks ran',flush=True)
        data = dict(platform=sys.platform, cross_user=privileged, supplementary_gid=supplementary,
                    checks=sum(r['checks'] for r in results), results=results,
                    acl='metadata-only: named ACL grants/denials are intentionally not enforced')
        if args.output: args.output.write_text(json.dumps(data,indent=2)+'\n')
        print(f'PASS: {data["checks"]} mounted permission checks; source image unchanged')
    finally:
        assert not mounted(), f'mount remains; retaining {root}'
        shutil.rmtree(root)


if __name__ == '__main__': main()
