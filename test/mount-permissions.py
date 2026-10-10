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
import ctypes, errno, json, os, sys, traceback
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
failures = []
def check(case):
    path = root + '/' + case['path']
    try:
        if case['op'] == 'read':
            with open(path, 'rb') as file: assert file.read() == b'permission fixture\n'
        elif case['op'] == 'list':
            assert 'payload' in os.listdir(path)
        elif case['op'] == 'stat':
            st = os.stat(path)
            assert st.st_uid == case['uid'] and st.st_gid == case['gid']
            expected_mode = case['mode'] if case.get('native') else case['mode'] & ~0o222
            assert st.st_mode & 0o777 == expected_mode
        elif case['op'] == 'xattr':
            assert xattr(path).hex() == case['value']
        elif case['op'] == 'write':
            fd = os.open(path, os.O_WRONLY | os.O_APPEND)
            os.close(fd)  # Do not write even if the read-only check fails.
        else: raise AssertionError(case)
    except OSError as error:
        if case.get('allow_absent') and error.errno == errno.ENODATA:
            return True
        assert not case['allow'], (case, error)
        expected = (errno.EACCES, errno.EPERM, errno.EROFS) if case['op']=='write' else (errno.EACCES, errno.EPERM)
        if case.get('hidden') and sys.platform=='darwin': expected += (errno.ENOENT,)
        assert error.errno in expected, (case, error)
    else:
        assert case['allow'], ('unexpected permission grant', case, identity)
    return False
for repeat in range(2):
    for case in cases:
        try:
            acl_absent += bool(check(case))
        except (AssertionError, OSError) as error:
            failures.append(dict(case=case, error=str(error)))
        count += 1
print(json.dumps(dict(checks=count, uid=os.getuid(), gid=os.getgid(), groups=actual_groups, acl_absent=acl_absent, failures=failures)))
'''


def credentials(identity):
    # Popen's POSIX credential parameters report errors in the parent instead
    # of hiding them behind a generic preexec_fn failure.
    # Darwin stores the effective GID in slot zero. Include it first so the
    # later setregid call does not replace the sole supplementary group.
    groups = [identity['gid']] + [g for g in identity['groups'] if g != identity['gid']]
    return dict(user=identity['uid'], group=identity['gid'], extra_groups=groups)


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
    parser.add_argument('--expect-posix-acl', action='store_true', help='require Linux FUSE 3 kernel ACL enforcement')
    parser.add_argument('--native-reference', action='store_true', help='also verify a disposable read-only native Linux ext4 mount')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assert sys.platform in ('darwin', 'linux'), 'requires macFUSE or Linux FUSE'
    assert not args.expect_posix_acl or sys.platform == 'linux', 'kernel POSIX ACL test requires Linux'
    privileged = os.geteuid() == 0
    assert not args.native_reference or (privileged and sys.platform=='linux' and args.expect_posix_acl), 'native reference requires root Linux ACL mode'
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
        'acl-deny': (foreign_uid, foreign_gid, 0o044),
        'acl-zero-mask-other': (foreign_uid, foreign_gid, 0o004),
        'acl-mask-deny': (foreign_uid, foreign_gid, 0o000),
        'acl-group-grant': (foreign_uid, foreign_gid, 0o040),
        'acl-group-union': (foreign_uid, gid, 0o040),
        'acl-group-deny': (foreign_uid, supplementary, 0o004),
        'acl-user-precedence': (foreign_uid, foreign_gid, 0o044),
        'acl-owner-precedence': (uid, foreign_gid, 0o040),
    }
    for name in entries: debug(f'write {payload} /{name}')
    acls = {}
    undefined = 0xffffffff
    def acl_entries(owner_perm, users, group_perm, groups, mask, other):
        return [(1,owner_perm,undefined)] + [(2,p,i) for i,p in sorted(users)] + [(4,group_perm,undefined)] + [(8,p,i) for i,p in sorted(groups)] + [(16,mask,undefined),(32,other,undefined)]
    acl_specs = {
        'acl-grant': acl_entries(4,[(peer_uid,4)],0,[],4,0),
        'acl-deny': acl_entries(0,[(peer_uid,0)],0,[],4,4),
        'acl-zero-mask-other': acl_entries(0,[(peer_uid,0)],0,[],0,4),
        'acl-mask-deny': acl_entries(0,[(peer_uid,4)],0,[],0,0),
        'acl-group-grant': acl_entries(0,[],0,[(supplementary,4)],4,0),
        'acl-group-union': acl_entries(0,[],0,[(gid,0),(supplementary,4)],4,0),
        'acl-group-deny': acl_entries(0,[],0,[(supplementary,0)],0,4),
        'acl-user-precedence': acl_entries(0,[(peer_uid,0)],0,[(supplementary,4)],4,4),
        'acl-owner-precedence': acl_entries(0,[(uid,4)],0,[],4,0),
    }
    for name, spec in acl_specs.items():
        acls[name] = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in spec)
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
    # A named-user directory grant must permit both enumeration and traversal.
    debug('mkdir /acl-traverse')
    debug(f'write {payload} /acl-traverse/payload')
    for field,value in [('uid',foreign_uid),('gid',foreign_gid),('mode',0o040050)]:
        debug(f'set_inode_field /acl-traverse {field} {value}')
    debug(f'set_inode_field /acl-traverse/payload mode {0o100004}')
    directory_acl = struct.pack('<I',2) + b''.join(struct.pack('<HHI',*e) for e in acl_entries(0,[(peer_uid,5)],0,[],5,0))
    host = root/'directory.acl'; host.write_bytes(directory_acl)
    debug(f'ea_set -f {host} /acl-traverse system.posix_acl_access')
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
    if args.native_reference: modes.append(('native-ext4','ro,noload',True,False))
    try:
        for label, options, shared, recovery in modes:
            log = (root/(label+'.log')).open('w+')
            native = label=='native-ext4'
            process = None
            if native:
                subprocess.run(['mount','-t','ext4','-o',options,str(image),str(mount)],check=True)
            else:
                process = subprocess.Popen([reader,str(image),str(mount),'-f','-s','-o',options], stdout=log, stderr=log,
                                           **(credentials(owner) if privileged else {}))
            try:
                for attempt in range(80):
                    if mounted(): break
                    if process is not None and process.poll() is not None: raise AssertionError('daemon exited before mounting')
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
                        allowed = permitted(owner_uid,owner_gid,mode,4)
                        if args.expect_posix_acl and visible and name in acl_specs:
                            spec = acl_specs[name]
                            mask = next(p for tag,p,i in spec if tag==16)
                            if identity['uid']==owner_uid: permission = spec[0][1]
                            else:
                                user_matches = [p for tag,p,i in spec if tag==2 and i==identity['uid']]
                                group_matches = [p for tag,p,i in spec if (tag==4 and owner_gid in identity['groups']+[identity['gid']]) or (tag==8 and i in identity['groups']+[identity['gid']])]
                                if user_matches: permission = user_matches[0] & mask
                                elif group_matches:
                                    permission = 0
                                    for p in group_matches: permission |= p & mask
                                else: permission = spec[-1][1]
                            # Linux generic_permission skips ACL lookup when the
                            # inode group/mask bits are zero; native ext4 agrees.
                            allowed = bool(permission & 4) if mask else permitted(owner_uid,owner_gid,mode,4)
                        cases.append(dict(op='read', path=name, allow=allowed))
                        cases.append(dict(op='stat', path=name, allow=visible, uid=owner_uid, gid=owner_gid, mode=mode,native=native))
                    for name,mode in [('traverse',0o050),('list-only',0o040),('search-only',0o010)]:
                        cases.append(dict(op='list',path=name,allow=permitted(foreign_uid,supplementary,mode,4)))
                        cases.append(dict(op='read',path=name+'/payload',allow=permitted(foreign_uid,supplementary,mode,1)))
                    directory_allowed = visible and (recovery or (args.expect_posix_acl and identity['uid']==peer_uid))
                    cases.append(dict(op='list',path='acl-traverse',allow=directory_allowed))
                    cases.append(dict(op='read',path='acl-traverse/payload',allow=directory_allowed))
                    cases.append(dict(op='read',path='link' ,allow=permitted(uid,foreign_gid,0o600,4)))
                    cases.append(dict(op='write',path='public',allow=False))
                    # ACL retrieval is checked as owner, independently of named-rule enforcement.
                    if role=='owner':
                        for name in ('acl-grant','acl-deny'):
                            value = acls[name]
                            cases.append(dict(op='xattr',path=name,allow=True,value=value.hex(),
                                              allow_absent=sys.platform=='linux' and not args.expect_posix_acl and position>0))
                    for case in cases: case['hidden'] = not visible
                    command = [sys.executable,str(helper),str(mount),json.dumps(cases),json.dumps(identity)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                            **(credentials(identity) if privileged else {}))
                    assert result.returncode==0, ('credential/driver failure',label,role,result.stdout,result.stderr)
                    row = dict(mode=label,role=role,**json.loads(result.stdout));results.append(row)
                    state = 'FAIL' if row['failures'] else 'PASS'
                    print(f'{state}: {label} {role}: {row["checks"]} permission checks',flush=True)
                    for failure in row['failures']: print(json.dumps(failure),flush=True)
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
                if process is not None:
                    if process.poll() is None: process.terminate()
                    process.wait(timeout=10)
                log.close()
            assert hashlib.sha256(image.read_bytes()).digest()==before, 'source image changed'
        if not privileged: print('SKIP: cross-user/allow_other probes require sudo; owner/group checks ran',flush=True)
        data = dict(platform=sys.platform, cross_user=privileged, supplementary_gid=supplementary,
                    checks=sum(r['checks'] for r in results), results=results,
                    acl='kernel-enforced' if args.expect_posix_acl else 'metadata-only')
        if args.output: args.output.write_text(json.dumps(data,indent=2)+'\n')
        failures = sum(len(row['failures']) for row in results)
        assert failures==0, f'{failures} permission mismatches; see complete matrix above'
        print(f'PASS: {data["checks"]} mounted permission checks; source image unchanged')
    finally:
        assert not mounted(), f'mount remains; retaining {root}'
        shutil.rmtree(root)


if __name__ == '__main__': main()
