#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Numeric caller permissions and ACL creation policy on managed image sessions."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import FrozenInstanceError
import session
from credentials import Credentials

here = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--fixtures', type=Path)
parser.add_argument('--limit', type=int)
args = parser.parse_args()
fixtures = args.fixtures or args.work / 'fixtures'
checks, rows = 0, []


def check(value, detail='check failed'):
    global checks
    assert value, detail
    checks += 1


def run(argv, code=0, env=None, data=None):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60, env=env, input=data)
    check(result.returncode == code, result.stdout + result.stderr)
    return result.stdout


def debug(image, command):
    return run(['debugfs', '-R', command, image]).decode()


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def acl_bytes(entries, version=2):
    return struct.pack('<I', version) + b''.join(struct.pack('<HH', t, p) +
        (struct.pack('<I', i if t in (2, 8) else 2**32-1) if version == 2 or t in (2, 8) else b'')
        for t, p, i in entries)


def write(path, data=b'permission checked', offset=0):
    return dict(kind='write', path=path, offset=offset, data_hex=data.hex())


def denied(function, expected):
    try:
        function()
    except Exception as e:
        check(isinstance(e, expected) if isinstance(expected, type) else getattr(e, 'errno', None) == expected, repr(e))
    else:
        raise AssertionError('unauthorized operation accepted')


def atomic(s, operations, expected):
    image = s.root / 'image.img'; before = sha(image); head = s.state['head']
    denied(lambda: s.apply(operations), expected)
    check(sha(image) == before and s.state['head'] == head and not s.state['pending'])


def metadata(image, path, mode, uid, gid):
    text = debug(image, 'stat ' + path)
    found = re.search(r'Mode:\s+0*([0-7]+)', text)
    check(found and int(found.group(1), 8) == mode, text)
    found = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)', text)
    check(found and tuple(map(int, found.groups())) == (uid, gid), text)


def get_acl(image, path, directory, key='system.posix_acl_access'):
    output = directory / 'acl-output'
    if output.exists(): output.unlink()
    debug(image, f'ea_get -r -f {output} {path} {key}')
    check(output.exists(), 'debugfs did not extract ACL')
    data = output.read_bytes(); output.unlink()
    return data


def open_session(root, caller):
    return session.Session(root, args.work / 'mutation-producer', args.work / 'reader-server', caller)


for constructor in (lambda: Credentials(True, 1), lambda: Credentials(2**32-1, 1),
                    lambda: Credentials(1, 1, (2**32-1,)), lambda: Credentials(1, 1, tuple(range(65))),
                    lambda: Credentials(1, 1, umask=0o1000)):
    denied(constructor, ValueError)
caller = Credentials(70000, 80000, [201, 200, 201], umask=0o027)
check(caller.groups == (200, 201))
denied(lambda: setattr(caller, 'uid', 0), FrozenInstanceError)

with tempfile.TemporaryDirectory(prefix='policy-test-', dir=args.work) as directory:
    directory = Path(directory)
    sources = [p for p in sorted(fixtures.glob('*-csum*.img')) if '-output' not in p.name]
    if args.limit: sources = sources[:args.limit]
    for source in sources:
        original = sha(source)
        seed = directory / (source.stem + '-seed.img'); shutil.copyfile(source, seed)
        payload = directory / 'payload'; payload.write_bytes(b'secret numeric content\0\xff')
        access = [(1,6,0),(2,6,101),(2,0,102),(4,4,0),(8,2,201),(8,4,202),(16,4,0),(32,4,0)]
        default = [(1,7,0),(2,6,101),(4,7,0),(8,4,201),(16,7,0),(32,1,0)]
        minimal = [(1,7,0),(4,5,0),(32,1,0)]
        split = [(1,7,0),(4,1,0),(8,2,201),(16,3,0),(32,7,0)]
        specs = {'access':access, 'default':default, 'minimal':minimal, 'split':split}
        acl_files = {}
        for name, entries in specs.items():
            p = directory / (name + '.acl'); p.write_bytes(acl_bytes(entries)); acl_files[name] = p
        commands = []
        def field(path, mode, uid=100, gid=200):
            commands.extend([f'set_inode_field {path} mode {mode}', f'set_inode_field {path} uid {uid}', f'set_inode_field {path} gid {gid}'])
        for path, mode, gid in (('/open',0o40777,200),('/closed',0o40700,200),('/inherit',0o42777,70000),('/minimal',0o40777,200),('/split',0o40737,200)):
            commands.append('mkdir ' + path); field(path, mode, gid=gid)
        for path, mode in (('/open/read-only',0o100400),('/open/acl-file',0o100644),('/closed/hidden',0o100644),('/open/setid',0o106777),('/open/root-setid',0o106777),('/open/cap',0o100666)):
            commands.append(f'write {payload} {path}'); field(path, mode)
        field('/existing-file',0o100660)
        commands.extend([f'ea_set -f {acl_files["access"]} /open/acl-file system.posix_acl_access',
                         f'ea_set -f {acl_files["default"]} /inherit system.posix_acl_default',
                         f'ea_set -f {acl_files["minimal"]} /minimal system.posix_acl_default',
                         f'ea_set -f {acl_files["split"]} /split system.posix_acl_access',
                         'ea_set /open/cap security.capability present'])
        script = directory / 'seed.commands'; script.write_text('\n'.join(commands) + '\n')
        run(['debugfs','-w','-f',script,seed])
        for path in ('/open/acl-file','/inherit','/minimal','/split'):
            check('system.posix_acl' in debug(seed,'ea_list '+path))
        run(['e2fsck','-fn',seed])
        root = directory / source.stem
        run(['python3',here/'chain.py','init',seed,root,args.work/'prototype'])
        image = root / 'image.img'
        initial = (image.stat().st_dev, image.stat().st_ino)
        model = bytearray((i*19+13)&255 for i in range(32768))
        with open_session(root, Credentials(100,200)) as s:
            check(s.read('/existing-file',0,len(model)) == model)
            denied(lambda: setattr(s,'credentials',Credentials(0,0)), AttributeError)
            denied(lambda: s._rpc(6,Credentials(0,0).encode()),errno.EPERM)
            s.apply([write('/existing-file',b'owner write',17)])
            model[17:28] = b'owner write'
            atomic(s,[write('/existing-file',b'prefix'),write('/open/read-only')],errno.EACCES)
            atomic(s,[write('/open/cap')],errno.EOPNOTSUPP)
            s.apply([write('/open/setid',b'changed')])
            metadata(image,'/open/setid',0o777,100,200)
            check(s.read('/open/read-only') == payload.read_bytes())
        with open_session(root, Credentials(999,9000,(200,))) as s:
            s.apply([write('/existing-file',b'supplementary group',33)])
            model[33:52] = b'supplementary group'
            check(s.read('/existing-file',0,len(model)) == model)
            denied(lambda: s.read('/closed/hidden'),errno.EACCES)
            denied(lambda: s.size('/closed/hidden'),errno.EACCES)
            atomic(s,[write('/existing-file',b'prefix'),dict(kind='create',path='/closed/new')],errno.EACCES)
        with open_session(root, Credentials(101,9000,umask=0o077)) as s:
            check(s.read('/open/acl-file') == payload.read_bytes())
            atomic(s,[write('/open/acl-file')],errno.EACCES)
            atomic(s,[dict(kind='truncate',path='/open/acl-file',size=1)],errno.EACCES)
            s.apply([dict(kind='create',path='/inherit/new',mode=0o666,data_hex='00ff63616c6c6572')])
            check(s.read('/inherit/new') == b'\0\xffcaller')
            metadata(image,'/inherit/new',0o660,101,70000)
            inherited = [(1,6,0),(2,6,101),(4,7,0),(8,4,201),(16,6,0),(32,0,0)]
            actual = get_acl(image,'/inherit/new',directory)
            check(actual == acl_bytes(inherited,1), (actual.hex(), acl_bytes(inherited,1).hex()))
            check(get_acl(image,'/inherit',directory,'system.posix_acl_default') == acl_bytes(default,1))
            s.apply([dict(kind='create',path='/minimal/new',mode=0o666)])
            metadata(image,'/minimal/new',0o640,101,9000)
            check(get_acl(image,'/minimal/new',directory) == acl_bytes([(1,6,0),(4,4,0),(32,0,0)],1))
            atomic(s,[dict(kind='create',path='/open/forbidden-owner',uid=0)],ValueError)
            atomic(s,[dict(kind='create',path='/open/forbidden-group',gid=0)],ValueError)
            atomic(s,[dict(kind='create',path='/open/unpublished',mode=0),write('/open/unpublished')],errno.EACCES)
            denied(lambda: s.size('/open/unpublished'),errno.ENOENT)
        with open_session(root, Credentials(102,9000)) as s:
            check(s.size('/open/acl-file') == len(payload.read_bytes()))
            denied(lambda: s.read('/open/acl-file'),errno.EACCES) # named denial, no other fallback
        with open_session(root, Credentials(999,9000,(201,))) as s:
            denied(lambda: s.read('/open/acl-file'),errno.EACCES) # matched group cannot fall through
            check(s.read('/inherit/new') == b'\0\xffcaller')
            atomic(s,[write('/inherit/new')],errno.EACCES)
        with open_session(root, Credentials(999,9000,(202,))) as s:
            check(s.read('/open/acl-file') == payload.read_bytes())
            denied(lambda: s.read('/inherit/new'),errno.EACCES)
        with open_session(root, Credentials(999,9000,(200,201))) as s:
            atomic(s,[dict(kind='create',path='/split/new')],errno.EACCES) # w+x split across groups
        with open_session(root, caller) as s:
            s.apply([dict(kind='create',path='/open/umask',mode=0o666)])
            metadata(image,'/open/umask',0o640,70000,80000)
            s.apply([dict(kind='create',path='/open/zero',mode=0,data_hex='696e697469616c')])
            metadata(image,'/open/zero',0,70000,80000)
            s.apply([dict(kind='create',path='/inherit/peer',mode=0o666,data_hex='6f6c64')])
            metadata(image,'/inherit/peer',0o660,70000,70000)
            denied(lambda: s.read('/open/zero'),errno.EACCES)
        with open_session(root, Credentials(101,9000)) as s:
            s.apply([write('/inherit/peer',b'named writer')])
            check(s.read('/inherit/peer') == b'named writer')
        with open_session(root, Credentials(999,9000)) as s:
            check(s.read('/open/acl-file') == payload.read_bytes()) # unmatched other class
            atomic(s,[write('/existing-file')],errno.EACCES)
        with open_session(root, Credentials(0,0)) as s:
            s.apply([write('/open/root-setid',b'root change')])
            metadata(image,'/open/root-setid',0o6777,100,200)
            check(s.read('/closed/hidden') == payload.read_bytes())
            check(s.read('/open/zero') == b'initial')
            check(s.read('/existing-file',0,len(model)) == model)
        # Raw caller requests cannot override ownership, even when bypassing JSON validation.
        c = Credentials(101,9000,umask=0o027)
        request = bytearray(session.write_api.encode([dict(kind='create',path='/open/raw-owner',mode=0o666)],c))
        record = 16 + len(c.encode()); struct.pack_into('<II',request,record+12,0,0)
        with session.chain.locked(root) as locked:
            session.write_api.apply_encoded_locked(locked,args.work/'mutation-producer',request)
        metadata(image,'/open/raw-owner',0o640,101,9000)
        run(['e2fsck','-fn',image])
        check((image.stat().st_dev,image.stat().st_ino) == initial)
        # Malformed ACL and mode/ACL disagreement must fail for root too. Keep
        # these deliberately invalid fixtures separate from fsck-clean successes.
        for bad in ('access','default','mismatch','richacl'):
            badseed = directory / (source.stem + '-' + bad + '.img'); shutil.copyfile(seed,badseed)
            malformed = directory / 'bad.acl'; malformed.write_bytes(struct.pack('<I',2)+struct.pack('<HHI',1,7,2**32-1))
            if bad == 'access':
                cmd = f'ea_set -f {malformed} /open/acl-file system.posix_acl_access'
            elif bad == 'default':
                cmd = f'ea_set -f {malformed} /inherit system.posix_acl_default'
            elif bad == 'mismatch': cmd = 'set_inode_field /open/acl-file mode 0100777'
            else: cmd = 'ea_set /open/acl-file system.richacl unsupported'
            run(['debugfs','-w','-R',cmd,badseed])
            badroot = directory / (source.stem + '-bad-' + bad)
            run(['python3',here/'chain.py','init',badseed,badroot,args.work/'prototype'])
            with open_session(badroot,Credentials(0,0)) as s:
                expected = errno.EOPNOTSUPP if bad == 'richacl' else errno.EIO
                if bad == 'default':
                    atomic(s,[write('/existing-file',b'prefix'),dict(kind='create',path='/inherit/rejected')],expected)
                else:
                    denied(lambda: s.read('/open/acl-file'),expected)
                    atomic(s,[write('/existing-file',b'prefix'),write('/open/acl-file')],expected)
        # Versioned credential transports: invalid contexts fail without an overlay.
        base = session.write_api.encode([write('/existing-file')],Credentials(100,200))
        frames = [base[:16], base[:16]+struct.pack('<IIII',0,0,0,65)+base[32:]]
        for i, frame in enumerate(frames):
            request_file = directory / 'request'; request_file.write_bytes(frame)
            result = run([args.work/'mutation-producer',image,'--stream'],code=1,
                         env=dict(os.environ,EXT4_MUTATION_REQUEST=str(request_file)))
            check(result == struct.pack('<8sQQ',b'E4ER0001',errno.EINVAL,0))
        if not rows:
            # Reject forged error frames rather than publishing an apparent batch.
            for code, reserved, trailing, exitcode in ((0,0,b'',1),(5000,0,b'',1),(errno.EACCES,1,b'',1),
                                                       (errno.EACCES,0,b'x',1),(errno.EACCES,0,b'',0)):
                frame = struct.pack('<8sQQ',b'E4ER0001',code,reserved) + trailing
                producer = directory / 'fake-producer'
                producer.write_text('#!/usr/bin/env python3\nimport os\nos.write(1,' + repr(frame) + ')\nraise SystemExit(' + str(exitcode) + ')\n')
                producer.chmod(0o700)
                with session.Session(root,producer,args.work/'reader-server',Credentials(100,200)) as s:
                    atomic(s,[write('/existing-file')],ValueError)
                    check(s.read('/existing-file',0,len(model)) == model)
        check(sha(source) == original)
        rows.append(dict(fixture=source.stem, numeric_access=True, inherited_acl=True,
                         setgid_owner=True, atomic_denial=True, invalid_acl_closed=True, fsck_clean=True))
        print('PASS permission policy',source.stem,flush=True)
    check(len(rows) == (args.limit or 12))
report = dict(checks=checks,result='passed',configurations=rows,
              scope='trusted explicit numeric credentials; offline images; no host credential changes or mounted frontend')
(args.work / ('policy-smoke-results.json' if args.limit else 'policy-results.json')).write_text(json.dumps(report,indent=2)+'\n')
print('PASS',checks,'image policy checks')
