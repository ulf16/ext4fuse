# SPDX-License-Identifier: GPL-2.0-only
"""Private named volumes; stable identity discovery and checked background mounts."""
import argparse
import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import time

import device_admission as admission
import inplace
import progress
from durable import directory
from mount_state import attached, mounts

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
FIELDS = {'version', 'name', 'platform', 'state', 'state_id', 'mountpoint', 'mount_id', 'mode', 'binding'}
DIRECT_BINDING = ('version', 'identity', 'size', 'sector', 'uuid', 'token_device', 'token_inode')


def default_directory():
    base = Path.home()/'Library'/'Application Support' if sys.platform == 'darwin' else Path.home()/'.config'
    return base/'ext4fuse-writer'/'volumes'


def name_check(name):
    if not isinstance(name,str) or NAME.fullmatch(name) is None:
        raise ValueError('volume names must be 1..64 letters, digits, underscores or hyphens, starting with a letter or digit')
    return name


def private(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o077):
        raise ValueError('volume profile files must be private, owned and singly linked')


@contextlib.contextmanager
def registry(args, create=False):
    path = args.profiles_dir.absolute()
    if path.is_symlink():raise ValueError('profile directory cannot be a symlink')
    if create:path.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not path.exists():
        yield None
        return
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('profile directory must be private and owned by the launching user')
    path = path.resolve()
    fd = os.open(path/'registry-lock',os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT if create else 0),0o600)
    try:
        private(os.fstat(fd))
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield path
    finally:os.close(fd)


def pair(path):
    info=os.stat(path,follow_symlinks=False)
    return [info.st_dev,info.st_ino]


def binding(root, mode, cli):
    if mode == 'direct':
        saved=cli.load_json(root/'device'/'direct-state')
        from direct_device import FIELDS as direct_fields
        if not isinstance(saved,dict) or set(saved)!=direct_fields:
            raise ValueError('invalid remembered direct-device state')
        return {key:saved[key] for key in DIRECT_BINDING}
    info=os.stat(root/'chain'/'image.img',follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:
        raise ValueError('managed image identity changed')
    return dict(device=info.st_dev,inode=info.st_ino,size=info.st_size)


def load(store, name, cli):
    name_check(name)
    if store is None:raise FileNotFoundError('no remembered volumes; add a volume first')
    value=cli.load_json(store/(name+'.json'))
    if (not isinstance(value,dict) or set(value)!=FIELDS or type(value['version']) is not int
            or value['version']!=1 or value['name']!=name or value['platform']!=sys.platform
            or value['mode'] not in ('image','direct')):
        raise ValueError('unsupported or damaged volume profile')
    for key in ('state','mountpoint'):
        if not isinstance(value[key],str) or not value[key].startswith('/') or '\0' in value[key]:
            raise ValueError('invalid remembered path')
    for key in ('state_id','mount_id'):
        if (not isinstance(value[key],list) or len(value[key])!=2
                or any(type(n) is not int or n<0 for n in value[key])):
            raise ValueError('invalid remembered path identity')
    root=cli.root_path(Path(value['state']))
    if str(root)!=value['state'] or pair(root)!=value['state_id']:
        raise ValueError('remembered recovery directory was replaced')
    data=cli.manifest(root)
    if data['mode']!=value['mode'] or binding(root,data['mode'],cli)!=value['binding']:
        raise ValueError('remembered volume binding changed; retain state and inspect it')
    return value


def check_mount(profile, cli):
    root=Path(profile['state']);mount=Path(profile['mountpoint'])
    if attached(mount):raise OSError(errno.EBUSY,'remembered mountpoint is already attached')
    if pair(mount)!=profile['mount_id']:raise ValueError('remembered mountpoint was replaced')
    cli.broker_module().validate_mount(root,cli.HERE/'native',mount)


def mac_candidates(identity):
    # Restrict inventory to the saved GPT UUID or owned backing image before
    # examining serials. No disk is opened, mounted or unmounted by discovery.
    if identity.get('kind')=='disk-image':
        expected=identity.get('backing',{})
        for image in admission.plist(['/usr/bin/hdiutil','info','-plist']).get('images',[]):
            candidate=image.get('image-path')
            if not isinstance(candidate,str) or Path(candidate).name!=Path(expected.get('path','')).name:continue
            try:
                info=os.lstat(candidate)
                if (info.st_dev,info.st_ino)!=(expected.get('device'),expected.get('inode')):continue
                if admission.owned_file(candidate)!=expected:continue
            except (FileNotFoundError,PermissionError):continue
            for entity in image.get('system-entities',[]):
                path=entity.get('dev-entry','')
                if re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)?',path):yield path
        return
    if identity.get('kind')!='physical':raise ValueError('profile device kind does not match macOS')
    def walk(value):
        if isinstance(value,dict):
            if 'DeviceIdentifier' in value:yield value['DeviceIdentifier']
            for entry in value.values():yield from walk(entry)
        elif isinstance(value,list):
            for entry in value:yield from walk(entry)
    listing=admission.plist(['/usr/sbin/diskutil','list','-plist'])
    for name in sorted(set(walk(listing))):
        if not re.fullmatch(r'disk[0-9]+s[0-9]+',name):continue
        info=admission.plist(['/usr/sbin/diskutil','info','-plist','/dev/'+name])
        if info.get('DiskUUID')==identity.get('partition'):yield '/dev/'+name


def linux_candidates(identity):
    if identity.get('kind')=='loop':
        for path in sorted(Path('/sys/block').glob('loop*/loop/backing_file')):
            try:
                backing='/'+path.read_text().strip().lstrip('/')
                if backing!=identity.get('backing',{}).get('path'):continue
                if admission.owned_file(backing)!=identity['backing']:continue
            except (FileNotFoundError,PermissionError):continue
            whole=path.parent.parent
            if identity.get('partition')=='whole':yield '/dev/'+whole.name
            else:
                for part in whole.iterdir():
                    if (part/'partition').exists():yield '/dev/'+part.name
        return
    if identity.get('kind')!='physical':raise ValueError('profile device kind does not match Linux')
    listing=json.loads(admission.command(['lsblk','--json','-b','-o','PATH,PARTUUID,TYPE']))
    def walk(nodes):
        for node in nodes:
            if node.get('partuuid')==identity.get('partition') and node.get('type')=='part':yield node['path']
            yield from walk(node.get('children',[]))
    yield from walk(listing.get('blockdevices',[]))


def describe(path):
    if sys.platform=='darwin':
        info=admission.plist(['/usr/sbin/diskutil','info','-plist',path])
        return admission.mac_identity(info),int(info['TotalSize']),int(info['DeviceBlockSize'])
    info=os.lstat(path)
    if not stat.S_ISBLK(info.st_mode):raise ValueError('discovered node is not a block device')
    node=(Path('/sys/dev/block')/f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}').resolve(strict=True)
    partition=(node/'partition').exists();whole=node.parent if partition else node
    if whole.name.startswith('loop'):
        backing='/'+(whole/'loop/backing_file').read_text().strip().lstrip('/')
        identity=dict(kind='loop',backing=admission.owned_file(backing),partition=node.name if partition else 'whole')
    else:
        serial=[p.read_text().strip() for p in (whole/'device/wwid',whole/'device/serial') if p.exists()]
        record=json.loads(admission.command(['lsblk','--json','-b','-o','PATH,PARTUUID',path]))['blockdevices'][0]
        identity=dict(kind='physical',serial=serial,partition=record.get('partuuid'))
    return identity,int((node/'size').read_text())*512,int((whole/'queue/logical_block_size').read_text())


def resolve(profile):
    saved=profile['binding'];identity=saved['identity']
    candidates=mac_candidates(identity) if sys.platform=='darwin' else linux_candidates(identity)
    matches=[]
    for path in sorted(set(candidates)):
        actual=describe(path)
        if actual==(identity,saved['size'],saved['sector']):matches.append(path)
    if not matches:raise FileNotFoundError('remembered volume is disconnected or its hardware/partition identity changed')
    if len(matches)!=1:raise ValueError('multiple devices match this volume; refusing ambiguous selection')
    return matches[0]


def add(args,cli):
    with registry(args,True) as store:
        name_check(args.name)
        if any(p.name.casefold()==(args.name+'.json').casefold() for p in store.iterdir()):
            raise FileExistsError('volume name already remembered; forget it before adding a new binding')
        root=cli.root_path(args.state)
        with cli.lock(root):
            data=cli.manifest(root)
            if data['phase']!='ready' or data['mountpoint']:
                raise ValueError('initialize/recover and unmount the volume before remembering it')
            mount=args.mountpoint.absolute()
            mount=mount.parent.resolve()/mount.name
            if attached(mount):raise OSError(errno.EBUSY,'mountpoint already contains a filesystem')
            if mount.is_symlink():raise ValueError('mountpoint cannot be a symlink')
            mount.mkdir(mode=0o700,parents=True,exist_ok=True)
            _,_,mount=cli.broker_module().validate_mount(root,cli.HERE/'native',mount)
            if any(a==b or a.is_relative_to(b) or b.is_relative_to(a) for a,b in ((store,mount),(store,root))):
                raise ValueError('profile directory must be outside recovery state and mountpoint')
            value=dict(version=1,name=args.name,platform=sys.platform,state=str(root),state_id=pair(root),
                mountpoint=str(mount),mount_id=pair(mount),mode=data['mode'],binding=binding(root,data['mode'],cli))
            if len(json.dumps(value).encode())>8192:raise ValueError('volume profile paths/identity exceed the supported size')
            pending=store/(args.name+'.json.pending')
            if pending.exists() or pending.is_symlink():private(os.lstat(pending))
            inplace.seal(store,args.name+'.json',value)
    print('Remembered '+args.name+'. Mount with: ext4fuse-writer volume mount '+args.name)


def background(profile,args,cli,lock_fd):
    root=Path(profile['state'])
    read_fd,write_fd=os.pipe()
    log=root/'volume-mount.log'
    child=None
    try:
        fd=os.open(log,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'ab',buffering=0) as output:
            private(os.fstat(output.fileno()))
            argv=[sys.executable,'-I',str(cli.HERE/'writer_cli.py'),'mount',str(root),profile['mountpoint'],
                '--lock-fd',str(lock_fd),'--ready-fd',str(write_fd),'--checkpoint-every',str(args.checkpoint_every),
                '--check-bytes',str(args.check_bytes),'--journal-bytes',str(args.journal_bytes)]
            if profile['mode']=='direct':argv+=['--device',resolve(profile)]
            child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=output,stderr=output,
                start_new_session=True,pass_fds=(lock_fd,write_fd))
        os.close(write_fd);write_fd=None
        print('Starting '+profile['name']+'; progress and diagnostics: '+str(log),flush=True)
        deadline=time.monotonic()+args.timeout
        notified=False
        while True:
            if notified:
                if (child.poll() is None and mounts().get(profile['mountpoint'],(None,None))[1]=='ext4fuse-experimental'
                        and cli.manifest(root)['phase']=='mounting'):
                    print('Mounted '+profile['name']+' at '+profile['mountpoint']+' (background writer '+str(child.pid)+').')
                    return
                if child.poll() is not None:raise OSError(errno.EIO,'writer exited during mount readiness; inspect '+str(log))
                time.sleep(.05)
            elif select.select([read_fd],[],[],min(1,max(0,deadline-time.monotonic())))[0]:
                ready=os.read(read_fd,1)
                if ready==b'M' and child.poll() is None:
                    notified=True
                    continue
                # EOF can precede the final process status by a scheduling tick.
                child.wait(timeout=10)
                raise OSError(errno.EIO,'background mount failed; inspect '+str(log)+' and volume status; state retained')
            if time.monotonic()>=deadline:
                raise TimeoutError('mount wait timed out; background writer '+str(child.pid)+' continues. Inspect '+str(log)+'; keep the device connected')
    except KeyboardInterrupt:
        if child is not None:
            print('Stopped waiting; background writer '+str(child.pid)+' continues. Use volume list/unmount; log: '+str(log),file=sys.stderr)
        raise
    finally:
        os.close(read_fd)
        if write_fd is not None:os.close(write_fd)


def stop(profile,args,cli,announce=True):
    root=Path(profile['state']);deadline=time.monotonic()+args.timeout
    while True:
        data=cli.manifest(root)
        try:
            with cli.lock(root):
                data=cli.manifest(root)
                if data['phase']=='ready' and not data['mountpoint']:
                    if announce:print(profile['name']+' is already unmounted; recovery state is ready.')
                    return
        except BlockingIOError:pass
        if data['mountpoint'] and attached(data['mountpoint']):break
        # A dead mount/failed worker is handled by ordinary unmount/recovery.
        try:
            with cli.lock(root):break
        except BlockingIOError:pass
        if time.monotonic()>=deadline:raise TimeoutError('mount is still starting; keep the device connected and inspect volume-mount.log')
        time.sleep(.1)
    cli.unmount(argparse.Namespace(state=root,timeout=max(.001,deadline-time.monotonic())),announce=announce)


def audit_device_users(path):
    """Check canonical raw users of every sibling, without touching file data."""
    if sys.platform=='darwin':
        info=admission.plist(['/usr/sbin/diskutil','info','-plist',path])
        whole=info.get('ParentWholeDisk',info['DeviceIdentifier'])
        listing=admission.plist(['/usr/sbin/diskutil','list','-plist','/dev/'+whole])
        def nodes(value):
            if isinstance(value,dict):
                if 'DeviceIdentifier' in value:yield value['DeviceIdentifier']
                for item in value.values():yield from nodes(item)
            elif isinstance(value,list):
                for item in value:yield from nodes(item)
        names=set(nodes(listing))|{whole}
        paths=[]
        for name in sorted(names):
            if not re.fullmatch(r'disk[0-9]+(?:s[0-9]+)*',name):raise ValueError('invalid OS disk identifier')
            detail=admission.plist(['/usr/sbin/diskutil','info','-plist','/dev/'+name])
            if detail.get('Mounted'):raise OSError(errno.EBUSY,'another partition is mounted; ejection refused')
            paths+=['/dev/'+name,'/dev/r'+name]
        result=subprocess.run(['/usr/sbin/lsof','-F','p','--',*paths],capture_output=True,timeout=30)
        if result.returncode not in (0,1):raise OSError(errno.EBUSY,'cannot audit disk users before ejection')
        if any(line.startswith(b'p') and int(line[1:])!=os.getpid() for line in result.stdout.splitlines()):
            raise OSError(errno.EBUSY,'another process has this drive open; ejection refused')
        return
    info=os.lstat(path)
    node=(Path('/sys/dev/block')/f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}').resolve(strict=True)
    whole=node.parent if (node/'partition').exists() else node
    devices={whole.joinpath('dev').read_text().strip()}
    devices.update(p.read_text().strip() for p in whole.glob('*/dev') if (p.parent/'partition').exists())
    for process in Path('/proc').iterdir():
        if not process.name.isdigit() or int(process.name)==os.getpid():continue
        try:
            for fd in (process/'fd').iterdir():
                try:
                    # Avoid statting descriptors into an unrelated, potentially
                    # disconnected network/FUSE filesystem. Device opens use
                    # the canonical /dev namespace admitted by this writer.
                    if not os.readlink(fd).startswith('/dev/'):continue
                    opened=os.stat(fd)
                    if stat.S_ISBLK(opened.st_mode) and f'{os.major(opened.st_rdev)}:{os.minor(opened.st_rdev)}' in devices:
                        raise OSError(errno.EBUSY,'another process has this drive open; ejection refused')
                except FileNotFoundError:continue
        except FileNotFoundError:continue
        except PermissionError as error:
            raise PermissionError('cannot audit device users; use the same privileged owner as device initialization') from error


def eject(profile,args,cli):
    if profile['mode']!='direct':raise ValueError('image profiles have no USB device to eject; use volume unmount')
    stop(profile,args,cli,announce=False)
    root=Path(profile['state'])
    with cli.lock(root):
        # Bind again after potentially lengthy unmount/recovery checks.
        current=cli.manifest(root)
        if current['phase']!='ready' or current['mountpoint'] or binding(root,'direct',cli)!=profile['binding']:
            raise ValueError('writer is not cleanly unmounted or volume binding changed')
        state=cli.load_json(root/'device'/'direct-state')
        if state['phase']!='clean':raise ValueError('device recovery must finish before ejection')
        path=resolve(profile)
        expected=profile['binding']
        def preflight():
            with admission.Device(path,root) as target:
                if (target.identity,target.size,target.sector)!=(expected['identity'],expected['size'],expected['sector']):
                    raise ValueError('device identity changed before ejection')
                import live_device
                if live_device.magic(target)!=b'\x53\xef':raise ValueError('device is still guarded; recover before ejection')
                audit_device_users(path)
                target.flush();target.check()
                return target.node
        # Linux udev can briefly probe a just-closed loop/USB node. Retry only
        # admission/audit, never an OS eject request or a different device.
        node=cli.device_admission(preflight)
        # Release our own claims before asking the OS to eject normally. Keep
        # writer-lock throughout, so another cooperating mount cannot start.
        if describe(path)!=(expected['identity'],expected['size'],expected['sector']):
            raise ValueError('device identity changed after releasing its claim')
        raw=Path('/dev/r'+Path(path).name) if sys.platform=='darwin' else Path(path)
        now=os.lstat(raw)
        if (now.st_dev,now.st_ino,now.st_rdev)!=node:raise ValueError('device node changed before OS ejection')
        identity=expected['identity']
        if sys.platform=='darwin':
            info=admission.plist(['/usr/sbin/diskutil','info','-plist',path])
            whole=info.get('ParentWholeDisk',info['DeviceIdentifier'])
            command=(['/usr/bin/hdiutil','detach','/dev/'+whole] if identity['kind']=='disk-image'
                     else ['/usr/sbin/diskutil','eject',identity['partition']])
        elif identity['kind']=='loop':command=['losetup','--detach',path]
        else:
            tool=shutil.which('udisksctl')
            if tool is None:raise FileNotFoundError('udisksctl is required for Linux USB power-off; install udisks2 or use the operating system after volume unmount')
            uuid=identity['partition']
            if not re.fullmatch(r'[A-Za-z0-9-]+',uuid):raise ValueError('invalid stable partition identifier')
            alias=Path('/dev/disk/by-partuuid')/uuid
            if alias.resolve(strict=True)!=Path(path):raise ValueError('stable device alias changed')
            command=[tool,'power-off','--block-device',str(alias),'--no-user-interaction']
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=60)
        if result.returncode:
            raise OSError(errno.EBUSY,'writer is unmounted, but OS ejection was refused: '+result.stderr.decode(errors='replace')[-2048:])
        if sys.platform=='linux' and identity['kind']=='loop':
            backing=Path('/sys/block')/Path(path).name/'loop/backing_file'
            if backing.exists() and backing.read_text().strip():raise OSError(errno.EBUSY,'loop detach is still pending; another process holds the device')
    print('Safely ejected '+profile['name']+'. Recovery state retained.')


def listing(args,cli):
    rows=[]
    with registry(args) as store:
        if store is not None:
            for file in sorted(store.glob('*.json')):
                name=file.stem
                if NAME.fullmatch(name) is None:continue
                try:
                    profile=load(store,name,cli);root=Path(profile['state']);data=cli.manifest(root)
                    try:
                        with cli.lock(root):busy=False
                    except BlockingIOError:busy=True
                    row=dict(name=name,state=str(root),mountpoint=profile['mountpoint'],mode=profile['mode'],
                        phase=data['phase'],busy=busy,mounted=bool(data['mountpoint'] and attached(data['mountpoint'])),checked=False)
                    row['needs_recovery']=not busy and (row['phase']!='ready' or row['mounted'])
                    if args.connected and profile['mode']=='direct':
                        try:row.update(connected=True,device=resolve(profile))
                        except FileNotFoundError:row['connected']=False
                    rows.append(row)
                except (OSError,ValueError) as error:rows.append(dict(name=name,error=str(error)))
    if args.json:print(json.dumps(rows,sort_keys=True))
    elif not rows:print('No remembered volumes. Use volume add NAME --state STATE --mountpoint MOUNTPOINT.')
    else:
        for row in rows:
            if 'error' in row:print(row['name']+': unavailable: '+row['error']);continue
            state='mounted' if row['mounted'] else 'starting/checking' if row['busy'] else 'needs recovery' if row['needs_recovery'] else 'ready'
            if row.get('connected') is False:state+='; disconnected'
            print(row['name']+': '+state+'; '+row['mountpoint'])


def execute(args,cli):
    if hasattr(args,'timeout') and not 0<args.timeout<=86400:raise ValueError('timeout must be greater than zero and at most 86400 seconds')
    if args.volume_action in ('mount','recover'):
        from direct_device import budget_check
        from journal_candidate import budget
        budget_check(args.check_bytes);budget(args.journal_bytes)
    if args.volume_action=='add':return add(args,cli)
    if args.volume_action=='list':return listing(args,cli)
    with contextlib.ExitStack() as locks:
        with registry(args) as store:
            profile=load(store,args.name,cli)
            root=Path(profile['state'])
            if args.volume_action=='forget':
                with cli.lock(root):
                    data=cli.manifest(root)
                    if data['phase']!='ready' or data['mountpoint']:
                        raise ValueError('unmount/recover before forgetting; recovery state is never deleted')
                    (store/(args.name+'.json')).unlink();directory(store)
                print('Forgot '+args.name+'; recovery state and volume contents retained.')
                return
            if args.volume_action=='mount':
                if not 0<=args.checkpoint_every<=1_000_000:raise ValueError('checkpoint interval must be 0..1000000')
                # Acquire before releasing registry-lock: forgetting/rebinding is
                # excluded by writer-lock from this point through child startup.
                fd=locks.enter_context(cli.lock(root))
                data=cli.manifest(root)
                if data['phase']!='ready' or data['mountpoint']:
                    raise ValueError('volume needs recovery; run volume recover '+args.name)
                check_mount(profile,cli)
        if args.volume_action=='mount':return background(profile,args,cli,fd)
        if args.volume_action=='unmount':return stop(profile,args,cli)
        if args.volume_action=='eject':return eject(profile,args,cli)
        if args.volume_action=='recover':
            cli.operate(argparse.Namespace(state=root,device=resolve(profile) if profile['mode']=='direct' else None,
                recover_journal=False,check_bytes=args.check_bytes,journal_bytes=args.journal_bytes),False)
            return
        raise ValueError('unknown volume operation')


def parser(sub):
    group=sub.add_parser('volume',help='remember volumes, mount in background, and safely unmount/eject')
    group.add_argument('--profiles-dir',type=Path,default=default_directory(),help='private registry; use the same owner as recovery state')
    actions=group.add_subparsers(dest='volume_action',required=True)
    add=actions.add_parser('add',help='remember an initialized clean state; creates an empty mountpoint if absent')
    add.add_argument('name');add.add_argument('--state',type=Path,required=True);add.add_argument('--mountpoint',type=Path,required=True)
    for name in ('mount','unmount','eject','recover','forget'):
        command=actions.add_parser(name)
        command.add_argument('name')
        if name in ('mount','unmount','eject'):command.add_argument('--timeout',type=float,default=3600)
        if name in ('mount','recover'):
            command.add_argument('--check-bytes',type=int,default=1024**3)
            command.add_argument('--journal-bytes',type=int,default=256*1024**2)
        if name=='mount':command.add_argument('--checkpoint-every',type=int,default=64)
    show=actions.add_parser('list',help='show saved volumes and workflow state without opening devices')
    show.add_argument('--json',action='store_true');show.add_argument('--connected',action='store_true',help='also discover matching devices without opening them')
