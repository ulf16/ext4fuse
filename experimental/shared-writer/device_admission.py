# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed offline device admission. No device is selected implicitly."""
import array,contextlib,ctypes,errno,fcntl,json,os,re,plistlib,stat,subprocess,sys,threading
from pathlib import Path
PAGE=4096

def command(args):return subprocess.check_output(list(map(str,args)),stderr=subprocess.PIPE,timeout=30)
def plist(args):return plistlib.loads(command(args))
def refuse(message):raise OSError(errno.EPERM,message)
def owned_file(path):
    p=Path(path);st=os.lstat(p)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1:refuse('disk image backing file must be owned and regular')
    return dict(path=str(p.resolve()),device=st.st_dev,inode=st.st_ino)

def mac_identity(info):
    whole=info['ParentWholeDisk'] if not info.get('WholeDisk',info.get('Whole',False)) else info['DeviceIdentifier']
    for image in plist(['/usr/bin/hdiutil','info','-plist']).get('images',[]):
        if any(e.get('dev-entry') in ('/dev/'+whole,info.get('DeviceNode','/dev/'+info['DeviceIdentifier'])) for e in image.get('system-entities',[])):
            return dict(kind='disk-image',backing=owned_file(image['image-path']),partition='whole' if info.get('WholeDisk',info.get('Whole',False)) else info.get('DiskUUID',info['DeviceIdentifier']))
    if info.get('WholeDisk',info.get('Whole',False)) or not info.get('DiskUUID'):refuse('physical writing requires a GPT partition with a stable UUID')
    tree=plist(['/usr/sbin/ioreg','-a','-l','-p','IOService'])
    def find(nodes,ancestors):
        for node in nodes:
            lineage=ancestors+[node]
            if node.get('BSD Name')==whole:return lineage
            found=find(node.get('IORegistryEntryChildren',[]),lineage)
            if found:return found
    lineage=find(tree,[])
    if not lineage:refuse('cannot establish physical hardware identity')
    for node in reversed(lineage):
        properties=[node,node.get('Device Characteristics',{}),node.get('Protocol Characteristics',{})]
        for props in properties:
            for key in ('Serial Number','USB Serial Number','SerialNumber','WWN','EUI-64'):
                value=props.get(key)
                if isinstance(value,(str,bytes,int)) and len(str(value).strip())>=4:
                    return dict(kind='physical',serial=str(value).strip(),partition=info['DiskUUID'])
    refuse('device has no trustworthy hardware serial identity')

class MacClaim:
    """Disk Arbitration ownership held by a live run-loop thread."""
    def __init__(self,names):self.names=names;self.ready=threading.Event();self.stop=threading.Event();self.error=None
    def __enter__(self):
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
        if not self.ready.wait(30):self.__exit__(None,None,None);raise TimeoutError('Disk Arbitration claim timeout')
        if self.error:self.__exit__(None,None,None);raise self.error
        return self
    def run(self):
        try:self._run()
        except BaseException as e:self.error=e;self.ready.set()
    def _run(self):
        cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        da=ctypes.CDLL('/System/Library/Frameworks/DiskArbitration.framework/DiskArbitration')
        ptr=ctypes.c_void_p;session=None;disks=[]
        def bind(lib,name,result,args):
            f=getattr(lib,name);f.restype=result;f.argtypes=args;return f
        release=bind(cf,'CFRelease',None,[ptr]);loop=bind(cf,'CFRunLoopGetCurrent',ptr,[])()
        mode=ptr.in_dll(cf,'kCFRunLoopDefaultMode');pump=bind(cf,'CFRunLoopRunInMode',ctypes.c_int,[ptr,ctypes.c_double,ctypes.c_bool])
        session=bind(da,'DASessionCreate',ptr,[ptr])(None)
        schedule=bind(da,'DASessionScheduleWithRunLoop',None,[ptr,ptr,ptr]);unschedule=bind(da,'DASessionUnscheduleFromRunLoop',None,[ptr,ptr,ptr])
        create=bind(da,'DADiskCreateFromBSDName',ptr,[ptr,ptr,ctypes.c_char_p])
        unclaim=bind(da,'DADiskUnclaim',None,[ptr]);dissent=bind(da,'DADissenterCreate',ptr,[ptr,ctypes.c_int32,ptr])
        status=bind(da,'DADissenterGetStatus',ctypes.c_int32,[ptr])
        R=ctypes.CFUNCTYPE(ptr,ptr,ptr);C=ctypes.CFUNCTYPE(None,ptr,ptr,ptr)
        reject=R(lambda disk,ctx:dissent(None,ctypes.c_int32(0xf8da0002).value,None))
        completed=threading.Event();errors=[]
        @C
        def callback(disk,error,ctx):
            if error:errors.append(status(error))
            completed.set()
        claim=bind(da,'DADiskClaim',None,[ptr,ctypes.c_uint32,R,ptr,C,ptr])
        E=ctypes.CFUNCTYPE(None,ptr,ptr)
        bsd=bind(da,'DADiskGetBSDName',ctypes.c_char_p,[ptr])
        @E
        def disappeared(disk,ctx):
            if bsd(disk) in [name.encode() for name in self.names]:self.error=OSError(errno.ENODEV,'claimed device disappeared')
        register=bind(da,'DARegisterDiskDisappearedCallback',None,[ptr,ptr,E,ptr])
        try:
            if not session:refuse('Disk Arbitration unavailable')
            schedule(session,loop,mode);register(session,None,disappeared,None)
            for name in self.names:
                disk=create(None,session,('/dev/'+name).encode())
                if not disk:refuse('Disk Arbitration cannot identify target')
                disks.append(disk);completed.clear();claim(disk,0,reject,None,callback,None)
                while not completed.is_set() and not self.stop.is_set():pump(mode,.1,True)
                if errors or self.stop.is_set():raise OSError(errno.EBUSY,'disk claim denied')
            self.ready.set()
            while not self.stop.is_set():pump(mode,.1,True)
        except BaseException as e:self.error=e;self.ready.set()
        finally:
            for disk in reversed(disks):unclaim(disk);release(disk)
            if session:unschedule(session,loop,mode);release(session)
    def __exit__(self,*unused):
        self.stop.set();self.thread.join(timeout=5)
        if self.thread.is_alive():raise RuntimeError('Disk Arbitration claim thread did not terminate')

class Device:
    def __init__(self,path,journal):
        self.path=Path(path);self.journal=Path(journal);self.fd=None;self.claim=None;self.whole_fd=None
    def inspect(self):
        if sys.platform=='darwin':
            if not re.fullmatch(r'/dev/r?disk[0-9]+(?:s[0-9]+)?',str(self.path)):refuse('canonical BSD disk node required')
            name=self.path.name.removeprefix('r');info=plist(['/usr/sbin/diskutil','info','-plist','/dev/'+name])
            whole=info['ParentWholeDisk'] if not info.get('WholeDisk',info.get('Whole',False)) else info['DeviceIdentifier']
            listing=plist(['/usr/sbin/diskutil','list','-plist','/dev/'+whole])
            def nodes(value):
                if isinstance(value,dict):
                    if 'DeviceIdentifier' in value:yield value
                    for v in value.values():yield from nodes(v)
                elif isinstance(value,list):
                    for v in value:yield from nodes(v)
            for node in nodes(listing):
                detail=plist(['/usr/sbin/diskutil','info','-plist','/dev/'+node['DeviceIdentifier']])
                if detail.get('Mounted') or node.get('MountPoint') or node.get('Content') in ('Apple_APFS','Apple_HFS'):refuse('whole drive must be offline and contain no macOS system/container volumes')
            if info.get('Mounted') or not info.get('WritableMedia',info.get('Writable',False)):refuse('target is mounted or read-only')
            journal_node=command(['/bin/df','-P',self.journal]).decode().splitlines()[-1].split()[0]
            if not journal_node.startswith('/dev/'):refuse('local off-device journal filesystem required')
            paths=['/dev/'+whole,'/dev/r'+whole,'/dev/'+name,'/dev/r'+name]
            busy=subprocess.run(['/usr/sbin/lsof','-F','p', '--',*dict.fromkeys(paths)],capture_output=True,timeout=30)
            if busy.returncode not in (0,1):refuse('cannot audit existing device users')
            if any(line.startswith(b'p') and int(line[1:])!=os.getpid() for line in busy.stdout.splitlines()):refuse('another process has the device open')
            location=plist(['/usr/sbin/diskutil','info','-plist',journal_node])
            if location.get('ParentWholeDisk',location.get('DeviceIdentifier'))==whole:refuse('recovery journal must be on another drive')
            return mac_identity(info),int(info['TotalSize']),int(info['DeviceBlockSize']),[whole]+([] if name==whole else [name])
        if sys.platform!='linux':refuse('unsupported device platform')
        if not re.fullmatch(r'/dev/[A-Za-z0-9_.-]+',str(self.path)):refuse('canonical device node required')
        st=os.lstat(self.path)
        if not stat.S_ISBLK(st.st_mode):refuse('target must be a block device')
        sysnode=(Path('/sys/dev/block')/f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}').resolve()
        if not sysnode.exists() or list((sysnode/'holders').iterdir()):refuse('unknown or layered/held device')
        partition=(sysnode/'partition').exists();whole=sysnode.parent if partition else sysnode
        related={whole.joinpath('dev').read_text().strip(),sysnode.joinpath('dev').read_text().strip()}
        related.update(p.read_text().strip() for p in whole.glob('*/dev') if (p.parent/'partition').exists())
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            if line.split()[2] in related:refuse('whole drive must be unmounted')
        jd=os.stat(self.journal).st_dev
        if f'{os.major(jd)}:{os.minor(jd)}' in related:refuse('journal must be off-device')
        if whole.name.startswith('loop'):
            backing=whole.joinpath('loop/backing_file').read_text().strip()
            identity=dict(kind='loop',backing=owned_file('/'+backing.lstrip('/')),partition=sysnode.name if partition else 'whole')
        else:
            if not partition:refuse('physical writing requires a partition')
            ids=[p.read_text().strip() for p in (whole/'device/wwid',whole/'device/serial') if p.exists()]
            props=json.loads(command(['lsblk','--json','-b','-o','PATH,PARTUUID',str(self.path)]))['blockdevices'][0]
            if not ids or not props.get('partuuid'):refuse('stable hardware and partition identity required')
            identity=dict(kind='physical',serial=ids,partition=props['partuuid'])
        if self.fd is None and partition:
            probe=os.open('/dev/'+whole.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_EXCL)
            os.close(probe)
        owned=self.fd is None
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_EXCL) if owned else self.fd
        try:
            cap=array.array('Q',[0]);sector=array.array('I',[0]);fcntl.ioctl(fd,0x80081272,cap,True);fcntl.ioctl(fd,0x1268,sector,True)
            return identity,cap[0],sector[0],[]
        finally:
            if owned:os.close(fd)
    def __enter__(self):
        try:
            self.identity,self.size,self.sector,names=self.inspect()
            if self.size<=0 or self.size%PAGE or self.sector not in (512,1024,2048,4096):refuse('unsupported aligned device geometry')
            if sys.platform=='darwin':self.claim=MacClaim(names);self.claim.__enter__()
            path=self.path
            if sys.platform=='darwin':path=Path('/dev/r'+self.path.name.removeprefix('r'))
            before=os.lstat(path)
            if not (stat.S_ISCHR(before.st_mode) if sys.platform=='darwin' else stat.S_ISBLK(before.st_mode)):refuse('device node changed type')
            exclusive=sys.platform=='linux'
            if exclusive:
                sysnode=(Path('/sys/dev/block')/f'{os.major(before.st_rdev)}:{os.minor(before.st_rdev)}').resolve()
                if (sysnode/'partition').exists():
                    # Keep the whole-drive kernel claim for the entire session:
                    # a sibling partition must not become mounted mid-publication.
                    self.whole_fd=os.open('/dev/'+sysnode.parent.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_EXCL)
                    exclusive=False
            self.fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|(os.O_EXCL if exclusive else 0))
            after=os.fstat(self.fd)
            if (before.st_dev,before.st_ino,before.st_rdev)!=(after.st_dev,after.st_ino,after.st_rdev):refuse('device node changed during open')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if sys.platform=='darwin':
                cap=array.array('Q',[0]);sector=array.array('I',[0]);fcntl.ioctl(self.fd,0x40086419,cap,True);fcntl.ioctl(self.fd,0x40046418,sector,True)
                if cap[0]*sector[0]!=self.size or sector[0]!=self.sector:refuse('kernel device geometry differs')
            # Recheck OS state after exclusive acquisition. Linux inspection
            # must not reopen O_EXCL while this descriptor owns the claim.
            if self.inspect()[:3]!=(self.identity,self.size,self.sector):refuse('device identity changed')
            self.node=(after.st_dev,after.st_ino,after.st_rdev)
            return self
        except BaseException:self.__exit__(None,None,None);raise
    def check(self):
        if self.claim is not None and (self.claim.error is not None or not self.claim.thread.is_alive()):refuse('device claim lost')
        info=os.fstat(self.fd)
        if (info.st_dev,info.st_ino,info.st_rdev)!=self.node:refuse('device descriptor changed')
        cap=array.array('Q',[0]);sector=array.array('I',[0])
        if sys.platform=='darwin':
            fcntl.ioctl(self.fd,0x40086419,cap,True);fcntl.ioctl(self.fd,0x40046418,sector,True)
            size=cap[0]*sector[0]
        else:
            fcntl.ioctl(self.fd,0x80081272,cap,True);fcntl.ioctl(self.fd,0x1268,sector,True);size=cap[0]
        if (size,sector[0])!=(self.size,self.sector):refuse('device geometry changed during publication')
        # Read failure/removal fails the operation, never selects a replacement.
        if len(os.pread(self.fd,self.sector,self.size-self.sector))!=self.sector:refuse('device no longer readable')
    def flush(self):
        if sys.platform=='darwin':fcntl.ioctl(self.fd,0x80186416,bytes(24))
        else:os.fsync(self.fd)
    def __exit__(self,*unused):
        if self.fd is not None:os.close(self.fd);self.fd=None
        if self.whole_fd is not None:os.close(self.whole_fd);self.whole_fd=None
        if self.claim is not None:self.claim.__exit__(*unused);self.claim=None
