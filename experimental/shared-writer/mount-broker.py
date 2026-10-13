#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private owner-only FUSE adapter for the managed-image transaction session."""
import argparse
import errno
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import chain
import session
import native_acl
from credentials import Credentials
HEADER=struct.Struct('<8sIIIIIIIQQQ')
REPLY=struct.Struct('<8sIIQQ')
LIMIT=1024*1024
class Broker:
    def __init__(self,s):
        self.s=s;self.handles={};self.identities={};self.hidden={};self.initialized=False;self.owner=os.getuid()
        # Reject unsupported writer features before starting the mount helper.
        self.s._mount_geometry()
    def handle(self,token):
        h=self.handles.get(token)
        if h is None:raise OSError(errno.EBADF,'invalid mounted handle')
        return h
    def native_get(self,path):
        fields=struct.unpack('<8QqQqQqQqQ',self.s._mount_stat(path))
        raw=self.s.getxattr(path,'system.posix_acl_access')
        return native_acl.render(raw,fields[1],native_acl.Membership().resolve)

    def native_set(self,path,value,flags=0):
        fields=struct.unpack('<8QqQqQqQqQ',self.s._mount_stat(path))
        if self.s.credentials.uid not in (0,fields[3]):raise OSError(errno.EPERM,'native ACL editing requires ownership')
        try:old=self.s.getxattr(path,'system.posix_acl_access')
        except OSError as e:
            if e.errno!=errno.ENODATA:raise
            old=None
        if flags==1 and old is not None:raise OSError(errno.EEXIST,'native ACL exists')
        if flags==2 and old is None:raise OSError(errno.ENODATA,'native ACL missing')
        membership=native_acl.Membership()
        if old is not None:
            try:projected=native_acl.render(old,fields[1],membership.resolve)
            except OSError as e:
                if e.errno not in (errno.EOPNOTSUPP,errno.E2BIG):raise
            else:
                if value==projected:return
        converted=native_acl.decode(value,fields[1],fields[3],fields[4],membership.identify)
        if converted is None:
            if old is not None:self.s.removexattr(path,'system.posix_acl_access')
        else:self.s.setxattr(path,'system.posix_acl_access',converted)

    def attr_name(self, name):
        if not name or len(name)>255 or b'\0' in name:raise OSError(errno.EINVAL,'attribute name')
        if name in (b'system.posix_acl_access',b'system.posix_acl_default'):return name
        if name.startswith((b'system.',b'security.',b'trusted.')) or name==b'com.apple.system.Security':
            raise OSError(errno.EOPNOTSUPP,'unsupported privilege/native ACL attribute')
        return b'user.'+name if sys.platform=='darwin' else name

    def dispatch(self,op,path,data,uid,gid,umask,groups,token,offset,arg):
        if uid!=self.owner:raise OSError(errno.EACCES,'private mount owner only')
        if op!=22 and not self.initialized:raise OSError(errno.EBUSY,'mount handshake required')
        if not 0<=umask<=0o777:raise OSError(errno.EINVAL,'caller umask')
        if len(groups)>64:raise OSError(errno.EOVERFLOW,'caller group limit')
        self.s._mount_context(Credentials(uid,gid,tuple(groups),umask))
        if op==22:
            if self.initialized:raise OSError(errno.EPERM,'handshake already complete')
            self.initialized=True;return 0,b''
        if path and (not path.startswith(b'/') or b'\0' in path):raise OSError(errno.EINVAL,'absolute FUSE path required')
        if op==1:
            handle=self.handle(token) if token else None
            raw=self.s._mount_stat(path,handle)
            if sys.platform=='darwin':
                try:acl=self.s.getxattr(path,'system.posix_acl_access',handle=handle)
                except OSError as e:
                    if e.errno!=errno.ENODATA:raise
                else:
                    mode=struct.unpack_from('<Q',raw,8)[0]
                    native_acl.render(acl,mode,native_acl.Membership().resolve)
            return 0,raw
        if op in (2,3,8):
            flags=arg&0xffffffff;mode=arg>>32
            allowed=os.O_ACCMODE
            # Linux FUSE sends the kernel O_LARGEFILE bit even where 64-bit
            # userspace exposes os.O_LARGEFILE as zero. It is a status hint.
            if sys.platform=='linux':allowed|=0o100000
            for name in ('O_CREAT','O_EXCL','O_TRUNC','O_APPEND','O_NOFOLLOW','O_DIRECTORY','O_CLOEXEC','O_NONBLOCK','O_NOCTTY','O_SYNC','O_DSYNC','O_LARGEFILE'):
                allowed|=getattr(os,name,0)
            if flags&~allowed:raise OSError(errno.EOPNOTSUPP,'unsupported mounted open flags')
            access={os.O_RDONLY:'r',os.O_WRONLY:'w',os.O_RDWR:'rw'}.get(flags&os.O_ACCMODE)
            if access is None:raise OSError(errno.EINVAL,'open access')
            if mode&~0o777:raise OSError(errno.EOPNOTSUPP,'special create mode')
            if op==8:flags=os.O_RDONLY|os.O_DIRECTORY;access='r'
            h=self.s.openat(None,path,access,create=op==3,exclusive=bool(flags&os.O_EXCL) if op==3 else False,
                    mode=mode,append=bool(flags&os.O_APPEND),truncate=bool(flags&os.O_TRUNC),
                    nofollow=bool(flags&os.O_NOFOLLOW),directory_only=op==8 or bool(flags&os.O_DIRECTORY))
            self.handles[h._token]=h
            if not isinstance(h,session.DirectoryHandle):
                st=self.s.statat(None,path);self.identities[h._token]=(st['inode'],st['generation'])
            return h._token,b''
        if op==4:return 0,self.handle(token).read(offset,arg)
        if op==5:
            if offset+len(data)>64*1024*1024:raise OSError(errno.EFBIG,'experimental file size limit')
            return self.handle(token).write(data,offset),b''
        if op==6:
            if offset>64*1024*1024:raise OSError(errno.EFBIG,'experimental file size limit')
            if token:self.handle(token).truncate(offset)
            else:
                with self.s.openat(None,path,'w') as h:h.truncate(offset)
            return 0,b''
        if op in (7,10):
            h=self.handle(token);del self.handles[token];self.identities.pop(token,None);h.close();return 0,b''
        if op==9:
            h=self.handle(token)
            if not isinstance(h,session.DirectoryHandle):raise OSError(errno.ENOTDIR,'not a directory')
            return self.s._rpc(27,self.s._file(h)+struct.pack('<I',128),offset,65536)
        if op==11:
            if arg&~0o1777:raise OSError(errno.EOPNOTSUPP,'special directory mode')
            self.s.mkdirat(None,path,arg)
        elif op==12:self.s.unlinkat(None,path,remove_directory=True)
        elif op==13:
            self.s.unlinkat(None,path);self.hidden.pop(path,None)
        elif op==14:
            if arg:raise OSError(errno.EOPNOTSUPP,'rename extensions unavailable')
            candidate=None
            if re.fullmatch(rb'\.fuse_hidden[0-9a-fA-F]{16}',data.rsplit(b'/',1)[-1]):
                st=self.s.statat(None,path,follow_symlinks=False)
                identity=(st['inode'],st['generation'])
                if identity in self.identities.values():candidate=identity
            self.s.renameat(None,path,None,data)
            # Volatile, exact-identity tracking is only for libfuse lifecycle
            # cleanup in this live mount, never a prefix scan on recovery.
            moved={}
            for name,identity in self.hidden.items():
                if name==path or name.startswith(path.rstrip(b'/')+b'/'):name=data+name[len(path):]
                moved[name]=identity
            self.hidden=moved
            if candidate:self.hidden[data]=candidate
        elif op==15:self.s.linkat(None,path,None,data)
        elif op==16:self.s.symlinkat(data,None,path)
        elif op==17:return 0,self.s.readlinkat(None,path)
        elif op==23:
            identity=self.hidden.get(path)
            if identity is None:raise OSError(errno.EACCES,'untracked maintenance unlink')
            try:st=self.s.statat(None,path,follow_symlinks=False)
            except FileNotFoundError:self.hidden.pop(path,None);return 0,b''
            if (st['inode'],st['generation'])!=identity:raise OSError(errno.ESTALE,'maintenance inode changed')
            self.s.unlinkat(None,path);self.hidden.pop(path,None)
        elif op in (24,25,26):
            handle=self.handle(token) if token else None
            if op==24:self.s.chmod(path,arg,handle=handle,follow_symlinks=False)
            elif op==25:self.s.chown(path,arg&0xffffffff,arg>>32,handle=handle,follow_symlinks=False)
            else:
                if len(data)!=32:raise OSError(errno.EINVAL,'timestamp payload')
                a,an,m,mn=struct.unpack('<qQqQ',data)
                def timestamp(sec,ns):
                    return None if ns==2**64-1 else 'omit' if ns==2**64-2 else (sec,ns)
                self.s.utimens(path,timestamp(a,an),timestamp(m,mn),handle=handle,follow_symlinks=False)
        elif op in (27,28,29,30):
            try:
                if op==27:
                    if b'\0' not in data:raise OSError(errno.EINVAL,'attribute payload')
                    name,value=data.split(b'\0',1)
                    if sys.platform=='darwin' and name==b'com.apple.system.Security':self.native_set(path,value,arg)
                    else:self.s.setxattr(path,self.attr_name(name),value,arg)
                elif op==28:
                    self.s.removexattr(path,'system.posix_acl_access' if sys.platform=='darwin' and data==b'com.apple.system.Security' else self.attr_name(data))
                elif op==29:return 0,self.native_get(path) if sys.platform=='darwin' and data==b'com.apple.system.Security' else self.s.getxattr(path,self.attr_name(data))
                else:
                    names=self.s.listxattrs(path)
                    if sys.platform=='darwin':
                        if 'system.posix_acl_access' in names:names.append('com.apple.system.Security')
                        names=[name[5:] if name.startswith('user.') else name for name in names]
                    return 0,b''.join(os.fsencode(name)+b'\0' for name in names)
            except OSError as e:
                if e.errno==errno.ENODATA and sys.platform=='darwin':raise OSError(errno.ENOATTR,'attribute not found') from e
                raise
        elif op==18:return 0,self.s._mount_geometry()
        elif op in (19,20):
            # Each data/namespace transaction is already durably committed before
            # acknowledgement. Flush never closes a handle shared by dup/fork.
            if token:self.s._mount_stat(handle=self.handle(token))
            else:self.s._ready()
        elif op==21:self.s._mount_access(path,arg)
        else:raise OSError(errno.ENOSYS,'unsupported FUSE operation')
        return 0,b''

def serve(broker,frontend):
    while True:
        raw=frontend.stdout.read(HEADER.size)
        if not raw:break
        if len(raw)!=HEADER.size:raise OSError(errno.EIO,'truncated mount request')
        magic,op,pathlen,datalen,uid,gid,umask,ngroups,token,offset,arg=HEADER.unpack(raw)
        if magic!=b'E4FM0001' or pathlen>4096 or datalen>LIMIT or ngroups>64 or offset>2**63-1:
            raise OSError(errno.EIO,'invalid mount request frame')
        def read(n):
            value=frontend.stdout.read(n)
            if len(value)!=n:raise OSError(errno.EIO,'truncated mount payload')
            return value
        groups=struct.unpack('<'+'I'*ngroups,read(ngroups*4));path=read(pathlen);data=read(datalen)
        error,size,result=0,0,b''
        try:size,result=broker.dispatch(op,path,data,uid,gid,umask,groups,token,offset,arg)
        except OSError as e:error=e.errno or errno.EIO
        except (ValueError,KeyError,struct.error):error=errno.EINVAL
        if len(result)>LIMIT:raise OSError(errno.EIO,'oversized mount reply')
        frontend.stdin.write(REPLY.pack(b'E4FP0001',error,0,0 if error else size,0 if error else len(result)))
        if not error:frontend.stdin.write(result)
        frontend.stdin.flush()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--mountpoint',type=Path,required=True)
    args=parser.parse_args();mount=args.mountpoint.absolute()
    if not mount.is_dir() or mount.is_symlink() or os.path.ismount(mount) or any(mount.iterdir()):
        raise ValueError('mountpoint must be an empty unmounted directory')
    if os.stat(mount).st_uid!=os.getuid():raise ValueError('mountpoint must be owned by launching user')
    if mount==args.root.absolute() or args.root.absolute().is_relative_to(mount) or mount.is_relative_to(args.root.absolute()):raise ValueError('mountpoint must be outside managed chain')
    mount=mount.resolve();root=args.root.resolve()
    if mount==root or root.is_relative_to(mount) or mount.is_relative_to(root):raise ValueError('mountpoint must be outside managed chain')
    work=args.work.resolve()
    if work.is_relative_to(mount):raise ValueError('build directory must be outside mountpoint')
    mask=os.umask(0);os.umask(mask)
    frontend=None
    with session.Session(args.root,work/'mutation-producer',work/'reader-server',Credentials(os.getuid(),os.getgid(),(),mask)) as s:
        broker=Broker(s)
        frontend=subprocess.Popen([str(work/'mount-frontend'),str(mount)],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        try:
            serve(broker,frontend)
            result=frontend.wait(timeout=10)
            if result:raise OSError(errno.EIO,f'FUSE frontend exited {result}')
        finally:
            if frontend.poll() is None:
                frontend.terminate()
                try:frontend.wait(timeout=10)
                except subprocess.TimeoutExpired:frontend.kill();frontend.wait(timeout=5)
            frontend.stdin.close();frontend.stdout.close()
    print('Experimental mount stopped; managed image and recovery logs retained.',file=sys.stderr)
if __name__=='__main__':main()
