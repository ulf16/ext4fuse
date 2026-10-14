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
    def optional_attr(self,path,name,handle=None):
        try:return self.s.getxattr(path,name,handle=handle)
        except OSError as e:
            if e.errno!=errno.ENODATA:raise
            return None

    def native_get(self,path,handle=None):
        if self.optional_attr(path,native_acl.LEGACY_KEY,handle) is not None:raise OSError(errno.EOPNOTSUPP,'legacy user-namespace inheritance requires owner removal')
        fields=struct.unpack('<8QqQqQqQqQ',self.s._mount_stat(path,handle))
        return native_acl.project(self.optional_attr(path,'system.posix_acl_access',handle),
                                  self.optional_attr(path,native_acl.INHERIT_KEY,handle),
                                  fields[1],native_acl.Membership().resolve)

    def native_set(self,path,value,flags=0,handle=None):
        if self.optional_attr(path,native_acl.LEGACY_KEY,handle) is not None:raise OSError(errno.EOPNOTSUPP,'legacy user-namespace inheritance requires owner removal')
        fields=struct.unpack('<8QqQqQqQqQ',self.s._mount_stat(path,handle))
        if self.s.credentials.uid not in (0,fields[3]):raise OSError(errno.EPERM,'native ACL editing requires ownership')
        old=self.optional_attr(path,'system.posix_acl_access',handle)
        previous=self.optional_attr(path,native_acl.INHERIT_KEY,handle)
        exists=old is not None or previous is not None
        if flags==1 and exists:raise OSError(errno.EEXIST,'native ACL exists')
        if flags==2 and not exists:raise OSError(errno.ENODATA,'native ACL missing')
        membership=native_acl.Membership()
        if exists:
            try:projected=native_acl.project(old,previous,fields[1],membership.resolve)
            except OSError as e:
                if e.errno not in (errno.EOPNOTSUPP,errno.E2BIG):raise
            else:
                if value==projected:return
        converted,policy=native_acl.split(value,fields[1],fields[3],fields[4],membership.identify)
        if policy is not None and self.optional_attr(path,'system.posix_acl_default',handle) is not None:
            raise OSError(errno.EOPNOTSUPP,'cannot combine native and POSIX default inheritance')
        operations=[]
        for name,before,after in [('system.posix_acl_access',old,converted),(native_acl.INHERIT_KEY,previous,policy)]:
            if before==after:continue
            operation=dict(kind='setxattr' if after is not None else 'removexattr',path=path,name=name,follow_symlinks=False)
            if after is not None:operation['value_hex']=after.hex()
            operations.append(operation)
        if operations:
            if handle is None:self.s.applyat(operations)
            else:self.s._mount_metadata_batch(operations,[handle]*len(operations))

    def validated_stat(self,path,handle=None):
        raw=self.s._mount_stat(path,handle)
        if sys.platform=='darwin':
            acl=None
            try:acl=self.s.getxattr(path,'system.posix_acl_access',handle=handle)
            except OSError as e:
                if e.errno!=errno.ENODATA:raise
            else:
                mode=struct.unpack_from('<Q',raw,8)[0]
                native_acl.render(acl,mode,native_acl.Membership().resolve)
            if self.optional_attr(path,native_acl.LEGACY_KEY,handle) is not None:raise OSError(errno.EOPNOTSUPP,'legacy user-namespace inheritance requires owner removal')
            policy=self.optional_attr(path,native_acl.INHERIT_KEY,handle)
            if policy is not None:
                mode=struct.unpack_from("<Q",raw,8)[0]
                native_acl.project(acl,policy,mode,native_acl.Membership().resolve)
        return raw

    def attr_name(self, name):
        if not name or len(name)>255 or b'\0' in name:raise OSError(errno.EINVAL,'attribute name')
        if name in (native_acl.INHERIT_KEY.encode(),native_acl.INHERIT_KEY.split('.',1)[1].encode(),native_acl.LEGACY_KEY.encode()):raise OSError(errno.EOPNOTSUPP,'reserved native inheritance attribute')
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
        if op==1:return 0,self.validated_stat(path,self.handle(token) if token else None)
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
            if offset+len(data)>(2**63-1):raise OSError(errno.EFBIG,'signed file offset overflow')
            return self.handle(token).write(data,offset),b''
        if op==6:
            if offset>(2**63-1):raise OSError(errno.EFBIG,'signed file offset overflow')
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
                    if sys.platform=='darwin' and data==b'com.apple.system.Security':
                        if self.optional_attr(path,'system.posix_acl_access') is None and self.optional_attr(path,native_acl.INHERIT_KEY) is None:raise OSError(errno.ENODATA,'native ACL missing')
                        self.native_set(path,native_acl.pack_native([]))
                    else:self.s.removexattr(path,self.attr_name(data))
                elif op==29:return 0,self.native_get(path) if sys.platform=='darwin' and data==b'com.apple.system.Security' else self.s.getxattr(path,self.attr_name(data))
                else:
                    names=self.s.listxattrs(path)
                    if sys.platform=='darwin':
                        if 'system.posix_acl_access' in names or native_acl.INHERIT_KEY in names:names.append('com.apple.system.Security')
                    names=[name for name in names if name not in (native_acl.INHERIT_KEY,native_acl.LEGACY_KEY)]
                    if sys.platform=='darwin':names=[name[5:] if name.startswith('user.') else name for name in names]
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

class LowBroker(Broker):
    """Kernel node IDs own lookup pins, independently of open handle grants.

    IDs never repeat in a mount. Native tokens bind ext4 inode+generation and
    deduplicate hard links. Kernel nlookup is consumed exactly, including batches;
    a zero-lookup node remains pinned while any open handle still refers to it.
    """
    NODE_LIMIT=4096
    def __init__(self,s):
        super().__init__(s)
        self.nodes={};self.native_nodes={};self.bindings={};self.last_node=1

    def node(self,number):
        if number not in self.nodes:raise OSError(errno.ESTALE,'forgotten kernel node')
        return self.nodes[number]

    def component(self,name,*,lookup=False):
        if not name or len(name)>255 or b'/' in name or b'\0' in name or (not lookup and name in (b'.',b'..')):
            raise OSError(errno.EINVAL,'invalid directory component')
        return name

    def capacity(self):
        if len(self.nodes)>=self.NODE_LIMIT:raise OSError(errno.EMFILE,'kernel node limit')
        if self.last_node>=2**63-1:raise OSError(errno.EOVERFLOW,'kernel node identity exhausted')
        self.s._mount_node_capacity()

    def remember(self,parent,name,*,root=False):
        handle,ino,generation=self.s._mount_lookup(parent,name,implicit_root=root)
        number=self.native_nodes.get(handle._token)
        if number is None:
            if root:number=1
            else:
                self.last_node+=1;number=self.last_node
            self.nodes[number]=dict(handle=handle,inode=ino,generation=generation,lookups=0,opens=0)
            self.native_nodes[handle._token]=number
        node=self.node(number)
        if not root:
            if node['lookups']==2**64-1:raise OSError(errno.EOVERFLOW,'kernel lookup counter overflow')
            node['lookups']+=1
        return number

    def stat(self,number,handle=None):
        node=self.node(number)
        raw=self.validated_stat(None,handle or node['handle'])
        if struct.unpack_from('<Q',raw)[0]!=node['inode']:raise OSError(errno.ESTALE,'kernel node changed identity')
        return raw

    def entry(self,number,fh=None):
        node=self.node(number)
        raw=struct.pack('<Q',node['generation'])+self.stat(number)
        return number,(struct.pack('<Q',fh)+raw if fh is not None else raw)

    def finish_entry(self,number,opened=None):
        fh=self.opened(number,opened) if opened is not None else None
        try:return self.entry(number,fh)
        except BaseException:
            try:
                if fh is not None:
                    del self.handles[fh];del self.bindings[fh]
                    self.node(number)['opens']-=1
                    opened.close()
            finally:self.forget(number,1)
            raise

    def drop(self,number):
        if number==1:return
        node=self.node(number)
        if not node['lookups'] and not node['opens']:
            del self.nodes[number];del self.native_nodes[node['handle']._token]
            node['handle'].close()

    def forget(self,number,count):
        if number==1:return
        node=self.node(number)
        if not count or count>node['lookups']:raise OSError(errno.EINVAL,'kernel forget underflow')
        node['lookups']-=count;self.drop(number)

    def opened(self,number,h):
        self.handles[h._token]=h;self.bindings[h._token]=number
        self.node(number)['opens']+=1
        return h._token

    def flags(self,flags,*,create=False,directory=False):
        allowed=os.O_ACCMODE|(0o100000 if sys.platform=='linux' else 0)
        for name in ('O_CREAT','O_EXCL','O_TRUNC','O_APPEND','O_NOFOLLOW','O_DIRECTORY','O_CLOEXEC','O_NONBLOCK','O_NOCTTY','O_SYNC','O_DSYNC','O_LARGEFILE'):
            allowed|=getattr(os,name,0)
        if flags&~allowed:raise OSError(errno.EOPNOTSUPP,'unsupported mounted open flags')
        rights={os.O_RDONLY:1,os.O_WRONLY:2,os.O_RDWR:3}.get(flags&os.O_ACCMODE)
        if rights is None or (directory and rights!=1):raise OSError(errno.EINVAL,'invalid open access')
        if not create and flags&(os.O_CREAT|os.O_EXCL):raise OSError(errno.EINVAL,'creation requires parent entry')
        return rights

    def bound(self,fh,number):
        h=self.handle(fh)
        if self.bindings.get(fh)!=number:raise OSError(errno.ESTALE,'handle belongs to another kernel node')
        return h

    def dispatch(self,op,path,data,uid,gid,umask,groups,token,offset,arg):
        if op<100:raise OSError(errno.ENOSYS,'low-level broker protocol required')
        if uid!=self.owner:raise OSError(errno.EACCES,'private mount owner only')
        if not 0<=umask<=0o777 or len(groups)>64:raise OSError(errno.EINVAL,'invalid mount credentials')
        self.s._mount_context(Credentials(uid,gid,tuple(groups),umask))
        if op==100:
            super().dispatch(22,b'',b'',uid,gid,umask,groups,0,0,0)
            self.s._mount_nodes();self.remember(None,b'.',root=True)
            return 0,b''
        if not self.initialized:raise OSError(errno.EBUSY,'mount handshake required')
        named={101,105,113,114,115,116,117,118}
        payload={106,107,108,116,118,124,125,126}
        if (bool(path)!=(op in named) or (data and op not in payload) or
            (op==106 and len(data)!=8) or (op==108 and len(data)!=64) or
            (op not in (103,106,107,108,109,111,112,116,121,122) and offset)):
            raise OSError(errno.EINVAL,'invalid low-level operation shape')
        if op==102:
            if path or data or offset:raise OSError(errno.EINVAL,'invalid forget request')
            self.forget(token,arg);return 0,b''
        node=self.node(token)
        h=node['handle']
        if op==101:
            self.component(path,lookup=True)
            # Existing identities can still be looked up when the pool is full.
            if len(self.nodes)>=self.NODE_LIMIT:
                st=self.s.statat(h,path,follow_symlinks=False)
                if not any((n['inode'],n['generation'])==(st['inode'],st['generation']) for n in self.nodes.values()):self.capacity()
            number=self.remember(h,path)
            return self.finish_entry(number)
        if op==103:return 0,self.stat(token,self.bound(offset,token) if offset else None)
        if op in (104,110):
            flags=arg&0xffffffff
            rights=self.flags(flags,directory=op==110)
            opened=self.s._mount_open_node(h,rights,bool(flags&os.O_APPEND),op==110 or bool(flags&os.O_DIRECTORY))
            try:
                if flags&os.O_TRUNC:opened.truncate(0)
            except BaseException:opened.close();raise
            return self.opened(token,opened),b''
        if op==105:
            self.capacity();self.component(path)
            flags=arg&0xffffffff;mode=arg>>32;rights=self.flags(flags,create=True)
            if mode&~0o777:raise OSError(errno.EOPNOTSUPP,'special create mode')
            opened=self.s.openat(h,path,{1:'r',2:'w',3:'rw'}[rights],create=True,
                    exclusive=bool(flags&os.O_EXCL),mode=mode,append=bool(flags&os.O_APPEND),
                    truncate=bool(flags&os.O_TRUNC),nofollow=True)
            try:number=self.remember(h,path)
            except BaseException:opened.close();raise
            return self.finish_entry(number,opened)
        if op in (106,107,111,121,122):
            fh=offset
            opened=self.bound(fh,token)
            original={106:4,107:5,111:9,121:19,122:20}[op]
            return super().dispatch(original,b'',b'' if op==106 else data,uid,gid,umask,groups,fh,arg,struct.unpack('<Q',data)[0] if op==106 and len(data)==8 else 0)
        if op in (109,112):
            opened=self.bound(offset,token)
            del self.handles[offset];del self.bindings[offset]
            node['opens']-=1;opened.close();self.drop(token);return 0,b''
        if op in (113,118):
            self.capacity();self.component(path)
            if op==113:self.s.mkdirat(h,path,arg)
            else:self.s.symlinkat(data,h,path)
            return self.finish_entry(self.remember(h,path))
        if op in (114,115):
            self.component(path);self.s.unlinkat(h,path,remove_directory=op==114);return 0,b''
        if op==116:
            if offset:raise OSError(errno.EOPNOTSUPP,'rename extensions unavailable')
            self.component(path);self.component(data)
            self.s.renameat(h,path,self.node(arg)['handle'],data);return 0,b''
        if op==117:
            self.component(path)
            if node['lookups']==2**64-1:raise OSError(errno.EOVERFLOW,'kernel lookup counter overflow')
            if isinstance(h,session.DirectoryHandle):raise OSError(errno.EPERM,'directory hard link')
            parent=self.node(arg)['handle']
            base=self.s._rpc(36,self.s._file(h))[1]
            target=self.s._at_context(parent,path)
            _,pins=self.s._rpc(12)
            request=session.write_api.encode_at([dict(kind='link',path=b'node',target=path)],self.s.credentials,pins,[(base,target)])
            self.s._apply_request(request)
            return self.finish_entry(self.remember(parent,path))
        if op==119:return 0,self.s._rpc(40,self.s._file(h))[1]
        if op==120:return 0,self.s._mount_geometry()
        if op==123:self.s._rpc(41,self.s._file(h),arg);return 0,b''
        if op==108:
            if len(data)!=64:raise OSError(errno.EINVAL,'invalid inode setattr')
            flags,mode,u,g,size,at,an,mt,mn=struct.unpack('<IIQQQqQqQ',data)
            if flags&~0x1bf:raise OSError(errno.EOPNOTSUPP,'unsupported setattr fields')
            operations=[];grants=[];temporary=None
            try:
                if flags&8:
                    if size>2**63-1:raise OSError(errno.EFBIG,'signed truncate size')
                    temporary=None if offset else self.s._mount_open_node(h,2)
                    opened=self.bound(offset,token) if offset else temporary
                    operations.append(dict(kind='truncate',size=size));grants.append(opened)
                if flags&6:
                    operations.append(dict(kind='chown',uid=u if flags&2 else -1,gid=g if flags&4 else -1));grants.append(h)
                if flags&1:operations.append(dict(kind='chmod',mode=mode&0o7777));grants.append(h)
                if flags&(16|32|128|256):
                    a=None if flags&128 else (at,an) if flags&16 else 'omit'
                    m=None if flags&256 else (mt,mn) if flags&32 else 'omit'
                    operations.append(dict(kind='utimens',atime=a,mtime=m));grants.append(h)
                if operations:self.s._mount_metadata_batch(operations,grants)
            finally:
                if temporary:temporary.close()
            return 0,self.stat(token)
        if op in (124,125,126,127):
            try:
                if op==124:
                    if b'\0' not in data:raise OSError(errno.EINVAL,'attribute payload')
                    name,value=data.split(b'\0',1)
                    if sys.platform=='darwin' and name==b'com.apple.system.Security':self.native_set(None,value,arg,h)
                    else:self.s.setxattr(None,self.attr_name(name),value,arg,handle=h)
                    return 0,b''
                if op==125:
                    if sys.platform=='darwin' and data==b'com.apple.system.Security':
                        if self.optional_attr(None,'system.posix_acl_access',h) is None and self.optional_attr(None,native_acl.INHERIT_KEY,h) is None:raise OSError(errno.ENODATA,'native ACL missing')
                        self.native_set(None,native_acl.pack_native([]),handle=h)
                    else:self.s.removexattr(None,self.attr_name(data),handle=h)
                    return 0,b''
                if op==126:return 0,self.native_get(None,h) if sys.platform=='darwin' and data==b'com.apple.system.Security' else self.s.getxattr(None,self.attr_name(data),handle=h)
                names=self.s.listxattrs(None,handle=h)
                if sys.platform=='darwin' and ('system.posix_acl_access' in names or native_acl.INHERIT_KEY in names):names.append('com.apple.system.Security')
                names=[n for n in names if n not in (native_acl.INHERIT_KEY,native_acl.LEGACY_KEY)]
                if sys.platform=='darwin':names=[n[5:] if n.startswith('user.') else n for n in names]
                return 0,b''.join(os.fsencode(n)+b'\0' for n in names)
            except OSError as e:
                if e.errno==errno.ENODATA and sys.platform=='darwin':raise OSError(errno.ENOATTR,'attribute not found') from e
                raise
        raise OSError(errno.ENOSYS,'unsupported low-level operation')

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

def validate_mount(root,work,mount):
    mount=mount.absolute()
    if not mount.is_dir() or mount.is_symlink() or os.path.ismount(mount) or any(mount.iterdir()):
        raise ValueError('mountpoint must be an empty unmounted directory')
    if os.stat(mount).st_uid!=os.getuid():raise ValueError('mountpoint must be owned by launching user')
    if mount==root.absolute() or root.absolute().is_relative_to(mount) or mount.is_relative_to(root.absolute()):raise ValueError('mountpoint must be outside managed chain')
    mount=mount.resolve();root=root.resolve()
    if mount==root or root.is_relative_to(mount) or mount.is_relative_to(root):raise ValueError('mountpoint must be outside managed chain')
    work=work.resolve()
    if work.is_relative_to(mount):raise ValueError('build directory must be outside mountpoint')
    return root,work,mount


def run_mount(s,work,mount):
    broker=LowBroker(s)
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

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--mountpoint',type=Path,required=True)
    parser.add_argument('--checkpoint-every',type=int,default=64,help='retire completed generations after this many commits; zero disables')
    args=parser.parse_args()
    root,work,mount=validate_mount(args.root,args.work,args.mountpoint)
    mask=os.umask(0);os.umask(mask)
    with session.Session(root,work/'mutation-producer',work/'reader-server',Credentials(os.getuid(),os.getgid(),(),mask),checkpoint_every=args.checkpoint_every) as s:
        run_mount(s,work,mount)
    print('Experimental mount stopped; managed image and recovery logs retained.',file=sys.stderr)
if __name__=='__main__':main()
