#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Serialized offline image session with one resident native reader."""
import image_io
import errno
import importlib.util
import os
from pathlib import Path
import select
import struct
import subprocess
import threading
import time
from durable import regular
import chain
import merkle
from credentials import Credentials

spec = importlib.util.spec_from_file_location('write_api', Path(__file__).with_name('write-api.py'))
write_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(write_api)
REQUEST = struct.Struct('<8sIIQQ')
REPLY = struct.Struct('<8sIIQQ')
LIMIT = 1024 * 1024


class Session:
    """Trusted numeric permission policy and session-local inode handles.

    Hold the global chain lock for the entire session. Readers and mutations are
    serialized inside this object; other cooperating processes are excluded.
    Any unresolvable recovery/reader error leaves the session failed closed.
    """
    def __init__(self, root, producer, reader, credentials=None, *, checkpoint_every=0, commit_sink=None, recover_journal=False):
        if credentials is not None and not isinstance(credentials, Credentials):
            raise ValueError('expected trusted Credentials')
        if type(checkpoint_every) is not int or not 0 <= checkpoint_every <= 1_000_000:
            raise ValueError('invalid checkpoint interval')
        if type(recover_journal) is not bool:
            raise ValueError('journal recovery option must be boolean')
        self._commit_sink = commit_sink
        self._checkpoint_every = checkpoint_every
        self._credentials = credentials
        self._mutex = threading.RLock()
        self._closed = False
        self._failed = False
        self._process = None
        self._verified = None
        self._verified_context = None
        self._files = set()
        self._lookup_files = {}
        self._file_key = object()
        self._cwd = None
        self._lock = chain.locked(root)
        self.root = self._lock.__enter__()
        self.producer = Path(producer).absolute()
        try:
            initial = getattr(self._commit_sink, 'initial_integrity', None)
            cache = initial(chain.read_state(self.root)) if initial is not None else None
            self.state, self._integrity = chain.recover_integrity_locked(self.root, cache)
            if recover_journal:
                from journal_recovery import managed_locked
                self.state=managed_locked(self.root,self.state)
                self.state, self._integrity = merkle.activate(self.root, self.state)
            if self._commit_sink is not None:
                self._recover_sink()
            from verified_reads import Reader
            self._verified = Reader(self.root / 'image.img', lambda: (self.state, self._integrity))
            verified_context = image_io.verified(self.root / 'image.img', self._verified)
            verified_context.__enter__()
            self._verified_context = verified_context
            self._checkpoint_head = self.state['head']
            with image_io.child_process(self.root / 'image.img') as options:
                self._process = subprocess.Popen([str(Path(reader).absolute()), str(self.root / 'image.img')],
                                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                 stderr=subprocess.DEVNULL, bufsize=0, **options)
            os.set_blocking(self._process.stdin.fileno(), False)
            if credentials is not None:
                self._rpc(6, credentials.encode())
            self._rpc(4)
            self._cleanup_orphans()
        except BaseException:
            self.close()
            raise

    @property
    def credentials(self):
        return self._credentials

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _ready(self):
        if self._verified is not None and self._verified.failed.is_set():
            self._failed = True
        if self._closed or self._failed:
            raise OSError(errno.EIO, 'session is closed or requires recovery in a new session')

    def _receive(self, length, deadline):
        result = bytearray()
        fd = self._process.stdout.fileno()
        while len(result) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise TimeoutError('resident reader response timed out')
            chunk = os.read(fd, length - len(result))
            if not chunk:
                raise OSError(errno.EIO, 'resident reader exited')
            result.extend(chunk)
        return bytes(result)

    def _send(self, data, deadline):
        fd = self._process.stdin.fileno()
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise TimeoutError('resident reader request timed out')
            try:
                count = os.write(fd, view)
            except BlockingIOError:
                continue
            if count <= 0:
                raise OSError(errno.EIO, 'resident reader request failed')
            view = view[count:]

    def _rpc(self, op, path=b'', offset=0, length=0):
        try:
            before_request = getattr(self._commit_sink, 'before_request', None)
            if before_request is not None:
                before_request()
            if self._verified is not None:
                self._verified.guard()
            deadline = time.monotonic() + 30
            self._send(REQUEST.pack(b'E4RD0001', op, len(path), offset, length) + path, deadline)
            magic, error, reserved, size, count = REPLY.unpack(self._receive(REPLY.size, deadline))
            if (magic != b'E4RP0001' or reserved or count > LIMIT or (error and (size or count))
                    or (op in (2, 8) and count > length) or (op in (1, 3, 4, 6, 9, 10, 28, 29, 37, 41, 42) and count)
                    or (op == 13 and (count != size or count > 4095))
                    or (op == 12 and (count % 8 or count > 65536*8))
                    or (not error and ((op in (7,14,18,19,22,24,38,39) and count != 24) or (op in (11,15,21,25) and count != 16)))
                    or (not error and op==23 and count!=8)
                    or (not error and op==27 and (count<8 or count>length or size>=2**63-1))
                    or (not error and op==28 and size>=2**63-1)
                    or (not error and op==29 and size)
                    or (op in (26,40) and (count!=size or count>4095))
                    or (not error and op in (30,31) and count!=128)
                    or (not error and op==32 and count!=80)
                    or (op in (33,34,37,41,42) and (count or size))
                    or (not error and op==35 and (count!=size or count>65536))
                    or (not error and op==36 and (count!=16 or size))
                    or (op in (17,20) and (count != size or count > 4096))):
                raise OSError(errno.EIO, 'invalid resident reader response')
            data = self._receive(count, deadline)
            if self._verified is not None:
                self._verified.guard()
        except BaseException:
            self._failed = True
            raise
        if error:
            if error == errno.EIO:
                self._failed = True
            # Ordinary lookup errors keep the session usable. Refresh failure
            # is caught by apply/recover, which keeps the reader suspended.
            raise OSError(error, os.strerror(error))
        return size, data

    @staticmethod
    def _path(path):
        if not isinstance(path, str):
            raise ValueError('path must be a string')
        encoded = path.encode('utf-8')
        if not 1 <= len(encoded) <= 4096 or b'\0' in encoded or not path.startswith('/'):
            raise ValueError('invalid path')
        if path != '/' and any(c in ('', '.', '..') or len(c.encode('utf-8')) > 255 for c in path[1:].split('/')):
            raise ValueError('invalid path components')
        return encoded

    def _absolute(self, path):
        if not isinstance(path,str):raise ValueError('path must be a string')
        if path.startswith('/'):return self._path(path)
        raw=path.encode('utf-8')
        if not raw or len(raw)>4096 or b'\0' in raw or any(not p or len(p.encode('utf-8'))>255 for p in path.split('/')):
            raise ValueError('invalid relative path')
        if self.credentials is None:return self._path('/'+path)
        parent,_,leaf=path.rpartition('/')
        if leaf in ('.','..'):
            parent=path;leaf=''
        else:parent=parent or '.'
        payload=self._cwd_token()+parent.encode('utf-8')
        _,base=self._rpc(20,payload)
        result=base.decode('utf-8')
        if leaf:result=result.rstrip('/')+'/'+leaf
        return self._path(result)

    def _cwd_token(self):
        return self._file(self._cwd) if self._cwd is not None else struct.pack('<Q',0)

    def _directory(self, reply, access):
        _,data=reply
        token,inode,generation,granted,flags=struct.unpack('<QIIII',data)
        if not token or not inode or granted!=access or flags!=2:
            self._failed=True;raise OSError(errno.EIO,'invalid directory open result')
        handle=DirectoryHandle(self,token,self._file_key)
        self._files.add(handle);return handle

    def opendir(self, path):
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'directory handles require bound credentials')
            return self._directory(self._rpc(14,self._absolute(path),4),4)

    @staticmethod
    def _at_path(path):
        if not isinstance(path,(str,bytes)):raise ValueError('path must be str or bytes')
        raw=os.fsencode(path)
        if not raw:raise OSError(errno.ENOENT,'empty pathname')
        if b'\0' in raw:raise ValueError('NUL in pathname')
        if len(raw)>4096:raise OSError(errno.ENAMETOOLONG,'pathname limit')
        return raw

    def _at_token(self, directory, path):
        # An absolute pathname ignores dirfd, even a released/non-directory fd.
        if self._at_path(path).startswith(b'/'):return struct.pack('<Q',0)
        if directory is None:return self._cwd_token()
        token=self._file(directory)
        if not isinstance(directory,DirectoryHandle):raise OSError(errno.ENOTDIR,'dirfd is not a directory')
        return token

    def _at_context(self, directory, path):
        self._at_path(path)
        return self._rpc(21,self._at_token(directory,path))[1]

    def _opened(self, reply):
        _,raw=reply
        token,inode,generation,access,flags=struct.unpack('<QIIII',raw)
        if not token or not inode or (flags==2 and access!=4) or (flags!=2 and (access not in (1,2,3) or flags>1)):
            self._failed=True;raise OSError(errno.EIO,'invalid openat admission')
        h=(DirectoryHandle if flags==2 else FileHandle)(self,token,self._file_key)
        self._files.add(h);return h

    def openat(self, directory, path, access='r', *, create=False, exclusive=False,
               mode=0o666, append=False, truncate=False, nofollow=False, directory_only=False):
        """Open from dirfd (None means cwd); absolute paths ignore dirfd.

        Flags use portable named options, not host-dependent O_* integers.
        Creation/truncation and open-time grants are one staged transaction.
        """
        if access not in ('r','w','rw') or any(type(v) is not bool for v in
                (create,exclusive,append,truncate,nofollow,directory_only)):
            raise ValueError('invalid openat options')
        rights={'r':1,'w':2,'rw':3}[access]
        if type(mode) is not int or not 0<=mode<=0o777 or (exclusive and not create) or ((append or truncate) and not rights&2) or (create and directory_only):
            raise ValueError('invalid openat flag combination')
        flags=rights|4*append|8*create|16*exclusive|32*truncate|64*nofollow|128*directory_only
        raw=self._at_path(path)
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'openat requires bound credentials')
            token=self._at_token(directory,path)
            if not (create or truncate):return self._opened(self._rpc(22,token+raw,flags))
            # Reserve a table slot and a new-inode pin before any image changes.
            # The broker exports capabilities, never user-supplied inode numbers.
            base=self._rpc(21,token)[1]
            root=self._rpc(21,struct.pack('<Q',0))[1]
            reserved=self._rpc(23)[1]
            try:
                _,pins=self._rpc(12)
                op=dict(kind='open',path=path,flags=flags,mode=mode)
                request=write_api.encode_at([op],self.credentials,pins,[(base,root)])
                self._apply_request(request, defer_checkpoint=True)
                report=self.root/f"g-{self.state['head']:08d}"/'operations.result'
                try:
                    with regular(report) as result:
                        grant=result.read(17)
                except BaseException:
                    self._failed=True;raise
                if len(grant)!=16:
                    self._failed=True;raise OSError(errno.EIO,'invalid committed open grant')
                ino,generation,granted,grant_flags=struct.unpack('<IIII',grant)
                expected=self.statat(directory,path,follow_symlinks=not nofollow)
                is_dir=expected['mode'] & 0o170000 == 0o040000
                if ((ino,generation)!=(expected['inode'],expected['generation']) or
                        granted!=(4 if is_dir else rights) or grant_flags!=(2 if is_dir else int(append))):
                    self._failed=True;raise OSError(errno.EIO,'committed open grant does not match request and image')
                handle = self._opened(self._rpc(24,reserved+grant))
                self._maybe_checkpoint()
                return handle
            finally:
                # Successful activation is now owned by the returned handle.
                if not any(struct.pack('<Q',h._token)==reserved for h in self._files):
                    if not self._failed:self._rpc(10,reserved)

    def chdirat(self, directory, path):
        raw=self._at_path(path)
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'cwd requires bound credentials')
            self._replace_cwd(self._directory(self._rpc(19,self._at_token(directory,path)+raw),8))

    def readat(self, directory, path, offset=0, length=LIMIT):
        with self.openat(directory,path) as f:return f.read(offset,length)

    def statat(self, directory, path, *, follow_symlinks=True):
        if type(follow_symlinks) is not bool:raise ValueError('invalid follow option')
        raw=self._at_path(path)
        with self._mutex:
            self._ready()
            return DirectoryHandle._stat(self._rpc(25,self._at_token(directory,path)+raw,int(follow_symlinks)))

    def readlinkat(self, directory, path):
        raw=self._at_path(path)
        with self._mutex:
            self._ready()
            return self._rpc(26,self._at_token(directory,path)+raw)[1]

    def applyat(self, operations, directory=None, *, target_directory=None):
        """Atomic batch, resolved sequentially in staged state from held dirfds."""
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'at operations require bound credentials')
            if not isinstance(operations,list) or not 1<=len(operations)<=64:raise ValueError('expected 1..64 operations')
            bases=[]
            for op in operations:
                if not isinstance(op,dict):raise ValueError('invalid operation')
                if op.get('kind')=='open':raise ValueError('open grants are allocated by openat')
                base=self._at_context(directory,op.get('path'))
                target=self._at_context(target_directory,op.get('target')) if op.get('kind') in ('link','rename') else base
                bases.append((base,target))
            _,pins=self._rpc(12)
            return self._apply_request(write_api.encode_at(operations,self.credentials,pins,bases))

    def mkdirat(self, directory, path, mode=0o777):
        return self.applyat([dict(kind='mkdir',path=path,mode=mode)],directory)

    def unlinkat(self, directory, path, *, remove_directory=False):
        if type(remove_directory) is not bool:raise ValueError('invalid remove-directory flag')
        return self.applyat([dict(kind='rmdir' if remove_directory else 'unlink',path=path)],directory)

    def renameat(self, source_directory, source, target_directory, target, *, flags=0):
        return self.applyat([dict(kind='rename',path=source,target=target,flags=flags)],source_directory,target_directory=target_directory)

    def linkat(self, source_directory, source, target_directory, target, *, follow_symlinks=False):
        if type(follow_symlinks) is not bool:raise ValueError('invalid follow option')
        return self.applyat([dict(kind='link',path=source,target=target,follow_symlinks=follow_symlinks)],source_directory,target_directory=target_directory)

    def mknodat(self, directory, path, mode, *, major=0, minor=0):
        return self.applyat([dict(kind='mknod',path=path,mode=mode,major=major,minor=minor)],directory)

    def symlinkat(self, target, directory, path):
        return self.applyat([dict(kind='symlink',path=path,target=target)],directory)

    def _metadata(self, operation, path=None, handle=None, follow_symlinks=True):
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'metadata requires bound credentials')
            if handle is None:return self.applyat([dict(operation,path=path,follow_symlinks=follow_symlinks)])
            _,grant=self._rpc(36,self._file(handle));_,pins=self._rpc(12)
            return self._apply_request(write_api.encode_metadata_grant(operation,self.credentials,grant,pins))

    def chmod(self, path, mode, *, handle=None, follow_symlinks=True):
        return self._metadata(dict(kind='chmod',mode=mode),path,handle,follow_symlinks)

    def chown(self, path, uid=-1, gid=-1, *, handle=None, follow_symlinks=True):
        return self._metadata(dict(kind='chown',uid=uid,gid=gid),path,handle,follow_symlinks)

    def utimens(self, path, atime=None, mtime=None, *, handle=None, follow_symlinks=True):
        return self._metadata(dict(kind='utimens',atime=atime,mtime=mtime),path,handle,follow_symlinks)

    def setxattr(self, path, name, value, flags=0, *, handle=None, follow_symlinks=False):
        if not isinstance(value,bytes):raise ValueError('attribute value must be bytes')
        return self._metadata(dict(kind='setxattr',name=name,value_hex=value.hex(),flags=flags),path,handle,follow_symlinks)

    def removexattr(self, path, name, *, handle=None, follow_symlinks=False):
        return self._metadata(dict(kind='removexattr',name=name),path,handle,follow_symlinks)

    def _xattr_query(self, path, name, handle, follow_symlinks):
        if type(follow_symlinks) is not bool:raise ValueError('invalid follow option')
        if name is not None:
            name=os.fsencode(name)
            if not 1<=len(name)<=255 or b'\0' in name:raise ValueError('invalid attribute name')
        with self._mutex:
            self._ready()
            token=self._file(handle) if handle is not None else struct.pack('<Q',0)
            raw=b'' if handle is not None else self._at_path(path)
            return self._rpc(35,token+raw+b'\0'+(name or b''),int(name is None),int(follow_symlinks))[1]

    def getxattr(self,path,name,*,handle=None,follow_symlinks=False):
        return self._xattr_query(path,name,handle,follow_symlinks)

    def listxattrs(self,path,*,handle=None,follow_symlinks=False):
        raw=self._xattr_query(path,None,handle,follow_symlinks)
        if raw and (not raw.endswith(b'\0') or any(not name or len(name)>255 for name in raw[:-1].split(b'\0'))):
            self._failed=True;raise OSError(errno.EIO,'invalid attribute list')
        return [os.fsdecode(name) for name in raw[:-1].split(b'\0')] if raw else []

    def _mount_nodes(self):
        with self._mutex:
            self._ready();self._rpc(37)

    def _mount_node_capacity(self):
        with self._mutex:
            self._ready();self._rpc(42)

    def _mount_lookup(self, parent, name, *, implicit_root=False):
        raw=os.fsencode(name)
        if not raw or len(raw)>255 or b'/' in raw or b'\0' in raw:
            raise OSError(errno.EINVAL,'invalid lookup component')
        with self._mutex:
            token=self._file(parent) if parent is not None else struct.pack('<Q',0)
            if implicit_root and (parent is not None or raw!=b'.'):
                raise ValueError('implicit root pin requires the virtual root')
            _,reply=self._rpc(38,token+raw,int(implicit_root))
            number,ino,generation,access,flags=struct.unpack('<QIIII',reply)
            if not number or not ino or ((flags,access) not in ((2,8),(4,0))):
                self._failed=True;raise OSError(errno.EIO,'invalid lookup pin')
            existing=self._lookup_files.get(number)
            if existing is not None:
                if existing._lookup_grant!=(ino,generation,access,flags):
                    self._failed=True;raise OSError(errno.EIO,'lookup identity alias')
                return existing,ino,generation
            h=(DirectoryHandle if flags==2 else FileHandle)(self,number,self._file_key)
            h._lookup_grant=(ino,generation,access,flags)
            self._files.add(h)
            self._lookup_files[number]=h
            return h,ino,generation

    def _mount_open_node(self, node, rights, append=False, directory=False):
        with self._mutex:
            reply=self._rpc(39,self._file(node),rights|4*append|128*directory)
            token,ino,generation,access,flags=struct.unpack('<QIIII',reply[1])
            expected=getattr(node,'_lookup_grant',None)
            is_dir=isinstance(node,DirectoryHandle)
            if (expected is None or (ino,generation)!=expected[:2] or
                access!=(4 if is_dir else rights) or flags!=(2 if is_dir else int(append))):
                self._failed=True;raise OSError(errno.EIO,'inode open grant mismatch')
            return self._opened(reply)

    def _mount_cache_reader(self, writable):
        """Private kernel RMW read capability derived only from a live writer."""
        with self._mutex:
            return self._opened(self._rpc(43,self._file(writable)))

    def _mount_writeback(self, handle, offset, data):
        """Kernel page write using existing open rights and a positional offset.

        O_APPEND affects write(2), not MAP_SHARED page offsets. The trusted
        broker may derive a positional grant; inode append-only and immutable
        checks still run in the writer. No grant comes from the mounted caller.
        """
        with self._mutex:
            _,grant=self._rpc(11,self._file(handle))
            inode,generation,access,flags=struct.unpack('<IIII',grant)
            if flags not in (0,1) or not access&2:raise OSError(errno.EBADF,'writeback requires a writable file')
            grant=struct.pack('<IIII',inode,generation,access,0)
            self._apply_request(write_api.encode_grant(self.credentials,grant,'write',offset,data))
            return len(data)

    def _mount_metadata_batch(self, operations, handles):
        with self._mutex:
            grants=[self._rpc(36,self._file(h))[1] for h in handles]
            _,pins=self._rpc(12)
            return self._apply_request(write_api.encode_metadata_batch(operations,self.credentials,grants,pins))

    def _mount_context(self, credentials):
        """Private authenticated mount broker entry; not JSON caller input."""
        if not isinstance(credentials,Credentials):raise ValueError('invalid mount context')
        with self._mutex:
            self._ready();self._rpc(33,credentials.encode());self._credentials=credentials

    def _mount_stat(self, path=None, handle=None):
        with self._mutex:
            self._ready()
            payload=self._file(handle) if handle is not None else struct.pack('<Q',0)+self._at_path(path)
            return self._rpc(30 if handle is not None else 31,payload)[1]

    def _mount_geometry(self):
        with self._mutex:
            self._ready();return self._rpc(32,struct.pack('<Q',0))[1]

    def _mount_access(self, path, want):
        with self._mutex:
            self._ready();self._rpc(34,struct.pack('<Q',0)+self._at_path(path),want)

    def getcwd(self):
        with self._mutex:
            self._ready()
            if self._cwd is None:return '/'
            return os.fsdecode(self._rpc(17,self._cwd_token())[1])

    def cwd_stat(self):
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'cwd metadata requires bound credentials')
            return DirectoryHandle._stat(self._rpc(15,self._cwd_token()))

    def _replace_cwd(self, handle):
        old=self._cwd;self._cwd=handle
        if old is not None:old.close()

    def chdir(self, path):
        if not isinstance(path,str):raise ValueError('path must be a string')
        raw=path.encode('utf-8')
        if not raw or len(raw)>4096 or b'\0' in raw:raise ValueError('invalid cwd path')
        with self._mutex:
            self._ready()
            if self.credentials is None:raise OSError(errno.EOPNOTSUPP,'cwd requires bound credentials')
            token=struct.pack('<Q',0) if path.startswith('/') else self._cwd_token()
            handle=self._directory(self._rpc(19,token+raw),8)
            self._replace_cwd(handle)

    def fchdir(self, handle):
        with self._mutex:
            self._ready()
            token=self._file(handle)
            if not isinstance(handle,DirectoryHandle):raise OSError(errno.ENOTDIR,'not a directory handle')
            self._replace_cwd(self._directory(self._rpc(18,token,1),8))

    def size(self, path):
        with self._mutex:
            self._ready()
            return self._rpc(1, self._absolute(path))[0]

    def read(self, path, offset=0, length=LIMIT):
        if type(offset) is not int or not 0 <= offset <= 2**63 - 1 or type(length) is not int or not 0 <= length <= LIMIT:
            raise ValueError('read bounds')
        with self._mutex:
            self._ready()
            return self._rpc(2, self._absolute(path), offset, length)[1]

    def counters(self):
        with self._mutex:
            self._ready()
            data = self._rpc(5)[1]
            if len(data) != 16:
                self._failed = True
                raise OSError(errno.EIO, 'invalid reader counters')
            return struct.unpack('<QQ', data)

    def apply(self, operations):
        with self._mutex:
            self._ready()
            if not isinstance(operations,list) or not 1<=len(operations)<=64:
                raise ValueError('expected 1..64 operations')
            normalized=[]
            for operation in operations:
                if not isinstance(operation,dict):raise ValueError('invalid operation')
                op=dict(operation)
                op['path']=self._absolute(op.get('path')).decode('utf-8')
                if op.get('kind') in ('link','rename'):
                    op['target']=self._absolute(op.get('target')).decode('utf-8')
                normalized.append(op)
            _, pins = self._rpc(12)
            return self._apply_request(write_api.encode_broker(normalized,self._credentials,pins))

    def _cleanup_orphans(self):
        head,pins=self._rpc(12)
        if head:
            self._apply_request(write_api.encode_broker([],self._credentials,pins))

    def link(self, source, target):
        return self.apply([dict(kind='link',path=source,target=target)])

    def rename(self, source, target, *, flags=0):
        return self.apply([dict(kind='rename',path=source,target=target,flags=flags)])

    def unlink(self, path):
        return self.apply([dict(kind='unlink',path=path)])

    def mkdir(self, path, mode=0o777):
        return self.apply([dict(kind='mkdir',path=path,mode=mode)])

    def rmdir(self, path):
        return self.apply([dict(kind='rmdir',path=path)])

    def mknod(self, path, mode, *, major=0, minor=0):
        return self.apply([dict(kind='mknod',path=path,mode=mode,major=major,minor=minor)])

    def symlink(self, target, path):
        return self.apply([dict(kind='symlink',path=path,target=target)])

    def readlink(self, path):
        with self._mutex:
            self._ready()
            return self._rpc(13,self._absolute(path))[1]

    def _apply_request(self, request, *, defer_checkpoint=False):
        with self._mutex:
            self._ready()
            try:
                self._rpc(3)
            except BaseException:
                self._failed = True
                raise
            try:
                previous = self.state
                committed = write_api.apply_encoded_locked(self.root, self.producer, request, self._integrity)
                if self._commit_sink is not None:
                    try:
                        self._commit_sink.publish(previous, committed)
                    except BaseException:
                        # The image may be ahead of the device. Never serve or
                        # acknowledge it after ambiguous physical publication.
                        self._failed = True
                        raise
                self.state = committed
            except BaseException:
                if self._verified.failed.is_set():
                    self._failed = True
                if self._failed:
                    raise
                # A failed producer may leave an unsealed intent; a transport
                # error after sealing may require completing a committed batch.
                # Resume only once recovery and reader refresh both succeed.
                try:
                    self.state, self._integrity = chain.recover_integrity_locked(self.root)
                    if self._commit_sink is not None:
                        self._recover_sink()
                    self._rpc(4)
                except BaseException:
                    self._failed = True
                raise
            try:
                self._rpc(4)
            except BaseException:
                self._failed = True
                raise
            if not defer_checkpoint:
                self._maybe_checkpoint()
            return dict(self.state)

    def _recover_sink(self):
        # Only direct mode shares this exact image/device view. Shadow backends
        # still validate their separate physical target independently.
        bind = getattr(self._commit_sink, 'recover_integrity', None)
        if bind is not None: bind(self.state, self._integrity)
        else: self._commit_sink.recover(self.state)

    def _maybe_checkpoint(self):
        if self._checkpoint_every and self.state['head'] - self._checkpoint_head >= self._checkpoint_every:
            self.checkpoint()

    def checkpoint(self):
        # Retire completed history without closing resident reader or handles.
        with self._mutex:
            self._ready()
            try:
                state = chain.read_state(self.root)
                if state != self.state or state['pending'] is not None:
                    raise ValueError('session generation changed before checkpoint')
                if self._commit_sink is not None:
                    checkpoint = getattr(self._commit_sink, 'checkpoint_integrity', None)
                    if checkpoint is not None: checkpoint(self.state, self._integrity)
                    else: self._commit_sink.checkpoint(self.state)
                self.state = chain.checkpoint_locked(self.root, self._integrity)
                self._checkpoint_head = self.state['head']
            except BaseException:
                self._failed = True
                raise
            return dict(self.state)

    def scrub(self):
        """Explicit full image audit; checkpoint retirement uses the live tree."""
        with self._mutex:
            self._ready()
            try:
                if chain.read_state(self.root) != self.state or self.state['pending'] is not None:
                    raise ValueError('session generation changed before scrub')
                with regular(self.root/'image.img') as image:
                    self._integrity.check(image, self.state)
                    verified = merkle.scan(image, self.state)
                if verified.root() != self.state['sha256']:
                    raise ValueError('full scrub found untouched corruption')
                self._integrity = verified
                if self._commit_sink is not None: self._recover_sink()
            except BaseException:
                self._failed = True
                raise
            return dict(self.state)

    def open(self, path, access='r', *, append=False, truncate=False):
        if access not in ('r','w','rw') or type(append) is not bool or type(truncate) is not bool:
            raise ValueError('invalid open options')
        rights={'r':1,'w':2,'rw':3}[access]
        if (append or truncate) and not rights&2:
            raise ValueError('write access required')
        with self._mutex:
            self._ready()
            if self._credentials is None:
                raise OSError(errno.EOPNOTSUPP,'handles require bound credentials')
            _, data = self._rpc(7,self._absolute(path),rights,int(append))
            token,inode,generation,granted,flags = struct.unpack('<QIIII',data)
            if not token or not inode or granted!=rights or flags!=int(append):
                self._failed=True
                raise OSError(errno.EIO,'invalid open result')
            handle=FileHandle(self,token,self._file_key)
            self._files.add(handle)
            try:
                if truncate:
                    handle.truncate(0)
            except BaseException:
                handle.close()
                raise
            return handle

    def _file(self, handle):
        if not isinstance(handle,FileHandle) or handle._owner is not self or handle not in self._files or handle._closed:
            raise OSError(errno.EBADF,'invalid or released file handle')
        self._ready()
        return struct.pack('<Q',handle._token)

    def close(self):
        with self._mutex:
            if self._closed:
                return
            if self._verified is not None and self._verified.failed.is_set():
                self._failed = True
            if self._failed and self._commit_sink is not None:
                self._commit_sink.abort()
            self._cwd=None
            tokens=[handle._token for handle in self._files]
            for handle in self._files:
                handle._closed = True
            self._files.clear()
            self._lookup_files.clear()
            cleanup_error=None
            if self._process is not None and not self._failed:
                try:
                    # Reader handles must be released before taking an empty pin snapshot.
                    for token in tokens:
                        self._rpc(10,struct.pack('<Q',token))
                    self._cleanup_orphans()
                except BaseException as e:
                    cleanup_error=e
            self._closed=True
            try:
                if self._process is not None:
                    try:
                        self._process.stdin.close()
                    except BrokenPipeError:
                        pass
                    try:
                        self._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                        self._process.wait(timeout=5)
                    self._process.stdout.close()
            finally:
                if self._failed and self._commit_sink is not None:
                    self._commit_sink.abort()
                if self._verified_context is not None:
                    self._verified_context.__exit__(None, None, None)
                    self._verified_context = None
                if self._verified is not None:
                    self._verified.close()
                self._lock.__exit__(None, None, None)
                self._integrity = None
            if cleanup_error is not None:
                raise cleanup_error


class FileHandle:
    """Session-local positional I/O; append ignores the supplied write offset.

    Construct via Session.open. Last-link removal retains a durable orphan
    until the final handle closes; restart reclaims abandoned session orphans.
    """
    __slots__ = ('_owner','_token','_closed','_lookup_grant')

    def __init__(self, owner, token, key):
        if key is not owner._file_key:
            raise ValueError('file handles are allocated by the session')
        self._owner=owner
        self._token=token
        self._closed=False
        self._lookup_grant=None

    @property
    def closed(self):
        return self._closed

    def __enter__(self):
        with self._owner._mutex:
            self._owner._file(self)
        return self

    def __exit__(self,*unused):
        self.close()

    def size(self):
        with self._owner._mutex:
            return self._owner._rpc(9,self._owner._file(self))[0]

    def read(self, offset=0, length=LIMIT):
        if type(offset) is not int or not 0<=offset<=2**63-1 or type(length) is not int or not 0<=length<=LIMIT:
            raise ValueError('read bounds')
        with self._owner._mutex:
            return self._owner._rpc(8,self._owner._file(self),offset,length)[1]

    def write(self, data, offset=0):
        if not isinstance(data,bytes):
            raise ValueError('write data must be bytes')
        with self._owner._mutex:
            _, grant = self._owner._rpc(11,self._owner._file(self))
            request=write_api.encode_grant(self._owner.credentials,grant,'write',offset,data)
            self._owner._apply_request(request)
            return len(data)

    def allocate(self, offset, length, mode=0):
        if type(length) is not int or not 0<length<=2**63-1 or type(mode) is not int or mode not in (0,1,3,4):
            raise ValueError('allocation length or mode')
        with self._owner._mutex:
            _,grant=self._owner._rpc(11,self._owner._file(self))
            request=write_api.encode_grant(self._owner.credentials,grant,'allocate',offset,struct.pack('<QQ',length,mode))
            return self._owner._apply_request(request)

    def truncate(self, size):
        with self._owner._mutex:
            _, grant = self._owner._rpc(11,self._owner._file(self))
            request=write_api.encode_grant(self._owner.credentials,grant,'truncate',size)
            return self._owner._apply_request(request)

    def close(self):
        with self._owner._mutex:
            if self._closed:
                return
            if self not in self._owner._files:
                self._closed=True
                raise OSError(errno.EBADF,'unregistered file handle')
            self._closed=True
            self._owner._files.discard(self)
            self._owner._lookup_files.pop(self._token,None)
            if not self._owner._closed and not self._owner._failed:
                self._owner._rpc(10,struct.pack('<Q',self._token))
                self._owner._cleanup_orphans()


class DirectoryHandle(FileHandle):
    """Read grants and inode identity survive rename and removal; no file data I/O."""
    @staticmethod
    def _stat(reply):
        size,data=reply
        inode,generation,mode,links=struct.unpack('<IIII',data)
        return dict(inode=inode,generation=generation,mode=mode,links=links,size=size)

    def stat(self):
        with self._owner._mutex:
            return self._stat(self._owner._rpc(15,self._owner._file(self)))

    def listdir(self):
        with self._owner._mutex:
            raw=self._owner._rpc(16,self._owner._file(self))[1]
            names=[];offset=0
            while offset<len(raw):
                if offset+2>len(raw):break
                length=struct.unpack_from('<H',raw,offset)[0];offset+=2
                if not 1<=length<=255 or offset+length>len(raw):break
                name=raw[offset:offset+length];offset+=length
                if b'/' in name or b'\0' in name or name in (b'.',b'..'):break
                names.append(os.fsdecode(name))
            else:return names
            self._owner._failed=True;raise OSError(errno.EIO,'invalid directory listing')

    def readdir(self, max_entries=128, *, max_bytes=65536, offset=None):
        """Return entries, next opaque offset, and EOF from a stable snapshot.

        None resumes the native cursor; zero starts the current snapshot. Rewind
        discards the snapshot and all nonzero cookies associated with it.
        """
        if type(max_entries) is not int or not 1<=max_entries<=4096 or type(max_bytes) is not int or not 8<=max_bytes<=LIMIT:
            raise ValueError('directory page bounds')
        if offset is not None and (type(offset) is not int or not 0<=offset<2**63-1):
            raise ValueError('invalid directory offset')
        with self._owner._mutex:
            token=self._owner._file(self)
            next_offset,raw=self._owner._rpc(27,token+struct.pack('<I',max_entries),2**63-1 if offset is None else offset,max_bytes)
            eof,count=struct.unpack_from('<II',raw);at=8;entries=[];previous=0
            valid=eof in (0,1) and count<=max_entries
            for unused in range(count) if valid else ():
                if at+16>len(raw):valid=False;break
                cookie,inode,kind,size=struct.unpack_from('<QIHH',raw,at);at+=16
                if (not 0<cookie<2**63-1 or (previous and cookie<=previous) or not inode or kind not in (0,1,2,4,6,8,10,12) or
                        not 1<=size<=255 or at+size>len(raw)):
                    valid=False;break
                name=raw[at:at+size];at+=size
                if b'/' in name or b'\0' in name:valid=False;break
                entries.append(dict(name=os.fsdecode(name),inode=inode,type=kind,offset=cookie));previous=cookie
            if not valid or at!=len(raw) or (entries and next_offset!=entries[-1]['offset']) or (not entries and not eof):
                self._owner._failed=True;raise OSError(errno.EIO,'invalid directory page')
            return dict(entries=entries,offset=next_offset,eof=bool(eof))

    def tell(self):
        with self._owner._mutex:
            return self._owner._rpc(28,self._owner._file(self),2**63-1)[0]

    def seek(self, offset):
        if type(offset) is not int or not 0<=offset<2**63-1:raise ValueError('invalid directory offset')
        with self._owner._mutex:
            return self._owner._rpc(28,self._owner._file(self),offset)[0]

    def rewind(self):
        with self._owner._mutex:
            self._owner._rpc(29,self._owner._file(self))

    def path(self):
        with self._owner._mutex:
            return os.fsdecode(self._owner._rpc(17,self._owner._file(self))[1])

    def dup(self):
        with self._owner._mutex:
            return self._owner._directory(self._owner._rpc(18,self._owner._file(self),4),4)

    def _no_data(self):
        with self._owner._mutex:
            self._owner._file(self)
            raise OSError(errno.EISDIR,'directory has no file data operations')

    def read(self,*args,**kwargs):return self._no_data()
    def write(self,*args,**kwargs):return self._no_data()
    def truncate(self,*args,**kwargs):return self._no_data()
