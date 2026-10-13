#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Serialized offline image session with one resident native reader."""
import errno
import importlib.util
import os
from pathlib import Path
import select
import struct
import subprocess
import threading
import time
import chain
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
    def __init__(self, root, producer, reader, credentials=None):
        if credentials is not None and not isinstance(credentials, Credentials):
            raise ValueError('expected trusted Credentials')
        self._credentials = credentials
        self._mutex = threading.RLock()
        self._closed = False
        self._failed = False
        self._process = None
        self._files = set()
        self._file_key = object()
        self._lock = chain.locked(root)
        self.root = self._lock.__enter__()
        self.producer = Path(producer).absolute()
        try:
            self.state = chain.recover_locked(self.root)
            self._process = subprocess.Popen([str(Path(reader).absolute()), str(self.root / 'image.img')],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, bufsize=0)
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
            deadline = time.monotonic() + 30
            self._send(REQUEST.pack(b'E4RD0001', op, len(path), offset, length) + path, deadline)
            magic, error, reserved, size, count = REPLY.unpack(self._receive(REPLY.size, deadline))
            if (magic != b'E4RP0001' or reserved or count > LIMIT or (error and (size or count))
                    or (op in (2, 8) and count > length) or (op in (1, 3, 4, 6, 9, 10) and count)
                    or (op == 12 and (count % 8 or count > 128*8))
                    or (not error and ((op == 7 and count != 24) or (op == 11 and count != 16)))):
                raise OSError(errno.EIO, 'invalid resident reader response')
            data = self._receive(count, deadline)
        except BaseException:
            self._failed = True
            raise
        if error:
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

    def size(self, path):
        path = self._path(path)
        with self._mutex:
            self._ready()
            return self._rpc(1, path)[0]

    def read(self, path, offset=0, length=LIMIT):
        path = self._path(path)
        if type(offset) is not int or not 0 <= offset <= 2**63 - 1 or type(length) is not int or not 0 <= length <= LIMIT:
            raise ValueError('read bounds')
        with self._mutex:
            self._ready()
            return self._rpc(2, path, offset, length)[1]

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
            _, pins = self._rpc(12)
            return self._apply_request(write_api.encode_broker(operations,self._credentials,pins))

    def _cleanup_orphans(self):
        head,pins=self._rpc(12)
        if head:
            self._apply_request(write_api.encode_broker([],self._credentials,pins))

    def link(self, source, target):
        return self.apply([dict(kind='link',path=source,target=target)])

    def rename(self, source, target):
        return self.apply([dict(kind='rename',path=source,target=target)])

    def unlink(self, path):
        return self.apply([dict(kind='unlink',path=path)])

    def _apply_request(self, request):
        with self._mutex:
            self._ready()
            try:
                self._rpc(3)
            except BaseException:
                self._failed = True
                raise
            try:
                self.state = write_api.apply_encoded_locked(self.root, self.producer, request)
            except BaseException:
                # A failed producer may leave an unsealed intent; a transport
                # error after sealing may require completing a committed batch.
                # Resume only once recovery and reader refresh both succeed.
                try:
                    self.state = chain.recover_locked(self.root)
                    self._rpc(4)
                except BaseException:
                    self._failed = True
                raise
            try:
                self._rpc(4)
            except BaseException:
                self._failed = True
                raise
            return dict(self.state)

    def open(self, path, access='r', *, append=False, truncate=False):
        path = self._path(path)
        if access not in ('r','w','rw') or type(append) is not bool or type(truncate) is not bool:
            raise ValueError('invalid open options')
        rights={'r':1,'w':2,'rw':3}[access]
        if (append or truncate) and not rights&2:
            raise ValueError('write access required')
        with self._mutex:
            self._ready()
            if self._credentials is None:
                raise OSError(errno.EOPNOTSUPP,'handles require bound credentials')
            _, data = self._rpc(7,path,rights,int(append))
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
            tokens=[handle._token for handle in self._files]
            for handle in self._files:
                handle._closed = True
            self._files.clear()
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
                self._lock.__exit__(None, None, None)
            if cleanup_error is not None:
                raise cleanup_error


class FileHandle:
    """Session-local positional I/O; append ignores the supplied write offset.

    Construct via Session.open. Last-link removal retains a durable orphan
    until the final handle closes; restart reclaims abandoned session orphans.
    """
    __slots__ = ('_owner','_token','_closed')

    def __init__(self, owner, token, key):
        if key is not owner._file_key:
            raise ValueError('file handles are allocated by the session')
        self._owner=owner
        self._token=token
        self._closed=False

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
            if not self._owner._closed and not self._owner._failed:
                self._owner._rpc(10,struct.pack('<Q',self._token))
                self._owner._cleanup_orphans()
