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

spec = importlib.util.spec_from_file_location('write_api', Path(__file__).with_name('write-api.py'))
write_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(write_api)
REQUEST = struct.Struct('<8sIIQQ')
REPLY = struct.Struct('<8sIIQQ')
LIMIT = 1024 * 1024


class Session:
    """Administrative API; no caller permission policy or persistent file handles.

    Hold the global chain lock for the entire session. Readers and mutations are
    serialized inside this object; other cooperating processes are excluded.
    Any unresolvable recovery/reader error leaves the session failed closed.
    """
    def __init__(self, root, producer, reader):
        self._mutex = threading.RLock()
        self._closed = False
        self._failed = False
        self._process = None
        self._lock = chain.locked(root)
        self.root = self._lock.__enter__()
        self.producer = Path(producer).absolute()
        try:
            self.state = chain.recover_locked(self.root)
            self._process = subprocess.Popen([str(Path(reader).absolute()), str(self.root / 'image.img')],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, bufsize=0)
            os.set_blocking(self._process.stdin.fileno(), False)
            self._rpc(4)
        except BaseException:
            self.close()
            raise

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
                    or (op == 2 and count > length) or (op in (1, 3, 4) and count)):
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
        request = write_api.encode(operations)
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

    def close(self):
        with self._mutex:
            if self._closed:
                return
            self._closed = True
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
