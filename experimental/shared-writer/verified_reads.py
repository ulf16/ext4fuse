# SPDX-License-Identifier: GPL-2.0-only
"""Session-local verified bytes, bound to a scanned or authenticated stored tree.

The private socket returns the bytes that were hashed, never permission to
reread a raw descriptor. Cached bytes are immutable and generation-bound; a
cache hit can return an older authenticated snapshot, never unchecked media.
Replay deliberately uses its existing preimage/redo verification, not this
service: partially published chunks do not yet belong to either live root.
"""
import collections
import contextlib
import errno
import socket
import struct
import threading

import image_io
import merkle

REQUEST = struct.Struct('<QQ')
REPLY = struct.Struct('<II')


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError('verified read channel closed')
        result.extend(part)
    return bytes(result)


class Reader:
    def __init__(self, path, binding, cache_chunks=32):
        self.path = path
        self.binding = binding
        self.failed = threading.Event()
        self.lock = threading.RLock()
        self.cache = collections.OrderedDict()
        self.cache_chunks = cache_chunks
        self.generation = None
        self.channels = {}
        self.channel_lock = threading.Lock()
        self.closed = False

    def check(self):
        if self.closed or self.failed.is_set():
            raise OSError(errno.EIO, 'verified image read failed; session requires recovery')

    def guard(self):
        """Native caches may reuse verified bytes; still audit every operation."""
        with self.lock:
            self.check()
            try:
                state, tree = self.binding()
                with image_io.opened(self.path) as image:
                    tree.check(image, state)
            except Exception:
                self.failed.set()
                self.cache.clear()
                raise

    def read(self, offset, length):
        with self.lock:
            self.check()
            try:
                state, tree = self.binding()
                if not 0 <= offset <= tree.size or not 0 <= length <= min(merkle.CHUNK, tree.size - offset):
                    raise ValueError('verified read outside image')
                with image_io.opened(self.path) as image:
                    tree.check(image, state)
                    generation = (id(tree), tree.root(), tree.stamp)
                    if generation != self.generation:
                        self.cache.clear()
                        self.generation = generation
                    result = bytearray()
                    end = offset + length
                    while offset < end:
                        index, inside = divmod(offset, merkle.CHUNK)
                        chunk = self.cache.pop(index, None)
                        if chunk is None:
                            image.seek(index * merkle.CHUNK)
                            size = min(merkle.CHUNK, tree.size - index * merkle.CHUNK)
                            chunk = image.read(size)
                            if len(chunk) != size or merkle.leaf(index, chunk) != tree.get(tree.width + index):
                                raise ValueError('authenticated image chunk mismatch')
                        self.cache[index] = chunk
                        if len(self.cache) > self.cache_chunks:
                            self.cache.popitem(last=False)
                        take = min(end - offset, len(chunk) - inside)
                        result.extend(chunk[inside:inside + take])
                        offset += take
                    tree.check(image, state)
                    return bytes(result)
            except Exception:
                self.failed.set()
                self.cache.clear()
                raise

    @contextlib.contextmanager
    def channel(self):
        server, client = socket.socketpair()
        # A killed child cannot leave an unread response in another child's
        # channel. Closing our client copy immediately after spawn also lets
        # the worker notice child exit. Bound blocked replies after process loss.
        server.settimeout(30)
        try:
            thread = threading.Thread(target=self.serve, args=(server,), daemon=True,
                                      name='ext4-verified-reads')
            with self.channel_lock:
                if self.closed:
                    raise OSError(errno.EIO, 'verified reader closed')
                self.channels[server] = thread
                try:
                    thread.start()
                except BaseException:
                    self.channels.pop(server, None)
                    raise
        except BaseException:
            server.close()
            client.close()
            raise
        try:
            yield client
        finally:
            client.close()

    def serve(self, server):
        try:
            while True:
                # Idle resident readers may legitimately wait for hours.
                server.settimeout(None)
                offset, length = REQUEST.unpack(exact(server, REQUEST.size))
                server.settimeout(30)
                try:
                    data = self.read(offset, length)
                except Exception:
                    server.sendall(REPLY.pack(errno.EIO, 0))
                    continue
                server.sendall(REPLY.pack(0, len(data)) + data)
        except (OSError, EOFError):
            pass
        finally:
            server.close()
            with self.channel_lock:
                self.channels.pop(server, None)

    def close(self):
        # Called only after all native children have exited.
        with self.channel_lock:
            self.closed = True
            channels = list(self.channels.items())
        for server, thread in channels:
            try:
                server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=5)
            if thread.is_alive():
                self.failed.set()
                raise OSError(errno.EIO, 'verified read worker did not stop')
        self.cache.clear()
