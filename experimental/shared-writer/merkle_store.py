# SPDX-License-Identifier: GPL-2.0-only
"""Ephemeral paged hash nodes; never a trusted persistent recovery index."""
from collections import OrderedDict
import errno
import hashlib
import struct
import os
import tempfile

PAGE = 65536
NODE = 32


class Nodes:
    def __init__(self, size, budget):
        if type(size) is not int or size <= 0 or size % NODE or size > 2**63-1:
            raise ValueError('invalid hash storage geometry')
        if type(budget) is not int or budget < PAGE:
            raise ValueError('hash page budget must hold at least one page')
        self.size = size
        # Reserve a page for checksum metadata. Large checksum tables recurse,
        # so no capacity-proportional checksum array grows without bound.
        self.capacity = max(1, budget // PAGE - 1)
        self.pages = OrderedDict()
        self.file = tempfile.TemporaryFile(prefix='ext4-hash-nodes-')
        self.tags = None
        try:
            self.file.truncate(size)
            tag_bytes = ((size+PAGE-1)//PAGE)*NODE
            self.tags = bytearray(tag_bytes) if tag_bytes <= PAGE else Nodes(tag_bytes, PAGE)
        except BaseException:
            self.close(); raise

    @staticmethod
    def _digest(index, data):
        return hashlib.sha256(b'E4HASH-PAGE01'+struct.pack('<QQ',index,len(data))+data).digest()

    def _tag(self, index, value=None):
        if isinstance(self.tags, Nodes):
            if value is None: return self.tags.get(index)
            self.tags.set(index, value)
        elif value is None:
            return bytes(self.tags[index*NODE:(index+1)*NODE])
        else:
            self.tags[index*NODE:(index+1)*NODE] = value

    def _write(self, index, data):
        offset = index*PAGE
        remaining = memoryview(data)
        while remaining:
            try: n = os.pwrite(self.file.fileno(), remaining, offset)
            except InterruptedError: continue
            if n <= 0: raise OSError(errno.EIO, 'short temporary hash-page write')
            remaining = remaining[n:]; offset += n
        self._tag(index, self._digest(index,data))

    def _page(self, index):
        if self.file is None: raise ValueError('closed hash storage')
        if index in self.pages:
            self.pages.move_to_end(index)
            return self.pages[index]
        if len(self.pages) >= self.capacity:
            old, (data, dirty) = next(iter(self.pages.items()))
            if dirty: self._write(old, data)
            del self.pages[old]
        offset = index*PAGE
        length = min(PAGE, self.size-offset)
        data = bytearray()
        while len(data) < length:
            try: chunk = os.pread(self.file.fileno(), length-len(data), offset+len(data))
            except InterruptedError: continue
            if not chunk: raise OSError(errno.EIO, 'short temporary hash-page read')
            data.extend(chunk)
        expected = self._tag(index)
        if (expected == bytes(NODE) and any(data)) or (expected != bytes(NODE) and self._digest(index,data) != expected):
            raise ValueError('temporary hash-page integrity mismatch')
        entry = [data, False]
        self.pages[index] = entry
        return entry

    def get(self, node):
        if type(node) is not int or not 0 <= node < self.size//NODE:
            raise ValueError('hash node outside geometry')
        page, offset = divmod(node*NODE, PAGE)
        data, _ = self._page(page)
        return bytes(data[offset:offset+NODE])

    def set(self, node, value):
        if type(node) is not int or not 0 <= node < self.size//NODE or len(value) != NODE:
            raise ValueError('hash node outside geometry or invalid digest')
        page, offset = divmod(node*NODE, PAGE)
        entry = self._page(page)
        entry[0][offset:offset+NODE] = value
        entry[1] = True

    def close(self):
        file = getattr(self, 'file', None)
        if file is not None:
            self.file = None
            self.pages.clear()
            if isinstance(self.tags, Nodes): self.tags.close()
            self.tags = None
            file.close()

    def __del__(self):
        self.close()
