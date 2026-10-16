# SPDX-License-Identifier: GPL-2.0-only
"""Ephemeral paged hash nodes; never a trusted persistent recovery index."""
from collections import OrderedDict
import errno
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
        self.capacity = max(1, budget // PAGE)
        self.pages = OrderedDict()
        self.file = tempfile.TemporaryFile(prefix='ext4-hash-nodes-')
        try: self.file.truncate(size)
        except BaseException:
            self.close(); raise

    def _write(self, index, data):
        offset = index*PAGE
        remaining = memoryview(data)
        while remaining:
            try: n = os.pwrite(self.file.fileno(), remaining, offset)
            except InterruptedError: continue
            if n <= 0: raise OSError(errno.EIO, 'short temporary hash-page write')
            remaining = remaining[n:]; offset += n

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
            file.close()

    def __del__(self):
        self.close()
