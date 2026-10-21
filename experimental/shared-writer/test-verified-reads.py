#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verified bytes, hidden media corruption, native consumers and failure latch."""
import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import random
import socket
import struct
import subprocess
import tempfile
import time
from unittest.mock import patch

import chain
import image_io
import merkle
import session
from verified_reads import Reader, REQUEST, REPLY, exact

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--fixtures', type=Path)
a = p.parse_args()
a.work.mkdir(parents=True, exist_ok=True)
checks = 0


def check(value):
    global checks
    assert value
    checks += 1


def denied(call):
    try:
        call()
    except (ValueError, OSError):
        check(True)
    else:
        raise AssertionError('unchecked bytes accepted')


def alter(path, offset):
    with path.open('r+b', buffering=0) as f:
        f.seek(offset)
        old = f.read(1)
        f.seek(offset)
        f.write(bytes([old[0] ^ 0x80]))


with tempfile.TemporaryDirectory(prefix='verified-', dir=a.work) as tmp:
    tmp = Path(tmp)
    image = tmp / 'arbitrary.img'
    data = random.Random(98).randbytes(2 * merkle.CHUNK + merkle.PAGE)
    image.write_bytes(data)
    info = image.stat()
    state = dict(device=info.st_dev, inode=info.st_ino, size=len(data))
    with image.open('rb') as f:
        tree = merkle.scan(f, state)
    state['sha256'] = tree.root()
    reader = Reader(image, lambda: (state, tree), cache_chunks=1)
    def native(offset, length):
        with image_io.verified(image, reader):
            with image_io.child_process(image) as options:
                process = subprocess.Popen([a.work/'verified-read-unit',image,str(offset),str(length)],
                                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,**options)
            output, errors = process.communicate(timeout=30)
        check(process.returncode == 0)
        check(output == data[offset:offset+length])

    try:
        native(merkle.CHUNK-17,35)
        native(len(data)-32,32)
        # Lost consumers cannot poison another process's framing or leave
        # threads/fds accumulating over repeated transactions.
        for _ in range(8):
            with reader.channel() as client:
                client.sendall(REQUEST.pack(0,merkle.CHUNK))
                exact(client,REPLY.size)
                # Close without consuming the payload.
            native(0,32)
        deadline=time.monotonic()+5
        while reader.channels and time.monotonic()<deadline:time.sleep(.01)
        check(not reader.channels)
        # Malformed or truncated replies must never cause a native raw-read
        # fallback, even though this ordinary image is readable.
        for reply in (b'',bytes(3),REPLY.pack(errno.EIO,0),REPLY.pack(0,4097),REPLY.pack(0,4096)+b'partial'):
            server,client=socket.socketpair()
            env=dict(os.environ,EXT4_VERIFIED_READ=f'{client.fileno()},{info.st_dev},{info.st_ino},{info.st_size}')
            env.pop('EXT4_DEVICE_VIEW',None)
            process=subprocess.Popen([a.work/'verified-read-unit',image,'0','4096'],
                                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     env=env,pass_fds=(client.fileno(),))
            client.close()
            exact(server,REQUEST.size)
            server.sendall(reply)
            server.close()
            output,_=process.communicate(timeout=10)
            check(process.returncode!=0 and not output)
        for config in ('garbage',f'0,{info.st_dev},{info.st_ino+1},{info.st_size}'):
            result=subprocess.run([a.work/'verified-read-unit',image,'0','4096'],capture_output=True,
                                  env=dict(os.environ,EXT4_VERIFIED_READ=config),timeout=10)
            check(result.returncode!=0 and not result.stdout)
        for offset, length in ((0,0), (0,32), (merkle.CHUNK-17,35),
                               (len(data)-32,32), (len(data),0)):
            check(reader.read(offset, length) == data[offset:offset+length])
            check(len(reader.cache) <= 1)
        with image_io.verified(image, reader):
            denied(lambda: image_io.child(image))
            with image_io.child_process(image) as options:
                check('EXT4_DEVICE_VIEW' not in options['env'])
                check(len(options['pass_fds']) == 1)
        # Simulate silent media damage: identity/timestamp unchanged. Verification
        # must fail before returning any bytes, including undamaged requested
        # bytes in a chunk with corruption elsewhere.
        reader.cache.clear()
        alter(image, merkle.CHUNK + 901)
        with patch('merkle.fingerprint', return_value=tree.stamp):
            denied(lambda: reader.read(merkle.CHUNK, 1))
        check(reader.failed.is_set())
        denied(lambda: reader.read(0,1))
        with reader.channel() as client:
            client.sendall(REQUEST.pack(0,16))
            check(REPLY.unpack(exact(client, REPLY.size)) == (errno.EIO,0))
    finally:
        reader.close()
    check(not reader.channels)

    # Real native reader and mutation producer use the same verified channel.
    fixtures = a.fixtures or a.work / 'fixtures'
    source = next(iter(sorted(fixtures.glob('*-csum1.img'))))
    for mode in ('reader', 'producer', 'stamp', 'bounds', 'short'):
        root = tmp / mode
        chain.clone(source, root)
        s = session.Session(root, a.work/'mutation-producer', a.work/'reader-server')
        try:
            original = s.read('/existing-file',0,64)
            check(len(original) == 64)
            s.apply([dict(kind='write',path='/existing-file',offset=0,data_hex=b'checked write'.hex())])
            check(s.read('/existing-file',0,13) == b'checked write')
            check(s._verified.generation[1] == s.state['sha256'])
            image = root / 'image.img'
            s._verified.cache.clear()
            if mode == 'bounds':
                with s._verified.channel() as client:
                    client.sendall(REQUEST.pack(s.state['size'],1))
                    check(REPLY.unpack(exact(client,8)) == (errno.EIO,0))
                denied(lambda: s.read('/existing-file',0,1))
            elif mode == 'short':
                # EOF cannot be accepted as zeros or a truncated successful read.
                with image.open('r+b') as f:f.truncate(4096)
                denied(lambda: s._rpc(4))
            else:
                alter(image, 4095)  # authenticated metadata chunk, outside requested superblock bytes
                stamp = s._integrity.stamp
                with (patch('merkle.fingerprint', return_value=stamp)
                      if mode != 'stamp' else contextlib.nullcontext()):
                    if mode == 'producer':
                        # Producer failure must never enter the generic rescan
                        # recovery branch and bless the damaged image.
                        with patch('chain.recover_integrity_locked', side_effect=AssertionError('corruption rescan')):
                            denied(lambda: s.apply([dict(kind='write',path='/existing-file',offset=0,data_hex='61')]))
                    else:
                        denied(lambda: s._rpc(4))
                check(s._verified.failed.is_set())
            check(s._failed)
            denied(lambda: s.read('/existing-file',0,1))
        finally:
            s.close()
        check(not s._verified.channels)

result = dict(checks=checks, status='passed')
(a.work/'verified-reads-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
