#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline managed-image write batches; permission policy belongs to future frontend."""
import argparse
import json
import os
from pathlib import Path
import struct
import chain
import inplace
from durable import directory
from credentials import Credentials

HEADER = struct.Struct('<IIIIIIQQ')
KINDS = {'write': 1, 'truncate': 2, 'create': 3}


def encode(operations, credentials=None):
    if not isinstance(operations, list) or not 1 <= len(operations) <= 64:
        raise ValueError('expected 1..64 operations')
    if credentials is not None and not isinstance(credentials, Credentials):
        raise ValueError('expected trusted Credentials')
    result = bytearray((b'E4REQ002' if credentials else b'E4REQ001') + struct.pack('<I', len(operations)))
    if credentials:
        context = credentials.encode()
        result += struct.pack('<I', len(context)) + context
    total = 0
    for op in operations:
        if not isinstance(op, dict) or op.get('kind') not in KINDS:
            raise ValueError('unknown operation')
        allowed = {'kind', 'path', 'offset', 'size', 'data_hex', 'mode', 'uid', 'gid'}
        if set(op) - allowed or not isinstance(op.get('path'), str):
            raise ValueError('invalid operation fields')
        path = op['path'].encode('utf-8')
        if not 1 <= len(path) <= 4096 or b'\0' in path:
            raise ValueError('invalid path')
        if credentials and op['kind'] == 'create' and set(op) & {'uid', 'gid'}:
            raise ValueError('creation ownership is derived from caller credentials')
        if op['kind'] == 'truncate':
            if set(op) != {'kind', 'path', 'size'}:
                raise ValueError('truncate needs path and size')
            offset = op['size']
            data = b''
        else:
            if 'size' in op or (op['kind'] == 'write' and set(op) - {'kind', 'path', 'offset', 'data_hex'}):
                raise ValueError('invalid write/create fields')
            text = op.get('data_hex', '')
            if not isinstance(text, str) or len(text) > 8 * 1024 * 1024:
                raise ValueError('data limit')
            data = bytes.fromhex(text)
            offset = op.get('offset', 0)
            if op['kind'] == 'create' and offset:
                raise ValueError('create offset must be zero')
        mode, uid, gid = op.get('mode', 0o644), op.get('uid', credentials.uid if credentials else os.getuid()), op.get('gid', credentials.gid if credentials else os.getgid())
        for name, value, maximum in (('offset', offset, 64 * 1024 * 1024), ('mode', mode, 0o777), ('uid', uid, 2**32-1), ('gid', gid, 2**32-1)):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError('invalid ' + name)
        total += len(data)
        if total > 4 * 1024 * 1024 or offset + len(data) > 64 * 1024 * 1024:
            raise ValueError('transaction bounds')
        result += HEADER.pack(KINDS[op['kind']], len(path), mode, uid, gid, 0, offset, len(data)) + path + data
    return result


def apply(root, producer, operations, credentials=None):
    request = encode(operations, credentials)
    with chain.locked(root) as root:
        return apply_encoded_locked(root, producer, request)


def apply_encoded_locked(root, producer, request):
    """Internal entry point; caller owns chain-lock for the entire operation."""
    state = chain.recover_locked(root)
    proposed = root / f"g-{state['head'] + 1:08d}"
    if state['head'] >= 99_999_998 or proposed.exists() or proposed.is_symlink():
        raise ValueError('invalid next generation')
    state['pending'] = state['head'] + 1
    inplace.seal(root, 'chain-state', state)
    proposed.mkdir(mode=0o700); directory(root)
    request_path = proposed / 'operations'
    request_path.write_bytes(request)
    adapter = proposed / 'request-producer'
    # repr creates Python string literals, never shell source. Data stays in
    # a bounded binary request retained with the generation until retirement.
    executable = str(Path(producer).absolute())
    adapter.write_text('#!/usr/bin/env python3\nimport os,sys\nos.environ["EXT4_MUTATION_REQUEST"] = ' + repr(str(request_path)) + '\nos.execv(' + repr(executable) + ', [' + repr(executable) + '] + sys.argv[1:])\n')
    adapter.chmod(0o700)
    inplace.capture_overlay(root / 'image.img', proposed, adapter)
    return chain.recover_locked(root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root'); parser.add_argument('producer'); parser.add_argument('operations', type=Path)
    args = parser.parse_args()
    if args.operations.stat().st_size > 9 * 1024 * 1024:
        raise ValueError('oversized request JSON')
    print(json.dumps(apply(args.root, args.producer, json.loads(args.operations.read_text())), sort_keys=True))
