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
KINDS = {'write': 1, 'truncate': 2, 'create': 3, 'link': 4, 'rename': 5, 'unlink': 6, 'mkdir': 7, 'rmdir': 8, 'symlink': 9, 'chmod':11, 'chown':12, 'utimens':13, 'setxattr':14, 'removexattr':15}


def encode(operations, credentials=None, *, _at=False):
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
        if not isinstance(op, dict) or op.get('kind') not in (dict(KINDS,open=10) if _at else KINDS):
            raise ValueError('unknown operation')
        allowed = {'kind', 'path', 'offset', 'size', 'data_hex', 'mode', 'uid', 'gid', 'target'} | ({'flags','follow_symlinks','atime','mtime','name','value_hex'} if _at else set())
        if set(op) - allowed or not isinstance(op.get('path'),(str,bytes) if _at else str):
            raise ValueError('invalid operation fields')
        path = os.fsencode(op['path']) if _at else op['path'].encode('utf-8')
        if not 1 <= len(path) <= 4096 or b'\0' in path:
            raise ValueError('invalid path')
        kind=op['kind']
        if 'follow_symlinks' in op and type(op['follow_symlinks']) is not bool:
            raise ValueError('invalid follow option')
        metadata=kind in ('chmod','chown','utimens','setxattr','removexattr')
        if metadata and not _at:raise ValueError('metadata requires trusted at/session context')
        namespace=kind in ('link','rename','unlink','mkdir','rmdir','symlink')
        creating=kind in ('create','mkdir','symlink')
        if namespace and not _at:
            candidates=(op['path'],op['target']) if kind in ('link','rename') and 'target' in op else (op['path'],)
            for candidate in candidates:
                if not isinstance(candidate,str) or not candidate.startswith('/') or candidate=='/' or any(c in ('','.','..') or len(c.encode('utf-8'))>255 for c in candidate[1:].split('/')):
                    raise ValueError('invalid namespace path')
        if credentials and creating and set(op)&{'uid','gid'}:
            raise ValueError('creation ownership is derived from caller credentials')
        mode=op.get('mode',0o777 if kind=='mkdir' else 0o644)
        uid=op.get('uid',credentials.uid if credentials else os.getuid())
        gid=op.get('gid',credentials.gid if credentials else os.getgid())
        if metadata:
            allowed_fields={'kind','path','follow_symlinks'}
            mode=uid=gid=offset=0;data=b''
            if kind=='chmod':
                allowed_fields.add('mode');mode=op.get('mode')
            elif kind=='chown':
                allowed_fields|={'uid','gid'}
                uid=op.get('uid',-1);gid=op.get('gid',-1)
                uid=2**32-1 if uid==-1 else uid;gid=2**32-1 if gid==-1 else gid
            elif kind=='utimens':
                allowed_fields|={'atime','mtime'}
                for field in ('atime','mtime'):
                    value=op.get(field)
                    if value is None:sec,ns=0,2**64-1
                    elif value=='omit':sec,ns=0,2**64-2
                    elif isinstance(value,(tuple,list)) and len(value)==2:
                        sec,ns=value
                        if type(sec) is not int or not -2**31<=sec<=15032385535 or type(ns) is not int or not 0<=ns<10**9:raise ValueError('invalid timestamp')
                    else:raise ValueError('invalid timestamp')
                    data+=struct.pack('<qQ',sec,ns)
            else:
                allowed_fields.add('name')
                name=op.get('name')
                if not isinstance(name,(str,bytes)):raise ValueError('invalid attribute name')
                name=os.fsencode(name)
                if not 1<=len(name)<=255 or b'\0' in name:raise ValueError('invalid attribute name')
                data=struct.pack('<I',len(name))+name
                if kind=='setxattr':
                    allowed_fields|={'value_hex','flags'};mode=op.get('flags',0)
                    value=op.get('value_hex')
                    if not isinstance(value,str) or len(value)>2*65536:raise ValueError('attribute value limit')
                    data+=bytes.fromhex(value)
                    if type(mode) is not int or not 0<=mode<=2:raise ValueError('invalid attribute flags')
            if set(op)-allowed_fields:raise ValueError('invalid metadata fields')
        elif namespace:
            allowed_fields={'kind','path'}
            if kind in ('link','rename','symlink'):allowed_fields.add('target')
            if kind=='mkdir':allowed_fields|={'mode','uid','gid'}
            if kind=='symlink':allowed_fields|={'uid','gid'}
            if _at and kind=='link':allowed_fields.add('follow_symlinks')
            if set(op)-allowed_fields:raise ValueError('invalid namespace fields')
            if kind in ('link','rename','symlink'):
                target=op.get('target')
                if not isinstance(target,(str,bytes) if _at else str):raise ValueError('invalid target')
                data=os.fsencode(target) if _at else target.encode('utf-8')
                if not data or len(data)>4096 or b'\0' in data:raise ValueError('invalid target')
            else:data=b''
            offset=0
            if not creating:mode=uid=gid=0
            if kind=='symlink':mode=0o777
        elif kind=='open' and _at:
            if set(op)-{'kind','path','mode','flags'}:raise ValueError('invalid open fields')
            offset=op.get('flags');data=b'';uid=gid=0
        elif kind=='truncate':
            if set(op)!={'kind','path','size'}:raise ValueError('truncate needs path and size')
            offset=op['size'];data=b''
        else:
            fields={'kind','path','offset','data_hex'}
            if kind=='create':fields|={'mode','uid','gid'}
            if set(op)-fields:raise ValueError('invalid write/create fields')
            text=op.get('data_hex','')
            if not isinstance(text,str) or len(text)>8*1024*1024:raise ValueError('data limit')
            data=bytes.fromhex(text);offset=op.get('offset',0)
            if kind=='create' and offset:raise ValueError('create offset must be zero')
        for name,value,maximum in (('offset',offset,(2**63-1)),('mode',mode,0o7777 if kind=='chmod' else 0o1777 if kind=='mkdir' else 0o777),('uid',uid,2**32-1),('gid',gid,2**32-1)):
            if type(value) is not int or not 0<=value<=maximum:raise ValueError('invalid '+name)
        total += len(data)
        if total > 4 * 1024 * 1024 or offset + len(data) > (2**63-1):
            raise ValueError('transaction bounds')
        result += HEADER.pack(10 if kind=='open' else KINDS[kind], len(path), mode, uid, gid, int(op.get('follow_symlinks',metadata)), offset, len(data)) + path + data
    return result


def encode_grant(credentials, grant, kind, offset=0, data=b''):
    """Internal trusted broker format; never accept inode grants from JSON."""
    if not isinstance(credentials, Credentials) or not isinstance(grant, bytes) or len(grant) != 16:
        raise ValueError('invalid broker grant')
    if kind not in ('write', 'truncate') or type(offset) is not int or not 0 <= offset <= (2**63-1):
        raise ValueError('invalid handle operation')
    if not isinstance(data, bytes) or len(data)>4*1024*1024 or (kind=='truncate' and data):
        raise ValueError('invalid handle payload')
    inode, generation, access, flags = struct.unpack('<IIII',grant)
    if not inode or not 1<=access<=3 or flags>1 or not access&2:
        raise ValueError('invalid write grant')
    if (kind=='truncate' or not flags) and offset+len(data)>(2**63-1):
        raise ValueError('transaction bounds')
    context=credentials.encode()
    return (b'E4REQ003'+struct.pack('<II',1,len(context))+context+
            HEADER.pack(KINDS[kind],16,0,0,0,0,offset,len(data))+grant+data)


def encode_broker(operations, credentials, pins):
    """Private V4 envelope: live inode identities, never accepted from JSON."""
    if not isinstance(pins,bytes) or len(pins)%8 or len(pins)>128*8:
        raise ValueError('invalid pin snapshot')
    if operations:
        request=encode(operations,credentials)
        count=request[8:12]
        if credentials:
            size=struct.unpack('<I',request[12:16])[0]
            context=request[12:16+size]; records=request[16+size:]
        else:
            context=struct.pack('<I',0); records=request[12:]
    else:
        if operations != []: raise ValueError('expected operation list')
        count=struct.pack('<I',0)
        raw=credentials.encode() if credentials else b''
        context=struct.pack('<I',len(raw))+raw; records=b''
    return b'E4REQ004'+count+context+struct.pack('<I',len(pins)//8)+pins+records


def encode_at(operations, credentials, pins, bases):
    """Private V5: per-operation directory capabilities, resolved in staged state."""
    if not isinstance(credentials,Credentials) or len(bases)!=len(operations):
        raise ValueError('invalid at context')
    request=encode(operations,credentials,_at=True)
    n=struct.unpack_from('<I',request,12)[0]
    body=request[16+n:];offset=0;records=bytearray()
    for pair in bases:
        if len(pair)!=2 or any(not isinstance(g,bytes) or len(g)!=16 for g in pair):
            raise ValueError('invalid directory capability')
        fields=HEADER.unpack_from(body,offset);length=HEADER.size+fields[1]+fields[-1]
        records+=pair[0]+pair[1]+body[offset:offset+length];offset+=length
    if not isinstance(pins,bytes) or len(pins)%8 or len(pins)>1024:
        raise ValueError('invalid pins')
    return b'E4REQ005'+request[8:16+n]+struct.pack('<I',len(pins)//8)+pins+records


def encode_metadata_grant(operation, credentials, grant, pins):
    """Private V6: live handle metadata, with current authorization and pins."""
    if not isinstance(grant,bytes) or len(grant)!=16:raise ValueError('invalid metadata grant')
    if not isinstance(pins,bytes) or len(pins)%8 or len(pins)>1024:raise ValueError('invalid pins')
    op=dict(operation,path='/');request=encode([op],credentials,_at=True)
    n=struct.unpack_from('<I',request,12)[0];body=request[16+n:];fields=list(HEADER.unpack_from(body));pathbytes=fields[1]
    fields[1]=16;fields[5]=0
    return b'E4REQ006'+request[8:16+n]+struct.pack('<I',len(pins)//8)+pins+HEADER.pack(*fields)+grant+body[HEADER.size+pathbytes:]


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
    inplace.capture_overlay(root / 'image.img', proposed, adapter, expected_base=state['sha256'])
    return chain.recover_locked(root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root'); parser.add_argument('producer'); parser.add_argument('operations', type=Path)
    args = parser.parse_args()
    if args.operations.stat().st_size > 9 * 1024 * 1024:
        raise ValueError('oversized request JSON')
    print(json.dumps(apply(args.root, args.producer, json.loads(args.operations.read_text())), sort_keys=True))
