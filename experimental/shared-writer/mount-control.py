#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private local control for mounted allocation where native syscalls are absent."""
import argparse,json,socket
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--socket',type=Path,required=True);p.add_argument('operation',choices=('allocate','keep-size','punch'));p.add_argument('path',help='absolute path inside the mounted filesystem');p.add_argument('offset',type=int);p.add_argument('length',type=int);a=p.parse_args()
if not a.path.startswith('/') or '\0' in a.path or len(a.path.encode())>4096:raise ValueError('virtual path')
if not 0<=a.offset<2**63 or not 0<a.length<=2**63-1-a.offset:raise ValueError('range bounds')
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(120);s.connect(str(a.socket));s.sendall(json.dumps(dict(operation=a.operation,path=a.path,offset=a.offset,length=a.length)).encode()+b'\n')
 with s.makefile('rb') as f:reply=json.loads(f.readline(4097))
 if reply.get('error'):raise OSError(reply['error'],reply['message'])
 print(json.dumps(reply,sort_keys=True))
