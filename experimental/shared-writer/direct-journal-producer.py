#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse,errno,struct,sys
from journal_candidate import producer
p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('--stream',action='store_true',required=True);p.add_argument('--work',required=True);p.add_argument('--journal-bytes',type=int,required=True);a=p.parse_args()
try:producer(a.source,a.work,a.journal_bytes)
except (OSError,ValueError) as error:
 print('Direct journal recovery refused: '+str(error),file=sys.stderr)
 try:
  code=error.errno if isinstance(error,OSError) and error.errno and 0<error.errno<4096 else errno.EIO
  sys.stdout.buffer.write(struct.pack('<8sQQ',b'E4ER0001',code,0));sys.stdout.buffer.flush()
 except BrokenPipeError:pass
 raise SystemExit(1)
