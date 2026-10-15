#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import errno,struct,sys
from journal_recovery import producer
if len(sys.argv)!=3 or sys.argv[2]!='--stream':raise SystemExit(2)
try:producer(sys.argv[1])
except (OSError,ValueError) as error:
 print('Native journal recovery refused: '+str(error),file=sys.stderr)
 sys.stdout.buffer.write(struct.pack('<8sQQ',b'E4ER0001',error.errno if isinstance(error,OSError) and error.errno else errno.EIO,0));sys.stdout.buffer.flush()
 raise SystemExit(1)
