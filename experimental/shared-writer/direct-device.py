#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Initialize, mount and recover explicitly selected devices without a data shadow."""
import argparse,importlib.util,os
from pathlib import Path
import session
from credentials import Credentials
from direct_device import Controller,init
spec=importlib.util.spec_from_file_location('direct_mount',Path(__file__).with_name('mount-broker.py'));broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)
p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
for action in ('init','mount','recover'):
 cmd=sub.add_parser(action);cmd.add_argument('device');cmd.add_argument('root',type=Path);cmd.add_argument('--work',type=Path,required=True)
 cmd.add_argument('--check-bytes',type=int,default=1024**3,help='maximum metadata scratch bytes emitted by consistency-check exporter')
 cmd.add_argument('--journal-bytes',type=int,default=256*1024**2)
 if action=='init':cmd.add_argument('--recover-journal',action='store_true')
 if action=='mount':
  cmd.add_argument('--mountpoint',type=Path,required=True);cmd.add_argument('--control-socket',type=Path);cmd.add_argument('--checkpoint-every',type=int,default=64)
a=p.parse_args()
if not 4096<=a.check_bytes<=2**40:p.error('metadata scratch budget must be 4 KiB..1 TiB')
if a.action=='init':print(init(a.device,a.root,a.work,check_bytes=a.check_bytes,recover_journal=a.recover_journal,journal_bytes=a.journal_bytes));raise SystemExit(0)
work=a.work.resolve()
if a.action=='mount':
 _,work,mount=broker.validate_mount(a.root/'chain',work,a.mountpoint)
 root=a.root.resolve()
 if mount.is_relative_to(root) or root.is_relative_to(mount):raise ValueError('mountpoint must be outside device recovery directory')
mask=os.umask(0);os.umask(mask)
with Controller(a.root,a.device,work,check_bytes=a.check_bytes,journal_bytes=a.journal_bytes) as target:
 with session.Session(target.chain,work/'mutation-producer',work/'reader-server',Credentials(os.getuid(),os.getgid(),(),mask),commit_sink=target,checkpoint_every=a.checkpoint_every if a.action=='mount' else 0) as s:
  if a.action=='mount':broker.run_mount(s,work,mount,a.control_socket)
 target.finish()
print('Direct device is synchronized, checked and cleanly published.')
