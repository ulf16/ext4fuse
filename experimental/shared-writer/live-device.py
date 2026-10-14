#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Initialize, mount or recover an explicitly selected continuously written device."""
import argparse
import importlib.util
import os
from pathlib import Path
import session
from credentials import Credentials
from live_device import Controller,init

spec=importlib.util.spec_from_file_location('mount_broker',Path(__file__).with_name('mount-broker.py'))
broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    initial=sub.add_parser('init');initial.add_argument('device');initial.add_argument('root',type=Path)
    for action in ('mount','recover'):
        command=sub.add_parser(action);command.add_argument('device');command.add_argument('root',type=Path)
        command.add_argument('--work',type=Path,required=True)
        command.add_argument('--checkpoint-every',type=int,default=64)
        if action=='mount':
            command.add_argument('--mountpoint',type=Path,required=True)
            command.add_argument('--control-socket',type=Path)
    a=p.parse_args()
    if a.action=='init':print(init(a.device,a.root));return
    work=a.work.resolve()
    if a.action=='mount':
        _,work,mount=broker.validate_mount(a.root/'chain',work,a.mountpoint)
        root=a.root.resolve()
        if mount.is_relative_to(root) or root.is_relative_to(mount):
            raise ValueError('mountpoint must be outside continuous device journal')
    mask=os.umask(0);os.umask(mask)
    with Controller(a.root,a.device) as target:
        with session.Session(target.chain,work/'mutation-producer',work/'reader-server',
                Credentials(os.getuid(),os.getgid(),(),mask),checkpoint_every=a.checkpoint_every,commit_sink=target) as s:
            if a.action=='mount':broker.run_mount(s,work,mount,a.control_socket)
        target.finish()
    print('Continuous device is synchronized, checked and cleanly published.')

if __name__=='__main__':main()
