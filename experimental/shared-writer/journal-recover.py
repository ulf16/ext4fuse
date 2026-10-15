#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Recover an internal native journal into a managed image; source stays read-only."""
import argparse,json
from pathlib import Path
import chain
from journal_recovery import managed
p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
c=sub.add_parser('image');c.add_argument('source',type=Path);c.add_argument('root',type=Path)
c=sub.add_parser('chain');c.add_argument('root',type=Path)
a=p.parse_args()
if a.action=='image':chain.clone(a.source,a.root)
print(json.dumps(managed(a.root),sort_keys=True))
