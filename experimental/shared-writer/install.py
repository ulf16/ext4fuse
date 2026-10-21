#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Install an isolated writer runtime; never replaces the read-only ext4fuse."""
import argparse
import ast
import json
import os
from pathlib import Path
import shlex
import shutil
import sys

HERE = Path(__file__).resolve().parent
BINARIES = ('mutation-producer', 'reader-server', 'mount-frontend', 'journal-candidate', 'metadata-snapshot')
MODULES = ('writer_cli.py', 'block-log.py', 'chain.py', 'credentials.py', 'device_admission.py',
           'device-writer.py', 'direct_device.py', 'direct-journal-producer.py', 'durable.py',
           'image_io.py', 'inplace.py', 'journal-producer.py', 'journal_candidate.py',
           'journal_recovery.py', 'live_device.py', 'merkle.py', 'merkle_store.py', 'mount-broker.py',
           'mount_control.py', 'mount_state.py', 'native_acl.py', 'progress.py', 'session.py', 'write-api.py')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix', type=Path, required=True)
    p.add_argument('--build-dir', type=Path, required=True)
    p.add_argument('--destdir', type=Path, help='staging root; launcher uses final prefix')
    p.add_argument('--python', type=Path, default=Path(sys.executable))
    p.add_argument('--tools-dir', type=Path, help='e2fsprogs binary directory, including keg-only Homebrew installs')
    p.add_argument('--version', required=True)
    args = p.parse_args()
    prefix = args.prefix.absolute()
    python = args.python.absolute()
    if not python.is_file() or not os.access(python, os.X_OK):
        p.error('--python must be an executable interpreter')
    # Kernel shebang parsing cannot represent whitespace in an interpreter path.
    if any(c.isspace() for c in str(python)):
        p.error('interpreter path cannot contain whitespace')
    for name in BINARIES:
        path = args.build_dir / name
        if not path.is_file() or not os.access(path, os.X_OK):
            p.error('missing built helper: ' + str(path))
    target = args.destdir.absolute() / prefix.relative_to('/') if args.destdir else prefix
    lib = target / 'libexec' / 'ext4fuse-writer'
    native = lib / 'native'
    native.mkdir(parents=True, exist_ok=True)
    for name in BINARIES:
        shutil.copy2(args.build_dir / name, native / name)
    for name in MODULES:
        text = (HERE / name).read_text()
        if text.startswith('#!'):
            text = text.split('\n', 1)[1]
        # Helpers launched by Session use this same isolated interpreter.
        tree = ast.parse(text)
        doc = tree.body[0] if ast.get_docstring(tree) is not None else None
        lines = text.splitlines(keepends=True)
        offset = doc.end_lineno if doc else 0
        lines.insert(offset, 'import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).resolve().parent))\n')
        (lib / name).write_text('#!' + str(python) + ' -I\n' + ''.join(lines))
        (lib / name).chmod(0o755 if name in ('journal-producer.py', 'direct-journal-producer.py') else 0o644)
    (lib / 'runtime.json').write_text(json.dumps(dict(format=1, version=args.version,
        tools=str(args.tools_dir.absolute()) if args.tools_dir else ''), sort_keys=True) + '\n')
    command = target / 'bin' / 'ext4fuse-writer'
    command.parent.mkdir(parents=True, exist_ok=True)
    command.write_text('#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' -I ' +
                       shlex.quote(str(prefix / 'libexec' / 'ext4fuse-writer' / 'writer_cli.py')) + ' "$@"\n')
    command.chmod(0o755)
    doc = target / 'share' / 'doc' / 'ext4fuse-writer'
    doc.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HERE / 'WORKFLOW.md', doc / 'WORKFLOW.md')
    shutil.copy2(HERE / 'DURABILITY.md', doc / 'DURABILITY.md')
    shutil.copy2(HERE / 'README.md', doc / 'ENGINE.md')
    shutil.copy2(HERE.parents[1] / 'COPYING', doc / 'COPYING')
    man = target / 'share' / 'man' / 'man1'
    man.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HERE / 'ext4fuse-writer.1', man / 'ext4fuse-writer.1')
    print('Installed ' + str(command))


if __name__ == '__main__':
    main()
