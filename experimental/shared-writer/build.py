#!/usr/bin/env python3
"""Build isolated experiments; production targets and build objects are untouched."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys

here = Path(__file__).resolve().parent
repo = here.parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()
work = args.work.resolve()
work.mkdir(parents=True, exist_ok=True)

def pkg(*options):
    return shlex.split(subprocess.check_output(['pkg-config', *options, 'fuse3', 'ext2fs'], text=True))

compiler = shlex.split(os.environ.get('CC', 'cc'))
flags = ['-O1' if args.sanitize else '-O2', '-g', '-std=gnu99', '-Wall', '-Wextra',
         '-I' + str(here), '-I' + str(repo), '-DFUSE_USE_VERSION=31', '-D_FILE_OFFSET_BITS=64']
if sys.platform == 'darwin':
    flags += ['-DFUSE_DARWIN_ENABLE_EXTENSIONS=0', '-mmacosx-version-min=15.0']
if args.sanitize:
    flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
flags += pkg('--cflags')
libs = pkg('--libs', '--static')

def compile_source(source, name):
    output = work / (name + '.o')
    subprocess.run(compiler + flags + ['-c', str(source), '-o', str(output)], check=True)
    return str(output)

reader_objects = []
for line in (repo / 'Makefile').read_text().splitlines():
    if line.startswith('SOURCES += '):
        for name in line.removeprefix('SOURCES += ').split():
            if name not in ('disk.o', 'fuse-main.o'):
                reader_objects.append(compile_source(repo / name.replace('.o', '.c'), 'reader-' + name[:-2]))
overlay = compile_source(here / 'overlay.c', 'overlay')
manager = compile_source(here / 'io-manager.c', 'io-manager')
reader = compile_source(here / 'reader.c', 'reader')
prototype = compile_source(here / 'prototype.c', 'prototype')
mutation = compile_source(here / 'mutation.c', 'mutation')
producer = compile_source(here / 'mutation-producer.c', 'mutation-producer')
step = compile_source(here / 'step-writer.c', 'step-writer')
verify = compile_source(here / 'verify-reader.c', 'verify-reader')
server = compile_source(here / 'reader-server.c', 'reader-server')
watch = compile_source(here / 'reader-watch.c', 'reader-watch')
unit = compile_source(here / 'overlay-unit.c', 'overlay-unit')
bench = compile_source(here / 'read-bench.c', 'read-bench')
for name, objects in [('prototype', [overlay, manager, reader, prototype, *reader_objects]),
                      ('step-writer', [overlay, manager, reader, step, *reader_objects]),
                      ('mutation-producer', [overlay, manager, mutation, producer]),
                      ('reader-server', [overlay, reader, server, *reader_objects]),
                      ('reader-watch', [overlay, reader, watch, *reader_objects]),
                      ('verify-reader', [overlay, reader, verify, *reader_objects]),
                      ('overlay-unit', [overlay, unit]),
                      ('read-bench', [overlay, bench, *reader_objects])]:
    subprocess.run(compiler + flags + objects + libs + ['-o', str(work / name)], check=True)
print('Built shared-writer experiments in', work)
