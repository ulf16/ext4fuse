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
policy_core = compile_source(here / 'policy-core.c', 'policy-core')
policy_fs = compile_source(here / 'policy-fs.c', 'policy-fs')
policy_acl = compile_source(repo / 'acl.c', 'policy-acl')
metadata = compile_source(here/'metadata.c','metadata')
mount_metadata = compile_source(here/'mount-metadata.c','mount-metadata')
path_at = compile_source(here / 'path-at.c', 'path-at')
directory_stream = compile_source(here / 'directory-stream.c', 'directory-stream')
directory_ref = compile_source(here / 'directory-ref.c', 'directory-ref')
namespace = compile_source(here / 'namespace.c', 'namespace')
grant = compile_source(here / 'grant.c', 'grant')
handles = compile_source(here / 'handles.c', 'handles')
mutation = compile_source(here / 'mutation.c', 'mutation')
handle_test = compile_source(here / 'handle-test-producer.c', 'handle-test-producer')
producer = compile_source(here / 'mutation-producer.c', 'mutation-producer')
step = compile_source(here / 'step-writer.c', 'step-writer')
verify = compile_source(here / 'verify-reader.c', 'verify-reader')
session_super = compile_source(here / 'super-session.c', 'super-session')
server_readers = [obj for obj in reader_objects if Path(obj).name != 'reader-super.o'] + [session_super]
server = compile_source(here / 'reader-server.c', 'reader-server')
watch = compile_source(here / 'reader-watch.c', 'reader-watch')
policy_unit = compile_source(here / 'policy-unit.c', 'policy-unit')
unit = compile_source(here / 'overlay-unit.c', 'overlay-unit')
bench = compile_source(here / 'read-bench.c', 'read-bench')
for name, objects in [('prototype', [overlay, manager, reader, prototype, *reader_objects]),
                      ('step-writer', [overlay, manager, reader, step, *reader_objects]),
                      ('mutation-producer', [overlay, manager, policy_core, policy_fs, policy_acl, grant, namespace, mutation, metadata, path_at, producer]),
                      ('handle-test-producer', [overlay, manager, handle_test]),
                      ('reader-server', [overlay, manager, policy_core, policy_fs, grant, namespace, mutation, path_at, directory_ref, directory_stream, mount_metadata, metadata, handles, reader, server, *server_readers]),
                      ('reader-watch', [overlay, reader, watch, *reader_objects]),
                      ('verify-reader', [overlay, reader, verify, *reader_objects]),
                      ('policy-unit', [policy_core, policy_acl, policy_unit]),
                      ('overlay-unit', [overlay, unit]),
                      ('read-bench', [overlay, bench, *reader_objects])]:
    subprocess.run(compiler + flags + objects + libs + ['-o', str(work / name)], check=True)
limited = work / 'directory-stream-limited.o'
subprocess.run(compiler + flags + ['-DDIRECTORY_STREAM_BYTES=4096','-DDIRECTORY_STREAM_TOTAL=8192',
               '-c',str(here/'directory-stream.c'),'-o',str(limited)],check=True)
objects=[overlay,manager,policy_core,policy_fs,grant,namespace,mutation,path_at,directory_ref,str(limited),mount_metadata,metadata,handles,reader,server,*server_readers]
subprocess.run(compiler + flags + objects + libs + ['-o',str(work/'reader-server-stream-limits')],check=True)
mount_frontend=compile_source(here/'mount-frontend.c','mount-frontend')
subprocess.run(compiler+flags+[mount_frontend]+libs+['-o',str(work/'mount-frontend')],check=True)
print('Built shared-writer experiments in', work)
