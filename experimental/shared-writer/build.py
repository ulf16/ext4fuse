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
parser.add_argument('--runtime-only', action='store_true', help='build only installed writer helpers')
args = parser.parse_args()
work = args.work.resolve()
work.mkdir(parents=True, exist_ok=True)

def pkg(*options):
    return shlex.split(subprocess.check_output(['pkg-config', *options, 'fuse3', 'ext2fs'], text=True))

subprocess.run(['pkg-config', '--atleast-version=1.47.0', 'ext2fs'], check=True)
compiler = shlex.split(os.environ.get('CC', 'cc'))
flags = ['-O1' if args.sanitize else '-O2', '-g', '-std=gnu99', '-Wall', '-Wextra',
         '-I' + str(here), '-I' + str(repo), '-DFUSE_USE_VERSION=31', '-D_FILE_OFFSET_BITS=64']
if sys.platform == 'darwin':
    flags += ['-DFUSE_DARWIN_ENABLE_EXTENSIONS=0', '-mmacosx-version-min=15.0']
if args.sanitize:
    flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
flags += shlex.split(os.environ.get('CPPFLAGS', '')) + shlex.split(os.environ.get('CFLAGS', ''))
flags += pkg('--cflags')
libs = shlex.split(os.environ.get('LDFLAGS', '')) + pkg('--libs', '--static')
jobs = {}
compiled = set()

def compile_source(source, name):
    output = work / (name + '.o')
    jobs[str(output)] = source
    return str(output)

def ensure(objects):
    for output in objects:
        if output not in compiled:
            subprocess.run(compiler + flags + ['-c', str(jobs[output]), '-o', output], check=True)
            compiled.add(output)

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
index = compile_source(here / 'directory-index.c', 'directory-index')
conversion = compile_source(here/'directory-convert.c','directory-convert')
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
native_unit = compile_source(here / 'native-inherit-unit.c', 'native-inherit-unit')
index_collision = compile_source(repo / 'test/collision-set.c', 'index-collision-fixture')
index_corrupt = compile_source(here / 'index-corrupt.c', 'index-corrupt')
candidate = compile_source(here / 'journal-candidate.c', 'journal-candidate')
snapshot = compile_source(here / 'metadata-snapshot.c', 'metadata-snapshot')
index_scale = compile_source(here/'index-scale-fixture.c','index-scale-fixture')
index_cache = compile_source(here/'index-cache-unit.c','index-cache-unit')
index_incremental = compile_source(here/'index-incremental-unit.c','index-incremental-unit')
index_convert = compile_source(here/'index-convert-unit.c','index-convert-unit')
unit = compile_source(here / 'overlay-unit.c', 'overlay-unit')
bench = compile_source(here / 'read-bench.c', 'read-bench')
for name, objects in [('index-scale-fixture',[index_scale]), ('index-convert-unit',[overlay,manager,index,conversion,index_convert]), ('index-incremental-unit',[overlay,manager,index,index_incremental]), ('index-cache-unit',[overlay,manager,index,index_cache]), ('journal-candidate', [overlay, candidate]), ('metadata-snapshot', [overlay, manager, snapshot]), ('index-collision-fixture', [index_collision]), ('index-corrupt', [index_corrupt]), ('native-inherit-unit', [policy_core, policy_acl, native_unit]),
                      ('prototype', [overlay, manager, reader, prototype, *reader_objects]),
                      ('step-writer', [overlay, manager, reader, step, *reader_objects]),
                      ('mutation-producer', [overlay, manager, policy_core, policy_fs, policy_acl, grant, namespace, index, conversion, mutation, metadata, path_at, producer]),
                      ('handle-test-producer', [overlay, manager, handle_test]),
                      ('reader-server', [overlay, manager, policy_core, policy_fs, grant, namespace, index, conversion, mutation, path_at, directory_ref, directory_stream, mount_metadata, metadata, handles, reader, server, *server_readers]),
                      ('reader-watch', [overlay, reader, watch, *reader_objects]),
                      ('verify-reader', [overlay, reader, verify, *reader_objects]),
                      ('policy-unit', [policy_core, policy_acl, policy_unit]),
                      ('overlay-unit', [overlay, unit]),
                      ('read-bench', [overlay, bench, *reader_objects])]:
    if args.runtime_only and name not in ('mutation-producer', 'reader-server', 'journal-candidate', 'metadata-snapshot'):
        continue
    ensure(objects)
    subprocess.run(compiler + flags + objects + libs + ['-o', str(work / name)], check=True)
if not args.runtime_only:
    limited_index=work/'directory-index-limited.o'
    subprocess.run(compiler+flags+['-DINDEX_LEAF_BYTES=2048','-c',str(here/'directory-index.c'),'-o',str(limited_index)],check=True)
    subprocess.run(compiler+flags+[overlay,manager,str(limited_index),index_incremental]+libs+['-o',str(work/'index-incremental-limits')],check=True)
    limited = work / 'directory-stream-limited.o'
    subprocess.run(compiler + flags + ['-DDIRECTORY_STREAM_BYTES=4096','-DDIRECTORY_STREAM_TOTAL=8192',
                   '-c',str(here/'directory-stream.c'),'-o',str(limited)],check=True)
    objects=[overlay,manager,policy_core,policy_fs,grant,namespace,index,conversion,mutation,path_at,directory_ref,str(limited),mount_metadata,metadata,handles,reader,server,*server_readers]
    subprocess.run(compiler + flags + objects + libs + ['-o',str(work/'reader-server-stream-limits')],check=True)
    limited_handles=work/'handles-limited.o'
    subprocess.run(compiler+flags+['-DHANDLE_LIMIT=128','-DNODE_LIMIT=256','-c',str(here/'handles.c'),'-o',str(limited_handles)],check=True)
    objects=[overlay,manager,policy_core,policy_fs,grant,namespace,index,conversion,mutation,path_at,directory_ref,directory_stream,mount_metadata,metadata,str(limited_handles),reader,server,*server_readers]
    subprocess.run(compiler+flags+objects+libs+['-o',str(work/'reader-server-handle-limits')],check=True)
mount_frontend=compile_source(here/'mount-frontend.c','mount-frontend')
ensure([mount_frontend])
subprocess.run(compiler+flags+[mount_frontend]+libs+['-o',str(work/'mount-frontend')],check=True)
print('Built writer runtime in' if args.runtime_only else 'Built shared-writer experiments in', work)
