#!/usr/bin/env python3
"""Optional warm-cache reader benchmark; never touches real disks or global caches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shlex
import shutil
import statistics
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixtures', type=Path, help='retain/reuse generated fixtures in this directory')
parser.add_argument('--output', type=Path, help='save measurements as JSON')
parser.add_argument('--mib', type=int, default=64)
parser.add_argument('--samples', type=int, default=3)
parser.add_argument('--native-linux', action='store_true', help='compare native ext4 using disposable read-only loop mounts and sudo')
args = parser.parse_args()
assert 8 <= args.mib <= 1024 and 1 <= args.samples <= 20
mkfs = shutil.which('mke2fs'); debugfs = shutil.which('debugfs'); fsck = shutil.which('e2fsck')
assert mkfs and debugfs and fsck, 'e2fsprogs sbin must be in PATH'
managed = args.fixtures is None
root = Path(tempfile.mkdtemp(prefix='ext4fuse-bulk-')) if managed else args.fixtures
root.mkdir(parents=True, exist_ok=True)
reader = os.environ.get('BULK_READER', './test/bulk-reader')
reference = root / 'reference-reader'
prefix = Path(mkfs).resolve().parent.parent
flags_env = dict(os.environ)
flags_env['PKG_CONFIG_PATH'] = str(prefix / 'lib/pkgconfig') + os.pathsep + flags_env.get('PKG_CONFIG_PATH', '')
flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', '--static', 'ext2fs'], env=flags_env, text=True))
subprocess.run([os.environ.get('CC', 'cc'), '-O2', 'test/bulk-reference.c', *flags, '-o', str(reference)], check=True)
def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()
payload = root / 'payload'
if not payload.exists():
    rng = random.Random(0x4f534655)
    with payload.open('wb') as file:
        for _ in range(args.mib): file.write(rng.randbytes(1024**2))
assert payload.stat().st_size == args.mib * 1024**2
source_hash = digest(payload)
results = []
for layout, options in [('extents', []), ('classic', ['-O', '^extent,^64bit,^flex_bg'])]:
    image = root / (layout + '.img')
    if not image.exists():
        with image.open('wb') as file: file.truncate((args.mib * 2 + 32) * 1024**2)
        subprocess.run([mkfs, '-q', '-F', '-t', 'ext4', '-b', '4096', *options, str(image)], capture_output=True, check=True)
        subprocess.run([debugfs, '-w', '-R', f'write {payload} /payload', str(image)], capture_output=True, check=True)
    subprocess.run([fsck, '-f', '-n', str(image)], capture_output=True, check=True)
    image_hash = digest(image)
    extracted = root / 'extracted'
    subprocess.run([debugfs, '-R', f'dump /payload {extracted}', str(image)], capture_output=True, check=True)
    assert digest(extracted) == source_hash, 'fixture content differs from payload'
    for mode in ['reader', 'snapshot']:
        subprocess.run([reader, mode, str(image), '65536', '1', str(extracted)], capture_output=True, check=True)
        assert digest(extracted) == source_hash, (layout, mode, 'reader content mismatch')
    extracted.unlink()
    for chunk in [4096, 65536, 1048576]:
        commands = {
            'raw': [reader, 'raw', str(payload), str(chunk), '1'],
            'reader': [reader, 'reader', str(image), str(chunk), '1'],
            'snapshot': [reader, 'snapshot', str(image), str(chunk), '1'],
            'libext2fs': [str(reference), str(image), str(chunk), '1'],
        }
        # Warm each path; no timing is described as a cold-cache/disk benchmark.
        for command in commands.values(): subprocess.run(command, capture_output=True, check=True)
        measurements = {mode: [] for mode in commands}
        for sample in range(args.samples):
            modes = list(commands)
            modes = modes[sample % len(modes):] + modes[:sample % len(modes)]
            for mode in modes:
                result = subprocess.run(commands[mode], text=True, capture_output=True, check=True)
                data = json.loads(result.stdout)
                assert data['bytes'] == payload.stat().st_size, data
                measurements[mode].append(data)
        for mode, values in measurements.items():
            speeds = [value['mib_per_second'] for value in values]
            row = dict(layout=layout, mode=mode, chunk=chunk,
                       median_mib_s=statistics.median(speeds), min_mib_s=min(speeds),
                       max_mib_s=max(speeds), measurements=values)
            results.append(row)
            print(f'{layout:8} {mode:10} {chunk:7} bytes: {row["median_mib_s"]:9.1f} MiB/s; preads={values[0].get("pread_calls", "n/a")}', flush=True)
    assert digest(image) == image_hash, 'benchmark changed image'
if args.native_linux:
    assert platform.system() == 'Linux', '--native-linux requires Linux'
    for layout in ['extents', 'classic']:
        image = root / (layout + '.img')
        image_hash = digest(image)
        mount = root / 'native-mount'
        mount.mkdir(exist_ok=True)
        device = subprocess.check_output(['sudo', 'losetup', '--find', '--show', '--read-only', str(image)], text=True).strip()
        mounted = False
        try:
            subprocess.run(['sudo', 'mount', '-t', 'ext4', '-o', 'ro,noload', device, str(mount)], check=True)
            mounted = True
            assert digest(mount / 'payload') == source_hash
            for chunk in [4096, 65536, 1048576]:
                command = [reader, 'raw', str(mount / 'payload'), str(chunk), '1']
                subprocess.run(command, capture_output=True, check=True)
                values = [json.loads(subprocess.check_output(command, text=True)) for _ in range(args.samples)]
                speeds = [value['mib_per_second'] for value in values]
                row = dict(layout=layout, mode='native-ext4', chunk=chunk,
                    median_mib_s=statistics.median(speeds), min_mib_s=min(speeds),
                    max_mib_s=max(speeds), measurements=values)
                results.append(row)
                print(f'{layout:8} native-ext4 {chunk:7} bytes: {row["median_mib_s"]:9.1f} MiB/s', flush=True)
        finally:
            if mounted: subprocess.run(['sudo', 'umount', str(mount)], check=True)
            subprocess.run(['sudo', 'losetup', '--detach', device], check=True)
        assert digest(image) == image_hash, 'native mount changed image'
report = dict(platform=platform.platform(), bytes=payload.stat().st_size, samples=args.samples,
              cache='warm; no global cache eviction', initialization='excluded',
              reference='libext2fs userspace; raw host file; native ext4 only with --native-linux', results=results)
if args.output: args.output.write_text(json.dumps(report, indent=2) + '\n')
if managed: shutil.rmtree(root)
