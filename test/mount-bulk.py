#!/usr/bin/env python3
"""Optional macFUSE throughput measurements on existing disposable benchmark images."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixtures', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--samples', type=int, default=3)
parser.add_argument('--layouts', nargs='+', choices=['extents', 'classic'], default=['extents', 'classic'])
parser.add_argument('--cache-modes', nargs='+', choices=['cached', 'noubc'], default=['cached', 'noubc'])
parser.add_argument('--mount-options', default='', help='extra options, e.g. iosize=1048576')
args = parser.parse_args()
assert sys.platform == 'darwin' and 1 <= args.samples <= 20
reader = os.environ.get('READER', './ext4fuse')
client = os.environ.get('BULK_READER', './test/bulk-reader')
def digest(path):
    with path.open('rb') as file: return hashlib.file_digest(file, 'sha256').hexdigest()
expected = digest(args.fixtures / 'payload')
results = []
for layout in args.layouts:
    image = args.fixtures / (layout + '.img')
    before = digest(image)
    for cache in args.cache_modes:
        root = Path(tempfile.mkdtemp(prefix='ext4fuse-mount-bulk-'))
        mount = root / 'mount'; mount.mkdir()
        log = (root / 'reader.log').open('w+')
        options = 'ro,defer_permissions' + (',noubc,noreadahead' if cache == 'noubc' else '')
        if args.mount_options: options += ',' + args.mount_options
        process = subprocess.Popen([reader, str(image), str(mount), '-f', '-s', '-o', options], stdout=log, stderr=log)
        try:
            for attempt in range(40):
                if (mount / 'payload').exists(): break
                if process.poll() is not None: raise AssertionError('reader exited before mount')
                time.sleep(.25)
            else: raise AssertionError('mount timeout')
            # First pass has a fresh mounted-file cache; the backing image is warm.
            command = [client, 'raw', str(mount / 'payload'), '65536', '1']
            first = json.loads(subprocess.check_output(command, text=True))
            results.append(dict(layout=layout, cache=cache, chunk=65536,
                phase='first-pass', median_mib_s=first['mib_per_second'],
                measurements=[first]))
            print(f'{layout:8} {cache:9} first pass: {first["mib_per_second"]:9.1f} MiB/s', flush=True)
            assert digest(mount / 'payload') == expected, 'mounted contents differ'
            for chunk in [65536, 1048576]:
                command = [client, 'raw', str(mount / 'payload'), str(chunk), '1']
                subprocess.run(command, capture_output=True, check=True)
                measurements = []
                for _ in range(args.samples):
                    data = json.loads(subprocess.check_output(command, text=True))
                    measurements.append(data)
                speeds = [m['mib_per_second'] for m in measurements]
                row = dict(layout=layout, cache=cache, chunk=chunk, phase='warm',
                           median_mib_s=statistics.median(speeds), min_mib_s=min(speeds),
                           max_mib_s=max(speeds), measurements=measurements)
                results.append(row)
                print(f'{layout:8} {cache:9} {chunk:7} bytes: {row["median_mib_s"]:9.1f} MiB/s', flush=True)
        except BaseException:
            log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
            raise
        finally:
            unmount = subprocess.run(['/sbin/umount', str(mount)], capture_output=True)
            if unmount.returncode and process.poll() is None:
                subprocess.run(['/sbin/umount', '-f', str(mount)], check=True)
            if process.poll() is None: process.terminate()
            process.wait(timeout=10)
            log.flush(); log.seek(0)
            for line in log:
                if line.startswith('PROFILE:'): print(line.strip(), flush=True)
            log.close()
        assert not os.path.ismount(mount), f'mount remains; keeping {root}'
        assert digest(image) == before, 'reader changed source image'
        import shutil
        shutil.rmtree(root)
args.output.write_text(json.dumps(dict(samples=args.samples,
    cache='warm backing images; cached mounts additionally warm kernel file cache; noubc,noreadahead disables mounted-file UBC and readahead',
    note='client pread counters count application calls, not backing-image daemon I/O',
    mount_options=args.mount_options, results=results), indent=2) + '\n')
