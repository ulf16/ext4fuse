#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Gate verification bytes independently of host image size, not noisy timing."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--work', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
a = p.parse_args()
results = []
with tempfile.TemporaryDirectory(prefix='hash-scaling-', dir=a.work) as tmp:
    tmp = Path(tmp)
    for size in (32*1024**2, 512*1024**2):
        image = tmp / f'{size}.img'
        shutil.copyfile(a.source, image)
        assert image.stat().st_size == 32*1024**2, 'expected a 32 MiB filesystem fixture'
        with image.open('r+b') as f:
            f.truncate(size)
        output = tmp / f'{size}.json'
        subprocess.run([sys.executable, str(Path(__file__).with_name('test-transaction-performance.py')),
                        '--work', str(a.work), '--source', str(image),
                        '--root', str(tmp/f'root-{size}'), '--output', str(output)], check=True)
        result = json.loads(output.read_text())
        # Native base reads now pass through Python's verifier and appear in
        # this counter. Keep the old replay budget and separately bound the
        # new verified reads; neither may grow with the container size.
        assert result['image_bytes_read'] - result['verified_read_bytes'] <= 5*8*1024**2, result
        assert 0 < result['verified_read_bytes'] <= 5*8*1024**2, result
        results.append(result)
    assert results[0]['image_bytes_read'] == results[1]['image_bytes_read'], results
    assert results[0]['verified_read_bytes'] == results[1]['verified_read_bytes'], results
(a.work/'hash-scaling-results.json').write_text(json.dumps(dict(result='passed', measurements=results), indent=2)+'\n')
print('PASS image verification bytes are independent of container size', flush=True)
