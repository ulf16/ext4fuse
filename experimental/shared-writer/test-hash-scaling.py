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
        assert result['image_bytes_read'] <= 5*8*1024**2, result
        results.append(result)
    assert results[0]['image_bytes_read'] == results[1]['image_bytes_read'], results
(a.work/'hash-scaling-results.json').write_text(json.dumps(dict(result='passed', measurements=results), indent=2)+'\n')
print('PASS image verification bytes are independent of container size', flush=True)
