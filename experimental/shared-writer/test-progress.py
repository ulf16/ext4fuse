#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Progress is opt-in, throttled and cannot turn a committed write into failure."""
import io
from unittest.mock import patch
import progress

out = io.StringIO()
with progress.reporting(out), patch.object(progress.time, 'monotonic', side_effect=[0, 1, 6, 7]):
    meter = progress.Scan(100)
    meter.update(10)
    meter.update(60)
    meter.update(100)
    meter.hashing()
    meter.complete()
text = out.getvalue()
assert '0%' in text and '60.0%' in text and '100.0%' in text
assert '10.0%' not in text
assert text.index('validating hash tree') < text.index(': complete.')
with patch.object(progress.sys, 'stderr', out):
    before = out.getvalue()
    progress.stage('must stay quiet')
    assert out.getvalue() == before
closed = io.StringIO(); closed.close()
with progress.reporting(closed):
    progress.stage('must not fail a publication')
class Broken:
    def write(self, data): raise BrokenPipeError()
    def flush(self): raise BrokenPipeError()
with progress.reporting(Broken()):
    progress.stage('must not fail a publication')
print('PASS progress: throttling, opt-in scope, closed diagnostics')
