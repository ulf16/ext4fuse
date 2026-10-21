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


# Progress is bounded and nonblocking even when replaced by a FIFO, symlink,
# hardlink, oversized/invalid document or a closed diagnostics stream.
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import writer_cli as cli

with tempfile.TemporaryDirectory(prefix='writer-observation-') as directory:
    root=Path(directory);root.chmod(0o700)
    (root/'writer-lock').write_bytes(b'');(root/'writer-lock').chmod(0o600)
    data=dict(version=1,mode='image',phase='ready',mountpoint=None)
    cli.inplace.seal(root,'writer-state',data)
    cli.seal(root,data,'mounting')
    with progress.reporting(closed),cli.lock(root),progress.operation(root,'mount'):
        progress.stage('Reading test volume','integrity-read',done=20,total=100)
        record=progress.read(root)
        assert record['done']==20 and record['total']==100
        before=(root/'writer-state').read_bytes()
        with patch.object(cli,'mounts',return_value={}),patch.object(cli,'attached',return_value=False):
            result=cli.snapshot(root)
            assert result['status']=='starting' and not result['checked']
            progress.lifecycle('closing','Checking final metadata')
            assert cli.snapshot(root)['status']=='checking before clean unmount'
        progress.lifecycle('ready','Complete')
        assert (root/'writer-state').read_bytes()==before
    # Old progress cannot turn an interrupted workflow into a successful check.
    cli.seal(root,data,'recovery-required')
    with patch.object(cli,'mounts',return_value={}),patch.object(cli,'attached',return_value=False):
        result=cli.snapshot(root)
        assert result['needs_recovery'] and result['status']=='recovery needed' and not result['progress_current']
    with patch.object(progress.os,'replace',side_effect=OSError('diagnostics unavailable')):
        with progress.operation(root,'recover'):progress.stage('Must not fail a workflow')
    path=root/'writer-progress';saved=path.read_bytes()
    for content in [b'x'*8193,b'{}',b'null',json.dumps(dict(record,pid=2**100)).encode(),json.dumps(dict(record,elapsed_seconds=float('nan'))).encode()]:
        path.write_bytes(content);assert progress.read(root) is None
    path.write_bytes(saved);path.chmod(0o644);assert progress.read(root) is None
    path.chmod(0o600);alias=root/'alias';os.link(path,alias);assert progress.read(root) is None;alias.unlink()
    path.unlink();path.symlink_to(root/'writer-state');assert progress.read(root) is None
    with progress.operation(root,'recover'):progress.stage('No symlink overwrite')
    assert path.is_symlink() and (root/'writer-state').read_bytes()!=b''
    path.unlink();os.mkfifo(path,0o600);assert progress.read(root) is None
    with progress.operation(root,'recover'):progress.stage('No FIFO overwrite')
    assert path.exists();path.unlink()
    # A watch is read-only, emits JSON lines, and Ctrl-C only stops the observer.
    state_before={p.name:p.read_bytes() for p in root.iterdir()}
    proc=subprocess.Popen([sys.executable,str(Path(cli.__file__)),'status',str(root),'--json','--watch','--interval','.2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        line=proc.stdout.readline();assert json.loads(line)['needs_recovery']
        proc.send_signal(signal.SIGINT);stdout,stderr=proc.communicate(timeout=10)
        assert proc.returncode==0 and not stderr
        assert state_before=={p.name:p.read_bytes() for p in root.iterdir()}
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
print('PASS progress observations: atomic private records, stale-state refusal, unsafe paths, read-only watch cancellation')
