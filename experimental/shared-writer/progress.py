# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in human progress; library users and machine-readable status stay quiet."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import uuid
import time

_sink = ContextVar('writer_progress', default=None)
_record = ContextVar('writer_progress_record', default=None)


@contextmanager
def reporting(stream=None):
    stream = sys.stderr if stream is None else stream
    def emit(message):
        # Diagnostics must never interrupt a durable publication on a closed pipe.
        try:
            print(message, file=stream, flush=True)
        except (OSError, ValueError):
            pass
    token = _sink.set(emit)
    try:
        yield
    finally:
        _sink.reset(token)


def stage(message, code='checking', **fields):
    recorder = _record.get()
    if recorder is not None:
        recorder.emit(message, code, fields)
    sink = _sink.get()
    if sink is not None:
        sink(message)


class Scan:
    def __init__(self, total, label='Checking volume integrity'):
        self.total = total
        self.label = label
        self.start = self.last = time.monotonic()
        stage(label + ': 0% (full-volume read; keep the device connected).', 'integrity-read', done=0, total=total)

    def update(self, done):
        now = time.monotonic()
        if done != self.total and now - self.last < 5:
            return
        self.last = now
        elapsed = max(now - self.start, .001)
        stage(f'{self.label}: {done * 100 / self.total:.1f}% '
              f'({done / 1024**2:.0f}/{self.total / 1024**2:.0f} MiB, '
              f'{done / 1024**2 / elapsed:.1f} MiB/s read).', 'integrity-read', done=done, total=self.total, bytes_per_second=done/elapsed)

    def hashing(self):
        stage(self.label + ': reads complete; validating hash tree...', 'integrity-tree')

    def complete(self):
        stage(self.label + ': complete.', 'integrity-complete')


class Record:
    """Best-effort observation only; never a recovery or safe-disconnect authority."""
    def __init__(self, root, operation):
        self.root = Path(root)
        self.started = self.changed = time.monotonic()
        self.code = None
        self.durations = {}
        self.value = dict(version=1, run=uuid.uuid4().hex, pid=os.getpid(),
                          operation=operation, lifecycle='starting' if operation=='mount' else operation)

    def emit(self, message, code, fields):
        now = time.monotonic()
        if self.code != code:
            if self.code is not None:
                self.durations[self.code] = self.durations.get(self.code, 0) + now-self.changed
            self.code, self.changed = code, now
        value = dict(self.value, stage=code, message=message[:1024], updated=time.time(),
                     elapsed_seconds=now-self.started,
                     stage_seconds=now-self.changed, completed_stage_seconds=dict(self.durations), **fields)
        temporary = None
        try:
            path = self.root/'writer-progress'
            if path.exists() or path.is_symlink():
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077:
                    return
            fd, temporary = tempfile.mkstemp(prefix='.writer-progress-', dir=self.root)
            with os.fdopen(fd,'w') as stream:
                json.dump(value,stream,sort_keys=True,allow_nan=False)
            # This disposable observation does not fsync or alter the durable state.
            os.replace(temporary,path)
            temporary = None
        except (OSError,ValueError,TypeError):
            pass
        finally:
            if temporary is not None:
                try:os.unlink(temporary)
                except OSError:pass


@contextmanager
def operation(root, name):
    recorder = Record(root, name)
    token = _record.set(recorder)
    try:
        stage(('Starting mount' if name=='mount' else 'Recovering volume' if name=='recover' else 'Initializing volume')+
              '; keep the device connected...', name)
        yield
    except BaseException:
        lifecycle('failed', 'Operation stopped; inspect status and retain recovery state.')
        raise
    finally:
        _record.reset(token)


def lifecycle(value, message):
    recorder = _record.get()
    if recorder is not None:recorder.value['lifecycle'] = value
    stage(message, value)


def invalid_constant(value):
    raise ValueError('nonfinite progress number')


def read(root):
    """Bounded, nonblocking, private-file read; malformed observations are ignored."""
    try:
        fd=os.open(Path(root)/'writer-progress',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077:return None
            raw=stream.read(8193)
        if len(raw)>8192:return None
        value=json.loads(raw,parse_constant=invalid_constant)
        if not isinstance(value,dict) or type(value.get('version')) is not int or value.get('version')!=1:return None
        if value.get('operation') not in ('init','mount','recover'):return None
        if value.get('lifecycle') not in ('init','starting','mounted','closing','recover','ready','failed'):return None
        if type(value.get('pid')) is not int or not 0<value['pid']<2**31:return None
        if not isinstance(value.get('run'),str) or len(value['run'])!=32:return None
        for key in ('stage','message'):
            if not isinstance(value.get(key),str) or len(value[key])>1024:return None
        for key in ('updated','elapsed_seconds','stage_seconds'):
            if type(value.get(key)) not in (int,float) or not math.isfinite(value[key]) or value[key]<0:return None
        durations=value.get('completed_stage_seconds')
        if not isinstance(durations,dict) or len(durations)>32:return None
        if any(not isinstance(k,str) or len(k)>64 or type(v) not in (int,float) or not math.isfinite(v) or v<0 for k,v in durations.items()):return None
        if 'done' in value or 'total' in value:
            if type(value.get('done')) is not int or type(value.get('total')) is not int or not 0<=value['done']<=value['total'] or value['total']<=0:return None
        if 'bytes_per_second' in value and (type(value['bytes_per_second']) not in (int,float) or not math.isfinite(value['bytes_per_second']) or value['bytes_per_second']<0):return None
        return value
    except (OSError,ValueError,TypeError,OverflowError,RecursionError):
        return None


def current(event, result):
    if not event or not result['busy'] or event['lifecycle'] in ('ready','failed'):return False
    if event['operation']!={'mounting':'mount','recovering':'recover','initializing':'init'}.get(result['phase']):return False
    try:os.kill(event['pid'],0)
    except (OSError,OverflowError):return False
    return True


def summary(result):
    """Describe observations without upgrading them into an integrity check."""
    event=result.get('progress') if result.get('progress_current') else None
    if result['needs_recovery'] or result['phase']=='recovery-required':return 'recovery needed'
    if result['busy']:
        if result['mounted']:return 'mounted'
        if event and event['lifecycle']=='closing':return 'checking before clean unmount'
        if result['phase']=='ready':return 'in use; waiting for workflow'
        return 'recovering' if result['phase']=='recovering' else 'initializing' if result['phase']=='initializing' else 'starting'
    return 'unmounted; last workflow completed' if result['phase']=='ready' else 'recovery needed'
