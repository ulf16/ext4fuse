# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in human progress; library users and machine-readable status stay quiet."""
from contextlib import contextmanager
from contextvars import ContextVar
import sys
import time

_sink = ContextVar('writer_progress', default=None)


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


def stage(message):
    sink = _sink.get()
    if sink is not None:
        sink(message)


class Scan:
    def __init__(self, total, label='Checking volume integrity'):
        self.total = total
        self.label = label
        self.start = self.last = time.monotonic()
        stage(label + ': 0% (full-volume read; keep the device connected).')

    def update(self, done):
        now = time.monotonic()
        if done != self.total and now - self.last < 5:
            return
        self.last = now
        elapsed = max(now - self.start, .001)
        stage(f'{self.label}: {done * 100 / self.total:.1f}% '
              f'({done / 1024**2:.0f}/{self.total / 1024**2:.0f} MiB, '
              f'{done / 1024**2 / elapsed:.1f} MiB/s read).')

    def hashing(self):
        stage(self.label + ': reads complete; validating hash tree...')

    def complete(self):
        stage(self.label + ': complete.')
