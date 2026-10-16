# SPDX-License-Identifier: GPL-2.0-only
"""Independent, deterministic transaction oracle for durability campaigns."""
import hashlib
import json
import random
import re
import stat
import subprocess
from pathlib import Path


def payload(seed, number):
    rng = random.Random((seed << 32) + number)
    length = rng.choice((0, 1, 511, 4095, 4096, 4097, 16391, 65539))
    data = bytearray(rng.randbytes(length))
    if length > 4096:
        data[512:4096] = bytes(3584)
    return bytes(data)


def batch(seed, number, previous):
    data = payload(seed, number)
    mode = 0o640 if number % 2 else 0o600
    name = f'/history/commit-{number:06d}'
    # The new current file, its hardlink, attributes and immutable history entry
    # must appear together. The old current file is replaced only at rename.
    initial = data + b'temporary-tail' if number % 3 == 0 else data[:512] if len(data) > 4096 else data
    operations = [dict(kind='create', path='/staging', data_hex=initial.hex(), mode=0o600)]
    if number % 3 != 0 and len(data) > 4096:
        operations.append(dict(kind='write', path='/staging', offset=4096, data_hex=data[4096:].hex()))
    operations.append(dict(kind='truncate', path='/staging', size=len(data)))
    operations += [dict(kind='chmod', path='/staging', mode=mode),
                  dict(kind='setxattr', path='/staging', name='user.endurance',
                       value_hex=str(number).encode().hex())]
    if previous is not None:
        operations.append(dict(kind='unlink', path='/witness'))
    operations += [dict(kind='link', path='/staging', target='/witness'),
                   dict(kind='rename', path='/staging', target='/current'),
                   dict(kind='create', path=name, data_hex=data.hex(), mode=0o600)]
    return operations


def verify(s, seed, head, history):
    with s.opendir('/') as directory:
        names = directory.listdir()
    assert 'staging' not in names, 'partially published staging file'
    with s.opendir('/history') as directory:
        assert set(directory.listdir()) == {f'commit-{n:06d}' for n in history}, 'history is not an atomic prefix'
    for number in history:
        assert s.read(f'/history/commit-{number:06d}') == payload(seed, number), ('acknowledged history changed', number)
    if head is None:
        assert 'current' not in names and 'witness' not in names
        return
    expected = payload(seed, head)
    assert s.read('/current') == expected
    assert s.read('/witness') == expected
    current = s.statat(None, '/current'); witness = s.statat(None, '/witness')
    assert current['inode'] == witness['inode'], (current, witness)
    assert current['links'] == 2 and witness['links'] == 2, (current, witness)
    assert stat.S_IMODE(current['mode']) == (0o640 if head % 2 else 0o600)
    assert s.getxattr('/current', 'user.endurance') == str(head).encode()
    assert s.readlink('/pointer') == b'current'


def actual(s, seed, previous, number, history):
    with s.opendir('/history') as directory:
        names = set(directory.listdir())
    after = f'commit-{number:06d}' in names
    head = number if after else previous
    expected_history = history | ({number} if after else set())
    verify(s, seed, head, expected_history)
    return head, expected_history


def command(argv):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
    if result.returncode:
        raise AssertionError((argv, result.returncode, result.stdout[-4096:], result.stderr[-4096:]))
    return result.stdout


def independent(image, seed, head, history):
    """e2fsprogs checks allocations independently; debugfs verifies exact bytes/names."""
    command(['e2fsck', '-fn', image])
    raw = command(['debugfs', '-R', 'ls -p /history', image])
    names = {name.decode() for name in re.findall(rb'/commit-([0-9]{6})/', raw)}
    assert names == {f'{n:06d}' for n in history}, raw
    if head is not None:
        expected = payload(seed, head)
        for path in ('/current', '/witness', f'/history/commit-{head:06d}'):
            assert command(['debugfs', '-R', 'cat ' + path, image]) == expected, path
        info = command(['debugfs', '-R', 'stat /current', image])
        assert re.search(rb'Links:\s+2\b', info), info
        assert f'Mode:  0{0o640 if head % 2 else 0o600:o}'.encode() in info, info
    return hashlib.sha256(Path(image).read_bytes()).hexdigest()
