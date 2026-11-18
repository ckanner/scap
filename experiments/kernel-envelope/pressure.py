#!/usr/bin/env python3
"""Bounded, owned kernel pressure; never application or database logic."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def cgroup():
    membership = Path('/proc/self/cgroup').read_text().strip()
    assert membership.startswith('0::/') and '\n' not in membership
    relative = membership.removeprefix('0::/')
    assert all(part not in ('.', '..') for part in relative.split('/'))
    return Path('/sys/fs/cgroup') / relative


def counters(path):
    return {key: int(value) for key, value in
            (line.split() for line in path.read_text().splitlines())}


def start_ticks(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    return int(raw.rsplit(')', 1)[1].split()[19])


def available(directory):
    status = os.statvfs(directory)
    return {'blocks': status.f_bfree, 'inodes': status.f_ffree}


def main(mode):
    group = cgroup()
    if mode == 'memory':
        maximum = int((group / 'memory.max').read_text())
        assert maximum == 64 * 1024 * 1024
        print(json.dumps({'mode': mode, 'memory_max': maximum,
                          'oom_group': (group / 'memory.oom.group').read_text().strip()}), flush=True)
        # At most 128 MiB even if the kernel fails to enforce the declared limit.
        buffers = []
        for _ in range(32):
            buffer = bytearray(4 * 1024 * 1024)
            # Touch every page even if the allocator supplies lazy zero pages.
            for offset in range(0, len(buffer), 4096):
                buffer[offset] = 1
            buffers.append(buffer)
        raise AssertionError(f'kernel failed to OOM-kill bounded allocation: {len(buffers)}')
    if mode == 'cpu':
        assert (group / 'cpu.max').read_text().split() == ['20000', '100000']
        before = counters(group / 'cpu.stat')
        started = time.monotonic_ns()
        end = started + 1200000000
        value = 0
        while time.monotonic_ns() < end:
            value = (value + 1) % 65536
        after = counters(group / 'cpu.stat')
        assert after['nr_throttled'] > before['nr_throttled']
        print(json.dumps({'mode': mode, 'before': before, 'after': after, 'value': value,
                          'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns()}))
    elif mode == 'tasks':
        assert int((group / 'pids.max').read_text()) == 16
        before = counters(group / 'pids.events')
        current_before = int((group / 'pids.current').read_text())
        children = []
        identities = []
        rejected = False
        try:
            for _ in range(32):
                try:
                    child = subprocess.Popen(['/bin/sleep', '30'])
                    children.append(child)
                    identities.append({'pid': child.pid, 'start_ticks': start_ticks(child.pid)})
                except OSError as error:
                    assert error.errno == errno.EAGAIN
                    rejected = True
                    break
            after = counters(group / 'pids.events')
            current_after = int((group / 'pids.current').read_text())
            members = [int(pid) for pid in (group / 'cgroup.procs').read_text().splitlines()]
            assert rejected and after['max'] > before['max']
        finally:
            for child in children:
                child.terminate()
            for child, record in zip(children, identities):
                record['wait_exit_code'] = child.wait(timeout=5)
                record['wait_monotonic_ns'] = time.monotonic_ns()
        # wait() reaps each owned child; allow the kernel's release accounting
        # to settle within a fixed observation window, without spawning again.
        deadline = time.monotonic() + 5
        released = int((group / 'pids.current').read_text())
        while released != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
            released = int((group / 'pids.current').read_text())
        assert released == 1
        print(json.dumps({'mode': mode, 'children_joined': len(children), 'rejected': rejected,
                          'before': before, 'after': after, 'children': identities, 'members_at_rejection': members,
                          'current_before': current_before, 'current_at_rejection': current_after,
                          'current_after_wait': released}))
    elif mode == 'storage':
        directory = Path.cwd()
        status = os.statvfs(directory)
        capacity = status.f_blocks * status.f_frsize
        assert capacity == 64 * 1024 * 1024
        path = directory / 'owned-pressure'
        before = available(directory)
        rejected = False
        try:
            with path.open('wb') as stream:
                try:
                    os.posix_fallocate(stream.fileno(), 0, capacity + 4096)
                except OSError as error:
                    assert error.errno == errno.ENOSPC
                    rejected = True
            assert rejected
        finally:
            path.unlink(missing_ok=True)
        after_rejection = available(directory)
        with path.open('wb') as stream:
            stream.write(bytes(1024 * 1024))
            stream.flush()
            os.fsync(stream.fileno())
        path.unlink()
        print(json.dumps({'mode': mode, 'capacity': capacity, 'enospc': rejected,
                          'reallocated_and_released_bytes': 1024 * 1024,
                          'before': before, 'after_rejection': after_rejection,
                          'after_release': available(directory), 'owned_file_absent': not path.exists()}))
    else:
        raise AssertionError('unknown bounded pressure mode')


if __name__ == '__main__':
    main(sys.argv[1])
