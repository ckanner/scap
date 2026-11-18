#!/usr/bin/env python3
"""Record the real unit process namespace, then exec the frozen target in place.

This observer imports only the standard library. It neither changes a limit nor
models admission. PID/start ticks survive exec; systemd independently reports
that PID's actual exit. No credential values or full environment are recorded.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import time

CONTROLS = ('cgroup.type', 'cgroup.procs', 'cgroup.events', 'memory.max',
            'memory.swap.max', 'memory.oom.group', 'memory.events', 'cpu.max',
            'cpu.stat', 'cpu.max.burst', 'pids.max', 'pids.current', 'pids.events')


def bounded(path, limit=262144):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('oversized kernel observation')
    return raw.decode('utf-8')


def identity(path):
    status = os.stat(path)
    return {'device': status.st_dev, 'inode': status.st_ino}


def fs_type(path):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    libc.statfs.restype = ctypes.c_int
    # Linux statfs starts with a native long f_type. An oversized aligned
    # destination avoids depending on the remaining architecture-specific ABI.
    buffer = (ctypes.c_long * 64)()
    if libc.statfs(os.fsencode(path), ctypes.byref(buffer)) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(path))
    return buffer[0]


def mount(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
        return {'path': path, 'missing_errno': errno.ENOENT}
    try:
        status, filesystem = os.fstat(descriptor), os.fstatvfs(descriptor)
        return {'path': path, 'device': status.st_dev, 'inode': status.st_ino,
                'kind': fs_type(f'/proc/self/fd/{descriptor}'),
                'blocks': filesystem.f_blocks, 'block_size': filesystem.f_bsize,
                'fragment_size': filesystem.f_frsize, 'inodes': filesystem.f_files}
    finally:
        os.close(descriptor)


def snapshot(target):
    started = time.monotonic_ns()
    membership = bounded('/proc/self/cgroup', 8192)
    if not membership.startswith('0::/') or not membership.endswith('\n') or membership.count('\n') != 1:
        raise ValueError('not a unified cgroup process')
    relative = membership[4:-1]
    if not relative or any(part in ('', '.', '..') for part in relative.split('/')):
        raise ValueError('invalid owned cgroup path')
    group = Path('/sys/fs/cgroup') / relative
    cwd = os.getcwd()
    directories = [cwd, os.environ['SQLITE_TMPDIR'], os.environ['TMPDIR'],
                   '/var/tmp', '/usr/tmp', '/tmp', cwd]
    with open(target[0], 'rb') as stream:
        target_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    executable = str(Path('/proc/self/exe').resolve())
    with open(executable, 'rb') as stream:
        interpreter_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    sched_ext = Path('/sys/kernel/sched_ext')
    try:
        sched_ext_identity = identity(sched_ext)
    except FileNotFoundError as error:
        scheduler = {'missing_errno': error.errno}
    else:
        scheduler = {'identity': sched_ext_identity, 'kind': fs_type(sched_ext),
                     'state': bounded(sched_ext / 'state', 1024)}
    value = {
        'schema': 1, 'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
        'started_monotonic_ns': started, 'boot_id': bounded('/proc/sys/kernel/random/boot_id', 128),
        'proc_stat': bounded('/proc/self/stat'), 'proc_status': bounded('/proc/self/status'),
        'thread_stat': bounded('/proc/thread-self/stat'), 'sched_ext': scheduler,
        'membership_before': membership, 'cgroup_path': str(group),
        'cgroup_identity': identity(group), 'cgroup_kind': fs_type(group),
        'controls': {name: bounded(group / name, 8192) for name in CONTROLS},
        'oom_score_adj': bounded('/proc/self/oom_score_adj', 1024),
        'mount_namespace': identity('/proc/self/ns/mnt'), 'mountinfo': bounded('/proc/self/mountinfo'),
        'cwd': cwd, 'temporary_directories': directories,
        'mounts': [mount(path) for path in directories],
        'interpreter': {'path': executable, 'sha256': interpreter_digest},
        'target': {'argv': target, 'sha256': target_digest},
    }
    if len(target) == 3 and target[1] == '--check-config':
        with open(target[2], 'rb') as stream:
            value['config_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    value['membership_after'] = bounded('/proc/self/cgroup', 8192)
    value['finished_monotonic_ns'] = time.monotonic_ns()
    return value


def main(args):
    if len(args) < 4 or args[1] != '--' or not __debug__:
        raise ValueError('expected snapshot -- absolute-target argv')
    path, target = Path(args[0]), args[2:]
    if not Path(target[0]).is_absolute():
        raise ValueError('target must be absolute')
    value = snapshot(target)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.execv(target[0], target)


if __name__ == '__main__':
    main(sys.argv[1:])
