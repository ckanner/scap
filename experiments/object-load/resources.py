"""Bounded observations of an owned exec process; no product instrumentation."""
from __future__ import annotations

import array
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time

from spec import BOUNDS


def stat_identity(raw):
    close = raw.rfind(')')
    if close < 1:
        raise ValueError('invalid proc stat')
    pid = int(raw[:raw.index(' (')])
    fields = raw[close + 2:].split()
    if pid <= 0 or len(fields) < 20:
        raise ValueError('incomplete proc stat')
    start = int(fields[19])
    if start <= 0:
        raise ValueError('invalid process start ticks')
    return {'proc_pid': pid, 'start_ticks': start}


def read_at(directory, name, maximum=16384):
    descriptor = os.open(name, os.O_RDONLY, dir_fd=directory)
    try:
        value = os.read(descriptor, maximum + 1)
        if len(value) > maximum:
            raise ValueError('proc observation exceeds bound')
        return value.decode()
    finally:
        os.close(descriptor)


def names_at(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory)
    try:
        names = os.listdir(descriptor)
        if len(names) > 65536 or any(not item.isdecimal() for item in names):
            raise ValueError('proc directory exceeds bound')
        return sorted(names, key=int)
    finally:
        os.close(descriptor)


def fields(raw):
    values = {}
    for line in raw.splitlines():
        if ':' not in line:
            continue
        key, text = line.split(':', 1)
        if key in ('Pid', 'Threads', 'VmRSS', 'VmHWM'):
            parts = text.split()
            if key in values or not parts or not parts[0].isdecimal():
                raise ValueError('invalid or duplicate proc metric')
            number = int(parts[0])
            if key in ('VmRSS', 'VmHWM'):
                if parts[1:] != ['kB']:
                    raise ValueError('proc memory units changed')
                number *= 1024
            elif len(parts) != 1:
                raise ValueError('proc scalar units changed')
            values[key] = number
    if set(values) != {'Pid', 'Threads', 'VmRSS', 'VmHWM'} or min(values.values()) <= 0:
        raise ValueError('required owned-process metric unavailable')
    return values


def receive_proof(channel, nonce):
    payload, ancillary, flags, _ = channel.recvmsg(8192, socket.CMSG_SPACE(array.array('i').itemsize * 2))
    descriptors = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array('i')
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
    try:
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) != 1:
            raise ValueError('invalid owned proc directory handoff')
        proof = json.loads(payload)
        if proof['nonce'] != nonce or proof['source'] != 'owned_pre_exec_proc_self_fd':
            raise ValueError('process handoff identity changed')
        original = stat_identity(proof['stat'])
        if stat_identity(read_at(descriptors[0], 'stat')) != original:
            raise ValueError('passed descriptor is not original process')
        return descriptors.pop(), proof, original
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def spawn_owned(command, environment, cwd, log, emit):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    nonce = secrets.token_hex(16)
    parent.settimeout(10)
    try:
        with Path(log).open('wb') as output:
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('launcher.py')),
                str(child.fileno()), nonce, *map(str, command)], cwd=cwd, env=environment,
                pass_fds=(child.fileno(),), stdout=output, stderr=output)
    except BaseException:
        parent.close(); child.close()
        raise
    child.close()
    identity = {'pid': process.pid, 'spawn_monotonic_ns': time.monotonic_ns(), 'pid_source': 'owned_Popen_child'}
    try:
        emit('service_spawned', identity=identity)
        proc, proof, original = receive_proof(parent, nonce)
    except BaseException:
        # Popen.send_signal/kill may poll and reap an already exited child,
        # which would discard the authoritative wait4 resource result.
        signal_owned(process, signal.SIGKILL)
        waited, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        emit('service_launch_failed', identity=identity, waited_pid=waited,
             status=process.returncode, maxrss_bytes=usage.ru_maxrss * 1024)
        raise
    finally:
        parent.close()
    identity.update(original, boot_id=proof['boot_id'], proc_source=proof['source'])
    return process, proc, identity, proof


def signal_owned(process, signal_number):
    if process.returncode is not None:
        return False
    try:
        os.kill(process.pid, signal_number)
        return True
    except ProcessLookupError:
        return False  # The unreaped child still belongs to the caller's wait4.


def executable(directory):
    name = os.readlink('exe', dir_fd=directory)
    descriptor = os.open('exe', os.O_RDONLY, dir_fd=directory)
    with os.fdopen(descriptor, 'rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'path': name, 'sha256': digest}


def disk_tree(root):
    result = {'logical_bytes': 0, 'allocated_bytes': 0, 'files': 0, 'races': 0}
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            if directory == Path(root):
                raise
            result['races'] += 1
            continue
        with entries:
            for entry in entries:
                try:
                    stat = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        raise ValueError('symlink in owned disk observation')
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        result['files'] += 1
                        if result['files'] > 100000:
                            raise ValueError('disk observation file count exceeded')
                        result['logical_bytes'] += stat.st_size
                        result['allocated_bytes'] += stat.st_blocks * 512
                except FileNotFoundError:
                    result['races'] += 1
    return result


class Sampler:
    def __init__(self, proc, identity, cache, backend, output, phase):
        self.proc, self.identity, self.cache, self.backend = proc, identity, Path(cache), Path(backend)
        self.output, self.phase = Path(output), phase
        self.stop_event, self.errors, self.count = threading.Event(), [], 0
        self.thread = threading.Thread(target=self.run, name='owned-resource-observer')

    def sample(self):
        started = time.monotonic_ns()
        stat = read_at(self.proc, 'stat')
        if stat_identity(stat) != {k: self.identity[k] for k in ('proc_pid', 'start_ticks')}:
            raise ValueError('owned resource process identity changed')
        status = read_at(self.proc, 'status')
        metrics = fields(status)
        if metrics['Pid'] != self.identity['proc_pid']:
            raise ValueError('owned status PID differs from stat')
        descriptors, threads = names_at(self.proc, 'fd'), names_at(self.proc, 'task')
        if not descriptors or not threads:
            raise ValueError('owned FD/task observation unavailable')
        space = os.statvfs(self.cache)
        free = space.f_bavail * space.f_frsize
        if free < BOUNDS['minimum_free_bytes']:
            raise ValueError('owned fixture disk space guard')
        phase = self.phase()
        cache, backend = disk_tree(self.cache), disk_tree(self.backend)
        return {'event': 'resource_sample', 'sample': self.count + 1,
                'monotonic_ns': started, 'completed_ns': time.monotonic_ns(),
                'phase': phase, 'identity': self.identity, 'stat_raw': stat, 'status_raw': status,
                'fd_names': descriptors, 'task_names': threads, 'metrics': metrics,
                'cache': cache, 'backend': backend,
                'filesystem_free_bytes': free}

    def run(self):
        try:
            with self.output.open('x') as stream:
                while not self.stop_event.is_set():
                    if self.count >= BOUNDS['samples']:
                        raise ValueError('resource sample count exceeded')
                    value = self.sample()
                    stream.write(json.dumps(value, sort_keys=True) + '\n')
                    stream.flush()
                    self.count += 1
                    self.stop_event.wait(BOUNDS['sample_interval_ms'] / 1000)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException as error:
            self.errors.append(repr(error))

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.errors.append('resource sampler did not join')
        os.close(self.proc)
        if self.errors or self.count == 0:
            raise RuntimeError({'errors': self.errors, 'samples': self.count})
