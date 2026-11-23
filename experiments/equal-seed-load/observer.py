"""Owned-process and filesystem acceptance monitoring; no hard-cap claim.

Every child supplies its original /proc/self directory before exec. Popen.pid
is used only to signal/reap our child, never to guess its procfs identity.
Samples can miss an overshoot between observations; timestamps expose lag.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import time
import traceback

import shared
import spec

resources = shared.resources


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def error_evidence(error, context):
    """Bounded failure provenance, including filename and the actual call stack.

    No locals, request bodies, environment values or credential contents are
    captured. Ordinary sampler stacks fit completely; truncation is explicit.
    """
    truncated = False
    def text(value, limit):
        nonlocal truncated
        value = str(value)
        # Bound the JSON representation, including escapes, rather than only
        # UTF-8 bytes: a single control character can occupy six output bytes.
        high = min(len(value), limit)
        if len(json.dumps(value[:high]).encode('ascii')) <= limit:
            end = high
        else:
            low = 0
            while low < high:
                middle = (low + high + 1) // 2
                if len(json.dumps(value[:middle]).encode('ascii')) <= limit:
                    low = middle
                else:
                    high = middle - 1
            end = low
        truncated = truncated or end != len(value)
        return value[:end]
    safe_context = {key: text(context[key], 512) for key in
                    ('operation', 'role', 'root', 'path', 'phase') if key in context}
    for key in ('sample', 'pid', 'proc_pid'):
        if key in context and type(context[key]) is int:
            if 0 <= context[key] < 1 << 64:
                safe_context[key] = context[key]
            else:
                truncated = True
    depth = sum(1 for _ in traceback.walk_tb(error.__traceback__))
    formatted = ''.join(traceback.format_exception(type(error), error, error.__traceback__, limit=-12))
    error_number = getattr(error, 'errno', None)
    record = {'error_type': text(type(error).__name__, 128), 'message': text(error, 2048),
              'errno': error_number if type(error_number) is int and -(1 << 63) <= error_number < 1 << 63 else None,
              'filename': None if getattr(error, 'filename', None) is None else text(error.filename, 512),
              'context': safe_context, 'traceback': text(formatted, 8192),
              'traceback_frame_limit_per_exception': 12, 'truncated': truncated or depth > 12}
    # All string literals together are bounded to 13,440 JSON bytes; keys,
    # punctuation and the bounded integers leave the whole record <16 KiB.
    return record


def tree(root, limit=spec.BOUNDS['matrix_inodes']):
    root = Path(root)
    initial = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(initial.st_mode):
        raise ValueError('observation root is not a real directory')
    def verify_root():
        current = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError('owned observation root was replaced')
    result = {'allocated_bytes': 0, 'logical_bytes': 0, 'inodes': 0, 'races': 0,
              'files': 0, 'file_bytes': 0}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            if directory == root:
                raise
            # Only an already enumerated, non-symlink descendant may have
            # disappeared. The original root must still be the same directory;
            # a missing/replaced root or another I/O failure is never zero use.
            verify_root()
            result['races'] += 1
            continue
        with entries:
            for entry in entries:
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        raise ValueError('symlink in original experiment tree')
                    result['inodes'] += 1
                    if result['inodes'] > limit:
                        raise ValueError('experiment inode acceptance ceiling')
                    result['allocated_bytes'] += entry_stat.st_blocks * 512
                    result['logical_bytes'] += entry_stat.st_size
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    else:
                        result['files'] += 1
                        result['file_bytes'] += entry_stat.st_size
                except FileNotFoundError:
                    result['races'] += 1
    verify_root()
    return result


def entry_tree(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('symlink in sealed evidence prefix')
    stat = path.stat()
    value = tree(path) if path.is_dir() else {
        'allocated_bytes': 0, 'logical_bytes': 0, 'inodes': 0, 'races': 0,
        'files': 1, 'file_bytes': stat.st_size}
    value['allocated_bytes'] += stat.st_blocks * 512
    value['logical_bytes'] += stat.st_size
    value['inodes'] += 1
    return value


def check_filesystem(evidence, private=None, sealed=None, current=None):
    if sealed is None:
        persistent = tree(evidence)
    else:
        active = entry_tree(current)
        persistent = {key: active[key] + sum(value[key] for value in sealed.values()) for key in active}
    temporary = entry_tree(private) if private is not None else {'allocated_bytes': 0, 'inodes': 0}
    if persistent['allocated_bytes'] + temporary['allocated_bytes'] > spec.BOUNDS['matrix_bytes']:
        raise ValueError('matrix evidence allocation ceiling')
    if persistent['inodes'] + temporary['inodes'] > spec.BOUNDS['matrix_inodes']:
        raise ValueError('matrix evidence inode ceiling')
    stat = os.statvfs(evidence)
    if stat.f_bavail * stat.f_frsize < spec.BOUNDS['minimum_free_bytes']:
        raise ValueError('matrix free-space reserve')
    return {'evidence': persistent, 'private': temporary,
            'filesystem_free_bytes': stat.f_bavail * stat.f_frsize,
            'filesystem_free_inodes': stat.f_favail}


def process_sample(proc, expected):
    started = time.monotonic_ns()
    stat = resources.read_at(proc, 'stat')
    if resources.stat_identity(stat) != {key: expected[key] for key in ('proc_pid', 'start_ticks')}:
        raise ValueError('owned proc identity changed')
    # An exited, unreaped owned child can legitimately have no VmRSS/status
    # fields. Its authoritative wait4 peak is recorded separately, not as zero.
    state = stat[stat.rfind(')') + 2:].split()[0]
    row = {'identity': expected, 'started_ns': started, 'stat_raw': stat, 'state': state}
    if state != 'Z':
        try:
            status = resources.read_at(proc, 'status')
            row.update(status_raw=status, metrics=resources.fields(status),
                       fd_names=resources.names_at(proc, 'fd'), task_names=resources.names_at(proc, 'task'))
        except (OSError, ValueError) as error:
            # The monitor lock prevents reap, not the kernel's own exit. Only a
            # second read of the same original proc fd, same identity and Z
            # state may explain missing live fields. All other failures close.
            final_stat = resources.read_at(proc, 'stat')
            if resources.stat_identity(final_stat) != {key: expected[key] for key in ('proc_pid', 'start_ticks')}:
                raise ValueError('owned proc identity changed during exit') from error
            final_state = final_stat[final_stat.rfind(')') + 2:].split()[0]
            if final_state != 'Z':
                raise
            row.update(stat_raw=final_stat, state='Z', exit_raced=True,
                       initial_stat_raw=stat, observation_error=repr(error))
    row['completed_ns'] = time.monotonic_ns()
    return row


def accept_processes(processes):
    totals = {name: {'rss_bytes': 0, 'fds': 0, 'tasks': 0} for name in spec.PROCESS_LIMITS}
    for row in processes:
        if 'metrics' not in row:
            continue
        total = totals[row['role']]
        total['rss_bytes'] += row['metrics']['VmRSS']
        total['fds'] += len(row['fd_names'])
        total['tasks'] += len(row['task_names'])
    for role, usage in totals.items():
        if any(usage[key] > limit for key, limit in spec.PROCESS_LIMITS[role].items()):
            raise ValueError('process acceptance ceiling: ' + role)
    return totals


class Monitor:
    def __init__(self, directory, evidence, private, events, phase):
        self.directory, self.evidence, self.private = map(Path, (directory, evidence, private))
        self.events, self.phase = events, phase
        self.lock = threading.RLock()
        self.owned, self.errors = {}, []
        self.stop = threading.Event()
        self.count = self.bytes = self.service_count = 0
        self.service_live = False
        self.previous = None
        self.sampling_context = {'operation': 'initializing'}
        self.thread = threading.Thread(target=self.run, name='equal-seed-envelope')
        descriptor = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
        stat = resources.stat_identity(resources.read_at(descriptor, 'stat'))
        self.observer = {'role': 'observer', 'process': None, 'proc': descriptor,
                         'identity': {**stat, 'source': 'observer_proc_self_fd'}}
        self.sealed = {path.name: entry_tree(path) for path in self.evidence.iterdir() if path != self.directory}
        self.sealed_digest = hashlib.sha256(encoded(self.sealed)).hexdigest()
        self.events.emit('envelope_sealed_prefix', entries=self.sealed, sha256=self.sealed_digest)

    def add(self, role, process, proc, identity, proof, executable, spawn_requested_ns):
        with self.lock:
            if process.pid in self.owned or role not in spec.PROCESS_LIMITS:
                raise ValueError('duplicate or unplanned process')
            self.owned[process.pid] = {'role': role, 'process': process, 'proc': proc,
                                      'identity': identity, 'executable': str(executable)}
            self.events.emit('envelope_process_started', role=role, identity=identity,
                             proof=proof, executable=str(executable), spawn_requested_ns=spawn_requested_ns)

    def check(self):
        if self.errors:
            raise RuntimeError({'monitor_errors': list(self.errors)})

    def sample(self):
        started = time.monotonic_ns()
        with self.lock:
            locked = time.monotonic_ns()
            processes = []
            service = None
            for item in (self.observer, *self.owned.values()):
                self.sampling_context = {'operation': 'owned_process_sample', 'role': item['role'],
                                         **{key: item['identity'][key] for key in ('pid', 'proc_pid')
                                            if key in item['identity']}}
                row = process_sample(item['proc'], item['identity'])
                row['role'] = item['role']
                processes.append(row)
                if item['role'] == 'service' and self.service_live and 'metrics' in row:
                    service = row
            self.sampling_context = {'operation': 'process_acceptance'}
            totals = accept_processes(processes)
            self.sampling_context = {'operation': 'filesystem_aggregate', 'root': str(self.evidence),
                                     'path': str(self.private)}
            filesystem = check_filesystem(self.evidence, self.private, self.sealed, self.directory)
            self.sampling_context = {'operation': 'backend_tree', 'root': str(self.private / 'backend')}
            backend = tree(self.private / 'backend') if (self.private / 'backend').exists() else None
            if backend is not None and backend['allocated_bytes'] > spec.BOUNDS['backend_bytes']:
                raise ValueError('backend allocation acceptance ceiling')
            value = {'event': 'envelope_sample', 'sample': self.count + 1, 'monotonic_ns': started,
                     'locked_ns': locked,
                     'completed_ns': time.monotonic_ns(), 'phase': self.phase(), 'processes': processes,
                     'totals': totals, 'filesystem': filesystem, 'backend': backend,
                     'sealed_prefix_sha256': self.sealed_digest,
                     'interval_ns': None if self.previous is None else started - self.previous,
                     'acceptance_is_hard_cap': False}
            projections = [(self.directory / 'envelope.jsonl', value)]
            if service is not None:
                self.sampling_context = {'operation': 'legacy_cache_projection', 'root': str(self.private / 'cache')}
                cache = resources.disk_tree(self.private / 'cache')
                self.service_count += 1
                self.sampling_context = {'operation': 'legacy_backend_projection', 'root': str(self.private / 'backend')}
                backend_projection = resources.disk_tree(self.private / 'backend')
                projections.append((self.directory / 'resources.jsonl', {
                    'event': 'resource_sample', 'sample': self.service_count,
                    'envelope_sample': self.count + 1, 'monotonic_ns': started,
                    'completed_ns': value['completed_ns'], 'phase': value['phase'],
                    **{key: service[key] for key in ('identity', 'stat_raw', 'status_raw',
                                                     'fd_names', 'task_names', 'metrics')},
                    'cache': cache, 'backend': backend_projection,
                    'filesystem_free_bytes': filesystem['filesystem_free_bytes']}))
            for root in (self.directory, self.private, self.private / 'backend'):
                self.sampling_context = {'operation': 'child_log_scan', 'root': str(root)}
                for path in root.glob('*'):
                    self.sampling_context = {'operation': 'child_log_stat', 'path': str(path)}
                    if path.is_file() and (path.suffix in ('.stdout', '.stderr', '.log')):
                        if path.stat().st_size > spec.BOUNDS['child_log_bytes']:
                            raise ValueError('child output log byte budget')
            completed = time.monotonic_ns()
            for _, row in projections:
                row['completed_ns'] = completed
            blobs = [(path, encoded(row)) for path, row in projections]
            self.sampling_context = {'operation': 'sample_output_budget'}
            size = sum(len(raw) for _, raw in blobs)
            if self.count >= spec.BOUNDS['samples'] or self.bytes + size > spec.BOUNDS['sample_bytes']:
                raise ValueError('aggregate resource sample budget')
            for path, raw in blobs:
                self.sampling_context = {'operation': 'sample_output_write', 'path': str(path)}
                with path.open('ab') as stream:
                    stream.write(raw)
                    stream.flush()
            self.count += 1
            self.bytes += size
            self.previous = started

    def run(self):
        try:
            while not self.stop.is_set():
                begin = time.monotonic()
                self.sample()
                self.stop.wait(max(0, spec.BOUNDS['sample_interval_ms'] / 1000 - (time.monotonic() - begin)))
        except BaseException as error:
            failure = error_evidence(error, {**self.sampling_context, 'phase': self.phase(), 'sample': self.count + 1})
            self.errors.append(failure)
            try:
                self.events.emit('monitor_failed', failure=failure)
            except BaseException as record_error:
                self.errors.append(error_evidence(record_error, {'operation': 'monitor_failure_record'}))

    def start(self):
        self.thread.start()

    def wait(self, process, timeout, check=True):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if check:
                self.check()
            with self.lock:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    item = self.owned.pop(pid)
                    os.close(item['proc'])
                    process.returncode = os.waitstatus_to_exitcode(status)
                    result = {'available': True, 'source': 'kernel_wait4_owned_child',
                              'maxrss_bytes': usage.ru_maxrss * 1024,
                              'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime}
                    self.events.emit('envelope_process_reaped', role=item['role'], identity=item['identity'],
                                     status=process.returncode, usage=result)
                    if result['maxrss_bytes'] > spec.PROCESS_LIMITS[item['role']]['rss_bytes']:
                        self.errors.append('wait4 RSS acceptance ceiling: ' + item['role'])
                    if check:
                        self.check()
                    return process.returncode, result
            time.sleep(.01)
        raise TimeoutError('owned process stage deadline')

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError('resource monitor did not join')
        if self.owned:
            raise RuntimeError('owned children remain at monitor close')
        os.close(self.observer['proc'])
        for name in ('resources.jsonl', 'envelope.jsonl'):
            path = self.directory / name
            if path.exists():
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
        self.check()
