#!/usr/bin/env python3
"""Preserve the completed original fixed-gib1 run's closed SQLite image.

Only the new destination is written. Original inputs, images, sidecars, private
credentials and backend data are never modified or copied as a directory.
The owned wait4 records are authoritative; /proc/PID is not probed because the
original fixture explicitly supports PID namespaces with a different host view.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

SIDE_SUFFIXES = ('', '-wal', '-shm', '-journal')
GIB = 1 << 30
PROCESS_EVENTS = {'worker_started', 'worker_stopped', 'all_compute_and_local_cache_lost',
                  'backend_started', 'backend_processes_killed', 'backend_restarted', 'backend_stopped'}


class CaptureError(ValueError):
    pass


def require(value, message):
    if not value:
        raise CaptureError(message)


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate original JSON key')
            value[key] = item
        return value

    def invalid(value):
        raise CaptureError('nonfinite original JSON value: ' + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def no_symlink_components(path):
    absolute = Path(os.path.abspath(path))
    for candidate in reversed((absolute, *absolute.parents)):
        require(not candidate.is_symlink(), 'symlink component: ' + str(candidate))
    return absolute


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def file_record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'not a regular file: ' + str(path))
    return {'bytes': info.st_size, 'sha256': digest(path)}


def image_inventory(source):
    no_symlink_components(source)
    values = {}
    for suffix in SIDE_SUFFIXES:
        path = Path(str(source) + suffix)
        require(not path.is_symlink(), 'symlink image/sidecar: ' + str(path))
        values[suffix] = file_record(path) if path.exists() else None
        if suffix in ('-wal', '-journal'):
            require(values[suffix] is None or values[suffix]['bytes'] == 0,
                    'nonempty WAL/journal must not be copied as a standalone image')
    require(values[''] is not None, 'missing actual native image')
    return values


def stat_signature(path):
    if not path.exists() and not path.is_symlink():
        return None
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode), 'not a regular original image/sidecar')
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def public_inventory(directory):
    values = {}
    for path in sorted(directory.rglob('*')):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'symlink in original evidence')
        if stat.S_ISREG(info.st_mode):
            values[path.relative_to(directory).as_posix()] = file_record(path)
        else:
            require(stat.S_ISDIR(info.st_mode), 'special file in original evidence')
    return values


def selected_history(path):
    selected = []
    completed = failed = 0
    with path.open('rb') as stream:
        for raw in stream:
            require(raw.endswith(b'\n'), 'truncated original history')
            row = parse(raw)
            if row['event'] in PROCESS_EVENTS:
                selected.append(row)
            completed += row['event'] == 'capacity_verification_passed'
            failed += row['event'] in ('capacity_verification_failed', 'transport_fixture_failed', 'resource_sampler_failed')
    require(completed == 1 and failed == 0, 'original capacity run is incomplete or failed')
    return selected


def one(values, message):
    require(len(values) == 1, message)
    return values[0]


def owned_exits(history, binary):
    """Verify all original three compute and eight backend incarnations exited."""
    starts = [r for r in history if r['event'] == 'worker_started']
    ends = [r for r in history if r['event'] == 'worker_stopped']
    require(len(starts) == len(ends) == 3 and {r['worker'] for r in starts} == {1, 2, 3},
            'missing/extra original compute incarnation')
    lifetimes, incarnations = defaultdict(list), set()

    def owned(start, end, finish):
        require(start['pid_source'] == end['pid_source'] == 'owned_Popen_child', 'unowned child identity')
        pid, begin = start['pid'], start['spawn_monotonic_ns']
        require(type(pid) is int and pid > 0 and type(begin) is int and 0 < begin < finish,
                'invalid owned process lifetime')
        require((pid, begin) == (end['pid'], end['spawn_monotonic_ns']), 'exit does not match original child')
        require((pid, begin) not in incarnations, 'duplicated child incarnation')
        require(all(finish <= lower or upper <= begin for lower, upper in lifetimes[pid]), 'overlapping child PID lifetimes')
        usage = end['kernel_usage']
        require(end['wait_status'] == -9 and usage['available'] is True
                and usage['source'] == 'kernel_wait4_owned_child', 'missing original SIGKILL/wait4 exit')
        incarnations.add((pid, begin)); lifetimes[pid].append((begin, finish))

    for start in starts:
        end = one([r for r in ends if r['worker'] == start['worker']], 'missing/duplicate original compute exit')
        require(start['binary'] == binary, 'compute binary differs from original build receipt')
        require(start['spawn_monotonic_ns'] <= start['monotonic_ns'] < end['monotonic_ns'],
                'compute start/exit timestamps are out of order')
        owned(start, end, end['monotonic_ns'])
    lost = one([r for r in history if r['event'] == 'all_compute_and_local_cache_lost'], 'missing original all-compute loss')
    require(lost['local_cache_deleted'] is True and lost['process_signal'] == 'SIGKILL'
            and {r['worker'] for r in lost['processes']} == {1, 2}, 'incomplete warm-cache loss')
    for saved in lost['processes']:
        end = one([r for r in ends if r['worker'] == saved['worker']], 'warm exit absent')
        require({key: end[key] for key in saved} == saved and end['monotonic_ns'] < lost['monotonic_ns']
                and end['fault'] is True, 'warm-cache loss precedes original complete exits')
    begun = one([r for r in history if r['event'] == 'backend_started'], 'missing backend start')
    killed = one([r for r in history if r['event'] == 'backend_processes_killed'], 'missing backend fault exits')
    reopened = one([r for r in history if r['event'] == 'backend_restarted'], 'missing backend restart')
    ended = one([r for r in history if r['event'] == 'backend_stopped'], 'missing final backend exits')
    require(begun['directory_identity'] == killed['directory_identity'] == reopened['directory_identity'], 'backend storage directory changed')
    require(lost['monotonic_ns'] < killed['monotonic_ns'] < reopened['monotonic_ns']
            and killed['signal'] == 'SIGKILL', 'backend loss/restart order changed')
    cold = one([r for r in starts if r['worker'] == 3], 'missing recovered compute process')
    require(cold['spawn_monotonic_ns'] > reopened['monotonic_ns'], 'recovered compute existed before backend restart')
    roles = {'master', 'volume', 'filer', 's3'}
    for first, final in ((begun, killed), (reopened, ended)):
        require(len(first['processes']) == len(final['processes']) == 4
                and {r['role'] for r in first['processes']} == {r['role'] for r in final['processes']} == roles,
                'backend owned process denominator')
        for start in first['processes']:
            end = one([r for r in final['processes'] if r['role'] == start['role']], 'missing backend role exit')
            require(start['spawn_monotonic_ns'] < first['monotonic_ns'] < final['monotonic_ns'],
                    'backend start/exit timestamps are out of order')
            owned(start, end, final['monotonic_ns'])
    require(len(incarnations) == 11, 'not all original compute/backend children were reaped')
    return {'compute_incarnations': 3, 'backend_incarnations': 8, 'owned_wait4': 11,
            'last_exit_monotonic_ns': max(r['monotonic_ns'] for r in ends + [ended])}


def validate_paths(actual, source, destination, metadata, private):
    actual = no_symlink_components(actual)
    source = no_symlink_components(source)
    destination = no_symlink_components(destination)
    metadata = no_symlink_components(metadata)
    private = no_symlink_components(private)
    require(actual.is_dir() and source.is_file(), 'missing original evidence/image')
    require(source.is_relative_to(private / 'compute'), 'source is not in original private compute tree')
    require(not destination.exists(), 'destination already exists; never overwrite an attempt')
    require(destination.parent.is_dir(), 'destination parent must already exist')
    require(not destination.is_relative_to(actual) and not destination.is_relative_to(private),
            'destination would write into original evidence or private state')
    require(metadata.parent == destination and metadata.name.endswith('.json')
            and metadata.name not in {'database.sqlite' + suffix for suffix in SIDE_SUFFIXES},
            'capture metadata must be a new JSON file directly in the new destination')
    return actual, source, destination, metadata, private


def copy_file(source, destination, expected_stat):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as incoming:
        observed = os.fstat(incoming.fileno())
        actual_stat = (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
        require(actual_stat == expected_stat and stat.S_ISREG(observed.st_mode), 'source replaced before copy')
        with destination.open('xb') as outgoing:
            os.fchmod(outgoing.fileno(), 0o600)
            while chunk := incoming.read(1024 * 1024):
                outgoing.write(chunk)
            outgoing.flush(); os.fsync(outgoing.fileno())
        observed = os.fstat(incoming.fileno())
        require((observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns) == expected_stat,
                'source changed while being copied')


def copy_closed_files(source, destination):
    before = image_inventory(source)
    stats = {suffix: stat_signature(Path(str(source) + suffix)) for suffix in SIDE_SUFFIXES}
    destination.mkdir(mode=0o700, exist_ok=False)
    image = destination / 'database.sqlite'
    try:
        for suffix, value in before.items():
            if value is not None:
                copy_file(Path(str(source) + suffix), Path(str(image) + suffix), stats[suffix])
        after, copied = image_inventory(source), image_inventory(image)
        require(before == after == copied, 'original image/sidecars changed or copied bytes differ')
        require(stats == {suffix: stat_signature(Path(str(source) + suffix)) for suffix in SIDE_SUFFIXES},
                'original image/sidecar identity changed')
        require(source.stat().st_ino != image.stat().st_ino or source.stat().st_dev != image.stat().st_dev,
                'public image must be an independent copy, not an original hard link')
        return image, before, after, copied
    except BaseException:
        # Preserve partial output and all originals. Never remove original data
        # or pretend a failed capture succeeded.
        raise


def capture(actual, source, destination, metadata):
    started, utc = time.monotonic_ns(), datetime.now(timezone.utc).isoformat()
    actual = no_symlink_components(actual)
    summary = parse((actual / 'summary.json').read_bytes())
    require(summary['status'] == 'passed' and summary['profile'] == 'gib1' and summary['diagnostic'] is False,
            'original fixed-gib1 non-diagnostic actual did not pass')
    private = Path(summary['private_fixture'])
    actual, source, destination, metadata, private = validate_paths(actual, source, destination, metadata, private)
    require(list((private / 'compute').rglob('database.sqlite')) == [source], 'explicit source is not the sole original recovery image')
    original = public_inventory(actual)
    original_summary = original['summary.json']['sha256']
    build = parse((actual / 'build-receipt.json').read_bytes())
    require(build['status'] == 'passed' and build['exit_code'] == 0 and build['profile'] == 'release',
            'missing original successful release receipt')
    exits = owned_exits(selected_history(actual / 'history.jsonl'), build['binary'])
    require(started > exits['last_exit_monotonic_ns'], 'capture began before all owned children exited')
    require(source.stat().st_size >= GIB, 'actual fixed-gib1 native image is too small')
    try:
        image, before, after, copied = copy_closed_files(source, destination)
        require(public_inventory(actual) == original, 'original public evidence changed during capture')
        value = {'schema': 1, 'status': 'CAPTURED_CLOSED_IMAGE', 'scope': 'completed original fixed gib1 contract',
                 'source_commit': build['source_commit'], 'original_path': str(source), 'image_path': str(image),
                 'image_sha256': before['']['sha256'], 'source_unchanged': True,
                 'source_before': before, 'source_after': after, 'copied': copied,
                 'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
                 'started_utc': utc, 'finished_utc': datetime.now(timezone.utc).isoformat(),
                 'owned_exits': exits, 'original_public_files': original,
                 'capacity_summary_sha256': original_summary, 'original_public_files_unchanged': True,
                 'capture_helper_sha256': digest(__file__), 'private_backend_and_credentials_copied': False,
                 'copy_is_not_a_second_s3_recovery': True}
        with metadata.open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
            stream.flush(); os.fsync(stream.fileno())
        descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print(json.dumps({'status': value['status'], 'capture': str(metadata),
                          'capture_sha256': digest(metadata), 'image': str(image), 'image_sha256': value['image_sha256'],
                          'image_bytes': before['']['bytes'], 'owned_exits': exits}, sort_keys=True))
        return value
    finally:
        require(public_inventory(actual) == original, 'original public evidence changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    arguments = parser.parse_args()
    require(not sys.flags.optimize, 'Python optimization is prohibited for validation')
    capture(arguments.actual, arguments.source, arguments.destination, arguments.capture)


if __name__ == '__main__':
    main()
