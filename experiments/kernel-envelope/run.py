#!/usr/bin/env python3
"""One fixed actual systemd/cgroup2/tmpfs run; failed originals are retained."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import spec
from evidence import (ROOT, archive_fixture, digest, fields, fixture_inputs, load_module,
                      persist, remember, require, safe_absolute)


def execute(argv, timeout):
    """Own and reap the command; original bytes and wait result are inseparable."""
    started = time.monotonic_ns()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, cwd=ROOT)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # The owned command raced its deadline; it is still reaped.
        stdout, stderr = process.communicate(timeout=10)
    record = {'argv': argv, 'pid_source': 'owned_Popen_child', 'pid': process.pid,
              'spawn_monotonic_ns': started, 'wait_monotonic_ns': time.monotonic_ns(),
              'exit_code': process.returncode, 'timed_out': timed_out}
    return record, stdout, stderr


def save_command(root, item, label, observation):
    result, stdout, stderr = observation
    item.setdefault('commands', {})[label] = result
    for suffix, raw in (('stdout', stdout), ('stderr', stderr)):
        path = root / f'{item["name"]}.{label}.{suffix}'
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        remember(root, item, f'{label}.{suffix}')
    return result


def command(root, item, label, argv, timeout=10):
    return save_command(root, item, label, execute(argv, timeout))


def wait_unit(root, item):
    deadline = time.monotonic() + 55
    last = None
    while time.monotonic() < deadline:
        last = execute(spec.show_command(item['unit']), 10)
        result, raw, _ = last
        if result['exit_code'] != 0 or result['timed_out']:
            break
        state = fields(raw)
        if state.get('ActiveState') == 'failed' or state.get('SubState') == 'exited':
            save_command(root, item, 'systemd', last)
            require(state.get('ExecMainCode') in ('1', '2', '3'), 'missing-real-process-exit')
            return
        time.sleep(0.025)
    if last is not None:
        save_command(root, item, 'systemd', last)
    raise ValueError('owned unit did not finish within the fixed deadline')


def cleanup_group(unit):
    path = Path('/sys/fs/cgroup/system.slice') / unit
    result = {'path': str(path), 'observed_monotonic_ns': time.monotonic_ns()}
    try:
        status = path.stat()
    except FileNotFoundError as error:
        result['missing_errno'] = error.errno
    else:
        result['identity'] = {'device': status.st_dev, 'inode': status.st_ino}
        result['cgroup.procs'] = (path / 'cgroup.procs').read_text()
        result['cgroup.events'] = (path / 'cgroup.events').read_text()
    return result


def cleanup(root, item):
    unit = item['unit']
    stopped = command(root, item, 'stop', ['sudo', '-n', 'systemctl', 'stop', unit])
    if stopped['exit_code'] != 0 or stopped['timed_out']:
        # Failure cleanup is retained and cannot qualify as a fixed successful
        # run. It still kills only this randomly named, owned transient unit.
        command(root, item, 'failed-kill', ['sudo', '-n', 'systemctl', 'kill', '--kill-whom=all',
                                           '--signal=KILL', unit])
        command(root, item, 'failed-stop', ['sudo', '-n', 'systemctl', 'stop', unit])
    command(root, item, 'is-active', ['sudo', '-n', 'systemctl', 'is-active', unit])
    # A completed transient unit may be unloaded after stop. Its show return
    # code is evidence, not a reason to discard the separate inactivity proof.
    command(root, item, 'stopped-systemd', spec.show_command(unit))
    persist(root / f'{item["name"]}.cleanup.json', cleanup_group(unit))
    remember(root, item, 'cleanup.json')
    command(root, item, 'reset-failed', ['sudo', '-n', 'systemctl', 'reset-failed', unit])


def run_case(root, record, name, environment_file):
    unit = 'scap-envelope-' + uuid.uuid4().hex + '.service'
    value, props = spec.case_inputs(name, unit, root, environment_file, record['uid'], record['gid'])
    path = root / f'{name}.config.json'
    persist(path, value)
    argv = spec.launcher(name, root, ROOT, record['binary']['path'], record['python']['path'])
    item = {'name': name, 'unit': unit, 'properties': props, 'launcher': argv}
    record['cases'].append(item)
    remember(root, item, 'config.json')
    for suffix in ('stdout', 'stderr'):
        (root / f'{name}.{suffix}').touch(mode=0o600, exist_ok=False)
    try:
        result = command(root, item, 'launch', spec.invocation(unit, props, argv), 15)
        require(result['exit_code'] == 0 and not result['timed_out'], 'unit-launch')
        wait_unit(root, item)
    finally:
        try:
            cleanup(root, item)
        finally:
            for suffix in ('stdout', 'stderr', 'preexec.json'):
                if (root / f'{name}.{suffix}').is_file():
                    remember(root, item, suffix)
            persist(root / 'run.json', record)


def private_observation(path):
    status = path.stat()
    return {'path': str(path), 'device': status.st_dev, 'inode': status.st_ino,
            'mode': status.st_mode & 0o777, 'created_monotonic_ns': time.monotonic_ns()}


def main(args):
    require(__debug__, 'assertions-required')
    root = args.evidence.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    record = {'schema': 2, 'status': 'NOT_RUN', 'cases': [], 'production_slo_passed': False,
              'started_monotonic_ns': time.monotonic_ns(), 'evidence_root': str(root),
              'source_root': str(ROOT), 'uid': os.getuid(), 'gid': os.getgid()}
    private = None
    try:
        safe_absolute(str(root))
        safe_absolute(str(ROOT))
        record['source_commit'] = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        record['fixture'] = archive_fixture(root, record['source_commit'])
        capabilities = {'linux': sys.platform == 'linux',
                        'systemd': Path('/run/systemd/system').is_dir(),
                        'cgroup_v2': Path('/sys/fs/cgroup/cgroup.controllers').is_file()}
        record['capabilities'] = capabilities
        if not all(capabilities.values()):
            raise ValueError('NOT_RUN: real Linux systemd and cgroup v2 are required')
        record['host_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text()
        record['runner_mount_namespace'] = {
            'device': os.stat('/proc/self/ns/mnt').st_dev, 'inode': os.stat('/proc/self/ns/mnt').st_ino}
        host = {'name': 'host'}
        record['host'] = host
        command(root, host, 'uname', ['uname', '-srvm'])
        command(root, host, 'systemd-version', ['systemd-run', '--version'])
        command(root, host, 'sudo', ['sudo', '-n', 'true'])
        for result in host['commands'].values():
            require(result['exit_code'] == 0 and not result['timed_out'], 'host-prerequisite')
        build = load_module('kernel_service_build', ROOT / 'experiments/object-service/build.py')
        value = build.verify(args.build_record, args.server)
        require(value['source_commit'] == record['source_commit'], 'build-candidate-commit')
        record['binary'] = value['binary']
        safe_absolute(record['binary']['path'])
        interpreter = str(Path(sys.executable).resolve())
        safe_absolute(interpreter)
        record['python'] = {'path': interpreter, 'sha256': digest(interpreter), 'version': sys.version}
        (root / 'build').mkdir()
        build.capture_receipt(args.build_record, args.server, root / 'build')
        independent = load_module('kernel_independent_build', ROOT / 'experiments/object-network/audit_build.py')
        independent.receipt(root / 'build', profile='service', source_root=ROOT)
        record['status'] = 'failed'
        with tempfile.TemporaryDirectory(prefix='scap-envelope-private-', dir=root.parent) as directory:
            private = Path(directory)
            record['private'] = private_observation(private)
            environment_file = private / 'credentials.env'
            environment_file.write_text('SCAP_ENVELOPE_ACCESS=' + secrets.token_hex(16) + '\n' +
                                        'SCAP_ENVELOPE_SECRET=' + secrets.token_hex(32) + '\n')
            environment_file.chmod(0o600)
            record['private']['credentials_mode'] = environment_file.stat().st_mode & 0o777
            for name in spec.CASES:
                run_case(root, record, name, environment_file)
            require(record['fixture']['inputs'] == fixture_inputs(), 'fixture-changed-during-run')
            build.verify(args.build_record, args.server)
            require(digest(interpreter) == record['python']['sha256'], 'interpreter-changed-during-run')
            require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() ==
                    record['source_commit'], 'candidate-commit-changed-during-run')
            record['status'] = 'completed'
    except BaseException as error:
        record['error'] = repr(error)
        raise
    finally:
        if private is not None:
            try:
                private.lstat()
            except FileNotFoundError as error:
                record['private']['removed_errno'] = error.errno
            else:
                record['private']['removed_errno'] = 0
                record['status'] = 'failed'
            record['private']['removed_monotonic_ns'] = time.monotonic_ns()
        record['finished_monotonic_ns'] = time.monotonic_ns()
        persist(root / 'run.json', record)
    # Independently derive the verdict, after credentials and units are gone.
    audit = load_module('kernel_final_oracle', ROOT / 'experiments/kernel-envelope/oracle.py')
    result = audit.audit(root)
    print(__import__('json').dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    main(parser.parse_args())
