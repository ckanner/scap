#!/usr/bin/env python3
"""Independent verdict from archived build, actual kernel and original process bytes."""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import re

import spec
from evidence import (ROOT, Rejected, audit_fixture, counters, decimal, digest, fields,
                      load_module, original, parse, require, safe_absolute, same)


def positive(value, rule):
    require(type(value) is int and value > 0, rule)
    return value


def identity(value, rule):
    require(isinstance(value, dict) and set(value) == {'device', 'inode'} and
            type(value['device']) is int and value['device'] >= 0, rule)
    positive(value['inode'], rule)
    return value


def process_command(root, item, label, argv, record, children, allowed=(0,)):
    value = item['commands'][label]
    require(value['argv'] == argv, 'original-command-argv')
    require(value['timed_out'] is False and type(value['exit_code']) is int and
            value['exit_code'] in allowed, 'original-command-exit')
    positive(value['spawn_monotonic_ns'], 'owned-command-lifetime')
    positive(value['wait_monotonic_ns'], 'owned-command-lifetime')
    require(record['started_monotonic_ns'] <= value['spawn_monotonic_ns'] <
            value['wait_monotonic_ns'] <= record['finished_monotonic_ns'], 'owned-command-lifetime')
    children.register(value, value['wait_monotonic_ns'])
    return (original(root, item, label + '.stdout'), original(root, item, label + '.stderr'))


def expected_controls(name, pid):
    return {
        'cgroup.type': 'domain\n', 'cgroup.procs': str(pid) + '\n', 'pids.current': '1\n',
        'memory.max': 'max\n' if name == 'memory-unlimited' else
                      ('67108864\n' if name == 'memory-pressure' else '1073741824\n'),
        'memory.swap.max': '1048576\n' if name == 'swap-over-budget' else '0\n',
        'cpu.max': '20000 100000\n' if name == 'cpu-pressure' else '200000 100000\n',
        'cpu.max.burst': '0\n',
        'pids.max': '16\n' if name == 'tasks-pressure' else '256\n',
        'memory.oom.group': '0\n' if name == 'oom-not-grouped' else '1\n',
    }


def mountinfo(raw):
    require(isinstance(raw, str) and raw.endswith('\n'), 'mountinfo-format')
    entries = {}
    for line in raw.splitlines():
        pair = line.split(' - ')
        require(len(pair) == 2, 'mountinfo-format')
        left, right = pair[0].split(), pair[1].split()
        require(len(left) >= 6 and len(right) == 3, 'mountinfo-format')
        point = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), left[4])
        # Stacked mounts are legal; the final matching mount is the visible one.
        entries[point] = {'device': left[2], 'kind': right[0]}
    return entries


def mounts(snapshot, name, cache):
    paths = [cache, '/tmp', '/tmp', '/var/tmp', '/usr/tmp', '/tmp', cache]
    require(snapshot['cwd'] == cache and snapshot['temporary_directories'] == paths,
            'complete-native-fallbacks')
    values = snapshot['mounts']
    require(len(values) == len(paths) and [value['path'] for value in values] == paths,
            'complete-native-fallbacks')
    infos = mountinfo(snapshot['mountinfo'])
    capacities, by_path = {}, {}
    for value in values:
        path = value['path']
        if 'missing_errno' in value:
            require(path == '/usr/tmp' and value == {'path': path, 'missing_errno': errno.ENOENT},
                    'native-fallback-missing')
            continue
        require(set(value) == {'path', 'device', 'inode', 'kind', 'blocks', 'block_size',
                               'fragment_size', 'inodes'}, 'mount-observation')
        for field in ('inode', 'blocks', 'block_size', 'fragment_size', 'inodes'):
            positive(value[field], 'mount-observation')
        require(type(value['device']) is int and value['device'] >= 0 and
                type(value['kind']) is int and value['block_size'] == value['fragment_size'],
                'mount-observation')
        geometry = (value['kind'], value['blocks'] * value['block_size'], value['inodes'])
        previous = capacities.setdefault(value['device'], geometry)
        require(previous == geometry, 'mount-alias-geometry')
        if path in by_path:
            require(by_path[path] == value, 'mount-alias-observation')
        by_path[path] = value
        # Every declared independent mount must exist in this process's own
        # mountinfo with the same device, not merely in a runner-side summary.
        if path in (cache, '/tmp') or (path == '/var/tmp' and name != 'unbounded-fallback'):
            require(path in infos and infos[path] == {'device': f'{os.major(value["device"])}:{os.minor(value["device"])}',
                                                      'kind': 'tmpfs'}, 'actual-mount-namespace')
    for path, size, inodes in ((cache, 67108864, 4096), ('/tmp', 16777216, 1024),
                                ('/var/tmp', 16777216, 1024)):
        value = by_path[path]
        if path == '/var/tmp' and name == 'unbounded-fallback':
            require(value['kind'] != spec.TMPFS_MAGIC, 'real-unbounded-fallback')
        else:
            require((value['kind'], value['blocks'] * value['block_size'], value['inodes']) ==
                    (spec.TMPFS_MAGIC, size, inodes), 'fixed-tmpfs-capacity')
    declared = {by_path[path]['device'] for path in (cache, '/tmp', '/var/tmp')}
    require(len(declared) == 3, 'separate-tmpfs-mounts')
    if '/usr/tmp' in by_path:
        require(by_path['/usr/tmp']['device'] in declared, 'extra-native-fallback')
    require(set(capacities) == declared, 'unique-mount-capacity')
    if name != 'unbounded-fallback':
        require(sum(value[1] for value in capacities.values()) == 100663296 and
                sum(value[2] for value in capacities.values()) == 6144, 'unique-mount-capacity')


def proc_status(raw):
    result = {}
    for line in raw.splitlines():
        require(':' in line, 'process-status-format')
        key, value = line.split(':', 1)
        require(key not in result, 'process-status-format')
        result[key] = value.strip()
    return result


def check_snapshot(snapshot, item, record, config_digest):
    name, unit = item['name'], item['unit']
    pid = positive(snapshot['pid'], 'unit-process-identity')
    require(type(snapshot['schema']) is int and snapshot['schema'] == 1 and snapshot['uid'] == record['uid'] and
            snapshot['gid'] == record['gid'] and snapshot['boot_id'] == record['host_boot_id'],
            'unit-process-identity')
    require(snapshot['membership_before'] == snapshot['membership_after'] == f'0::/system.slice/{unit}\n'
            and snapshot['cgroup_path'] == '/sys/fs/cgroup/system.slice/' + unit,
            'actual-cgroup-membership')
    identity(snapshot['cgroup_identity'], 'cgroup-identity')
    require(snapshot['cgroup_kind'] == spec.CGROUP2_MAGIC, 'real-cgroup-v2')
    controls = snapshot['controls']
    require(set(controls) == set(spec.CONTROLS), 'complete-kernel-controls')
    for key, expected in expected_controls(name, pid).items():
        require(controls[key] == expected, 'fixed-kernel-controls')
    events = counters(controls['cgroup.events'], 'cgroup-events')
    require(events.get('populated') == 1 and events.get('frozen') == 0, 'cgroup-events')
    memory = counters(controls['memory.events'], 'memory-events')
    require(memory.get('oom') == 0 and memory.get('oom_kill') == 0, 'fresh-cgroup-events')
    require(counters(controls['pids.events'], 'pids-events').get('max') == 0, 'fresh-cgroup-events')
    require({'usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec'} <=
            set(counters(controls['cpu.stat'], 'cpu-stat')), 'cpu-stat')
    require(snapshot['oom_score_adj'] == '0\n', 'nonimmune-unit-process')
    status = proc_status(snapshot['proc_status'])
    require(status['Pid'] == str(pid) and status['Uid'].split() == [str(record['uid'])] * 4 and
            status['Gid'].split() == [str(record['gid'])] * 4 and status['NoNewPrivs'] == '1' and
            int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0 and status['Threads'] == '1',
            'unit-process-sandbox')
    stat = snapshot['proc_stat']
    require(stat.startswith(str(pid) + ' (') and ') ' in stat, 'unit-process-start-ticks')
    tail = stat.rsplit(')', 1)[1].split()
    require(len(tail) >= 20, 'unit-process-start-ticks')
    ticks = positive(int(tail[19]), 'unit-process-start-ticks')
    thread = snapshot['thread_stat']
    require(thread.startswith(str(pid) + ' (') and ') ' in thread, 'cfs-thread-policy')
    thread_tail = thread.rsplit(')', 1)[1].split()
    require(len(thread_tail) >= 39 and thread_tail[38] == '0', 'cfs-thread-policy')
    scheduler = snapshot['sched_ext']
    if 'missing_errno' in scheduler:
        require(scheduler == {'missing_errno': errno.ENOENT}, 'no-active-bpf-scheduler')
    else:
        identity(scheduler['identity'], 'sched-ext-identity')
        require(scheduler['kind'] == spec.SYSFS_MAGIC and scheduler['state'] == 'disabled\n',
                'no-active-bpf-scheduler')
    identity(snapshot['mount_namespace'], 'mount-namespace-identity')
    require(snapshot['mount_namespace'] != record['runner_mount_namespace'], 'isolated-mount-namespace')
    cache = '/run/' + unit.removesuffix('.service')
    mounts(snapshot, name, cache)
    expected = spec.command(name, record['evidence_root'], record['source_root'],
                            record['binary']['path'], record['python']['path'])
    executable = record['python'] if name.endswith('-pressure') else record['binary']
    require(snapshot['target'] == {'argv': expected, 'sha256': executable['sha256']} and
            snapshot['interpreter'] == {key: record['python'][key] for key in ('path', 'sha256')},
            'exec-target-identity')
    if name.endswith('-pressure'):
        require('config_sha256' not in snapshot, 'exec-config-identity')
    else:
        require(snapshot.get('config_sha256') == config_digest, 'exec-config-identity')
    positive(snapshot['started_monotonic_ns'], 'snapshot-process-lifetime')
    positive(snapshot['finished_monotonic_ns'], 'snapshot-process-lifetime')
    require(item['commands']['launch']['spawn_monotonic_ns'] <= snapshot['started_monotonic_ns'] <
            snapshot['finished_monotonic_ns'] < item['commands']['systemd']['wait_monotonic_ns'],
            'snapshot-process-lifetime')
    return pid, ticks


def check_systemd(state, item, record, snapshot):
    name = item['name']
    require(set(state) == set(spec.SHOW_FIELDS), 'complete-systemd-properties')
    expected = {'Id': item['unit'], 'LoadState': 'loaded', 'Type': 'exec', 'User': str(record['uid']),
                'Group': str(record['gid']), 'MemoryMax': 'infinity' if name == 'memory-unlimited' else
                ('67108864' if name == 'memory-pressure' else '1073741824'),
                'MemorySwapMax': '1048576' if name == 'swap-over-budget' else '0',
                'TasksMax': '16' if name == 'tasks-pressure' else '256',
                'OOMPolicy': 'continue' if name == 'oom-not-grouped' else 'kill', 'OOMScoreAdjust': '0',
                'RemainAfterExit': 'yes', 'RuntimeMaxUSec': '45s', 'NoNewPrivileges': 'yes',
                'CapabilityBoundingSet': '', 'ProtectControlGroups': 'yes', 'NRestarts': '0',
                'CPUSchedulingPolicy': '0', 'LimitRTPRIO': '0', 'LimitRTPRIOSoft': '0', 'RestrictRealtime': 'yes',
                'WorkingDirectory': '/run/' + item['unit'].removesuffix('.service'),
                'CPUQuotaPerSecUSec': '200ms' if name == 'cpu-pressure' else '2s',
                'CPUQuotaPeriodUSec': '100ms',
                'ExecMainPID': str(snapshot['pid'])}
    for key, value in expected.items():
        require(state[key] == value, 'fixed-systemd-properties')
    # systemd can release an empty failed unit's cgroup before the final show.
    # The same-PID pre-exec snapshot binds the actual original membership;
    # cleanup separately requires that original path to be absent or empty.
    require(state['ControlGroup'] in ('', '/system.slice/' + item['unit']), 'fixed-systemd-properties')
    # MemoryPeak is preserved as a diagnostic only; no RSS/peak SLO is claimed.
    start = decimal(state['ExecMainStartTimestampMonotonic'], 'systemd-process-lifetime') * 1000
    end = decimal(state['ExecMainExitTimestampMonotonic'], 'systemd-process-lifetime') * 1000
    require(0 < start <= snapshot['started_monotonic_ns'] < snapshot['finished_monotonic_ns'] <= end + 999
            and end <= item['commands']['systemd']['wait_monotonic_ns'], 'systemd-process-lifetime')
    argv = spec.launcher(name, record['evidence_root'], record['source_root'],
                         record['binary']['path'], record['python']['path'])
    match = re.fullmatch(r'\{ path=([^ ;]+) ; argv\[\]=([^;]+) ; ignore_errors=no ; '
                         r'start_time=\[[^\]]*\] ; stop_time=\[[^\]]*\] ; pid=([0-9]+) ; '
                         r'code=(exited|killed|dumped) ; status=([0-9]+)(?:/[A-Z0-9_+-]+)? \}', state['ExecStart'])
    require(match is not None and match[1] == argv[0] and match[2] == ' '.join(argv)
            and match[3] == str(snapshot['pid']), 'actual-execstart-target')
    code = {'exited': '1', 'killed': '2', 'dumped': '3'}[match[4]]
    require(state['ExecMainCode'] == code and state['ExecMainStatus'] == match[5], 'original-unit-exit')
    if name == 'memory-pressure':
        expected_exit = ('2', '9', 'oom-kill', 'failed', 'failed')
    elif name in spec.REJECTIONS:
        expected_exit = ('1', '1', 'exit-code', 'failed', 'failed')
    else:
        expected_exit = ('1', '0', 'success', 'active', 'exited')
    require(tuple(state[key] for key in ('ExecMainCode', 'ExecMainStatus', 'Result', 'ActiveState', 'SubState')) ==
            expected_exit, 'original-unit-exit')
    return start, end


def output_event(raw, rule):
    require(raw.endswith(b'\n') and len(raw.splitlines()) == 1, rule)
    return parse(raw)


def pressure(name, stdout, stderr, snapshot, lifetime):
    require(stderr == b'', 'pressure-original-stderr')
    event = output_event(stdout, 'pressure-original-stdout')
    mode = name.removesuffix('-pressure')
    require(event.get('mode') == mode, 'pressure-mode')
    if mode == 'memory':
        require(event == {'mode': 'memory', 'memory_max': 67108864, 'oom_group': '1'}, 'kernel-oom-input')
    elif mode == 'cpu':
        before, after = event['before'], event['after']
        require(set(before) == set(after) and all(type(value) is int and value >= 0 for value in before.values())
                and all(type(after[key]) is int and after[key] >= value for key, value in before.items()),
                'kernel-cpu-counters')
        require(after['nr_throttled'] > before['nr_throttled'] and
                after['throttled_usec'] > before['throttled_usec'], 'kernel-cpu-throttle')
        require(lifetime[0] <= event['started_monotonic_ns'] and event['finished_monotonic_ns'] <= lifetime[1] + 999
                and event['finished_monotonic_ns'] - event['started_monotonic_ns'] >= 1200000000,
                'fixed-cpu-pressure-duration')
        require(type(event['value']) is int and 0 <= event['value'] < 65536, 'kernel-cpu-work')
    elif mode == 'tasks':
        children = event['children']
        require(event['rejected'] is True and len(children) == event['children_joined'] == 15 and
                event['current_before'] == event['current_after_wait'] == 1 and
                event['current_at_rejection'] == 16, 'kernel-task-rejection')
        require(event['after']['max'] > event['before']['max'] >= 0, 'kernel-task-counter')
        pids = {value['pid'] for value in children}
        require(len(pids) == len(children) and snapshot['pid'] not in pids and
                sorted(event['members_at_rejection']) == sorted([snapshot['pid'], *pids]), 'owned-pressure-children')
        for child in children:
            positive(child['pid'], 'owned-pressure-children')
            positive(child['start_ticks'], 'owned-pressure-children')
            require(type(child['wait_exit_code']) is int and child['wait_exit_code'] in (-15, 0) and
                    snapshot['finished_monotonic_ns'] < child['wait_monotonic_ns'] <= lifetime[1] + 999,
                    'owned-pressure-child-wait')
    elif mode == 'storage':
        require(event['capacity'] == 67108864 and event['enospc'] is True and
                event['reallocated_and_released_bytes'] == 1048576 and event['owned_file_absent'] is True,
                'kernel-storage-reclaim')
        before = event['before']
        require(set(before) == {'blocks', 'inodes'} and before['blocks'] > 0 and before['inodes'] == 4095 and
                event['after_rejection'] == event['after_release'] == before, 'kernel-storage-capacity-returned')
    else:
        raise Rejected('unknown-pressure-mode')


def cleanup(root, item, record, snapshot, children):
    unit = item['unit']
    process_command(root, item, 'stop', ['sudo', '-n', 'systemctl', 'stop', unit], record, children)
    active, _ = process_command(root, item, 'is-active', ['sudo', '-n', 'systemctl', 'is-active', unit],
                                record, children, (3, 4))
    require(active in (b'inactive\n', b'failed\n', b'unknown\n'), 'owned-unit-inactive')
    raw, _ = process_command(root, item, 'stopped-systemd', spec.show_command(unit), record, children, (0, 4))
    if raw:
        state = fields(raw)
        require(state.get('ActiveState') in ('inactive', 'failed') and not state.get('ControlGroup'),
                'owned-unit-stopped-state')
        if item['commands']['stopped-systemd']['exit_code'] == 4:
            require(state.get('LoadState') == 'not-found', 'unloaded-unit-state')
    else:
        require(item['commands']['stopped-systemd']['exit_code'] == 4, 'unloaded-unit-state')
    observed = parse(original(root, item, 'cleanup.json'))
    require(observed['path'] == snapshot['cgroup_path'] and
            item['commands']['stopped-systemd']['wait_monotonic_ns'] <= observed['observed_monotonic_ns'],
            'owned-cgroup-cleanup-order')
    if 'missing_errno' in observed:
        require(observed['missing_errno'] == errno.ENOENT and set(observed) ==
                {'path', 'observed_monotonic_ns', 'missing_errno'}, 'owned-cgroup-absent')
    else:
        require(observed['identity'] == snapshot['cgroup_identity'] and observed['cgroup.procs'] == '' and
                counters(observed['cgroup.events'], 'owned-cgroup-empty').get('populated') == 0,
                'owned-cgroup-empty')
    process_command(root, item, 'reset-failed', ['sudo', '-n', 'systemctl', 'reset-failed', unit],
                    record, children, (0, 1, 4, 5))
    require(observed['observed_monotonic_ns'] <= item['commands']['reset-failed']['spawn_monotonic_ns'],
            'owned-cgroup-cleanup-order')
    sequence = ('systemd', 'stop', 'is-active', 'stopped-systemd', 'reset-failed')
    require(all(item['commands'][left]['wait_monotonic_ns'] <= item['commands'][right]['spawn_monotonic_ns']
                for left, right in zip(sequence, sequence[1:])), 'owned-unit-cleanup-order')


def check_case(root, item, record, children):
    name, unit = item['name'], item['unit']
    require(isinstance(unit, str) and re.fullmatch(r'scap-envelope-[0-9a-f]{32}\.service', unit), 'owned-unit-name')
    value, props = spec.case_inputs(name, unit, record['evidence_root'],
                                    Path(record['private']['path']) / 'credentials.env', record['uid'], record['gid'])
    raw = original(root, item, 'config.json')
    require(same(parse(raw), value), 'fixed-config-variant')
    require(same(item['properties'], props), 'fixed-requested-properties')
    argv = spec.launcher(name, record['evidence_root'], record['source_root'],
                         record['binary']['path'], record['python']['path'])
    require(item['launcher'] == argv, 'fixed-launcher-command')
    require(set(item['commands']) == {'launch', 'systemd', 'stop', 'is-active', 'stopped-systemd', 'reset-failed'},
            'complete-owned-commands')
    process_command(root, item, 'launch', spec.invocation(unit, props, argv), record, children)
    show, show_errors = process_command(root, item, 'systemd', spec.show_command(unit), record, children)
    require(show_errors == b'', 'systemd-original-stderr')
    snapshot = parse(original(root, item, 'preexec.json'))
    incarnation = check_snapshot(snapshot, item, record, item['files']['config.json']['sha256'])
    lifetime = check_systemd(fields(show), item, record, snapshot)
    stdout, stderr = original(root, item, 'stdout'), original(root, item, 'stderr')
    if name == 'valid':
        require(stdout == b'' and same(output_event(stderr, 'valid-admission'),
                {'event': 'configuration_validated', 'kernel_resource_envelope': True}), 'valid-admission')
    elif name in spec.REJECTIONS:
        require(stdout == b'' and stderr == b'scapd: RESOURCE_ENVELOPE\n', 'fail-closed-admission')
    else:
        pressure(name, stdout, stderr, snapshot, lifetime)
    cleanup(root, item, record, snapshot, children)
    return incarnation


def audit(root):
    require(__debug__, 'assertions-required')
    root = Path(root)
    record = parse((root / 'run.json').read_bytes())
    require(record.get('schema') == 2 and record.get('production_slo_passed') is False, 'contract-scope')
    require([item.get('name') for item in record['cases']] == list(spec.CASES), 'complete-case-order')
    require(len({item['unit'] for item in record['cases']}) == len(spec.CASES), 'unique-owned-units')
    safe_absolute(record['evidence_root'])
    safe_absolute(record['source_root'])
    safe_absolute(record['binary']['path'])
    interpreter = safe_absolute(record['python']['path'])
    require(interpreter.is_file() and digest(interpreter) == record['python']['sha256'], 'original-python-runtime')
    require(type(record['uid']) is int and record['uid'] >= 0 and type(record['gid']) is int and record['gid'] >= 0,
            'unit-account')
    positive(record['started_monotonic_ns'], 'run-lifetime')
    positive(record['finished_monotonic_ns'], 'run-lifetime')
    require(record['finished_monotonic_ns'] > record['started_monotonic_ns'], 'run-lifetime')
    require(record['capabilities'] == {'linux': True, 'systemd': True, 'cgroup_v2': True}, 'real-kernel-prerequisites')
    audit_fixture(root, record)
    independent = load_module('kernel_independent_build_audit', ROOT / 'experiments/object-network/audit_build.py')
    try:
        build = independent.receipt(root / 'build', profile='service', source_root=ROOT)
    except (ValueError, KeyError, OSError) as error:
        raise Rejected('build-receipt') from error
    receipt = parse((root / 'build/build-receipt.json').read_bytes())
    require(receipt['source_commit'] == record['source_commit'] and receipt['source_root'] == record['source_root']
            and build['binary'] == record['binary'], 'build-executable-binding')
    identity(record['runner_mount_namespace'], 'runner-mount-namespace')
    require(re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\n', record['host_boot_id']), 'host-boot-identity')
    children = independent.OwnedChildren()
    host = record['host']
    require(host['name'] == 'host' and set(host['commands']) == {'uname', 'systemd-version', 'sudo'}, 'host-observations')
    uname, err = process_command(root, host, 'uname', ['uname', '-srvm'], record, children)
    require(uname.startswith(b'Linux ') and uname.endswith(b'\n') and not err, 'host-kernel-original')
    version, err = process_command(root, host, 'systemd-version', ['systemd-run', '--version'], record, children)
    require(re.match(rb'systemd [0-9]+ ', version) and version.endswith(b'\n') and not err, 'host-systemd-original')
    out, err = process_command(root, host, 'sudo', ['sudo', '-n', 'true'], record, children)
    require(not out and not err, 'host-sudo-original')
    private = record['private']
    path = safe_absolute(private['path'])
    require(path.parent == Path(record['evidence_root']).parent and path.name.startswith('scap-envelope-private-') and
            private['mode'] == 0o700 and private['credentials_mode'] == 0o600 and private['removed_errno'] == errno.ENOENT
            and not path.exists(), 'private-credentials-released')
    require(record['started_monotonic_ns'] < private['created_monotonic_ns'] <
            private['removed_monotonic_ns'] <= record['finished_monotonic_ns'], 'private-directory-lifetime')
    identities = [check_case(root, item, record, children) for item in record['cases']]
    require(len(set(identities)) == len(spec.CASES), 'unique-main-incarnations')
    for previous, following in zip(record['cases'], record['cases'][1:]):
        require(previous['commands']['reset-failed']['wait_monotonic_ns'] <=
                following['commands']['launch']['spawn_monotonic_ns'], 'sequential-owned-cases')
    require(record['cases'][-1]['commands']['reset-failed']['wait_monotonic_ns'] <
            private['removed_monotonic_ns'], 'private-directory-lifetime')
    # Runner status and derived exit summaries intentionally have no authority.
    return {'status': 'passed', 'actual_cases': len(spec.CASES), 'startup_rejections': len(spec.REJECTIONS),
            'kernel_pressure_cases': 4, 'build_verification': build['verification_scope'],
            'production_slo_passed': False, 'aws_qualification': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), indent=2, sort_keys=True))
