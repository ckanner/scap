"""Frozen workload and deployment inputs, shared without importing the runner."""
from __future__ import annotations

import hashlib
from pathlib import Path

CASES = ('valid', 'memory-unlimited', 'memory-over-budget', 'swap-over-budget',
         'cpu-over-budget', 'tasks-over-budget', 'storage-over-budget',
         'inodes-over-budget', 'unbounded-fallback', 'oom-not-grouped',
         'memory-pressure', 'cpu-pressure', 'tasks-pressure', 'storage-pressure')
REJECTIONS = CASES[1:10]
CONTROLS = ('cgroup.type', 'cgroup.procs', 'cgroup.events', 'memory.max',
            'memory.swap.max', 'memory.oom.group', 'memory.events', 'cpu.max',
            'cpu.stat', 'cpu.max.burst', 'pids.max', 'pids.current', 'pids.events')
SHOW_FIELDS = ('Id', 'LoadState', 'Result', 'ExecMainPID', 'ExecMainCode',
               'ExecMainStatus', 'ExecMainStartTimestampMonotonic',
               'ExecMainExitTimestampMonotonic', 'ExecStart', 'MemoryPeak',
               'NRestarts', 'ActiveState', 'SubState', 'ControlGroup', 'Type',
               'User', 'Group', 'MemoryMax', 'MemorySwapMax', 'TasksMax',
               'OOMPolicy', 'OOMScoreAdjust', 'RemainAfterExit', 'RuntimeMaxUSec',
               'NoNewPrivileges', 'CapabilityBoundingSet', 'ProtectControlGroups',
               'WorkingDirectory', 'CPUQuotaPerSecUSec', 'CPUQuotaPeriodUSec',
               'CPUSchedulingPolicy', 'LimitRTPRIO', 'LimitRTPRIOSoft', 'RestrictRealtime')
TMPFS_MAGIC = 0x01021994
CGROUP2_MAGIC = 0x63677270
SYSFS_MAGIC = 0x62656572
SOURCE_NAMES = ('PLAN.md', 'README.md', 'spec.py', 'evidence.py', 'launch.py',
                'run.py', 'pressure.py', 'oracle.py', 'controls.py', 'test_contract.py')
EXTERNAL_INPUTS = ('experiments/object-network/audit_build.py',
                   'experiments/object-network/build_evidence.py',
                   'experiments/object-service/build.py')


def config(cache):
    return {
        'version': 1, 'listen': '127.0.0.1:0', 'worker_instance': '100',
        'cache_directory': cache,
        'resource_envelope': {'version': 1, 'memory_bytes': 1073741824, 'swap_bytes': 0,
                              'cpu_millis_per_second': 2000, 'tasks': 256,
                              'temporary_bytes': 100663296, 'temporary_inodes': 6144},
        's3': {'endpoint': 'http://127.0.0.1:1', 'region': 'test', 'bucket': 'scap-test',
               'access_key_env': 'SCAP_ENVELOPE_ACCESS', 'secret_key_env': 'SCAP_ENVELOPE_SECRET',
               'session_token_env': None, 'allow_http': True, 'timeout_ms': 1000},
        'admission': {'active_database_actors': 2, 'active_database_actors_per_tenant': 2,
                      'actor_idle_timeout_ms': 60000, 'control_workers': 1, 'queued_total': 8,
                      'queued_per_tenant': 6, 'queued_per_database': 4, 'reserved_controls': 1,
                      'data_intake': 4, 'control_intake': 2, 'recovery_intake': 1,
                      'max_body_bytes': 1048576, 'timeout_ms': 1000, 'recovery_timeout_ms': 2000},
        'cache': {'pages_per_actor': 2621440, 'parallel_recoveries': 1},
        'credentials': [{'sha256': hashlib.sha256(b'a' * 32).hexdigest(), 'deployment': '1',
                         'tenant': '2', 'principal': '3', 'provision': True}],
    }


def properties(cache, environment_file, uid, gid):
    mount = f'uid={uid},gid={gid},mode=0700'
    return {
        'User': str(uid), 'Group': str(gid), 'Type': 'exec', 'MemoryMax': '1G',
        'MemorySwapMax': '0', 'CPUQuota': '200%', 'CPUQuotaPeriodSec': '100ms',
        'TasksMax': '256', 'OOMPolicy': 'kill', 'OOMScoreAdjust': '0',
        'RuntimeMaxSec': '45s', 'RemainAfterExit': 'yes', 'NoNewPrivileges': 'yes',
        'CPUSchedulingPolicy': 'other', 'LimitRTPRIO': '0', 'RestrictRealtime': 'yes',
        'CapabilityBoundingSet': '', 'ProtectControlGroups': 'yes',
        'WorkingDirectory': cache, 'EnvironmentFile': str(environment_file),
        'Environment': 'SQLITE_TMPDIR=/tmp TMPDIR=/tmp',
        'TemporaryFileSystem': f'{cache}:size=64M,nr_inodes=4096,{mount} '
                               f'/tmp:size=16M,nr_inodes=1024,{mount} '
                               f'/var/tmp:size=16M,nr_inodes=1024,{mount}',
    }


def variant(name, value, props):
    if name not in CASES:
        raise ValueError('unknown frozen case')
    envelope = value['resource_envelope']
    if name == 'memory-unlimited':
        props['MemoryMax'] = 'infinity'
    elif name == 'memory-over-budget':
        envelope['memory_bytes'] -= 1
    elif name == 'swap-over-budget':
        props['MemorySwapMax'] = '1M'
    elif name == 'cpu-over-budget':
        envelope['cpu_millis_per_second'] = 1999
    elif name == 'tasks-over-budget':
        envelope['tasks'] = 255
    elif name == 'storage-over-budget':
        envelope['temporary_bytes'] -= 1
    elif name == 'inodes-over-budget':
        envelope['temporary_inodes'] -= 1
    elif name == 'unbounded-fallback':
        props['TemporaryFileSystem'] = ' '.join(
            item for item in props['TemporaryFileSystem'].split() if not item.startswith('/var/tmp:'))
    elif name == 'oom-not-grouped':
        props['OOMPolicy'] = 'continue'
    elif name == 'memory-pressure':
        props['MemoryMax'] = '64M'
    elif name == 'cpu-pressure':
        props['CPUQuota'] = '20%'
    elif name == 'tasks-pressure':
        props['TasksMax'] = '16'


def case_inputs(name, unit, evidence, environment_file, uid, gid):
    cache = '/run/' + unit.removesuffix('.service')
    value, props = config(cache), properties(cache, environment_file, uid, gid)
    variant(name, value, props)
    for stream, property_name in (('stdout', 'StandardOutput'), ('stderr', 'StandardError')):
        props[property_name] = 'append:' + str(Path(evidence) / f'{name}.{stream}')
    return value, props


def command(name, evidence, source, server, python):
    if name.endswith('-pressure'):
        return [python, '-I', '-B', str(Path(source) / 'experiments/kernel-envelope/pressure.py'),
                name.removesuffix('-pressure')]
    return [server, '--check-config', str(Path(evidence) / f'{name}.config.json')]


def launcher(name, evidence, source, server, python):
    return [python, '-I', '-B', str(Path(source) / 'experiments/kernel-envelope/launch.py'),
            str(Path(evidence) / f'{name}.preexec.json'), '--',
            *command(name, evidence, source, server, python)]


def invocation(unit, props, argv):
    return ['sudo', '-n', 'systemd-run', '--quiet', '--unit', unit,
            *[f'--property={key}={value}' for key, value in props.items()], *argv]


def show_command(unit):
    return ['sudo', '-n', 'systemctl', 'show', '--all', unit, '--property=' + ','.join(SHOW_FIELDS)]
