"""Tool unit/negative tests. Every synthetic record is explicitly non-acceptance."""
from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import controls
import evidence
import launch
import oracle
import run
import spec

BUILD = evidence.load_module('kernel_unit_build_auditor', evidence.ROOT / 'experiments/object-network/audit_build.py')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def write(root, item, suffix, raw):
    (root / f'{item["name"]}.{suffix}').write_bytes(raw)
    evidence.remember(root, item, suffix)


def fixture(root):
    record = {'schema': 2, 'synthetic_fixture_only': True, 'status': 'SYNTHETIC_NOT_ACTUAL',
              'production_slo_passed': False, 'evidence_root': '/synthetic/evidence',
              'source_root': '/synthetic/source', 'uid': 1001, 'gid': 1001,
              'started_monotonic_ns': 1000000000, 'finished_monotonic_ns': 200000000000,
              'binary': {'path': '/synthetic/target/release/scapd', 'sha256': 'a' * 64},
              'python': {'path': '/synthetic/python3.12', 'sha256': 'b' * 64, 'version': 'synthetic'},
              'host_boot_id': '11111111-1111-1111-1111-111111111111\n',
              'runner_mount_namespace': {'device': 4, 'inode': 99},
              'private': {'path': '/synthetic/scap-envelope-private-unit'}, 'cases': []}
    for number, name in enumerate(spec.CASES):
        base, pid = (number + 1) * 10000000000, 1000 + number
        unit = f'scap-envelope-{number:032x}.service'
        value, props = spec.case_inputs(name, unit, record['evidence_root'],
                                        record['private']['path'] + '/credentials.env', record['uid'], record['gid'])
        argv = spec.launcher(name, record['evidence_root'], record['source_root'],
                             record['binary']['path'], record['python']['path'])
        item = {'name': name, 'unit': unit, 'properties': props, 'launcher': argv, 'commands': {}}
        record['cases'].append(item)
        write(root, item, 'config.json', json_bytes(value))
        command_list = [('launch', spec.invocation(unit, props, argv), 0, base, base + 2000000000),
                        ('systemd', spec.show_command(unit), 0, base + 2100000000, base + 2200000000),
                        ('stop', ['sudo', '-n', 'systemctl', 'stop', unit], 0, base + 2300000000, base + 2400000000),
                        ('is-active', ['sudo', '-n', 'systemctl', 'is-active', unit], 3, base + 2500000000, base + 2600000000),
                        ('stopped-systemd', spec.show_command(unit), 4, base + 2700000000, base + 2800000000),
                        ('reset-failed', ['sudo', '-n', 'systemctl', 'reset-failed', unit], 1, base + 2900000000, base + 3000000000)]
        for command_index, (label, command, code, start, end) in enumerate(command_list):
            item['commands'][label] = {'argv': command, 'pid_source': 'owned_Popen_child',
                                       'pid': 4000 + number * 10 + command_index, 'spawn_monotonic_ns': start,
                                       'wait_monotonic_ns': end, 'exit_code': code, 'timed_out': False}
            write(root, item, label + '.stdout', b'')
            write(root, item, label + '.stderr', b'')
        write(root, item, 'is-active.stdout', b'inactive\n')
        write(root, item, 'stopped-systemd.stdout',
              f'Id={unit}\nLoadState=not-found\nActiveState=inactive\nControlGroup=\n'.encode())
        write(root, item, 'stopped-systemd.stderr', f'Unit {unit} could not be found.\n'.encode())
        write(root, item, 'reset-failed.stderr', f'Unit {unit} not loaded.\n'.encode())
        cache = value['cache_directory']
        mounts, info = {}, []
        for mount_index, (path, size, count) in enumerate(((cache, 67108864, 4096), ('/tmp', 16777216, 1024),
                                                          ('/var/tmp', 16777216, 1024))):
            kind = spec.TMPFS_MAGIC
            if name == 'unbounded-fallback' and path == '/var/tmp':
                kind, size, count = 0xEF53, 2147483648, 200000
            device = os.makedev(0, 100 + number * 3 + mount_index)
            mounts[path] = {'path': path, 'device': device, 'inode': 1, 'kind': kind, 'blocks': size // 4096,
                            'block_size': 4096, 'fragment_size': 4096, 'inodes': count}
            info.append(f'{10 + mount_index} 1 0:{os.minor(device)} / {path} rw - '
                        f'{"tmpfs" if kind == spec.TMPFS_MAGIC else "ext4"} source rw\n')
        paths = [cache, '/tmp', '/tmp', '/var/tmp', '/usr/tmp', '/tmp', cache]
        raw_mounts = [copy.deepcopy(mounts[path]) if path in mounts else {'path': path, 'missing_errno': errno.ENOENT}
                      for path in paths]
        tail = ['0'] * 50
        tail[0], tail[19], tail[38] = 'R', str(pid * 100), '0'
        stat = f'{pid} (synthetic python) ' + ' '.join(tail) + '\n'
        memory = {'1G': '1073741824\n', '64M': '67108864\n', 'infinity': 'max\n'}[props['MemoryMax']]
        kernel = {'cgroup.type': 'domain\n', 'cgroup.procs': str(pid) + '\n',
                  'cgroup.events': 'populated 1\nfrozen 0\n', 'memory.max': memory,
                  'memory.swap.max': '1048576\n' if props['MemorySwapMax'] == '1M' else '0\n',
                  'memory.oom.group': '1\n' if props['OOMPolicy'] == 'kill' else '0\n',
                  'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n',
                  'cpu.max': f'{int(props["CPUQuota"].removesuffix("%")) * 1000} 100000\n',
                  'cpu.max.burst': '0\n',
                  'cpu.stat': 'usage_usec 1000\nnr_periods 1\nnr_throttled 0\nthrottled_usec 0\n',
                  'pids.max': props['TasksMax'] + '\n', 'pids.current': '1\n', 'pids.events': 'max 0\n'}
        target = spec.command(name, record['evidence_root'], record['source_root'],
                              record['binary']['path'], record['python']['path'])
        snapshot = {'schema': 1, 'pid': pid, 'uid': 1001, 'gid': 1001, 'started_monotonic_ns': base + 20000000,
                    'finished_monotonic_ns': base + 30000000, 'boot_id': record['host_boot_id'], 'proc_stat': stat,
                    'thread_stat': stat, 'sched_ext': {'missing_errno': errno.ENOENT},
                    'proc_status': f'Pid:\t{pid}\nUid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\n'
                                   'NoNewPrivs:\t1\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nThreads:\t1\n',
                    'membership_before': f'0::/system.slice/{unit}\n', 'membership_after': f'0::/system.slice/{unit}\n',
                    'cgroup_path': '/sys/fs/cgroup/system.slice/' + unit,
                    'cgroup_identity': {'device': 12, 'inode': pid + 1000}, 'cgroup_kind': spec.CGROUP2_MAGIC,
                    'controls': kernel, 'oom_score_adj': '0\n',
                    'mount_namespace': {'device': 4, 'inode': pid + 1000}, 'mountinfo': ''.join(info),
                    'cwd': cache, 'temporary_directories': paths, 'mounts': raw_mounts,
                    'interpreter': {key: record['python'][key] for key in ('path', 'sha256')},
                    'target': {'argv': target, 'sha256': ('b' if name.endswith('-pressure') else 'a') * 64}}
        if not name.endswith('-pressure'):
            snapshot['config_sha256'] = item['files']['config.json']['sha256']
        write(root, item, 'preexec.json', json_bytes(snapshot))
        code, status, result, active, substate = ('1', '0', 'success', 'active', 'exited')
        if name in spec.REJECTIONS:
            code, status, result, active, substate = ('1', '1', 'exit-code', 'failed', 'failed')
        elif name == 'memory-pressure':
            code, status, result, active, substate = ('2', '9', 'oom-kill', 'failed', 'failed')
        state = {'Id': unit, 'LoadState': 'loaded', 'Result': result, 'ExecMainPID': str(pid),
                 'ExecMainCode': code, 'ExecMainStatus': status, 'ExecMainStartTimestampMonotonic': str((base + 10000000) // 1000),
                 'ExecMainExitTimestampMonotonic': str((base + 1500000000) // 1000),
                 'ExecStart': '{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) +
                              ' ; ignore_errors=no ; start_time=[synthetic] ; stop_time=[synthetic] ; pid=' + str(pid) +
                              ' ; code=' + ('killed' if code == '2' else 'exited') + ' ; status=' + status + ' }',
                 'MemoryPeak': '20000000', 'NRestarts': '0', 'ActiveState': active, 'SubState': substate,
                 'ControlGroup': '/system.slice/' + unit, 'Type': 'exec', 'User': '1001', 'Group': '1001',
                 'MemoryMax': 'infinity' if memory == 'max\n' else memory.strip(),
                 'MemorySwapMax': kernel['memory.swap.max'].strip(), 'TasksMax': props['TasksMax'],
                 'OOMPolicy': props['OOMPolicy'], 'OOMScoreAdjust': '0', 'RemainAfterExit': 'yes', 'RuntimeMaxUSec': '45s',
                 'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': '', 'ProtectControlGroups': 'yes', 'WorkingDirectory': cache,
                 'CPUQuotaPerSecUSec': '200ms' if props['CPUQuota'] == '20%' else '2s', 'CPUQuotaPeriodUSec': '100ms',
                 'CPUSchedulingPolicy': '0', 'LimitRTPRIO': '0', 'LimitRTPRIOSoft': '0', 'RestrictRealtime': 'yes'}
        write(root, item, 'systemd.stdout', ''.join(f'{key}={value}\n' for key, value in state.items()).encode())
        write(root, item, 'cleanup.json', json_bytes({'path': snapshot['cgroup_path'], 'missing_errno': errno.ENOENT,
                                                     'observed_monotonic_ns': base + 2850000000}))
        stdout, stderr = b'', b''
        if name == 'valid':
            stderr = json_bytes({'event': 'configuration_validated', 'kernel_resource_envelope': True})
        elif name in spec.REJECTIONS:
            stderr = b'scapd: RESOURCE_ENVELOPE\n'
        elif name == 'memory-pressure':
            stdout = json_bytes({'mode': 'memory', 'memory_max': 67108864, 'oom_group': '1'})
        elif name == 'cpu-pressure':
            stdout = json_bytes({'mode': 'cpu', 'before': {'nr_throttled': 0, 'throttled_usec': 0},
                                 'after': {'nr_throttled': 10, 'throttled_usec': 800000}, 'value': 10,
                                 'started_monotonic_ns': base + 40000000, 'finished_monotonic_ns': base + 1240000000})
        elif name == 'tasks-pressure':
            children = [{'pid': 5000 + i, 'start_ticks': 100000, 'wait_exit_code': -15,
                         'wait_monotonic_ns': base + 1400000000 + i} for i in range(15)]
            stdout = json_bytes({'mode': 'tasks', 'children_joined': 15, 'rejected': True,
                                 'before': {'max': 0}, 'after': {'max': 1}, 'children': children,
                                 'members_at_rejection': [pid, *[child['pid'] for child in children]],
                                 'current_before': 1, 'current_at_rejection': 16, 'current_after_wait': 1})
        else:
            free = {'blocks': 16384, 'inodes': 4095}
            stdout = json_bytes({'mode': 'storage', 'capacity': 67108864, 'enospc': True,
                                 'reallocated_and_released_bytes': 1048576, 'before': free,
                                 'after_rejection': free, 'after_release': free, 'owned_file_absent': True})
        write(root, item, 'stdout', stdout)
        write(root, item, 'stderr', stderr)
    (root / 'run.json').write_bytes(json_bytes(record))
    return record


class ContractTests(unittest.TestCase):
    def assert_rejected(self, expected, function, *args):
        with self.assertRaises(evidence.Rejected) as caught:
            function(*args)
        self.assertEqual(caught.exception.rule, expected)

    def audit_cases(self, root, record):
        owned = BUILD.OwnedChildren()
        return [oracle.check_case(root, item, record, owned) for item in record['cases']]

    def test_frozen_case_and_pressure_counts(self):
        self.assertEqual(len(spec.CASES), 14)
        self.assertEqual(len(set(spec.CASES)), 14)
        self.assertEqual(len(spec.REJECTIONS), 9)
        self.assertEqual(sum(name.endswith('-pressure') for name in spec.CASES), 4)
        self.assertEqual(launch.CONTROLS, spec.CONTROLS)
        for name in spec.CASES:
            with self.subTest(name=name):
                value, props = spec.case_inputs(name, 'scap-envelope-0.service', '/evidence', '/private/env', 1, 2)
                self.assertEqual(props['OOMScoreAdjust'], '0')
                self.assertEqual(props['CPUSchedulingPolicy'], 'other')
                self.assertEqual(props['LimitRTPRIO'], '0')
                self.assertEqual(props['RestrictRealtime'], 'yes')
                self.assertEqual(value['resource_envelope']['swap_bytes'], 0)
                self.assertEqual(props['RuntimeMaxSec'], '45s')
        with self.assertRaises(ValueError):
            spec.variant('invented', {}, {})

    def test_all_fourteen_original_record_projections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            self.assertEqual(len(set(self.audit_cases(root, record))), 14)
            # These synthetic projections deliberately have neither a formal
            # build nor the real runtime artifacts needed for actual admission.
            self.assert_rejected('original-python-runtime', oracle.audit, root)

    def test_semantic_case_controls_repair_outer_hashes(self):
        excluded = {'missing-case', 'production-slo-claim', 'changed-archived-fixture', 'changed-build-binary'}
        for name, expected in controls.NEGATIVES:
            if name in excluded:
                continue
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = fixture(root)
                controls.mutate(name, root, record)
                # Each file digest is current; failure must be semantic.
                for item in record['cases']:
                    for suffix in item['files']:
                        evidence.original(root, item, suffix)
                self.assert_rejected(expected, self.audit_cases, root, record)

    def test_positive_summary_and_unloaded_unit_controls(self):
        for name in controls.POSITIVES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = fixture(root)
                controls.mutate(name, root, record)
                self.assertEqual(len(self.audit_cases(root, record)), 14)

    def test_missing_case_and_false_slo_are_rejected_before_build(self):
        for name, expected in controls.NEGATIVES[:2]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = fixture(root)
                controls.mutate(name, root, record)
                controls.save_record(root, record)
                self.assert_rejected(expected, oracle.audit, root)

    def test_named_exit_suffix_and_empty_loaded_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            item = record['cases'][0]
            controls.change_show(root, item, lambda state: state.update(ExecStart=state['ExecStart'].replace('status=0 }', 'status=0/SUCCESS }')))
            item['commands']['stopped-systemd']['exit_code'] = 0
            controls.put(root, item, 'stopped-systemd.stdout', b'LoadState=loaded\nActiveState=inactive\nControlGroup=\n')
            snapshot = evidence.parse((root / 'valid.preexec.json').read_bytes())
            def empty(value):
                value.pop('missing_errno')
                value.update(identity=snapshot['cgroup_identity'], **{'cgroup.procs': '', 'cgroup.events': 'populated 0\nfrozen 0\n'})
            controls.modify_json(root, item, 'cleanup.json', empty)
            self.assertEqual(len(self.audit_cases(root, record)), 14)

    def test_unknown_show_needs_independent_cgroup_and_inactive_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            item = record['cases'][0]
            controls.put(root, item, 'stopped-systemd.stdout', b'')
            self.assertEqual(len(self.audit_cases(root, record)), 14)
            controls.mutate('cgroup-still-populated', root, record)
            self.assert_rejected('owned-cgroup-empty', self.audit_cases, root, record)

    def test_disabled_sysfs_bpf_state_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            controls.modify_json(root, record['cases'][0], 'preexec.json', lambda value: value.update(sched_ext={
                'kind': spec.SYSFS_MAGIC, 'identity': {'device': 0, 'inode': 1}, 'state': 'disabled\n'}))
            self.assertEqual(len(self.audit_cases(root, record)), 14)

    def test_finished_unit_may_release_cgroup_but_not_move_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            controls.change_show(root, record['cases'][1], lambda state: state.update(ControlGroup=''))
            self.assertEqual(len(self.audit_cases(root, record)), 14)
            controls.change_show(root, record['cases'][1], lambda state: state.update(ControlGroup='/system.slice/alien'))
            self.assert_rejected('fixed-systemd-properties', self.audit_cases, root, record)

    def test_boolean_cannot_impersonate_numeric_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            controls.modify_json(root, record['cases'][0], 'config.json', lambda value: value.update(version=True))
            self.assert_rejected('fixed-config-variant', self.audit_cases, root, record)

    def test_other_fallback_may_alias_but_cannot_add_unbounded_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            def alias(value):
                value['mounts'][4] = dict(value['mounts'][3], path='/usr/tmp')
            controls.modify_json(root, record['cases'][0], 'preexec.json', alias)
            self.assertEqual(len(self.audit_cases(root, record)), 14)
            def extra(value):
                value['mounts'][4]['device'] += 1
            controls.modify_json(root, record['cases'][0], 'preexec.json', extra)
            self.assert_rejected('extra-native-fallback', self.audit_cases, root, record)

    def test_cleanup_and_snapshot_lifetime_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            record['cases'][0]['commands']['is-active']['spawn_monotonic_ns'] -= 200000000
            self.assert_rejected('owned-unit-cleanup-order', self.audit_cases, root, record)

    def test_original_hash_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = fixture(root)
            (root / 'valid.stdout').write_bytes(b'invented')
            self.assert_rejected('original-bytes', self.audit_cases, root, record)
        self.assert_rejected('duplicate-json-key', evidence.parse, b'{"key":1,"key":2}')
        self.assert_rejected('nonfinite-json-number', evidence.parse, b'{"key":NaN}')
        self.assert_rejected('systemd-duplicate-field', evidence.fields, b'Id=a\nId=b\n')
        self.assert_rejected('systemd-original-format', evidence.fields, b'Id=a')

    def test_safe_paths_do_not_ambiguously_round_trip_execstart(self):
        self.assertEqual(evidence.safe_absolute('/a/b-1.2+3'), Path('/a/b-1.2+3'))
        for value in ('relative', '/a/../b', '/a;b', '/a b', '/a//b', '/a/./b'):
            with self.subTest(value=value):
                self.assert_rejected('absolute-safe-path', evidence.safe_absolute, value)

    def test_fixture_archive_repaired_hash_still_rejects_wrong_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {'source_commit': 'a' * 40, 'cases': [{'name': 'valid'}]}
            record['fixture'] = evidence.archive_fixture(root, record['source_commit'])
            evidence.audit_fixture(root, record)
            controls.mutate('changed-archived-fixture', root, record)
            self.assert_rejected('fixture-source-bytes', evidence.audit_fixture, root, record)

    def test_hardlink_control_replacement_preserves_baseline_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, copy_path = root / 'original', root / 'copy'
            source.mkdir()
            (source / 'run.json').write_bytes(b'original\n')
            shutil.copytree(source, copy_path, copy_function=os.link)
            controls.save_record(copy_path, {'changed': True})
            self.assertEqual((source / 'run.json').read_bytes(), b'original\n')
            self.assertNotEqual((source / 'run.json').stat().st_ino, (copy_path / 'run.json').stat().st_ino)

    def test_preexec_observer_reads_actual_descriptor_and_bounds_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            status = os.statvfs(directory)
            actual = launch.mount(directory)
            self.assertEqual(actual['device'], os.stat(directory).st_dev)
            self.assertEqual(actual['blocks'], status.f_blocks)
            missing = launch.mount(directory + '/missing')
            self.assertEqual(missing['missing_errno'], errno.ENOENT)
            path = Path(directory) / 'large'
            path.write_bytes(b'123456789')
            with self.assertRaises(ValueError):
                launch.bounded(path, 8)
            self.assertEqual(launch.bounded(path, 9), '123456789')
        with mock.patch.object(launch.os, 'open', side_effect=PermissionError(errno.EACCES, 'denied')):
            with self.assertRaises(PermissionError):
                launch.mount('/denied')

    def test_owned_command_wait_and_timeout_are_original_results(self):
        result, stdout, stderr = run.execute(['/bin/true'], 1)
        self.assertEqual((result['exit_code'], result['timed_out'], stdout, stderr), (0, False, b'', b''))
        self.assertLess(result['spawn_monotonic_ns'], result['wait_monotonic_ns'])
        result, _, _ = run.execute(['/bin/sleep', '1'], 0.01)
        self.assertEqual((result['exit_code'], result['timed_out']), (-9, True))

    def test_not_run_is_never_a_complete_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'run.json').write_bytes(json_bytes({'schema': 2, 'status': 'NOT_RUN',
                                                       'cases': [], 'production_slo_passed': False}))
            self.assert_rejected('complete-case-order', oracle.audit, root)

    def test_missing_host_retains_not_run_and_complete_source_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'evidence'
            args = SimpleNamespace(evidence=root, server=Path('/missing/scapd'), build_record=Path('/missing/build.json'))
            with mock.patch.object(run.sys, 'platform', 'unit-unsupported'):
                with self.assertRaisesRegex(ValueError, 'NOT_RUN'):
                    run.main(args)
            record = evidence.parse((root / 'run.json').read_bytes())
            self.assertEqual(record['status'], 'NOT_RUN')
            self.assertEqual(record['cases'], [])
            evidence.audit_fixture(root, record)
            self.assert_rejected('complete-case-order', oracle.audit, root)


if __name__ == '__main__':
    unittest.main()
