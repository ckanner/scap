#!/usr/bin/env python3
"""Semantic controls repair outer hashes, retain originals, and require named failures."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile

import oracle
import spec
from evidence import Rejected, digest, fields, parse, require

NEGATIVES = (
    ('missing-case', 'complete-case-order'),
    ('production-slo-claim', 'contract-scope'),
    ('wrong-config-budget', 'fixed-config-variant'),
    ('wrong-requested-limit', 'fixed-requested-properties'),
    ('wrong-launch-argv', 'original-command-argv'),
    ('wrong-actual-memory', 'fixed-kernel-controls'),
    ('cpu-burst', 'fixed-kernel-controls'),
    ('realtime-policy', 'cfs-thread-policy'),
    ('active-bpf-scheduler', 'no-active-bpf-scheduler'),
    ('oom-immune', 'nonimmune-unit-process'),
    ('changed-membership', 'actual-cgroup-membership'),
    ('omitted-fallback', 'complete-native-fallbacks'),
    ('alias-capacity-mismatch', 'mount-alias-geometry'),
    ('wrong-target-bytes', 'exec-target-identity'),
    ('wrong-execstart-target', 'actual-execstart-target'),
    ('ready-on-rejection', 'fail-closed-admission'),
    ('external-sigkill', 'original-unit-exit'),
    ('no-cpu-throttle', 'kernel-cpu-throttle'),
    ('unreaped-pressure-child', 'owned-pressure-child-wait'),
    ('storage-not-reclaimed', 'kernel-storage-capacity-returned'),
    ('unit-still-active', 'owned-unit-inactive'),
    ('cgroup-still-populated', 'owned-cgroup-empty'),
    ('changed-archived-fixture', 'fixture-source-bytes'),
    ('changed-build-binary', 'build-receipt'),
)
POSITIVES = ('untrusted-summary', 'unloaded-transient-unit')


def replacement(path, raw):
    """Replace an inode: hard-linked control copies cannot alter the baseline."""
    temporary = path.with_name(path.name + '.replacement')
    with temporary.open('xb') as stream:
        stream.write(raw)
    os.replace(temporary, path)


def save_record(root, record):
    replacement(root / 'run.json', (json.dumps(record, indent=2, sort_keys=True) + '\n').encode())


def put(root, item, suffix, raw):
    path = root / f'{item["name"]}.{suffix}'
    replacement(path, raw)
    item['files'][suffix]['sha256'] = hashlib.sha256(raw).hexdigest()


def modify_json(root, item, suffix, change):
    value = parse((root / f'{item["name"]}.{suffix}').read_bytes())
    change(value)
    indent = None if suffix == 'stdout' else 2
    put(root, item, suffix, (json.dumps(value, indent=indent, sort_keys=True) + '\n').encode())


def change_show(root, item, change):
    value = fields((root / f'{item["name"]}.systemd.stdout').read_bytes())
    change(value)
    put(root, item, 'systemd.stdout', ''.join(f'{key}={entry}\n' for key, entry in value.items()).encode())


def mutate(name, root, record):
    cases = {item['name']: item for item in record['cases']}
    item = cases['valid']
    if name == 'missing-case':
        record['cases'].pop()
    elif name == 'production-slo-claim':
        record['production_slo_passed'] = True
    elif name == 'wrong-config-budget':
        modify_json(root, item, 'config.json', lambda value: value['resource_envelope'].update(memory_bytes=2147483648))
    elif name == 'wrong-requested-limit':
        item['properties']['MemoryMax'] = '2G'
    elif name == 'wrong-launch-argv':
        item['commands']['launch']['argv'][-2] = '--help'
    elif name in ('wrong-actual-memory', 'cpu-burst'):
        key, value = ('memory.max', '2147483648\n') if name == 'wrong-actual-memory' else ('cpu.max.burst', '1000\n')
        modify_json(root, item, 'preexec.json', lambda value_: value_['controls'].update({key: value}))
    elif name == 'realtime-policy':
        def realtime(value):
            head, tail = value['thread_stat'].rsplit(')', 1)
            parts = tail.split()
            parts[38] = '1'
            value['thread_stat'] = head + ') ' + ' '.join(parts) + '\n'
        modify_json(root, item, 'preexec.json', realtime)
    elif name == 'active-bpf-scheduler':
        modify_json(root, item, 'preexec.json', lambda value: value.update(sched_ext={
            'identity': {'device': 0, 'inode': 1}, 'kind': spec.SYSFS_MAGIC, 'state': 'enabled\n'}))
    elif name == 'oom-immune':
        modify_json(root, item, 'preexec.json', lambda value: value.update(oom_score_adj='-1000\n'))
    elif name == 'changed-membership':
        modify_json(root, item, 'preexec.json', lambda value: value.update(membership_after='0::/system.slice/alien\n'))
    elif name == 'omitted-fallback':
        modify_json(root, item, 'preexec.json', lambda value: value['mounts'].pop(4))
    elif name == 'alias-capacity-mismatch':
        def alias(value):
            value['mounts'][-1]['blocks'] += 1
        modify_json(root, item, 'preexec.json', alias)
    elif name == 'wrong-target-bytes':
        modify_json(root, item, 'preexec.json', lambda value: value['target'].update(sha256='0' * 64))
    elif name == 'wrong-execstart-target':
        change_show(root, item, lambda value: value.update(ExecStart=value['ExecStart'].replace('--check-config', '--help')))
    elif name == 'ready-on-rejection':
        item = cases['memory-unlimited']
        put(root, item, 'stderr', b'{"event":"configuration_validated","kernel_resource_envelope":true}\n')
    elif name == 'external-sigkill':
        change_show(root, cases['memory-pressure'], lambda value: value.update(Result='signal'))
    elif name == 'no-cpu-throttle':
        def no_throttle(value):
            value['after']['nr_throttled'] = value['before']['nr_throttled']
            value['after']['throttled_usec'] = value['before']['throttled_usec']
        modify_json(root, cases['cpu-pressure'], 'stdout', no_throttle)
    elif name == 'unreaped-pressure-child':
        modify_json(root, cases['tasks-pressure'], 'stdout',
                    lambda value: value['children'][0].update(wait_exit_code=None))
    elif name == 'storage-not-reclaimed':
        def retained(value):
            value['after_release']['blocks'] -= 1
        modify_json(root, cases['storage-pressure'], 'stdout', retained)
    elif name == 'unit-still-active':
        put(root, item, 'is-active.stdout', b'active\n')
    elif name == 'cgroup-still-populated':
        snapshot = parse((root / 'valid.preexec.json').read_bytes())
        def populated(value):
            value.pop('missing_errno', None)
            value.update(identity=snapshot['cgroup_identity'],
                         **{'cgroup.procs': str(snapshot['pid']) + '\n', 'cgroup.events': 'populated 1\nfrozen 0\n'})
        modify_json(root, item, 'cleanup.json', populated)
    elif name == 'changed-archived-fixture':
        path = root / 'fixture-source.tar'
        output = io.BytesIO()
        with tarfile.open(path, 'r:') as source, tarfile.open(fileobj=output, mode='w:') as destination:
            for member in source.getmembers():
                with source.extractfile(member) as stream:
                    raw = stream.read()
                if member.name == 'experiments/kernel-envelope/pressure.py':
                    raw += b'\n# altered after the run\n'
                    member.size = len(raw)
                destination.addfile(member, io.BytesIO(raw))
        replacement(path, output.getvalue())
        record['fixture']['archive_sha256'] = digest(path)
    elif name == 'changed-build-binary':
        path = root / 'build/build-receipt.json'
        value = parse(path.read_bytes())
        value['binary']['sha256'] = '0' * 64
        replacement(path, (json.dumps(value, sort_keys=True) + '\n').encode())
    elif name == 'untrusted-summary':
        record.update(status='invented summary; ignored', derived_exit_code=999)
        for item in record['cases']:
            item.update(exit_code=999, stop_exit_code=999)
    elif name == 'unloaded-transient-unit':
        item['commands']['stopped-systemd']['exit_code'] = 4
        put(root, item, 'stopped-systemd.stdout',
            f'Id={item["unit"]}\nLoadState=not-found\nActiveState=inactive\nControlGroup=\n'.encode())
        put(root, item, 'stopped-systemd.stderr', f'Unit {item["unit"]} could not be found.\n'.encode())
    else:
        raise ValueError('unknown fixed control')


def main(args):
    require(__debug__, 'assertions-required')
    source, output = args.evidence.resolve(), args.output.resolve()
    require(not output.is_relative_to(source) and not source.is_relative_to(output), 'independent-control-output')
    output.mkdir(parents=True, exist_ok=False)
    verdict = oracle.audit(source)
    baseline = digest(source / 'run.json')
    results = []
    for name, expected in (*NEGATIVES, *((name, None) for name in POSITIVES)):
        destination = output / name
        shutil.copytree(source, destination, copy_function=os.link)
        record = parse((destination / 'run.json').read_bytes())
        mutate(name, destination, record)
        save_record(destination, record)
        try:
            oracle.audit(destination)
        except Rejected as error:
            require(error.rule == expected, f'wrong-control-rejection:{name}:{error.rule}')
            results.append({'name': name, 'expected_rule': expected, 'observed_rule': error.rule, 'status': 'passed'})
        else:
            require(expected is None, 'control-was-not-rejected:' + name)
            results.append({'name': name, 'status': 'passed', 'kind': 'positive'})
        require(digest(source / 'run.json') == baseline, 'baseline-mutated')
    # A second full baseline audit catches any accidental hard-link mutation of
    # raw bytes, archives or metadata, not just run.json damage.
    require(oracle.audit(source) == verdict, 'baseline-verdict-changed')
    result = {'status': 'passed', 'negative_controls': len(NEGATIVES), 'positive_controls': len(POSITIVES),
              'baseline': verdict, 'results': results}
    (output / 'controls.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
