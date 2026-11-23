#!/usr/bin/env python3
"""Directed projections of verified originals; one full audit and no SQL rerun."""
import argparse
import copy
import json
from pathlib import Path

import oracle
import shared
import spec

lifecycle = shared.lifecycle
with shared.siblings(oracle=shared.auditor(4), lifecycle=lifecycle, spec=spec):
    _legacy = shared.module('baseline_controls', shared.ROOT / 'experiments/equal-seed-load/controls.py')
ledger_cases = _legacy.ledger_cases


def reject(name, rule, operation):
    try:
        with oracle.normalized():
            operation()
    except oracle.Rejected as error:
        if error.rule != rule:
            raise AssertionError(f'{name}: expected {rule}, reached {error.rule}') from error
        return {'name': name, 'expected': rule, 'observed': error.rule}
    raise AssertionError('directed mutation accepted: ' + name)


def oversized_snapshot(snapshot, kind, cap=4):
    """Project cap+1 members while preserving all ordinary equations.

    A consumed-size mutation also adds a declined, cap-compliant selection and
    a completed zero-duration group observation. This preserves consumption,
    duration and histogram conservation without adding an oversized selection.
    A valid all-singleton source may contain no groups: add synthetic group
    counters only to this in-memory negative control, never to original bytes.
    """
    if kind not in ('selected_sizes', 'consumed_sizes'):
        raise ValueError('unplanned group histogram projection')
    oracle.snapshot_cap(snapshot, cap)
    result = copy.deepcopy(snapshot)
    groups = result['groups']
    index = next((index for index, count in enumerate(groups[kind][:cap]) if int(count)), None)

    def increase(container, name, count=1):
        container[name] = str(int(container[name]) + count)

    def completed_duration(count=1):
        duration = groups['duration']
        increase(duration, 'completed', count)
        increase(duration['buckets'], 0, count)

    increase(groups[kind], cap)
    if index is None:
        increase(groups, 'selected', cap + 1)
        increase(groups, 'declined')
        if kind == 'selected_sizes':
            increase(groups, 'attempts')
            completed_duration()
        else:
            increase(groups, 'attempts', 2)
            increase(groups, 'completed')
            increase(groups, 'consumed', cap + 1)
            increase(groups['selected_sizes'], cap - 1)
            increase(groups['selected_sizes'], 0)
            completed_duration(2)
    else:
        increment = cap - index
        increase(groups[kind], index, -1)
        increase(groups, 'selected' if kind == 'selected_sizes' else 'consumed', increment)
        if kind == 'consumed_sizes':
            for name in ('attempts', 'declined'):
                increase(groups, name)
            increase(groups, 'selected', increment)
            increase(groups['selected_sizes'], increment - 1)
            completed_duration()
    # Failure here is a broken projection, not a passing cap negative control.
    lifecycle.parse(result)
    return result


def baseline_cap_snapshots(baseline, end, cap=4):
    """Use observed end groups at both boundaries so the oversized delta is zero."""
    oracle.snapshot_cap(baseline, cap)
    oversized = oversized_snapshot(end, 'selected_sizes', cap)
    before, after = copy.deepcopy(baseline), copy.deepcopy(end)
    before['groups'] = copy.deepcopy(oversized['groups'])
    after['groups'] = copy.deepcopy(oversized['groups'])
    lifecycle.parse(before)
    lifecycle.parse(after)
    return before, after


def missing_hook_projection(baseline, end, load_successes):
    """Remove a proven successful body hook, preferring load over seed ACKs."""
    if type(load_successes) is not int or load_successes < 0:
        raise ValueError('invalid original load success count')
    source = 'load' if load_successes else 'seed_baseline'
    changed = copy.deepcopy(end if load_successes else baseline)
    body = changed['lanes'][0]['intervals'][0]
    old = (baseline['lanes'][0]['intervals'][0] if load_successes else
           {'completed': '0', 'buckets': ['0'] * len(spec.BUCKETS_US), 'total_us': '0'})
    amount = int(body['completed']) - int(old['completed'])
    if amount <= 0:
        raise AssertionError('actual positive completed-body control unavailable: ' + source)
    body['not_reached'] = str(int(body['not_reached']) + amount)
    for key in ('completed', 'buckets', 'total_us'):
        body[key] = copy.deepcopy(old[key])
    lifecycle.parse(changed)
    return {'source_phase': source, 'snapshot': changed}


def head_projection(directory, contract):
    """Recover adjacent real HEADs and closures before projecting a delta.

    Read only dependencies of the selected pair into memory, rather than every
    historical image in the cell. All source bytes remain hash-checked by the
    independent reader. The full original audit has already validated the trace.
    Prefer load; valid zero-load-ACK samples use guaranteed original seed ACKs.
    """
    directory = Path(directory)
    reader = shared.reader(contract.max_members)
    rows = reader.rows(directory / 's3.jsonl')
    requests = {row['request_serial']: row for row in rows if row['event'] == 'request'}
    responses = {row['request_serial']: row for row in rows if row['event'] == 'response'}
    descriptions, heads = {}, []
    for serial, request in requests.items():
        if request['method'] != 'PUT' or responses[serial]['status'] != 200:
            continue
        if request['path'].startswith(reader.PREFIX):
            descriptions[request['path']] = request['request']
        elif request['path'] == reader.HEAD:
            heads.append((request, reader.wire.parse(reader.raw(directory, request['request']))))
    heads.sort(key=lambda item: item[1]['head_serial'])

    class Objects(dict):
        def __contains__(self, key):
            return key in descriptions

        def __missing__(self, key):
            value = reader.raw(directory, descriptions[key])
            self[key] = value
            return value

    objects = Objects()
    for phase in ('load', 'seed_rows', 'seed'):
        for (previous_request, previous), (current_request, current) in zip(heads, heads[1:]):
            if current_request['phase'] != phase or current['sequence'] <= previous['sequence']:
                continue
            with oracle.normalized():
                before = reader.closure(objects, previous, contract)
                after = reader.closure(objects, current, contract)
                count = reader.publication(previous, current, before, after, True)
            return {'previous': previous, 'current': current, 'before': before, 'after': after,
                    'original_members': count, 'original_phase': phase,
                    'original_head_requests': [previous_request['request'], current_request['request']]}
    raise AssertionError('actual transaction publication control unavailable')


def projected_controls(directory, original):
    directory = Path(directory)
    cell = directory / 'rate-32-cap4-1'
    contract = spec.CONTRACTS[32, 4]
    reader, auditor = shared.reader(4), shared.auditor(4)
    configuration = reader.wire.parse((cell / 'service-config.json').read_bytes())
    sdk, intents = reader.rows(cell / 'sdk.jsonl'), reader.rows(cell / 'intents.jsonl')
    with oracle.normalized():
        planned, calls, original_measurements = reader.client(cell, configuration, sdk, intents, contract)
    events, rows = reader.rows(cell / 'events.jsonl'), reader.rows(cell / 'diagnostics.jsonl')

    def check_projection(projection):
        if 'sdk.jsonl' in projection:
            history = projection['sdk.jsonl']
            oracle.need(len(history) <= spec.BOUNDS['sdk_rows'], 'ledger-row-budget')
            oracle.need(sum(row['event'] == 'http_request' for row in history)
                        <= spec.BOUNDS['http_posts'], 'http-post-budget')
            reader.client(cell, configuration, history, intents, contract)
        elif 'service-config.json' in projection:
            oracle.configuration(projection['service-config.json'], contract)
        elif 's3.jsonl' in projection:
            auditor.s3_exchanges(projection['s3.jsonl'])
            auditor.head_conditions(cell, projection['s3.jsonl'])
        else:
            auditor.diagnostic_cohort(cell, configuration,
                projection.get('events.jsonl', events), projection.get('diagnostics.jsonl', rows), planned, calls)

    cases = [reject(name, rule, lambda: check_projection(projection))
             for name, rule, projection in ledger_cases(cell)]
    selected = {row['boundary']: row['attempt'] for row in events if row['event'] == 'diagnostic_boundary'}
    snapshots = {boundary: reader.wire.parse(reader.raw(cell,
        next(row['response'] for row in rows if row['attempt'] == attempt))) for boundary, attempt in selected.items()}
    before, after = (lifecycle.parse(snapshots[name]) for name in ('baseline', 'end'))
    expected = original['cells'][cell.name]['lifecycle']['expected_acquires']
    invalid = copy.deepcopy(snapshots['end'])
    invalid['valid'] = False
    cases.append(reject('invalid-snapshot', 'lifecycle-invalid', lambda: lifecycle.parse(invalid)))
    wrong = dict(expected, data=expected['data'] + 1)
    cases.append(reject('wrong-acquire-cohort', 'lifecycle-cohort-denominator',
                        lambda: lifecycle.cohort(before, after, wrong)))
    active = copy.deepcopy(snapshots['end'])
    active['lanes'][0]['acquired'] = str(int(active['lanes'][0]['acquired']) + 1)
    active['lanes'][0]['active'] = '1'
    cases.append(reject('nonquiescent-end', 'lifecycle-nonquiescent',
                        lambda: lifecycle.cohort(before, lifecycle.parse(active), expected)))
    changed_baseline = copy.deepcopy(snapshots['baseline'])
    changed_baseline['lanes'][0]['acquired'] = str(int(changed_baseline['lanes'][0]['acquired']) + 1)
    changed_baseline['lanes'][0]['active'] = '1'
    cases.append(reject('baseline-seed-cohort-missing', 'lifecycle-seed-cohort-denominator',
        lambda: auditor.seed_baseline(lifecycle.parse(changed_baseline), planned, calls)))
    missing = missing_hook_projection(snapshots['baseline'], snapshots['end'],
                                      original['cells'][cell.name]['lifecycle']['proven_complete_successes']['data'])
    missing_parsed = lifecycle.parse(missing['snapshot'])
    if missing['source_phase'] == 'load':
        delta = lifecycle.cohort(before, missing_parsed, expected)
        check_missing_hook = lambda: auditor.complete_intervals(delta, planned, calls)
    else:
        check_missing_hook = lambda: auditor.seed_baseline(missing_parsed, planned, calls)
    cases.append(reject('missing-hook-with-conserved-counts', 'lifecycle-success-interval-complete',
                        check_missing_hook))
    envelope = reader.rows(cell / 'envelope.jsonl')
    starts, ends = auditor.owned_inventory(events)
    sample = copy.deepcopy(next(row for row in envelope
        if any(process['role'] == 'backend' for process in row['processes'])))
    sample['processes'] = [row for row in sample['processes'] if row['role'] not in ('backend', 'node', 'observer')]
    for role in ('backend', 'node', 'observer'):
        sample['totals'][role] = {'rss_bytes': 0, 'fds': 0, 'tasks': 0}
    cases.append(reject('deleted-live-role-samples-with-zero-totals', 'resource-live-process-denominator',
                        lambda: auditor.process_presence(sample, starts, ends)))
    duplicate = [*events, copy.deepcopy(next(iter(starts.values())))]
    cases.append(reject('duplicate-owned-process-start', 'resource-process-denominator',
                        lambda: auditor.owned_inventory(duplicate)))
    boundaries = auditor.round_boundaries(directory)
    boundaries[0], boundaries[3] = boundaries[3], boundaries[0]
    cases.append(reject('swapped-cap8-cells', 'round-run-order', lambda: auditor.validate_round_order(boundaries)))
    manifest = copy.deepcopy(reader.wire.parse((directory / 'inputs.json').read_bytes())['fixture'])
    manifest[next(iter(manifest))] = '0' * 64
    cases.append(reject('changed-fixture-source', 'fixture-control-source',
        lambda: reader.archive(directory / 'fixture-source.tar', manifest, 'fixture-control-source')))

    wider = copy.deepcopy(configuration)
    wider['admission']['group_commit']['max_members'] = 8
    cases.append(reject('cap4-configured-as-cap8', 'paired-configuration',
                        lambda: oracle.configuration(wider, contract)))
    disabled = copy.deepcopy(configuration)
    disabled['admission']['group_commit'] = None
    cases.append(reject('cap4-group-disabled', 'paired-configuration',
                        lambda: oracle.configuration(disabled, contract)))
    matrix = reader.wire.parse((directory / 'result.json').read_bytes())['cells']
    wrong_cap = copy.deepcopy(matrix)
    wrong_cap[1]['max_members'] = 8
    cases.append(reject('matrix-cell-cap-mismatch', 'cell-order', lambda: oracle.validate_cells(wrong_cap)))
    wrong_label = copy.deepcopy(matrix)
    wrong_label[1]['name'] = wrong_label[0]['name']
    cases.append(reject('matrix-cell-label-mismatch', 'cell-order', lambda: oracle.validate_cells(wrong_label)))
    publication = head_projection(cell, contract)
    changed_head = copy.deepcopy(publication['current'])
    changed_head['sequence'] = publication['previous']['sequence'] + 5
    cases.append(reject('cap4-five-member-publication', 'group-width',
        lambda: reader.publication(publication['previous'], changed_head,
                                   publication['before'], publication['after'], True)))
    for kind in ('selected_sizes', 'consumed_sizes'):
        oversized = oversized_snapshot(snapshots['end'], kind)
        cases.append(reject('cap4-oversized-' + kind, 'lifecycle-group-cap',
                            lambda: oracle.snapshot_cap(oversized, 4)))
    oversized_before, oversized_after = baseline_cap_snapshots(snapshots['baseline'], snapshots['end'])
    conserved = lifecycle.cohort(lifecycle.parse(oversized_before), lifecycle.parse(oversized_after), expected)
    oracle.same(conserved['groups']['selected_sizes'], [0] * 64, 'control-oversized-zero-delta')
    cases.append(reject('baseline-over-cap-with-zero-delta', 'lifecycle-group-cap',
                        lambda: oracle.snapshot_cap(oversized_before, 4)))

    with oracle.normalized():
        unchanged = auditor.diagnostic_cohort(cell, configuration, events, rows, planned, calls)
    oracle.same(unchanged, original['cells'][cell.name]['lifecycle'], 'positive-control')
    for phase, measured in original_measurements.items():
        oracle.same(measured, {key: original['cells'][cell.name]['measurements'][phase][key] for key in measured},
                    'positive-client-projection')
    return {'status': 'PASSED', 'negative_controls': cases, 'positive_controls': 1,
            'actual_originals_rerun': False, 'projection_deadline_seconds': spec.DEADLINES['matrix_audit_seconds'],
            'missing_hook_source_phase': missing['source_phase'],
            'positive_control_scope': 'unchanged independently audited client and lifecycle projections',
            'cap_control_source': {'cell': cell.name, 'original_members': publication['original_members'],
                'original_phase': publication['original_phase'],
                'original_head_requests': publication['original_head_requests'],
                'original_group_counts': {name: after['groups'][name] for name in
                    ('attempts', 'active', 'selected', 'consumed', 'declined', 'completed', 'incomplete')},
                'mode': {kind: 'observed-group-rebucketed' if any(after['groups'][kind])
                         else 'synthetic-group-added' for kind in ('selected_sizes', 'consumed_sizes')},
                'interpretation': 'In-memory negative controls only; injected groups are not actual observations.'},
            'runtime_commit': original['runtime_commit']}


def check(directory):
    # The only full eight-cell original audit; controls use immutable projections
    # and the remainder of the same frozen matrix-extra audit budget.
    original = oracle.verify(directory)
    remaining = spec.DEADLINES['matrix_audit_seconds'] - original['matrix_extra_audit_seconds_used']
    oracle.need(remaining > 0, 'independent-audit-deadline')
    with oracle.deadline(remaining):
        controls = projected_controls(directory, original)
    return {'audit': original, 'controls': controls}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(check(parser.parse_args().evidence), indent=2, sort_keys=True))
