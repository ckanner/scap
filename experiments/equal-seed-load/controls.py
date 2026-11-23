#!/usr/bin/env python3
"""Directed in-memory projections of audited originals; never reruns SQL."""
import argparse
import copy
import json
from pathlib import Path

import lifecycle
import oracle
import spec


def ledger_cases(directory):
    sdk = oracle.base.rows(directory / 'sdk.jsonl')
    events = oracle.base.rows(directory / 'events.jsonl')
    s3 = oracle.base.rows(directory / 's3.jsonl')
    def pick(rows, event, identifier='load-0'):
        return next(row for row in rows if row['event'] == event and row.get('id') == identifier)
    def client(change):
        result = copy.deepcopy(sdk)
        change(result)
        return {'sdk.jsonl': result}
    yield 'missing-seed-terminal', 'http-denominator', client(
        lambda rows: rows.remove(pick(rows, 'call_finished', 'seed_rows-0')))
    yield 'missing-original-failure-or-terminal', 'http-denominator', client(
        lambda rows: rows.remove(pick(rows, 'call_finished')))
    yield 'duplicate-original-post', 'http-denominator', client(
        lambda rows: rows.append(copy.deepcopy(pick(rows, 'http_request'))))
    yield 'two-sql-posts', 'single-original-post', client(
        lambda rows: pick(rows, 'call_finished').update(posts=2))
    yield 'changed-open-loop-arrival', 'fixed-arrival', client(
        lambda rows: pick(rows, 'call_offered').update(
            scheduled_ns=str(int(pick(rows, 'call_offered')['scheduled_ns']) + 1)))
    yield 'load-relabelled-as-seed', 'original-phase', client(
        lambda rows: pick(rows, 'call_started').update(phase='seed_rows'))
    configuration = oracle.base.wire.parse((directory / 'service-config.json').read_bytes())
    configuration['admission']['data_intake'] += 1
    yield 'increased-admission-limit', 'paired-configuration', {'service-config.json': configuration}
    changed = copy.deepcopy(events)
    changed.remove(next(row for row in changed if row['event'] == 'diagnostic_boundary' and row['boundary'] == 'baseline'))
    yield 'missing-baseline', 'diagnostic-boundary', {'events.jsonl': changed}
    changed = copy.deepcopy(events)
    diagnostics = oracle.base.rows(directory / 'diagnostics.jsonl')
    diagnostics = copy.deepcopy(diagnostics)
    boundary = next(row for row in changed if row['event'] == 'diagnostic_boundary' and row['boundary'] == 'end')
    original = next(row for row in diagnostics if row['attempt'] == boundary['attempt'])
    verify = next(row for row in changed if row['event'] == 'phase_started' and row['phase'] == 'verify')
    original['response_ns'] = oracle.moment(verify) + 1
    boundary['response_ns'] = original['response_ns']
    boundary['monotonic_ns'] = original['response_ns'] + 1
    yield 'diagnostic-end-after-settlement', 'diagnostic-poll-window', {
        'events.jsonl': changed, 'diagnostics.jsonl': diagnostics}
    changed = copy.deepcopy(s3)
    changed.remove(next(row for row in changed if row['event'] == 'delivered'))
    for index, row in enumerate(changed, 1):
        row['sequence'] = index
    yield 'missing-s3-delivery', 's3-exchange', {'s3.jsonl': changed}
    changed = copy.deepcopy(s3)
    target = next(row['request_serial'] for row in changed
                  if row['event'] == 'request' and row['path'] == oracle.base.HEAD and row['if_match'])
    for row in changed:
        if row['request_serial'] == target:
            row['if_match'] = 'different-original-etag'
    yield 'rebound-head-etag', 'original-head-cas', {'s3.jsonl': changed}
    yield 'sdk-row-ceiling', 'ledger-row-budget', {
        'sdk.jsonl': [sdk[0]] * (spec.BOUNDS['sdk_rows'] + 1)}
    request = pick(sdk, 'http_request')
    yield 'http-post-ceiling', 'http-post-budget', {
        'sdk.jsonl': [request] * (spec.BOUNDS['http_posts'] + 1)}


def reject(name, rule, operation):
    try:
        operation()
    except (oracle.Rejected, lifecycle.Invalid) as error:
        if error.rule != rule:
            raise AssertionError(f'{name}: expected {rule}, reached {error.rule}') from error
        return {'name': name, 'expected': rule, 'observed': error.rule}
    raise AssertionError('directed mutation accepted: ' + name)


def projected_controls(directory, original):
    directory = Path(directory)
    cell = directory / 'rate-32-off-1'
    contract = spec.CONTRACTS[32]
    configuration = oracle.base.wire.parse((cell / 'service-config.json').read_bytes())
    sdk = oracle.base.rows(cell / 'sdk.jsonl')
    intents = oracle.base.rows(cell / 'intents.jsonl')
    planned, calls, original_measurements = oracle.base.client(cell, configuration, sdk, intents, contract)
    original_events = oracle.base.rows(cell / 'events.jsonl')
    original_diagnostics = oracle.base.rows(cell / 'diagnostics.jsonl')
    def check_projection(projection):
        if 'sdk.jsonl' in projection:
            history = projection['sdk.jsonl']
            oracle.need(len(history) <= spec.BOUNDS['sdk_rows'], 'ledger-row-budget')
            oracle.need(sum(row['event'] == 'http_request' for row in history)
                        <= spec.BOUNDS['http_posts'], 'http-post-budget')
            oracle.base.client(cell, configuration, history, intents, contract)
        elif 'service-config.json' in projection:
            oracle.configuration(projection['service-config.json'], False, contract)
        elif 's3.jsonl' in projection:
            oracle.s3_exchanges(projection['s3.jsonl'])
            oracle.head_conditions(cell, projection['s3.jsonl'])
        else:
            oracle.diagnostic_cohort(cell, configuration,
                projection.get('events.jsonl', original_events),
                projection.get('diagnostics.jsonl', original_diagnostics), planned, calls)
    cases = []
    for name, rule, projection in ledger_cases(cell):
        cases.append(reject(name, rule, lambda: check_projection(projection)))
    rows, events = original_diagnostics, original_events
    selected = {row['boundary']: row['attempt'] for row in events if row['event'] == 'diagnostic_boundary'}
    snapshots = {boundary: oracle.base.wire.parse(oracle.raw(cell,
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
        lambda: oracle.seed_baseline(lifecycle.parse(changed_baseline), planned, calls)))
    # Keep every ordinary conservation equation true while deleting all load
    # body completions. A missing hook must not pass as valid not_reached data.
    missing = copy.deepcopy(snapshots['end'])
    body = missing['lanes'][0]['intervals'][0]
    old = snapshots['baseline']['lanes'][0]['intervals'][0]
    amount = int(body['completed']) - int(old['completed'])
    if amount <= 0:
        raise AssertionError('actual positive completed-body control unavailable')
    body['not_reached'] = str(int(body['not_reached']) + amount)
    for key in ('completed', 'buckets', 'total_us'):
        body[key] = copy.deepcopy(old[key])
    delta = lifecycle.cohort(before, lifecycle.parse(missing), expected)
    cases.append(reject('missing-hook-with-conserved-counts', 'lifecycle-success-interval-complete',
                        lambda: oracle.complete_intervals(delta, planned, calls)))
    envelope = oracle.base.rows(cell / 'envelope.jsonl')
    starts, ends = oracle.owned_inventory(events)
    sample = copy.deepcopy(next(row for row in envelope
        if any(process['role'] == 'backend' for process in row['processes'])))
    sample['processes'] = [row for row in sample['processes'] if row['role'] not in ('backend', 'node', 'observer')]
    for role in ('backend', 'node', 'observer'):
        sample['totals'][role] = {'rss_bytes': 0, 'fds': 0, 'tasks': 0}
    cases.append(reject('deleted-live-role-samples-with-zero-totals', 'resource-live-process-denominator',
                        lambda: oracle.process_presence(sample, starts, ends)))
    duplicate = [*events, copy.deepcopy(next(iter(starts.values())))]
    cases.append(reject('duplicate-owned-process-start', 'resource-process-denominator',
                        lambda: oracle.owned_inventory(duplicate)))
    boundaries = oracle.round_boundaries(directory)
    boundaries[0], boundaries[3] = boundaries[3], boundaries[0]
    cases.append(reject('swapped-off-cells', 'round-run-order', lambda: oracle.validate_round_order(boundaries)))
    manifest = copy.deepcopy(oracle.base.wire.parse((directory / 'inputs.json').read_bytes())['fixture'])
    manifest[next(iter(manifest))] = '0' * 64
    cases.append(reject('changed-fixture-source', 'fixture-control-source',
        lambda: oracle.base.archive(directory / 'fixture-source.tar', manifest, 'fixture-control-source')))
    unchanged = oracle.diagnostic_cohort(cell, configuration, original_events, original_diagnostics, planned, calls)
    oracle.same(unchanged, original['cells'][cell.name]['lifecycle'], 'positive-control')
    for phase, measured in original_measurements.items():
        oracle.same(measured, {key: original['cells'][cell.name]['measurements'][phase][key] for key in measured},
                    'positive-client-projection')
    return {'status': 'PASSED', 'negative_controls': cases, 'positive_controls': 1,
            'actual_originals_rerun': False, 'projection_deadline_seconds': spec.DEADLINES['matrix_audit_seconds'],
            'positive_control_scope': 'unchanged independently audited client and lifecycle projections',
            'runtime_commit': original['runtime_commit']}


def check(directory):
    # Exactly one full original audit. Projections below reuse only its verified
    # immutable inputs; they are controls, not additional actual observations.
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
