#!/usr/bin/env python3
"""Independent cap-aware original audit; existing byte readers stay unchanged."""
import argparse
from contextlib import contextmanager
import json
import math
from pathlib import Path
import time

import shared
import spec

base = shared.reader(8)
Rejected, need, same, raw, one = base.Rejected, base.need, base.same, base.raw, base.one
REJECTIONS = tuple(shared.reader(cap).Rejected for cap in spec.CAPS)
common = shared.auditor(8)
deadline = common.deadline


@contextmanager
def normalized():
    """Each static original reader owns its error class; expose one public type."""
    try:
        yield
    except (*REJECTIONS, shared.lifecycle.Invalid) as error:
        if type(error) is Rejected:
            raise
        raise Rejected(error.rule) from error


def configuration(value, contract):
    with normalized():
        shared.auditor(contract.max_members).configuration(value, True, contract)


def snapshot_cap(value, cap):
    spec.member_cap(cap)
    with normalized():
        parsed = shared.lifecycle.parse(value)
    for name in ('selected_sizes', 'consumed_sizes'):
        need(not any(parsed['groups'][name][cap:]), 'lifecycle-group-cap')
    return parsed


def diagnostic_caps(directory, rows, events, cap):
    """Check every successful original, including unselected polling responses."""
    observations = {}
    for row in rows:
        if row.get('status') == 200 and 'response' in row:
            observations[row['attempt']] = snapshot_cap(base.wire.parse(raw(directory, row['response'])), cap)
    selected = {event['boundary']: event['attempt'] for event in events
                if event['event'] == 'diagnostic_boundary'}
    need(set(selected) == {'baseline', 'end'} and all(attempt in observations for attempt in selected.values()),
         'diagnostic-cap-boundaries')
    return {'configured_max_members': cap, 'successful_snapshots_checked': len(observations),
            'baseline_groups': observations[selected['baseline']]['groups'],
            'end_groups': observations[selected['end']]['groups']}


def audit_cell(directory, contract, projections=None):
    directory, projections = Path(directory), projections or {}
    reader = shared.auditor(contract.max_members)
    with normalized():
        # The original full reader validates config, plan, all SQL identities,
        # HTTP/S3 closure, native SQLite and resources with this fixed cap.
        report = reader.audit_cell(directory, True, contract, projections)
        rows = projections.get('diagnostics.jsonl')
        if rows is None:
            rows = reader.ledger(directory / 'diagnostics.jsonl', spec.BOUNDS['diagnostic_gets'],
                                 spec.BOUNDS['diagnostic_ledger_bytes'])
        events = projections.get('events.jsonl')
        if events is None:
            events = reader.ledger(directory / 'events.jsonl', spec.BOUNDS['events_rows'], spec.BOUNDS['events_bytes'])
        same(one([row for row in events if row['event'] == 'cell_started'], 'cell-start')['name'],
             directory.name, 'observed-cell-name')
        widths = diagnostic_caps(directory, rows, events, contract.max_members)
    widths['publication_sizes_by_phase'] = {
        phase: value['groups'] for phase, value in report['s3_total']['phases'].items()}
    return {**report, 'max_members': contract.max_members, 'group_width': widths}


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def comparison(baseline_cell, candidate_cell):
    need(baseline_cell['max_members'] == 8 and candidate_cell['max_members'] == 4
         and baseline_cell['group_commit'] is candidate_cell['group_commit'] is True
         and baseline_cell['rate'] == candidate_cell['rate'], 'comparison-arms')
    baseline, candidate = (cell['measurements']['load'] for cell in (baseline_cell, candidate_cell))
    def tail(value, controls=False):
        return (value['control_scheduled_to_terminal_ms'].get('p99') if controls else
                value['scheduled_to_terminal_ms'].get('success', {}).get('p99'))
    def body(value):
        parts = [value['cost_per_original_ack'][key] for key in ('request_body_bytes', 'response_body_bytes')]
        return sum(parts) if all(type(item) in (int, float) and math.isfinite(item) and item >= 0 for item in parts) else None
    metrics = (
        ('original_ack', baseline['original_ack_count'], candidate['original_ack_count']),
        ('offer_window_ack', baseline['original_ack_within_offer_window'], candidate['original_ack_within_offer_window']),
        ('success_p99', tail(baseline), tail(candidate)),
        ('control_p99', tail(baseline, True), tail(candidate, True)),
        ('s3_requests_per_ack', baseline['cost_per_original_ack']['requests'], candidate['cost_per_original_ack']['requests']),
        ('body_bytes_per_ack', body(baseline), body(candidate)))
    checks, costs = {}, []
    values = {}
    for label, left, right in metrics:
        valid = positive(left) and positive(right)
        if label in ('original_ack', 'offer_window_ack'):
            minimum = 1 if label == 'original_ack' else 0
            valid = type(left) is type(right) is int and left >= minimum and right >= minimum
        values[label] = left, right, valid
        if label in ('original_ack', 'offer_window_ack'):
            checks[label + '_not_reduced'] = valid and right >= left
        else:
            checks[label + '_within_5_percent'] = valid and right * 100 <= left * 105
        costs.append({'metric': label, 'baseline_cap8': left, 'candidate_cap4': right,
                      'candidate_over_baseline': right / left if valid and left > 0 else None})
    improvement = {}
    for label in ('original_ack', 's3_requests_per_ack', 'success_p99'):
        left, right, valid = values[label]
        improvement[label] = valid and (right * 100 >= left * 105 if label == 'original_ack'
                                       else right * 100 <= left * 95)
    checks['predeclared_target_improved_5_percent'] = any(improvement.values())
    return {'criteria_met': all(checks.values()), 'checks': checks, 'comparisons': costs,
            'improvement_targets': improvement,
            'interpretation': 'Four predeclared local finite-growth pairs; 5% is an engineering threshold, not statistical significance.'}


def validate_cells(rows):
    fields = ('name', 'group_commit', 'rate', 'max_members', 'contract')
    need(type(rows) is list and all(type(row) is dict and set(fields) <= set(row)
         and row['group_commit'] is True and type(row['rate']) is type(row['max_members']) is int for row in rows),
         'cell-order')
    same([{key: row[key] for key in fields} for row in rows], spec.cells(), 'cell-order')


def matrix_inputs(directory):
    same(base.wire.parse((directory / 'plan.json').read_bytes()), spec.matrix_plan(), 'fixed-matrix-plan')
    result = base.wire.parse((directory / 'result.json').read_bytes())
    need(result['status'] == 'OBSERVED_NOT_AUDITED' and result['profile'] == spec.NAME
         and result['aws_standard'] == result['production_slo'] == 'NOT_RUN', 'run-completion')
    validate_cells(result['cells'])
    need(all(row['status'] == 'OBSERVED_NOT_AUDITED' and not row['cleanup_errors'] for row in result['cells']),
         'cell-completion')
    inputs = base.provenance(directory)
    common.validate_round_order(common.round_boundaries(directory))
    private = []
    for cell in spec.cells():
        events = base.rows(directory / cell['name'] / 'events.jsonl')
        private.append(one([row for row in events if row['event'] == 'cell_started'], 'cell-start')['private_directory'])
    need(len(set(private)) == len(spec.cells()), 'fresh-private-cell-directories')
    need(type(inputs['matrix_start_ns']) is int and type(result['finished_ns']) is int
         and 0 < result['finished_ns'] - inputs['matrix_start_ns'] <= spec.DEADLINES['run_seconds'] * 1_000_000_000,
         'matrix-deadline')
    return inputs


def verify(directory):
    directory = Path(directory)
    extra_started = time.monotonic()
    with deadline(spec.DEADLINES['matrix_audit_seconds']):
        inputs = matrix_inputs(directory)
    extra_used = time.monotonic() - extra_started
    audited, seed = {}, None
    for cell in spec.cells():
        contract = spec.CONTRACTS[cell['rate'], cell['max_members']]
        with deadline(spec.DEADLINES['audit_seconds']):
            report = audit_cell(directory / cell['name'], contract)
        same(report['binary'], inputs['tools']['scapd'], 'observed-service-binary')
        geometry = report['geometry_and_cost']['seed']
        if seed is None:
            seed = geometry
        same(geometry, seed, 'equal-seed-geometry')
        audited[cell['name']] = report
    extra_started = time.monotonic()
    remaining = spec.DEADLINES['matrix_audit_seconds'] - extra_used
    need(remaining > 0, 'independent-audit-deadline')
    with deadline(remaining):
        pairs = []
        for rate in spec.RATES:
            for suffix in ('1', '2'):
                baseline, candidate = f'rate-{rate}-cap8-{suffix}', f'rate-{rate}-cap4-{suffix}'
                pairs.append({'rate': rate, 'baseline': baseline, 'candidate': candidate,
                              **comparison(audited[baseline], audited[candidate])})
        allocated = inodes = 0
        for path in directory.rglob('*'):
            need(not path.is_symlink(), 'evidence-symlink')
            inodes += 1
            allocated += path.stat().st_blocks * 512
        need(allocated <= spec.BOUNDS['matrix_bytes'] and inodes <= spec.BOUNDS['matrix_inodes'], 'matrix-final-budget')
    extra_used += time.monotonic() - extra_started
    plan = spec.matrix_plan()
    return {'status': 'PASSED', 'profile': spec.NAME, 'cells': audited, 'pairs': pairs,
            'improvement_criteria_met_all_pairs': all(pair['criteria_met'] for pair in pairs),
            'measured_inserts': plan['measured_inserts'], 'seed_inserts': plan['seed_inserts'], 'equal_seed': seed,
            'runtime_commit': inputs['build_source_commit'], 'aws_standard': 'NOT_RUN',
            'production_slo': 'NOT_RUN', 'finite_growth_not_steady_state': True,
            'evidence_allocated_bytes': allocated, 'evidence_inodes': inodes,
            'matrix_extra_audit_seconds_used': extra_used}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2, sort_keys=True))
