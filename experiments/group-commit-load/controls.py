#!/usr/bin/env python3
"""Directed original-ledger projections; no SQL, backend or actual run is repeated."""
import argparse
import copy
import json
from pathlib import Path

import oracle
import spec


def cases(directory, contract=spec.SHORT):
    ledger = oracle.rows(directory / 'sdk.jsonl')
    s3 = oracle.rows(directory / 's3.jsonl')
    original = 'low-0'
    def client_change(function):
        changed = copy.deepcopy(ledger)
        function(changed)
        return {'sdk.jsonl': changed}
    def pick(rows, event, identifier=original):
        return next(row for row in rows if row['event'] == event and row.get('id') == identifier)
    yield 'missing-terminal', 'http-denominator', client_change(
        lambda rows: rows.remove(pick(rows, 'call_finished')))
    yield 'duplicate-post-observation', 'http-denominator', client_change(
        lambda rows: rows.append(copy.deepcopy(pick(rows, 'http_request'))))
    yield 'two-business-posts', 'single-original-post', client_change(
        lambda rows: pick(rows, 'call_finished').update(posts=2))
    yield 'changed-offer-clock', 'fixed-arrival', client_change(
        lambda rows: pick(rows, 'call_offered').update(scheduled_ns=str(int(pick(rows, 'call_offered')['scheduled_ns']) + 1)))
    yield 'missing-offer', 'arrival-denominator', client_change(
        lambda rows: rows.remove(pick(rows, 'call_offered')))
    yield 'incorrect-invoke-schedule', 'offered-before-call', client_change(
        lambda rows: pick(rows, 'call_started').update(scheduled_ns='1'))
    yield 'fabricated-active-count', 'generator-active-count', client_change(
        lambda rows: pick(rows, 'call_offered').update(active=192))
    yield 'original-phase-changed', 'original-phase', client_change(
        lambda rows: pick(rows, 'call_started').update(phase='contended'))
    successful = [row['id'] for row in ledger if row['event'] == 'call_finished' and row['ok']
                  and row['id'].startswith(('low-', 'contended-')) and '-control-' not in row['id']]
    target, donor = (successful[0], 'schema') if successful else ('schema', 'create')
    def wrong_ack(rows):
        pick(rows, 'http_response', target)['response'] = pick(rows, 'http_response', donor)['response']
        value = oracle.wire.parse(oracle.raw(directory, pick(rows, 'http_response', donor)['response']))['value']
        pick(rows, 'call_finished', target)['state'] = value.get('state')
    yield 'ack-result-from-other-request', 'original-random-result', client_change(wrong_ack)
    yield 'lookup-wrong-original', 'lookup-original-identity', client_change(
        lambda rows: pick(rows, 'http_request', 'lookup-' + original).update(
            request=pick(rows, 'http_request', 'lookup-low-1')['request']))
    yield 'http-success-relabelled-failure', 'sdk-http-outcome', client_change(
        lambda rows: pick(rows, 'call_finished', 'schema').update(ok=False, state=None,
            error={'name': 'TypeError', 'code': None, 'outcome': None}))
    yield 'terminal-after-finish', 'http-terminal-before-finish', client_change(
        lambda rows: pick(rows, 'call_finished', 'schema').update(monotonic_ns=
            str(int(pick(rows, 'http_response', 'schema')['monotonic_ns']) - 1)))
    def early_arrival_end(rows):
        origin = next(int(row['origin_ns']) for row in rows if row['event'] == 'phase_started' and row['phase'] == 'low')
        next(row for row in rows if row['event'] == 'arrivals_finished' and row['phase'] == 'low')['monotonic_ns'] = str(origin + 1)
    yield 'shortened-offer-window', 'arrival-duration', client_change(early_arrival_end)
    def unissued_commit(rows):
        offered = copy.deepcopy(pick(rows, 'call_offered'))
        rows[:] = [row for row in rows if not (row.get('id') == original and row['event'] in
                   ('call_started', 'call_finished', 'http_request', 'http_response', 'http_error'))]
        offered.update(event='generator_rejected', posts=0, reason='client_inflight_limit')
        rows.append(offered)
    yield 'never-posted-but-committed', oracle.generator_rule(contract), client_change(unissued_commit)
    first_write = next(row for row in s3 if row['event'] == 'request' and row['method'] == 'PUT'
        and row['path'] == oracle.HEAD and oracle.wire.parse(oracle.raw(directory, row['request']))['sequence'] == 1)
    yield 'publication-before-original-post', 'original-request-before-head', client_change(
        lambda rows: pick(rows, 'http_request', 'schema').update(monotonic_ns=str(oracle.moment(first_write) + 1)))
    config = oracle.wire.parse((directory / 'service-config.json').read_bytes())
    config['output']['bytes'] += 1
    yield 'unequal-capacity', 'paired-configuration', {'service-config.json': config}
    events = oracle.rows(directory / 'events.jsonl')
    for name, event, field, rule in (
        ('changed-launched-config', 'service_start_requested', 'configuration_sha256', 'observed-config-bytes'),
        ('changed-node-binary', 'node_started', 'binary_sha256', 'observed-node-binary'),
        ('changed-backend-binary', 'backend_started', 'binary_sha256', 'observed-backend-binary')):
        changed = copy.deepcopy(events)
        next(row for row in changed if row['event'] == event)[field] = '0' * 64
        yield name, rule, {'events.jsonl': changed}
    changed = copy.deepcopy(s3)
    changed[0]['event'] = 'gate_armed'
    yield 'artificial-gate', 'no-artificial-gates', {'s3.jsonl': changed}
    changed = copy.deepcopy(s3)
    delivered = next(row for row in changed if row['event'] == 'delivered')
    changed.remove(delivered)
    for index, row in enumerate(changed, 1):
        row['sequence'] = index
    yield 'missing-s3-delivery', 's3-exchange', {'s3.jsonl': changed}
    changed = copy.deepcopy(s3)
    serial = next(row['request_serial'] for row in changed if row['phase'] == 'contended')
    for row in changed:
        if row['request_serial'] == serial:
            row['phase'] = 'verify'
    yield 'relabelled-phase-cost', 's3-phase-interval', {'s3.jsonl': changed}
    changed = copy.deepcopy(s3)
    serial = next(row['request_serial'] for row in changed
                  if row['event'] == 'request' and row['path'] == oracle.HEAD and row['if_match'])
    for row in changed:
        if row['request_serial'] == serial:
            row['if_match'] = 'not-the-original-etag'
    yield 'rebound-head-condition', 'original-head-cas', {'s3.jsonl': changed}
    changed = copy.deepcopy(s3)
    serial = next(row['request_serial'] for row in changed
                  if row['event'] == 'request' and row['method'] == 'PUT' and row['path'].startswith(oracle.PREFIX))
    for row in changed:
        if row['request_serial'] == serial:
            row['if_none_match'], row['if_match'] = None, 'unconditional-replacement'
    yield 'immutable-overwrite', 'immutable-create-only', {'s3.jsonl': changed}

    yield 'missing-original-diagnostic-capture', 'rejection-capture', client_change(
        lambda rows: pick(rows, 'http_response', 'schema').pop('rejection_header'))
    yield 'wrong-http-admission-class', 'http-admission-class', client_change(
        lambda rows: pick(rows, 'http_request', 'schema').update(admission='control'))
    annotated = [row for row in ledger if row['event'] == 'http_response' and row.get('rejection_header')]
    if annotated:
        target = annotated[0]['id']
        yield 'changed-original-diagnostic-header', 'rejection-original-header', client_change(
            lambda rows: pick(rows, 'http_response', target).update(
                rejection_header=pick(rows, 'http_response', target)['rejection_header'] + ';extra=1'))
        yield 'diagnostic-wrong-http-status', 'rejection-http-status', client_change(
            lambda rows: pick(rows, 'http_response', target).update(status=200))
        def success_metadata(rows):
            source, destination = pick(rows, 'http_response', target), pick(rows, 'http_response', 'schema')
            for key in ('rejection_header', 'rejection_header_bytes'):
                destination[key] = source[key]
        yield 'diagnostic-attached-to-success', 'rejection-code', client_change(success_metadata)
    backpressure = [row for row in annotated if oracle.wire.parse(
        oracle.raw(directory, row['response']))['error']['code'] == 'BACKPRESSURE']
    if backpressure:
        target = backpressure[0]['id']
        yield 'removed-backpressure-diagnostic', 'rejection-missing', client_change(
            lambda rows: pick(rows, 'http_response', target).update(rejection_header=None, rejection_header_bytes=None))
    typed = [row for row in ledger if row['event'] == 'call_finished' and
             (row.get('error') or {}).get('resource_rejection') is not None]
    if typed:
        target = typed[0]['id']
        yield 'sdk-lost-original-diagnostic', 'sdk-rejection', client_change(
            lambda rows: pick(rows, 'call_finished', target)['error'].update(resource_rejection=None))
        yield 'sdk-diagnostic-version-bool', 'sdk-rejection', client_change(
            lambda rows: pick(rows, 'call_finished', target)['error']['resource_rejection'].update(version=True))
    counted = [row for row in typed if 'used' in row['error']['resource_rejection']]
    if counted:
        target = counted[0]['id']
        yield 'sdk-altered-budget-usage', 'sdk-rejection', client_change(
            lambda rows: pick(rows, 'call_finished', target)['error']['resource_rejection'].update(
                used=str(int(pick(rows, 'call_finished', target)['error']['resource_rejection']['used']) + 1)))


def check(directory):
    original = oracle.verify(directory)
    contract = spec.CONTRACTS[original['profile']]
    root = Path(directory) / 'off-1'
    results = []
    for name, rule, projection in cases(root, contract):
        try:
            oracle.audit_round(root, False, projection, contract)
        except oracle.Rejected as error:
            if error.rule != rule:
                raise AssertionError(f'{name}: expected {rule}, reached {error.rule}') from error
            results.append({'name': name, 'expected': rule, 'observed': error.rule})
        else:
            raise AssertionError('directed mutation accepted: ' + name)
    # Swapping the two off directories preserves their configurations and the
    # reported ABBA list, but contradicts the original monotonic run order.
    boundaries = oracle.round_boundaries(Path(directory))
    boundaries[0], boundaries[3] = boundaries[3], boundaries[0]
    try:
        oracle.validate_round_order(boundaries)
    except oracle.Rejected as error:
        assert error.rule == 'round-run-order'
        results.append({'name': 'swapped-off-round-directories', 'expected': 'round-run-order', 'observed': error.rule})
    else:
        raise AssertionError('directed round-order mutation accepted')
    # Unchanged projection must preserve the original independent report.
    assert oracle.audit_round(root, False, {}, contract) == original['rounds']['off-1']
    names = {row['name'] for row in results}
    coverage = {'original_diagnostic': 'changed-original-diagnostic-header',
                'backpressure': 'removed-backpressure-diagnostic',
                'sdk_typed_diagnostic': 'sdk-lost-original-diagnostic',
                'sdk_counted_diagnostic': 'sdk-altered-budget-usage'}
    return {'status': 'PASSED', 'profile': contract.name,
            'negative_controls': len(results), 'positive_controls': 1,
            'diagnostic_projection_coverage': {key: 'OBSERVED' if name in names else 'NOT_OBSERVED'
                                               for key, name in coverage.items()},
            'kind': 'original ledger projections; additional actual executions: 0', 'controls': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(check(parser.parse_args().evidence), indent=2, sort_keys=True))
