#!/usr/bin/env python3
"""Twenty-eight targeted negatives over a fully audited, unchanged matrix.

Only fresh in-memory copies and a new output directory are written. A changed
raw body gets a new content-addressed reference on the selected exchange; an
identical original blob used by another exchange is never changed. Sources and
release receipts pass the full oracle before the reduced history re-audits.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

import oracle


C1 = 'C1_same_policy_prepare_restart'
C2_POLICY = 'C2_same_creator_policy'
C2_CREATOR = 'C2_different_creators'
C3 = 'C3_claimed_abort'
C4_RESOURCE = 'C4_resource_refusal'
C4_STORE = 'C4_s3_unavailable'
C5 = 'C5_shutdown_deadline'

# The denominator is fixed before observing any result. A wrong guard, an
# unexpected exception, a missing target or an accepted mutant is a failure.
CONTROL_PLAN = (
    ('invalid-s3-signature', C1, 'actual-s3-signatures'),
    ('http-operation-disagrees-with-original', C1, 'http-original-operation'),
    ('controller-dispatches-sql', C1, 'controller-never-sql'),
    ('unconditional-head-publication', C1, 'conditional-s3-put'),
    ('late-cas-with-unread-etag', C5, 'head-original-exact-get'),
    ('late-cas-body-changed', C5, 'late-original-candidate-unchanged'),
    ('owner-descriptor-hash-changed', C1, 'original-owner-descriptor'),
    ('claim-target-guard-changed', C1, 'owner-actual-target-guard'),
    ('active-report-without-active-http', C1, 'active-report-has-original-http'),
    ('accepted-reference-changed', C1, 'accepted-original-reference'),
    ('accepted-nonce-changed', C1, 'accepted-original-nonce'),
    ('controller-mutation-budget-exceeded', C1, 'per-tick-admission'),
    ('original-client-ack-omitted', C1, 'two-original-client-acks'),
    ('original-client-ack-rewritten', C1, 'original-ack-bytes'),
    ('original-unknown-relabelled-ack', C1, 'business-unknown-preserved'),
    ('recovered-lookup-result-rewritten', C1, 'recovered-original-result'),
    ('retained-snapshot-reference-changed', C1, 'snapshot-preserved'),
    ('native-query-random-blob-changed', C1, 'no-sql-replay-counter-and-random'),
    ('owned-wait4-source-fabricated', C1, 'owned-wait4'),
    ('owner-cache-not-removed', C1, 'cache-loss-after-owned-exit'),
    ('backpressure-http-429-relabelled', C4_RESOURCE, 'original-http-error-status'),
    ('limit-http-413-relabelled', C4_RESOURCE, 'original-http-error-status'),
    ('s3-unknown-relabelled-unavailable', C4_STORE, 's3-unavailable-not-owner-death'),
    ('late-aborted-resume-relabelled-active', C3, 'accepted-current-marker'),
    ('original-sdk-request-hash-changed', C1, 'original-sdk-request-hash'),
    ('foreign-policy-report-reused', C2_POLICY, 'foreign-policy-remains-blocked'),
    ('foreign-creator-report-reused', C2_CREATOR, 'foreign-creator-remains-blocked'),
    ('first-candidate-cut-target-changed', C1, 'real-first-candidate-failure'),
)
EXPECTED_CONTROLS = 28


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       separators=(',', ':')) + '\n').encode()


def save(path, raw):
    with Path(path).open('xb') as output:
        output.write(raw)


def changed_hash(value):
    assert isinstance(value, str) and len(value) == 64
    return ('0' if value[0] != '0' else '1') + value[1:]


def inventory(directory):
    """Hash bytes and stable metadata; reading does not change the inventory."""
    result = {}
    for path in sorted(Path(directory).rglob('*')):
        if path.is_symlink():
            raise ValueError('evidence inventory cannot contain symbolic links')
        if not path.is_file():
            continue
        before = path.stat()
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        after = path.stat()
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                               value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if stamp(before) != stamp(after):
            raise ValueError('evidence changed during inventory')
        result[path.relative_to(directory).as_posix()] = {
            'bytes': after.st_size, 'sha256': digest.hexdigest(),
            'device': after.st_dev, 'inode': after.st_ino, 'mode': after.st_mode,
            'mtime_ns': after.st_mtime_ns, 'ctime_ns': after.st_ctime_ns}
    if not result:
        raise ValueError('empty evidence inventory')
    return result


class Evidence:
    """One independent case copy plus explicitly referenced raw replacements."""

    def __init__(self, directory, original):
        self.directory = Path(directory)
        self.inputs, self.events, self.business, self.ledger = copy.deepcopy(original)
        self.overlays, self.targets = {}, []

    def read(self, reference):
        if reference.get('sha256') not in self.overlays:
            return oracle.raw_file(self.directory, reference)
        raw = self.overlays[reference['sha256']]
        oracle.need(set(reference) == {'file', 'bytes', 'sha256'}, 'raw-fields')
        oracle.need(reference['file'] == 'raw/' + reference['sha256'], 'raw-path')
        oracle.need(type(reference['bytes']) is int and len(raw) == reference['bytes']
                    and oracle.sha(raw) == reference['sha256'], 'raw-hash')
        return raw

    def replace_raw(self, event, field, raw):
        previous = event[field]
        assert raw != self.read(previous), 'negative raw mutation must change bytes'
        digest = oracle.sha(raw)
        assert digest not in self.overlays or self.overlays[digest] == raw
        self.overlays[digest] = raw
        event[field] = {'file': 'raw/' + digest, 'bytes': len(raw), 'sha256': digest}
        self.targets.append({'event': event['event'], 'sequence': event.get('sequence'),
            'role': event.get('role'), 'serial': event.get('serial'), 'field': field,
            'original_sha256': previous['sha256'], 'replacement_sha256': digest})

    def request(self, operation, principal=None):
        values = [row for row in oracle.select(self.events, 'http_proxy_request', operation=operation)
                  if principal is None or row['principal'] == principal]
        assert values, ('missing original request', operation, principal)
        return values[0]

    def response(self, operation=None, state=None, error=None):
        for request in oracle.select(self.events, 'http_proxy_request'):
            if request['principal'] not in ('12', '13') or operation and request['operation'] != operation:
                continue
            values = oracle.select(self.events, 'http_proxy_backend_response',
                                   role=request['role'], serial=request['serial'])
            if not values:
                continue
            assert len(values) == 1
            row = values[0]
            body = oracle.wire.parse(self.read(row['response']))
            if state is not None and (body.get('ok') is not True or body['value'].get('state') != state):
                continue
            if error is not None and (body.get('ok') is not False or body['error']['code'] != error):
                continue
            return row, body
        raise AssertionError(('missing original response', operation, state, error))

    def http_response(self, row, body, sdk=None):
        """Update only this exchange's HTTP aliases and its optional SDK view."""
        raw, previous = encoded(body), copy.deepcopy(row['response'])
        aliases = [event for event in self.events if event['event'].startswith('http_proxy_')
                   and event.get('role') == row['role'] and event.get('serial') == row['serial']
                   and event.get('response') == previous]
        assert row in aliases
        for event in aliases:
            self.replace_raw(event, 'response', raw)
            if 'content-length' in event.get('headers', {}):
                event['headers']['content-length'] = str(len(raw))
        if sdk is not None:
            # This one SDK response is the second observation of the same
            # delivered exchange, not a replacement of equal bodies elsewhere.
            assert oracle.wire.b64(sdk['body']) == self.read(previous)
            sdk['body'], sdk['body_sha256'] = base64.b64encode(raw).decode(), oracle.sha(raw)

    def business_response(self, event_name):
        call_id = oracle.one(self.business, event_name)['call']
        endpoints = {row['role']: row['endpoint'] for row in oracle.select(self.events, 'http_proxy_started')}
        remaining = [row for row in oracle.select(self.events, 'http_proxy_request') if row['principal'] == '11']
        for client in oracle.select(self.ledger, 'http_request'):
            raw = oracle.wire.b64(client['body'])
            found = [row for row in remaining if self.read(row['request']) == raw and
                     client['url'] == endpoints[row['role']] + row['path']]
            assert found, 'business request correspondence'
            request = found[0]
            remaining.remove(request)
            if client['call_id'] == call_id:
                response = oracle.one(self.events, 'http_proxy_backend_response',
                                      role=request['role'], serial=request['serial'])
                sdk = oracle.one(self.ledger, 'http_response', call_id=call_id)
                return response, oracle.wire.parse(self.read(response['response'])), sdk
        raise AssertionError('missing original business response')

    def report(self, name, change):
        output = oracle.one(self.events, 'controller_reports', id=name)
        stopped = oracle.one(self.events, 'child_stopped', id=name)
        assert output['raw'] == stopped['stderr']
        reports = [oracle.wire.parse(line) for line in self.read(output['raw']).splitlines()]
        assert reports
        change(reports[0])
        raw = b''.join(encoded(row) for row in reports)
        self.replace_raw(output, 'raw', raw)
        self.replace_raw(stopped, 'stderr', raw)
        for row in oracle.select(self.events, 'controller_report_observed', id=name):
            if row['line_index'] == 0:
                row['report'] = copy.deepcopy(reports[0])

    def dump(self, directory):
        save(directory / 'inputs.json', encoded(self.inputs))
        for name, values in (('events.jsonl', self.events), ('business.jsonl', self.business),
                             ('http-client-ledger.jsonl', self.ledger)):
            save(directory / name, b''.join(encoded(row) for row in values))
        raw_directory = directory / 'raw'
        raw_directory.mkdir()
        for digest, raw in self.overlays.items():
            save(raw_directory / digest, raw)


def late_request(evidence):
    fault = oracle.one(evidence.events, 'fault_arrived', id='original-active-cas-held')
    return oracle.one(evidence.events, 's3_request', role=fault['role'], serial=fault['serial'])


def reused_report(evidence, reason):
    cut = oracle.one(evidence.events, 'controller_report_cut')
    rows = [row for row in oracle.select(evidence.events, 'controller_report_observed', id=cut['id'])
            if row['sequence'] > cut['sequence'] and row['line_index'] >= cut['line_count']
            and row['report']['state'] == 'blocked' and row['report'].get('reason') == reason]
    assert len(rows) == 2 and rows[0]['line_index'] != rows[1]['line_index']
    rows[1]['line_index'] = rows[0]['line_index']
    rows[1]['report'] = copy.deepcopy(rows[0]['report'])


def mutate(name, evidence):
    e = evidence
    if name == 'invalid-s3-signature':
        oracle.select(e.events, 's3_request')[0]['signature_valid'] = False
    elif name == 'http-operation-disagrees-with-original':
        e.request('status', '12')['operation'] = 'execute'
    elif name == 'controller-dispatches-sql':
        request = e.request('status', '12')
        body = oracle.wire.parse(e.read(request['request']))
        body['operation'] = request['operation'] = 'execute'
        e.replace_raw(request, 'request', encoded(body))
    elif name == 'unconditional-head-publication':
        request = next(row for row in oracle.select(e.events, 's3_request') if
                       row['method'] == 'PUT' and row['path'].endswith('/head') and row['headers'].get('if-match'))
        del request['headers']['if-match']
    elif name == 'late-cas-with-unread-etag':
        request = late_request(e)
        unused = '"negative-controller-matrix-no-original-read"'
        assert not any(row.get('headers', {}).get('etag') == unused for row in e.events)
        request['headers']['if-match'] = unused
    elif name == 'late-cas-body-changed':
        request = late_request(e)
        body = oracle.wire.parse(e.read(request['request']))
        body['transition']['nonce'] = (body['transition']['nonce'] + 1) % (1 << 64) or 1
        e.replace_raw(request, 'request', encoded(body))
    elif name == 'owner-descriptor-hash-changed':
        row, body = e.response('owner_prepare', state='prepared')
        reference = body['value']['prepared']['reference']
        reference['descriptor_hash'] = changed_hash(reference['descriptor_hash'])
        e.http_response(row, body)
    elif name == 'claim-target-guard-changed':
        request = e.request('owner_claim', '12')
        body = oracle.wire.parse(e.read(request['request']))
        assert body['expected_worker_instance'] != '9601'
        body['expected_worker_instance'] = '9601'
        e.replace_raw(request, 'request', encoded(body))
    elif name in ('active-report-without-active-http', 'accepted-reference-changed', 'accepted-nonce-changed'):
        row, body = e.response('owner_resume', state='active')
        if name == 'active-report-without-active-http':
            body['value']['state'] = 'claimed'
        elif name == 'accepted-reference-changed':
            reference = body['value']['accepted']['reference']
            reference['descriptor_hash'] = changed_hash(reference['descriptor_hash'])
        else:
            phase = body['value']['accepted']['phase']
            phase['nonce'] = str((int(phase['nonce']) + 1) % (1 << 64) or 1)
        e.http_response(row, body)
    elif name == 'controller-mutation-budget-exceeded':
        e.report('controller-one', lambda row: row.update(mutations=2))
    elif name == 'original-client-ack-omitted':
        e.business.remove(oracle.select(e.business, 'original_ack')[0])
    elif name == 'original-client-ack-rewritten':
        oracle.select(e.business, 'original_ack')[0]['value']['result'] = 'AA=='
    elif name == 'original-unknown-relabelled-ack':
        oracle.one(e.business, 'original_unknown')['outcome'] = 'ACK'
    elif name == 'recovered-lookup-result-rewritten':
        oracle.select(e.business, 'recovered_lookup')[0]['value']['result'] = 'AA=='
    elif name == 'retained-snapshot-reference-changed':
        row, body, sdk = e.business_response('snapshot_retained')
        reference = body['value']['prepared']['reference']
        reference['descriptor_hash'] = changed_hash(reference['descriptor_hash'])
        e.http_response(row, body, sdk)
    elif name == 'native-query-random-blob-changed':
        row, body, sdk = e.business_response('recovered_query')
        raw = oracle.wire.b64(body['value']['result'])
        blob = oracle.wire.result(raw)[0]['rows'][0][1]
        assert type(blob) is bytes and len(blob) == 64 and raw.count(blob) == 1
        offset = raw.index(blob)
        altered = raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]
        body['value']['result'] = base64.b64encode(altered).decode()
        e.http_response(row, body, sdk)
    elif name == 'owned-wait4-source-fabricated':
        oracle.one(e.events, 'child_stopped', id='service-B')['usage']['source'] = 'controller_summary'
    elif name == 'owner-cache-not-removed':
        oracle.one(e.events, 'cache_removed', id='service-A')['absent'] = False
    elif name in ('backpressure-http-429-relabelled', 'limit-http-413-relabelled'):
        code = 'BACKPRESSURE' if name == 'backpressure-http-429-relabelled' else 'LIMIT'
        response, _ = e.response(error=code)
        response['status'] = 503
        for row in oracle.select(e.events, 'http_proxy_delivery_started',
                                 role=response['role'], serial=response['serial']):
            row['status'] = 503
    elif name == 's3-unknown-relabelled-unavailable':
        row, body = e.response('status', error='UNKNOWN')
        body['error']['code'] = 'UNAVAILABLE'
        e.http_response(row, body)
    elif name == 'late-aborted-resume-relabelled-active':
        row, body = e.response('owner_resume', state='aborted')
        body['value']['state'] = 'active'
        e.http_response(row, body)
    elif name == 'original-sdk-request-hash-changed':
        request = oracle.select(e.ledger, 'http_request')[0]
        request['body_sha256'] = changed_hash(request['body_sha256'])
    elif name in ('foreign-policy-report-reused', 'foreign-creator-report-reused'):
        reused_report(e, 'POLICY' if name == 'foreign-policy-report-reused' else 'FOREIGN_CREATOR')
    elif name == 'first-candidate-cut-target-changed':
        oracle.one(e.events, 'http_proxy_cut_started', id='first-b-candidate')['role'] = 'C'
    else:
        raise AssertionError('unknown fixed control')


def run(evidence, destination):
    evidence, destination = Path(evidence).resolve(), Path(destination).resolve()
    root = Path(__file__).resolve().parents[2]
    if (destination.is_relative_to(evidence) or evidence.is_relative_to(destination)
            or destination.is_relative_to(root)):
        raise ValueError('control output must be new and outside original evidence and source')
    assert len(CONTROL_PLAN) == EXPECTED_CONTROLS == len({row[0] for row in CONTROL_PLAN})
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    plan = [{'name': name, 'case_id': case, 'expected_guard': guard} for name, case, guard in CONTROL_PLAN]
    save(destination / 'controls-plan.json', encoded(plan))
    before = inventory(evidence)
    save(destination / 'positive-inventory-before.json', encoded(before))
    result = {'schema': 1, 'status': 'FAILED', 'expected_controls': EXPECTED_CONTROLS,
        'executed_controls': 0, 'original_evidence': str(evidence), 'controls': [],
        'positive_audit': {'status': 'NOT_RUN'}, 'original_evidence_unchanged': False,
        'positive_reaudit': {'status': 'NOT_RUN'},
        'negative_input_scope': 'single-case-deep-copy-and-targeted-raw-overlays',
        'source_validation': 'full-original-matrix-before-reduced-history-audits'}
    try:
        result['positive_audit'] = oracle.audit(evidence)
        assert result['positive_audit']['status'] == 'PASS_COMPLETE_CONTROLLER_MATRIX'
        originals = {}
        for name, case, expected_guard in CONTROL_PLAN:
            directory = evidence / case
            if case not in originals:
                originals[case] = (oracle.wire.parse((directory / 'inputs.json').read_bytes()),
                    oracle.read_rows(directory / 'events.jsonl'), oracle.read_rows(directory / 'business.jsonl'),
                    oracle.read_rows(directory / 'http-client-ledger.jsonl'))
            working = Evidence(directory, originals[case])
            output = destination / name
            output.mkdir()
            control = {'name': name, 'case_id': case, 'expected_guard': expected_guard,
                       'observed_guard': None, 'status': 'FAILED', 'base_case': str(directory)}
            try:
                mutate(name, working)
                try:
                    oracle.audit_history(directory, working.inputs, working.events, working.business,
                                         working.ledger, working.read)
                except oracle.Rejected as error:
                    control['observed_guard'] = str(error)
                    if str(error) == expected_guard:
                        control['status'] = 'REJECTED_EXPECTED'
                    else:
                        control['error'] = 'wrong_guard'
                else:
                    control['error'] = 'negative_evidence_accepted'
            except Exception as error:
                control['error'] = type(error).__name__ + ': ' + str(error)
            working.dump(output)
            control['raw_targets'] = working.targets
            control['raw_overlay_count'] = len(working.overlays)
            control['input_sha256'] = {key: oracle.sha(encoded(value)) for key, value in (
                ('inputs', working.inputs), ('events', working.events),
                ('business', working.business), ('ledger', working.ledger))}
            save(output / 'control.json', encoded(control))
            result['controls'].append(control)
            result['executed_controls'] += 1
        # Re-read the untouched original histories. Full source/receipt checks
        # have already passed, and the final inventory also includes every
        # source archive and receipt. No mutant verdict is reused here.
        positive_cases = []
        for case in oracle.CASES:
            directory = evidence / case
            positive_cases.append(oracle.audit_history(directory,
                oracle.wire.parse((directory / 'inputs.json').read_bytes()),
                oracle.read_rows(directory / 'events.jsonl'),
                oracle.read_rows(directory / 'business.jsonl'),
                oracle.read_rows(directory / 'http-client-ledger.jsonl'),
                lambda reference, directory=directory: oracle.raw_file(directory, reference)))
        assert len(positive_cases) == 12 and all(
            row['status'] == 'PASS_CONTROLLER_MATRIX_CASE' for row in positive_cases)
        result['positive_reaudit'] = {'status': 'PASS_UNCHANGED_ORIGINAL_HISTORIES',
                                      'case_count': len(positive_cases), 'cases': positive_cases}
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['positive_inventory_sha256'] = oracle.sha(encoded(before))
        try:
            after = inventory(evidence)
            save(destination / 'positive-inventory-after.json', encoded(after))
            result['original_evidence_unchanged'] = before == after
            result['positive_inventory_after_sha256'] = oracle.sha(encoded(after))
        except Exception as error:
            result['inventory_error'] = type(error).__name__ + ': ' + str(error)
        if (result['positive_audit'].get('status') == 'PASS_COMPLETE_CONTROLLER_MATRIX'
                and result['positive_reaudit'].get('status') == 'PASS_UNCHANGED_ORIGINAL_HISTORIES'
                and result['executed_controls'] == EXPECTED_CONTROLS
                and result['original_evidence_unchanged']
                and all(row['status'] == 'REJECTED_EXPECTED' for row in result['controls'])):
            result['status'] = 'PASS_FIXED_CONTROLLER_MATRIX_CONTROLS'
        save(destination / 'manifest.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', '--out', dest='output', required=True, type=Path,
                        help='new directory outside the original evidence and source')
    args = parser.parse_args()
    try:
        result = run(args.evidence, args.output)
    except Exception as error:
        result = {'schema': 1, 'status': 'FAILED', 'expected_controls': EXPECTED_CONTROLS,
                  'error': type(error).__name__ + ': ' + str(error)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS_FIXED_CONTROLLER_MATRIX_CONTROLS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
