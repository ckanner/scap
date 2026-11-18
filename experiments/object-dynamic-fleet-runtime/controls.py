#!/usr/bin/env python3
"""Reject altered observation copies; never write to the original actual evidence."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import oracle


class Copy:
    def __init__(self, directory):
        self.directory = directory
        self.events = deepcopy(oracle.old.read_rows(directory / 'events.jsonl'))
        self.business = deepcopy(oracle.old.read_rows(directory / 'business.jsonl'))
        self.ledger = deepcopy(oracle.old.read_rows(directory / 'http-client-ledger.jsonl'))
        self.raw = {}

    def read(self, reference):
        return self.raw[reference['sha256']] if reference['sha256'] in self.raw else oracle.old.raw_file(self.directory, reference)

    def store(self, value):
        raw = value if isinstance(value, bytes) else (json.dumps(value, separators=(',', ':')) + '\n').encode()
        digest = hashlib.sha256(raw).hexdigest()
        self.raw[digest] = raw
        return {'file': 'raw/' + digest, 'bytes': len(raw), 'sha256': digest}

    def reports(self, change):
        event = oracle.one(self.events, 'controller_reports', id='controller-dynamic')
        original = event['raw']
        rows = [oracle.wire.parse(line) for line in self.read(original).splitlines()]
        change(rows)
        replacement = self.store(b''.join((json.dumps(row, separators=(',', ':')) + '\n').encode() for row in rows))
        event['raw'] = replacement
        oracle.one(self.events, 'child_stopped', id='controller-dynamic')['stderr'] = replacement

    def audit(self):
        return oracle.audit_history(self.directory, self.events, self.business, self.ledger, self.read)


def rejected(label, function, guard):
    try:
        function()
    except (oracle.old.Rejected, oracle.matrix.Rejected) as error:
        if str(error) != guard:
            raise AssertionError((label, 'wrong rejection', str(error), guard)) from error
        return {'name': label, 'guard': guard, 'rejected': True}
    raise AssertionError(label + ' was accepted')


def controls(directory):
    directory = Path(directory)
    original = oracle.audit(directory)
    files_before = {path.relative_to(directory).as_posix(): oracle.sha(path.read_bytes())
                    for path in directory.rglob('*') if path.is_file()}
    results = []

    def changed(label, change, guard):
        copy = Copy(directory); change(copy)
        results.append(rejected(label, copy.audit, guard))

    def omitted_history(copy):
        event = oracle.one(copy.events, 'dynamic_configuration', label='retire-B')
        value = oracle.wire.parse(copy.read(event['config']))
        value['scopes'][0]['previousPolicies'].pop()
        event['config'] = copy.store(value)
    changed('omit_original_policy_history', omitted_history, 'complete-original-policy-history')

    def accepted_rollback(copy):
        copy.reports(lambda rows: next(row for row in rows if row.get('event') == 'fleet_reloaded' and
                     row['revision'] == '5').update(revision='2'))
    changed('accept_revision_rollback', accepted_rollback, 'monotonic-successful-reloads')

    def accepted_revival(copy):
        copy.reports(lambda rows: [row for row in rows if row.get('event') == 'fleet_reload_rejected'][-1].update(
            event='fleet_reloaded', revision='6'))
    changed('accept_retired_worker_revival', accepted_revival, 'monotonic-successful-reloads')

    def forgot_unknown(copy):
        copy.reports(lambda rows: next(row for row in rows if row.get('state') == 'active_observed').update(pastUnknown=False))
    changed('forget_original_unknown_after_reload', forgot_unknown, 'unknown-survives-all-reloads')

    def controller_sql(copy):
        event = next(row for row in copy.events if row['event'] == 'http_proxy_request' and row['principal'] == '12')
        value = oracle.wire.parse(copy.read(event['request'])); value['operation'] = 'execute'
        event['operation'] = 'execute'; event['request'] = copy.store(value)
    changed('controller_replays_business_sql', controller_sql, 'controller-never-sql')

    def wrong_result(copy):
        rows = oracle.select(copy.business, 'recovered_lookup')
        rows[0]['value'] = deepcopy(rows[1]['value'])
    changed('replace_cold_original_result', wrong_result, 'recovered-original-result')

    def rebased_cas(copy):
        event = next(row for row in copy.events if row['event'] == 's3_request' and row['method'] == 'PUT'
                     and row['path'].endswith('/head') and row['headers'].get('if-match'))
        event['headers']['if-match'] = '"not-the-original-etag"'
    changed('refresh_original_head_condition', rebased_cas, 'head-original-exact-get')

    changed('omit_owned_replacement_exit', lambda copy: copy.events.remove(
        oracle.one(copy.events, 'child_stopped', id='service-A-2')), 'owned-process-denominator')

    events = oracle.old.read_rows(directory / 'events.jsonl')
    read = lambda ref: oracle.old.raw_file(directory, ref)
    scope = oracle.wire.parse((directory / 'inputs.json').read_bytes())['scope']
    _, commitments = oracle.configurations(events, read, scope)
    calls = oracle.matrix.http_exchanges(events, read)
    mutations = [call for call in calls if call['request']['principal'] == '12'
                 and call['body']['operation'] in oracle.matrix.MUTATIONS]
    originals = oracle.fixed_owner_recipes(mutations, commitments)

    def recipe(label, change, guard):
        copy = deepcopy(mutations); change(copy)
        results.append(rejected(label, lambda: oracle.fixed_owner_recipes(copy, commitments), guard))

    recipe('replace_original_worker_guard', lambda rows: next(row for row in rows if row['body']['operation'] ==
        'owner_claim')['body'].update(expected_worker_instance='9601'), 'original-target-guard')

    def resume_retired(rows):
        row = next(row for row in rows if row['body']['operation'] == 'owner_resume')
        row['body']['plan'] = deepcopy(originals['9602']['reference'])
        row['body']['expected_worker_instance'] = '9602'
        row['value']['value']['prepared'] = deepcopy(originals['9602'])
    recipe('resume_retired_original_target', resume_retired, 'retired-target-never-resumed')

    recipe('rewrite_original_descriptor_reference', lambda rows: next(row for row in rows if row['body']['operation'] ==
        'owner_abort')['body']['plan'].update(descriptor_hash='0' * 64), 'original-recipe-never-rebased')
    recipe('use_old_policy_nonce_for_new_plan', lambda rows: next(row for row in rows if row['body']['operation'] ==
        'owner_prepare')['body']['input'].update(nonces=commitments[0]['nonces']), 'prepare-exact-current-policy')

    files = {row['path']: row for row in oracle.wire.parse((directory / 'source.json').read_bytes())['files']}
    receipt = oracle.wire.parse((directory / 'service-build/build-receipt.json').read_bytes())['inputs']
    incomplete = dict(receipt); incomplete.pop('Cargo.toml')
    results.append(rejected('omit_required_release_source', lambda: oracle.matrix.release_source_equivalence(
        files, incomplete), 'release-source-equivalence'))

    positive = Copy(directory).audit()
    if positive != original:
        raise AssertionError('unchanged positive control differs')
    files_after = {path.relative_to(directory).as_posix(): oracle.sha(path.read_bytes())
                   for path in directory.rglob('*') if path.is_file()}
    if files_before != files_after:
        raise AssertionError('actual original files changed')
    return {'status': 'PASSED', 'negative_controls': len(results), 'positive_controls': 1,
            'original_files_unchanged': len(files_before), 'results': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(controls(parser.parse_args().evidence), sort_keys=True))
