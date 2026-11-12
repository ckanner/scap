#!/usr/bin/env python3
"""Mutate in-memory evidence copies; never overwrite the real run or its verdict."""
import argparse
import copy
import json
from pathlib import Path

import oracle


def controls(directory):
    directory = Path(directory)
    original = oracle.audit(directory)
    source = (oracle.read_rows(directory / 'events.jsonl'), oracle.read_rows(directory / 'business.jsonl'),
              oracle.read_rows(directory / 'http-client-ledger.jsonl'))
    cases = [
        ('signature', 'actual-s3-signatures'),
        ('ack', 'two-original-client-acks'),
        ('unknown', 'business-unknown-preserved'),
        ('result', 'recovered-original-result'),
        ('sql', 'controller-never-sql'),
        ('guard', 'stale-worker-guard-rejected'),
        ('cache', 'cache-loss-after-owned-exit'),
        ('restart', 'controller-restart-joined'),
        ('budget', 'per-tick-admission'),
    ]
    results = []
    for case, guard in cases:
        events, business, client = copy.deepcopy(source)
        replacements = {}
        if case == 'signature':
            oracle.select(events, 's3_request')[0]['signature_valid'] = False
        elif case == 'ack':
            business.remove(oracle.select(business, 'original_ack')[0])
        elif case == 'unknown':
            oracle.one(business, 'original_unknown')['outcome'] = 'ACK'
        elif case == 'result':
            oracle.select(business, 'recovered_lookup')[0]['value']['result'] = 'AA=='
        elif case == 'guard':
            oracle.one(business, 'stale_guard')['outcome'] = 'ACK'
        elif case == 'cache':
            oracle.one(events, 'cache_removed')['absent'] = False
        elif case == 'restart':
            oracle.one(events, 'child_started', id='controller-two')['sequence'] = 0
        elif case == 'sql':
            event = next(row for row in oracle.select(events, 'http_proxy_request') if row['principal'] == '12')
            body = json.loads(oracle.raw_file(directory, event['request']))
            body['operation'] = event['operation'] = 'execute'
            replacements[event['request']['sha256']] = json.dumps(body).encode()
        elif case == 'budget':
            event = oracle.one(events, 'controller_reports', id='controller-one')
            rows = [json.loads(line) for line in oracle.raw_file(directory, event['raw']).splitlines()]
            rows[0]['mutations'] = 2
            replacements[event['raw']['sha256']] = b''.join((json.dumps(row) + '\n').encode() for row in rows)

        def read(description):
            return replacements.get(description['sha256'], oracle.raw_file(directory, description))

        try:
            oracle.audit_history(directory, events, business, client, read)
        except oracle.Rejected as error:
            if str(error) != guard:
                raise AssertionError((case, 'wrong guard', str(error), guard)) from error
            results.append({'case': case, 'guard': guard, 'rejected': True})
        else:
            raise AssertionError((case, 'negative evidence was accepted'))
    return {'status': 'PASS_FIXED_CONTROLLER_CONTROLS', 'negative_controls': results,
            'unchanged_positive': original['status'], 'original_evidence_modified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    print(json.dumps(controls(args.evidence), sort_keys=True))
