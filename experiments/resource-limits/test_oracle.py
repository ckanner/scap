"""Reject malformed observation records before any release/transport claim."""
import base64
import copy
import hashlib
import unittest

import oracle
from spec import SCOPES, UNKNOWN_SQL


class ObservationValidation(unittest.TestCase):
    def test_numbered_accepts_strict_positive_sequence(self):
        oracle.numbered([{'schema': 1, 'sequence': i, 'monotonic_ns': i * 10} for i in (1, 2, 3)])

    def test_numbered_rejects_gap_duplicate_and_reversed_time(self):
        source = [{'schema': 1, 'sequence': i, 'monotonic_ns': i * 10} for i in (1, 2, 3)]
        for key, value in (('sequence', 1), ('sequence', 4), ('monotonic_ns', 10), ('monotonic_ns', -1)):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(source)
                changed[1][key] = value
                with self.assertRaises(ValueError):
                    oracle.numbered(changed)

    def test_numbered_rejects_bool_counter_and_clock(self):
        for key in ('sequence', 'monotonic_ns'):
            row = {'schema': 1, 'sequence': 1, 'monotonic_ns': 1}
            row[key] = True
            with self.assertRaises(ValueError):
                oracle.numbered([row])

    def test_raw_requires_canonical_base64_and_original_hash(self):
        record = {'body': 'eA==', 'sha256': hashlib.sha256(b'x').hexdigest()}
        self.assertEqual(oracle.raw(record), b'x')
        for key, value in (('body', 'eB=='), ('body', 'eA==='), ('sha256', '0' * 64)):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    oracle.raw({**record, key: value})

    def test_keyed_rejects_duplicate_operation_identity(self):
        row = {'event': 'http_input', 'id': 'first'}
        self.assertEqual(oracle.keyed([row], 'http_input'), {'first': row})
        with self.assertRaises(ValueError):
            oracle.keyed([row, row], 'http_input')

    def test_only_requires_one_actual_witness(self):
        self.assertEqual(oracle.only([7], 'test'), 7)
        for values in ([], [7, 7]):
            with self.assertRaises(ValueError):
                oracle.only(values, 'test')

    def test_original_intent_binds_sql_scope_identity_and_fingerprint(self):
        statements = [{'sql': UNKNOWN_SQL, 'params': []}]
        original = {'scope': SCOPES['a'], 'statements': statements,
                    'request': {'epoch': '1', 'id': '1', 'principal': '11', 'fingerprint': oracle.fingerprint(statements)}}
        oracle.original_intent(original)
        mutations = []
        changed = copy.deepcopy(original); changed['scope']['tenant'] = '8'; mutations.append(changed)
        changed = copy.deepcopy(original); changed['request']['id'] = '2'; mutations.append(changed)
        changed = copy.deepcopy(original); changed['request']['fingerprint'] = '0' * 64; mutations.append(changed)
        changed = copy.deepcopy(original); changed['statements'][0]['sql'] = 'SELECT 1'; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ValueError):
                oracle.original_intent(changed)

    def test_expected_timeout_lookup_cancel_share_original_request(self):
        original = {'request': {'id': '17'}, 'statements': [{'sql': 'SELECT 1', 'params': []}]}
        for label in ('timeout_execute', 'original_lookup', 'original_cancel', 'cancelled_lookup'):
            body, principal = oracle.expected_call(label, original)
            self.assertEqual(body['request'], original['request'])
            self.assertEqual(principal, 'a')
        self.assertEqual(oracle.expected_call('timeout_same_tenant', original)[1], 'rival')

    def test_every_frozen_call_has_explicit_operation(self):
        original = {'request': {}, 'statements': []}
        actions = [oracle.expected_call(label, original)[0]['operation'] for label in oracle.CALLS]
        self.assertEqual(actions.count('execute'), 1)
        self.assertEqual(actions.count('cancel'), 1)
        self.assertEqual(actions.count('lookup'), 2)


if __name__ == '__main__':
    unittest.main()
