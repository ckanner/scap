"""Reject malformed observation records before any release/transport claim."""
import base64
import copy
import hashlib
import struct
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

    @staticmethod
    def query_bytes(*, columns=('witness',), values=(b'\x01' + struct.pack('<q', 7),),
                    affected_rows=0, last_insert_rowid=0):
        names = b''.join(struct.pack('<I', len(name.encode())) + name.encode() for name in columns)
        return (b'SCAPRES1' + struct.pack('<II', 1, len(columns)) + names + struct.pack('<I', 1)
                + b''.join(values) + struct.pack('<Qq', affected_rows, last_insert_rowid))

    @staticmethod
    def read_calls(raw):
        cancelled = {'response': {'status': 200}, 'body': {'operation': 'cancel'},
                     'value': {'value': {'state': 'cancelled', 'transition': {'revision': '3', 'nonce': '1'}}}}
        return {'a_warm': {'response': {'status': 200}, 'body': {'operation': 'query'},
                           'value': {'value': {'result': base64.b64encode(raw).decode()}}},
                'original_cancel': cancelled, 'cancelled_lookup': copy.deepcopy(cancelled)}

    def test_read_result_metadata_and_wire_types_are_complete(self):
        oracle.values(self.read_calls(self.query_bytes()))
        for changes in ({'affected_rows': 1}, {'last_insert_rowid': 1}, {'last_insert_rowid': -1},
                        {'columns': ('effects',)},
                        {'values': (b'\x02' + struct.pack('<d', 7.0),)},
                        {'values': (b'\x00',)},
                        {'columns': ('witness', 'extra'),
                         'values': (b'\x01' + struct.pack('<q', 7), b'\x01' + struct.pack('<q', 7))}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    oracle.values(self.read_calls(self.query_bytes(**changes)))

    def test_read_result_statement_and_row_counts_are_exact(self):
        valid = self.query_bytes()
        missing_statement = b'SCAPRES1' + struct.pack('<I', 0)
        # One statement, one column name, but zero/two rows are both legal
        # SCAPRES1 encodings and must be refused for this fixed workload.
        before_rows = 8 + 4 + 4 + 4 + len('witness')
        zero_rows = valid[:before_rows] + struct.pack('<I', 0) + struct.pack('<Qq', 0, 0)
        two_rows = (valid[:before_rows] + struct.pack('<I', 2)
                    + (b'\x01' + struct.pack('<q', 7)) * 2 + struct.pack('<Qq', 0, 0))
        for raw in (missing_statement, zero_rows, two_rows):
            with self.assertRaises(ValueError):
                oracle.values(self.read_calls(raw))


if __name__ == '__main__':
    unittest.main()
