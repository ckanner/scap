"""Reject malformed observation records before any release/transport claim."""
import base64
import copy
import hashlib
import struct
import unittest

import oracle
import controls
from spec import SCOPES, UNKNOWN_SQL


def captured(event, value, at):
    raw = controls.encoded(value) + b'\n'
    return {'event': event, 'monotonic_ns': at, 'raw': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest()}


def window_case():
    calls = {
        'body_held': {'response': {'monotonic_ns': 50}},
        'body_after': {'request': {'monotonic_ns': 90}},
        'timeout_execute': {'response': {'monotonic_ns': 110}},
        'timeout_control': {'response': {'monotonic_ns': 145}},
        'after_worker': {'request': {'monotonic_ns': 190}},
        'response_held': {'headers': {'monotonic_ns': 210}, 'response': {'monotonic_ns': 250}},
        'response_after': {'request': {'monotonic_ns': 290}, 'response': {'monotonic_ns': 310}},
    }
    rows = [{'event': 'http_body_sent', 'id': 'body_held', 'monotonic_ns': 10},
            {'event': 'http_body_completed', 'id': 'body_held', 'monotonic_ns': 40}]
    for phase, at in (('body-held', 20), ('body-released', 60), ('after-http-timeout', 120),
                      ('worker-released', 170), ('slow-response', 220), ('response-released', 260), ('final', 320)):
        label = phase + '-0'
        rows.append(captured('operator_command', {'operation': 'observe', 'id': label}, at))
        rows.append(captured('worker_event', {'event': 'admission_observed', 'fields': {
            'id': label, 'data_available': 1 if phase in ('body-held', 'after-http-timeout', 'slow-response') else 2,
            'control_available': 2, 'recovery_available': 2, 'lifecycle': {}}}, at + 1))
    rows.append(captured('operator_command', {'operation': 'shutdown', 'id': 'shutdown'}, 350))
    return sorted(rows, key=lambda row: row['monotonic_ns']), calls, {'monotonic_ns': 160}, {'monotonic_ns': 150}


def check_windows(rows, calls, complete, release):
    originals = [row for row in rows if row['event'] == 'worker_event']
    events = [oracle.parse(oracle.raw(row, 'raw')) for row in originals]
    return oracle.observation_windows(rows, calls, originals, events, complete, release)


class ObservationValidation(unittest.TestCase):
    def test_all_original_observation_commands_are_bound_to_external_phase_windows(self):
        check_windows(*window_case())

    def test_swapped_phase_labels_are_rejected_even_with_matching_original_commands(self):
        rows, *rest = window_case()
        controls.mutation('lifecycle-swapped-held-phases', rows)
        with self.assertRaisesRegex(ValueError, 'outside phase window'):
            check_windows(rows, *rest)

    def test_missing_duplicate_or_unmatched_observations_do_not_pass_as_proof(self):
        for mutation in ('missing-command', 'missing-observation', 'duplicate-command', 'duplicate-observation', 'unmatched'):
            rows, *rest = window_case()
            if mutation == 'unmatched':
                controls.mutation('lifecycle-unmatched-observation', rows)
            else:
                event = 'operator_command' if mutation.endswith('command') else 'worker_event'
                selected = next(row for row in rows if row['event'] == event)
                if mutation.startswith('missing'):
                    rows.remove(selected)
                else:
                    rows.append(copy.deepcopy(selected))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_windows(rows, *rest)

    def test_each_poll_index_starts_at_zero_and_cannot_skip_or_reorder(self):
        for label in ('body-held-1', 'body-held-00', 'body-held-100', 'unknown-0'):
            rows, *rest = window_case()
            for row in rows:
                if row['event'] == 'operator_command' and oracle.parse(oracle.raw(row, 'raw')).get('id') == 'body-held-0':
                    controls.worker(row, lambda value: value.update(id=label))
                elif row['event'] == 'worker_event' and oracle.parse(oracle.raw(row, 'raw'))['fields']['id'] == 'body-held-0':
                    controls.worker(row, lambda value: value['fields'].update(id=label))
            with self.subTest(label=label), self.assertRaises(ValueError):
                check_windows(rows, *rest)

    def test_observation_cannot_precede_its_command_or_borrow_a_later_release_window(self):
        for phase, too_early, too_late in (('body-held', 10, 40), ('body-released', 50, 90),
                ('after-http-timeout', 110, 150), ('worker-released', 160, 190),
                ('slow-response', 210, 250), ('response-released', 250, 290), ('final', 310, 350)):
            for boundary in ('early', 'late', 'before-command'):
                rows, *rest = window_case()
                command = next(row for row in rows if row['event'] == 'operator_command'
                               and oracle.parse(oracle.raw(row, 'raw')).get('id') == phase + '-0')
                observation = next(row for row in rows if row['event'] == 'worker_event'
                                   and oracle.parse(oracle.raw(row, 'raw'))['fields']['id'] == phase + '-0')
                if boundary == 'early':
                    command['monotonic_ns'] = too_early
                elif boundary == 'late':
                    observation['monotonic_ns'] = too_late
                else:
                    observation['monotonic_ns'] = command['monotonic_ns']
                with self.subTest(phase=phase, boundary=boundary), self.assertRaisesRegex(ValueError, 'outside phase window'):
                    check_windows(rows, *rest)

    def test_intermediate_polls_keep_their_real_quota_snapshot_without_forcing_an_atomic_read(self):
        rows, *rest = window_case()
        for row in rows:
            if row['event'] == 'operator_command' and oracle.parse(oracle.raw(row, 'raw')).get('id') == 'body-released-0':
                extra = copy.deepcopy(row)
                controls.worker(extra, lambda value: value.update(id='body-released-1'))
                extra['monotonic_ns'] += 2
                rows.append(extra)
                break
        observation = next(row for row in rows if row['event'] == 'worker_event'
                           and oracle.parse(oracle.raw(row, 'raw'))['fields']['id'] == 'body-released-0')
        extra = copy.deepcopy(observation)
        controls.worker(extra, lambda value: value['fields'].update(id='body-released-1'))
        extra['monotonic_ns'] += 2
        rows.append(extra)
        rows.sort(key=lambda row: row['monotonic_ns'])
        check_windows(rows, *rest)

    @staticmethod
    def startup_events():
        listening = b'{"event":"listening","fields":{"address":"127.0.0.1:1"}}'
        return [{'event': 'worker_started', 'spawn_requested_ns': 10, 'monotonic_ns': 45,
                 'identity': {'pid': 123, 'spawn_monotonic_ns': 40, 'pid_source': 'owned_Popen_child'}},
                {'event': 'worker_event', 'monotonic_ns': 50,
                 'raw': base64.b64encode(listening).decode(), 'sha256': hashlib.sha256(listening).hexdigest()}]

    def test_startup_uses_pre_popen_request_even_when_child_precedes_parent_observation(self):
        self.assertEqual(oracle.worker_startup(self.startup_events()),
                         {'worker': oracle.PLAN['worker_instance'], 'role': None, 'start': 10, 'ready': 50})

    def test_startup_cannot_fall_back_to_post_popen_observation_or_borrow_readiness(self):
        for change in ('missing-request', 'reversed-request', 'unowned', 'missing-ready', 'duplicate-ready'):
            rows = self.startup_events()
            if change == 'missing-request':
                del rows[0]['spawn_requested_ns']
            elif change == 'reversed-request':
                rows[0]['spawn_requested_ns'] = 41
            elif change == 'unowned':
                rows[0]['identity']['pid_source'] = '/proc/guess'
            elif change == 'missing-ready':
                rows.pop()
            else:
                rows.append(copy.deepcopy(rows[1]))
            with self.subTest(change=change), self.assertRaises(ValueError):
                oracle.worker_startup(rows)

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
