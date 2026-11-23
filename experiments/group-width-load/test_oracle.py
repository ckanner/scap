"""Synthetic cap and decision counterexamples; these are not actual evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import controls
import oracle
import shared
import spec


def snapshot(size=4):
    def histogram(count=0):
        return {'completed': str(count), 'censored': '0', 'not_reached': '0',
                'total_us': '0', 'buckets': [str(count)] + ['0'] * (len(spec.BUCKETS_US) - 1)}
    lanes = [{'lane': name, 'acquired': '0', 'released': '0', 'active': '0',
              'intervals': [{'interval': interval, **histogram()} for interval in spec.INTERVALS]}
             for name in spec.LANES]
    sizes = ['0'] * 64
    if size:
        sizes[size - 1] = '1'
    return {'version': 1, 'valid': True, 'unit': 'microseconds',
            'histogram_upper_bounds_us': [str(value) for value in spec.BUCKETS_US], 'lanes': lanes,
            'groups': {'attempts': str(int(bool(size))), 'active': '0', 'selected': str(size), 'consumed': str(size),
                       'declined': '0', 'completed': str(int(bool(size))), 'incomplete': '0',
                       'duration': histogram(int(bool(size))),
                       'selected_sizes': sizes.copy(), 'consumed_sizes': sizes.copy()}}


def publication(count):
    previous = {'sequence': 10, 'revision': 11, 'head_serial': 12, 'data_root': 'old',
                'transition': {'revision': 11, 'nonce': 99}, 'windows': ['old-window']}
    entries, stored = {}, {}
    for identifier in range(1, count + 1):
        entries[identifier] = {'outcome': {'state': 'committed'}}
        stored[identifier] = {'metadata': {'sequence': 10 + identifier,
            'transition': {'revision': 11 + identifier, 'nonce': identifier},
            'request': {'id': identifier}, 'data_root': f'root-{identifier}'}}
    last = stored[count]['metadata']
    current = {**previous, 'sequence': 10 + count, 'revision': 11 + count,
               'head_serial': 12 + count, 'data_root': last['data_root'],
               'transition': last['transition'], 'windows': ['new-window']}
    return previous, current, {'entries': {}}, {'entries': entries, 'stored': stored}


def cell(cap, ack=100, window=80, success=100, control=10, requests=20, body=1000):
    return {'max_members': cap, 'group_commit': True, 'rate': 12, 'measurements': {'load': {
        'original_ack_count': ack, 'original_ack_within_offer_window': window,
        'scheduled_to_terminal_ms': {'success': {'p99': success}},
        'control_scheduled_to_terminal_ms': {'p99': control},
        'cost_per_original_ack': {'requests': requests, 'request_body_bytes': body / 2,
                                 'response_body_bytes': body / 2}}}}


class Caps(unittest.TestCase):
    def reject(self, rule, operation):
        with self.assertRaises(oracle.Rejected) as caught:
            operation()
        self.assertEqual(caught.exception.rule, rule)

    def test_same_publication_five_passes_eight_and_rejects_four(self):
        args = publication(5)
        self.assertEqual(shared.reader(8).publication(*args, True), 5)
        with oracle.normalized():
            self.assertEqual(shared.reader(4).publication(*publication(4), True), 4)
        def wrong():
            with oracle.normalized():
                shared.reader(4).publication(*args, True)
        self.reject('group-width', wrong)
        self.assertEqual(shared.reader(8).publication(*publication(8), True), 8)
        self.reject('group-width', lambda: shared.reader(8).publication(*publication(9), True))
        for cap in (4, 8):
            self.assertEqual(shared.reader(cap).publication(*publication(1), True), 1)

    def test_configuration_binds_cap_and_requires_enabled(self):
        contract = spec.CONTRACTS[12, 4]
        config = spec.configuration('127.0.0.1:8000', '/cache', 'http://127.0.0.1:8001',
                                    'a' * 64, True, contract, 'b' * 64)
        oracle.configuration(config, contract)
        for profile in ({**config['admission']['group_commit'], 'max_members': 8}, None):
            changed = copy.deepcopy(config)
            changed['admission']['group_commit'] = profile
            self.reject('paired-configuration', lambda: oracle.configuration(changed, contract))

    def test_ordinary_conservation_does_not_prove_cap(self):
        value = snapshot(5)
        parsed = shared.lifecycle.parse(value)
        self.assertEqual(parsed['groups']['selected'], 5)
        self.assertEqual(oracle.snapshot_cap(value, 8), parsed)
        self.reject('lifecycle-group-cap', lambda: oracle.snapshot_cap(value, 4))
        oracle.snapshot_cap(snapshot(4), 4)

    def test_selected_only_and_consumed_only_are_checked(self):
        selected = snapshot(4)
        selected['groups'].update(selected='5', selected_sizes=['0'] * 4 + ['1'] + ['0'] * 59)
        shared.lifecycle.parse(selected)
        self.reject('lifecycle-group-cap', lambda: oracle.snapshot_cap(selected, 4))
        consumed = snapshot(5)
        # A completed group consumes five, while total selected is two valid
        # groups of four. The second attempt is declined: every old equation
        # remains true and neither selected bucket exceeds four.
        group = consumed['groups']
        group.update(attempts='2', selected='8', declined='1',
                     selected_sizes=['0'] * 3 + ['2'] + ['0'] * 60)
        group['duration']['completed'] = '2'
        group['duration']['buckets'][0] = '2'
        shared.lifecycle.parse(consumed)
        self.reject('lifecycle-group-cap', lambda: oracle.snapshot_cap(consumed, 4))

    def test_baseline_violation_cannot_disappear_in_zero_delta(self):
        original = snapshot(5)
        parsed = shared.lifecycle.parse(original)
        delta = shared.lifecycle.cohort(parsed, parsed, {lane: 0 for lane in spec.LANES})
        self.assertFalse(any(delta['groups']['selected_sizes']))
        self.reject('lifecycle-group-cap', lambda: oracle.snapshot_cap(original, 4))

    def test_all_original_polling_responses_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'raw').mkdir()
            def response(value):
                data = json.dumps(value).encode()
                checksum = hashlib.sha256(data).hexdigest()
                (directory / 'raw' / checksum).write_bytes(data)
                return {'file': 'raw/' + checksum, 'sha256': checksum, 'bytes': len(data)}
            valid = response(snapshot(4))
            invalid = response(snapshot(5))
            rows = [{'attempt': index, 'status': 200, 'response': value}
                    for index, value in enumerate((valid, invalid, valid), 1)]
            events = [{'event': 'diagnostic_boundary', 'boundary': boundary, 'attempt': index}
                      for boundary, index in (('baseline', 1), ('end', 3))]
            self.reject('lifecycle-group-cap', lambda: oracle.diagnostic_caps(directory, rows, events, 4))
            result = oracle.diagnostic_caps(directory, rows, events, 8)
            self.assertEqual(result['successful_snapshots_checked'], 3)
            rows[1]['response'] = valid
            self.assertEqual(oracle.diagnostic_caps(directory, rows, events, 4)['successful_snapshots_checked'], 3)

    def test_both_reader_error_classes_are_normalized_without_swallowing_other_errors(self):
        for reader in (shared.reader(4), shared.reader(8)):
            def rejected():
                with oracle.normalized():
                    reader.need(False, 'chosen-rule')
            self.reject('chosen-rule', rejected)
        with self.assertRaisesRegex(RuntimeError, 'unrelated'):
            with oracle.normalized():
                raise RuntimeError('unrelated')

    def test_matrix_labels_caps_order_and_boolean_types_are_bound(self):
        oracle.validate_cells(spec.cells())
        for key, value in (('max_members', 4), ('max_members', 8.0), ('rate', 12.0),
                           ('group_commit', 1), ('group_commit', False), ('contract', 'wrong'), ('name', 'wrong')):
            rows = spec.cells()
            rows[0][key] = value
            self.reject('cell-order', lambda: oracle.validate_cells(rows))
        for rows in (spec.cells()[:-1], [*spec.cells(), spec.cells()[0]], list(reversed(spec.cells()))):
            self.reject('cell-order', lambda: oracle.validate_cells(rows))


class Decision(unittest.TestCase):
    def test_latency_target_is_predeclared_but_no_improvement_is_not_passed(self):
        baseline = cell(8)
        self.assertFalse(oracle.comparison(baseline, cell(4))['criteria_met'])
        result = oracle.comparison(baseline, cell(4, success=95))
        self.assertTrue(result['criteria_met'])
        self.assertEqual(result['improvement_targets'], {
            'original_ack': False, 's3_requests_per_ack': False, 'success_p99': True})
        self.assertTrue(oracle.comparison(baseline, cell(4, ack=105))['criteria_met'])
        self.assertTrue(oracle.comparison(baseline, cell(4, requests=19))['criteria_met'])

    def test_drain_ack_cannot_replace_window_ack_or_mask_tail_and_cost_regressions(self):
        for options, rule in (({'ack': 99}, 'original_ack_not_reduced'),
                              ({'window': 79}, 'offer_window_ack_not_reduced'),
                              ({'control': 10.501}, 'control_p99_within_5_percent'),
                              ({'requests': 21.001}, 's3_requests_per_ack_within_5_percent'),
                              ({'body': 1050.01}, 'body_bytes_per_ack_within_5_percent')):
            with self.subTest(options=options):
                result = oracle.comparison(cell(8), cell(4, **{'success': 90, **options}))
                self.assertFalse(result['criteria_met'])
                self.assertFalse(result['checks'][rule])
        result = oracle.comparison(cell(8), cell(4, ack=105, success=105.01))
        self.assertFalse(result['checks']['success_p99_within_5_percent'])

    def test_exact_five_percent_cost_boundary_and_missing_denominators(self):
        self.assertTrue(oracle.comparison(cell(8), cell(4, success=95, control=10.5,
                                                     requests=21, body=1050))['criteria_met'])
        for invalid in (None, 0, -1, float('nan'), float('inf'), True):
            for cap in (8, 4):
                with self.subTest(invalid=invalid, cap=cap):
                    baseline, candidate = cell(8), cell(4, success=90)
                    target = baseline if cap == 8 else candidate
                    target['measurements']['load']['scheduled_to_terminal_ms']['success']['p99'] = invalid
                    result = oracle.comparison(baseline, candidate)
                    self.assertFalse(result['criteria_met'])
                    self.assertFalse(result['checks']['success_p99_within_5_percent'])
        self.assertFalse(oracle.comparison(cell(8, ack=0), cell(4, ack=10, success=90))['criteria_met'])
        missing = cell(4, success=90)
        missing['measurements']['load']['cost_per_original_ack']['request_body_bytes'] = None
        self.assertFalse(oracle.comparison(cell(8), missing)['criteria_met'])

    def test_zero_window_ack_is_a_count_and_not_a_cost_denominator(self):
        for candidate_count in (0, 1):
            result = oracle.comparison(cell(8, window=0), cell(4, window=candidate_count, success=95))
            self.assertTrue(result['criteria_met'])
            metric = next(item for item in result['comparisons'] if item['metric'] == 'offer_window_ack')
            self.assertIsNone(metric['candidate_over_baseline'])
        result = oracle.comparison(cell(8, window=1), cell(4, window=0, success=95))
        self.assertFalse(result['criteria_met'])
        self.assertFalse(result['checks']['offer_window_ack_not_reduced'])
        for invalid in (True, 0.0, -1):
            self.assertFalse(oracle.comparison(cell(8, window=0),
                                              cell(4, window=invalid, success=95))['criteria_met'])

    def test_wrong_cap_direction_disabled_arm_and_cross_rate_pair_are_rejected(self):
        for baseline, candidate in ((cell(4), cell(8)), (cell(8), cell(8))):
            with self.assertRaises(oracle.Rejected) as caught:
                oracle.comparison(baseline, candidate)
            self.assertEqual(caught.exception.rule, 'comparison-arms')
        for key, value in (('group_commit', False), ('rate', 32)):
            candidate = cell(4, success=90)
            candidate[key] = value
            with self.assertRaises(oracle.Rejected):
                oracle.comparison(cell(8), candidate)


class DirectedProjections(unittest.TestCase):
    def test_missing_hook_prefers_load_and_uses_seed_for_zero_load_success(self):
        def data_snapshot(count):
            value = snapshot(0)
            lane = value['lanes'][0]
            lane['acquired'] = lane['released'] = str(count)
            for interval in lane['intervals']:
                interval['completed'] = interval['buckets'][0] = str(count)
            return value
        baseline, end = data_snapshot(2), data_snapshot(3)
        planned = {str(index): {'phase': 'seed_rows' if index < 2 else 'load', 'operation': 'execute'}
                   for index in range(3)}
        calls = {key: {'finish': {'ok': True}, 'reply': {'ok': True}} for key in planned}
        auditor = shared.auditor(4)
        missing = controls.missing_hook_projection(baseline, end, 1)
        self.assertEqual(missing['source_phase'], 'load')
        delta = shared.lifecycle.cohort(shared.lifecycle.parse(baseline), shared.lifecycle.parse(missing['snapshot']),
                                       {lane: int(lane == 'data') for lane in spec.LANES})
        controls.reject('load-hook', 'lifecycle-success-interval-complete',
                        lambda: auditor.complete_intervals(delta, planned, calls))
        missing = controls.missing_hook_projection(baseline, baseline, 0)
        self.assertEqual(missing['source_phase'], 'seed_baseline')
        controls.reject('seed-hook', 'lifecycle-success-interval-complete',
                        lambda: auditor.seed_baseline(shared.lifecycle.parse(missing['snapshot']), planned, calls))
        self.assertEqual(baseline, data_snapshot(2))
        self.assertEqual(end, data_snapshot(3))

    def test_both_oversized_projections_preserve_all_old_equations(self):
        for size in (0, 1, 2, 4):
            for kind in ('selected_sizes', 'consumed_sizes'):
                with self.subTest(size=size, kind=kind):
                    original = snapshot(size)
                    changed = controls.oversized_snapshot(original, kind)
                    self.assertEqual(original, snapshot(size))
                    parsed = shared.lifecycle.parse(changed)
                    self.assertTrue(shared.lifecycle.quiescent(parsed))
                    self.assertEqual(parsed['groups'][kind][4], 1)
                    if kind == 'consumed_sizes':
                        self.assertFalse(any(parsed['groups']['selected_sizes'][4:]))
                    rejected = controls.reject('oversized', 'lifecycle-group-cap',
                                               lambda: oracle.snapshot_cap(changed, 4))
                    self.assertEqual(rejected['observed'], 'lifecycle-group-cap')

    def test_projected_baseline_and_end_keep_zero_delta_without_hiding_violation(self):
        for first, last in ((2, 4), (0, 0)):
            original_before, original_after = snapshot(first), snapshot(last)
            before, after = controls.baseline_cap_snapshots(original_before, original_after)
            delta = shared.lifecycle.cohort(shared.lifecycle.parse(before), shared.lifecycle.parse(after),
                                           {lane: 0 for lane in spec.LANES})
            self.assertFalse(any(delta['groups']['selected_sizes']))
            controls.reject('baseline', 'lifecycle-group-cap', lambda: oracle.snapshot_cap(before, 4))
            controls.reject('end', 'lifecycle-group-cap', lambda: oracle.snapshot_cap(after, 4))
            self.assertEqual(original_before, snapshot(first))
            self.assertEqual(original_after, snapshot(last))

    def test_negative_controls_require_the_exact_rule_and_a_rejection(self):
        for cap in spec.CAPS:
            reader = shared.reader(cap)
            result = controls.reject('exact', 'expected', lambda: reader.need(False, 'expected'))
            self.assertEqual(result, {'name': 'exact', 'expected': 'expected', 'observed': 'expected'})
            with self.assertRaisesRegex(AssertionError, 'expected expected, reached unrelated'):
                controls.reject('wrong', 'expected', lambda: reader.need(False, 'unrelated'))
        with self.assertRaisesRegex(AssertionError, 'mutation accepted'):
            controls.reject('accepted', 'expected', lambda: None)
        def unrelated():
            raise RuntimeError('not a directed rejection')
        with self.assertRaises(RuntimeError):
            controls.reject('exception', 'expected', unrelated)


if __name__ == '__main__':
    unittest.main()
