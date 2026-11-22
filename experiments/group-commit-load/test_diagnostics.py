"""Independent admission/curve oracle checks; no service or actual load run."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import diagnostics
import oracle
import spec


class AdmissionContract(unittest.TestCase):
    def reject(self, rule, function):
        with self.assertRaises((oracle.Rejected, diagnostics.Invalid)) as raised:
            function()
        self.assertEqual(raised.exception.rule, rule)

    def config(self):
        return spec.configuration('127.0.0.1:1', '/cache', 'http://127.0.0.1:2', 'digest', False)

    def test_named_curve_keeps_all_original_short_inputs_and_capacities(self):
        short, long = spec.SHORT, spec.ADMISSION_CURVE
        self.assertEqual(short.phases, spec.PHASES)
        self.assertEqual(short.deadlines['run_seconds'], 720)
        self.assertEqual((short.image_pages, short.retained_entries), (32, 161))
        self.assertEqual(long.phase_rows, (('low', 64, 4, 16000), ('steady', 192, 12, 16000),
                                         ('contended', 512, 32, 16000)))
        self.assertEqual((long.run_seconds, long.image_pages, long.retained_entries, long.window_ms),
                         (1200, 128, 769, 4000))
        writes = [item for item in spec.calls(long) if 'row' in item]
        self.assertEqual(len(writes) * len(spec.ROUNDS), 3072)
        self.assertEqual([item['row'] for item in writes], list(range(768)))
        self.assertEqual([item['request_id'] for item in writes], [str(index) for index in range(2, 770)])
        self.assertEqual(len([item for item in spec.calls(long) if item['operation'] == 'execute']), 769)
        for name, settings in long.phases.items():
            selected = [item for item in writes if item['phase'] == name]
            self.assertEqual([item['offset_ns'] for item in selected],
                             [index * 1000000000 // settings['rate'] for index in range(settings['count'])])
        for enabled in (False, True):
            first = spec.configuration('listen', 'cache', 's3', 'digest', enabled, short)
            second = spec.configuration('listen', 'cache', 's3', 'digest', enabled, long)
            self.assertEqual(first, second)
            self.assertTrue(first['resource_diagnostics'])
        self.assertEqual(oracle.generator_rule(short), 'generator-impossible-rejection')
        self.assertEqual(oracle.generator_rule(long), 'generator-rejection')

    def test_profile_name_cannot_supply_arbitrary_limits_or_change_default(self):
        for contract in spec.CONTRACTS.values():
            self.assertIs(oracle.select_contract(contract.plan), contract)
        self.reject('fixed-profile', lambda: oracle.select_contract({'profile': 'try-a-larger-limit'}))
        for field, key in (('bounds', 'trace_rows'), ('oracle_bounds', 'image_pages'),
                           ('deadlines', 'run_seconds')):
            plan = copy.deepcopy(spec.ADMISSION_CURVE.plan)
            plan[field][key] += 1
            self.reject('fixed-plan', lambda: oracle.select_contract(plan))
        self.assertEqual(spec.PLAN, spec.SHORT.plan)
        self.assertEqual(len([item for item in spec.calls() if 'row' in item]), 160)

    def test_entire_fixed_reason_dictionary_and_source_only_shape(self):
        self.assertEqual(len(diagnostics.COUNTED), 41)
        self.assertEqual(len(diagnostics.SOURCE_ONLY), 5)
        for reason, code in diagnostics.COUNTED.items():
            header = f'v=1;reason={reason};used=40;limit=40;requested=1'
            self.assertEqual(diagnostics.parse(header, code),
                             {'version': 1, 'reason': reason, 'used': '40', 'limit': '40', 'requested': '1'})
            self.reject('rejection-counter-shape', lambda: diagnostics.parse('v=1;reason=' + reason, code))
        for reason, code in diagnostics.SOURCE_ONLY.items():
            self.assertEqual(diagnostics.parse('v=1;reason=' + reason, code), {'version': 1, 'reason': reason})
            self.reject('rejection-counter-shape', lambda: diagnostics.parse(
                f'v=1;reason={reason};used=1;limit=1;requested=1', code))
        self.assertIsNone(diagnostics.parse(None, 'LIMIT'))
        self.assertIsNone(diagnostics.parse(None, None))
        for code in ('BACKPRESSURE', 'RECOVERY_BUSY'):
            self.reject('rejection-missing', lambda: diagnostics.parse(None, code))

    def test_header_rejects_noncanonical_unbounded_unknown_and_wrong_code(self):
        valid = 'v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1'
        malformed = [valid.replace('v=1', 'v=2'), valid + ';used=40', ' ' + valid,
                     valid + '\n', valid + ', ' + valid, valid.replace('used=40', 'used=040'),
                     valid.replace('used=40', 'used=-1'), valid.replace('used=40;limit=40', 'limit=40;used=40'),
                     valid.replace('requested=1', 'requested=1.0')]
        for header in malformed:
            self.reject('rejection-header-format', lambda: diagnostics.parse(header, 'BACKPRESSURE'))
        for header in (b'v=1', 1, 'x' * 257, valid + 'é'):
            self.reject('rejection-header-bound', lambda: diagnostics.parse(header, 'BACKPRESSURE'))
        self.reject('rejection-reason', lambda: diagnostics.parse('v=1;reason=unrecognized', 'BACKPRESSURE'))
        self.reject('rejection-code', lambda: diagnostics.parse(valid, 'LIMIT'))

    def test_counter_math_is_exact_u64_with_wider_sum_and_actual_trigger(self):
        def parse(used, limit, requested):
            return diagnostics.parse(f'v=1;reason=queue_database_data;used={used};limit={limit};requested={requested}',
                                     'BACKPRESSURE')
        maximum = diagnostics.U64_MAX
        self.assertEqual(parse(maximum, maximum, 1)['used'], str(maximum))
        for values in ((maximum + 1, maximum, 1), (1, maximum + 1, 1), (1, 1, maximum + 1),
                       (0, 0, 1), (65, 64, 1)):
            self.reject('rejection-counter-range', lambda: parse(*values))
        for values in ((63, 64, 1), (64, 64, 0)):
            self.reject('rejection-not-triggered', lambda: parse(*values))

    def test_actual_omitted_profiles_and_per_body_reservation_are_bound(self):
        config = self.config()
        limits = diagnostics.effective_limits(config)
        expected = {'intake_data_requests_global': (80, 1), 'intake_data_requests_tenant': (40, 1),
            'intake_data_body_global': (5242880, 65536), 'intake_data_body_tenant': (5242880, 65536),
            'intake_control_requests_tenant': (4, 1), 'intake_control_body_tenant': (524288, 65536),
            'intake_recovery_requests_tenant': (2, 1), 'intake_recovery_body_tenant': (262144, 65536),
            'queue_global_data': (88, 1), 'queue_tenant_data': (72, 1), 'queue_database_data': (64, 1),
            'queue_global_total': (96, 1), 'queue_tenant_total': (80, 1), 'queue_database_total': (72, 1),
            'actors_global': (2, 1), 'actors_tenant': (1, 1),
            'output_base_shared_global': (528482304, 65536), 'output_base_shared_tenant': (401604608, 65536),
            'output_base_control_global': (8388608, 65536), 'output_base_control_tenant': (1048576, 65536),
            'output_growth_global': (528482304, None), 'output_growth_tenant': (401604608, None)}
        for reason, value in expected.items():
            self.assertEqual(limits[reason], value)
        value = diagnostics.parse('v=1;reason=intake_data_body_tenant;used=5242880;limit=5242880;requested=65536', 'BACKPRESSURE')
        diagnostics.bind(value, 'execute', 'data', config)
        self.reject('rejection-config-requested', lambda: diagnostics.bind(dict(value, requested='1024'), 'execute', 'data', config))
        self.reject('rejection-config-limit', lambda: diagnostics.bind(dict(value, limit='5242881'), 'execute', 'data', config))
        self.reject('http-admission-class', lambda: diagnostics.bind(value, 'execute', 'control', config))
        self.reject('rejection-admission-class', lambda: diagnostics.bind(value, 'status', 'control', config))
        absent_route = diagnostics.parse('v=1;reason=discovery_global;used=2;limit=2;requested=1', 'BACKPRESSURE')
        self.reject('rejection-route', lambda: diagnostics.bind(absent_route, 'execute', 'data', config))
        native = diagnostics.parse('v=1;reason=native_recovery_busy', 'RECOVERY_BUSY')
        for operation, kind in (('execute', 'data'), ('query', 'data'), ('activate', 'recovery')):
            diagnostics.bind(native, operation, kind, config)
        self.reject('rejection-admission-class', lambda: diagnostics.bind(native, 'create', 'data', config))

    def save(self, directory, data):
        digest = hashlib.sha256(data).hexdigest()
        (directory / 'raw').mkdir(exist_ok=True)
        (directory / 'raw' / digest).write_bytes(data)
        return {'file': 'raw/' + digest, 'sha256': digest, 'bytes': len(data)}

    def test_original_header_body_status_and_sdk_are_checked_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            header = 'v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1'
            value = diagnostics.parse(header, 'BACKPRESSURE')
            terminal = {'status': 429, 'rejection_header': header,
                        'rejection_header_bytes': self.save(directory, header.encode())}
            finish = {'error': {'name': 'RemoteError', 'resource_rejection': value}}
            reply = {'ok': False, 'error': {'code': 'BACKPRESSURE'}}
            def check(t=terminal, r=reply, f=finish):
                return oracle.validate_rejection(directory, self.config(), {'admission': 'data'}, t, r, f, 'execute')
            self.assertEqual(check(), value)
            self.reject('rejection-http-status', lambda: check(dict(terminal, status=200)))
            self.reject('rejection-original-header', lambda: check(dict(terminal, rejection_header=header + ';x=1')))
            self.reject('rejection-code', lambda: check(r={'ok': True, 'value': {'state': 'committed'}}))
            self.reject('rejection-missing', lambda: check(dict(terminal, rejection_header=None, rejection_header_bytes=None)))
            for changed in (None, dict(value, used='39'), dict(value, version=True), dict(value, used=40)):
                self.reject('sdk-rejection', lambda: check(f={'error': {'name': 'RemoteError', 'resource_rejection': changed}}))
            # A late original header is still audited; it cannot upgrade the
            # separately validated public SDK UNKNOWN into a RemoteError.
            late = {'ok': False, 'error': {'name': 'UnknownError', 'code': 'UNKNOWN',
                    'outcome': 'unknown', 'cause_code': 'DEADLINE', 'resource_rejection': None}}
            self.assertEqual(check(f=late), value)
            self.assertEqual(oracle.observed_outcome({'finish': late}), 'unknown')

    def test_header_summary_preserves_exact_histograms_and_source_only(self):
        counted = diagnostics.parse('v=1;reason=queue_database_data;used=64;limit=64;requested=1', 'BACKPRESSURE')
        source = diagnostics.parse('v=1;reason=actor_draining', 'BACKPRESSURE')
        summary = diagnostics.summary([counted, counted, None, source])
        self.assertEqual(summary['queue_database_data']['used'], {'64': 2})
        self.assertEqual(summary['queue_database_data']['requested'], {'1': 2})
        self.assertIn('charged credits', summary['queue_database_data']['unit'])
        self.assertFalse(summary['actor_draining']['counted'])
        self.assertNotIn('used', summary['actor_draining'])
        self.assertIn('charged queue credits', diagnostics.unit('catalogue_queue_name'))
        self.assertIn('charged queue credits', diagnostics.unit('restore_queue_global'))
        self.assertEqual(diagnostics.unit('discovery_threads'), 'native thread handles')

    def image_fixture(self, pages, mutate=None):
        objects = {}
        def save(kind, value, body=b''):
            header = json.dumps({'scope': {key: int(value) for key, value in spec.SCOPE.items()},
                'format': 2, 'payload': {'kind': kind, 'value': value}}, separators=(',', ':')).encode()
            data = b'SCAPOBJ2' + struct.pack('<IQ', len(header), len(body)) + header + body
            checksum = hashlib.sha256(data).hexdigest()
            objects[oracle.PREFIX + checksum] = data
            return checksum
        children, pieces = [], []
        for index in range((pages + 31) // 32):
            chunk = {'first_page': index * 32 + 1, 'bytes': []}
            body = bytes([index + 1]) * (min(32, pages - index * 32) * 4096)
            pieces.append(body)
            if mutate:
                chunk, body = mutate(index, chunk, body)
            children.append(save('chunk', chunk, body))
        node = {'level': 0, 'first_chunk': 0, 'children': children}
        manifest = {'page_count': pages, 'root': save('node', node)}
        def load(checksum, kind):
            key = oracle.PREFIX + checksum
            oracle.need(key in objects, 'publication-closure')
            actual, value, body = oracle.frame(objects[key], key)
            oracle.same(actual, kind, 'dependency-type')
            return value, body
        return manifest, load, b''.join(pieces), objects, node

    def test_long_image_requires_all_contiguous_chunks_and_partial_final_length(self):
        for pages in (33, 65, 128):
            manifest, load, expected, _, _ = self.image_fixture(pages)
            self.assertEqual(oracle.data_image(manifest, load, spec.ADMISSION_CURVE), expected)
            self.reject('fixed-image-bound', lambda: oracle.data_image(manifest, load, spec.SHORT))
        manifest, load, expected, _, _ = self.image_fixture(32)
        self.assertEqual(oracle.data_image(manifest, load), expected)
        for mutate in (lambda index, chunk, body: (dict(chunk, first_page=1), body) if index else (chunk, body),
                       lambda index, chunk, body: (chunk, body[:-4096]) if index else (chunk, body)):
            manifest, load, _, _, _ = self.image_fixture(33, mutate)
            self.reject('fixed-image-chunk', lambda: oracle.data_image(manifest, load, spec.ADMISSION_CURVE))

    def test_long_image_does_not_fill_missing_chunks_or_ignore_hash_identity(self):
        manifest, load, _, objects, node = self.image_fixture(65)
        objects.pop(oracle.PREFIX + node['children'][1])
        self.reject('publication-closure', lambda: oracle.data_image(manifest, load, spec.ADMISSION_CURVE))
        manifest, load, _, objects, node = self.image_fixture(65)
        key = oracle.PREFIX + node['children'][1]
        objects[key] = objects[key][:-1] + b'x'
        self.reject('immutable-frame', lambda: oracle.data_image(manifest, load, spec.ADMISSION_CURVE))
        manifest, load, _, _, _ = self.image_fixture(65)
        def fewer(checksum, kind):
            value, body = load(checksum, kind)
            if kind == 'node':
                value['children'].pop()
            return value, body
        self.reject('fixed-image-node', lambda: oracle.data_image(manifest, fewer, spec.ADMISSION_CURVE))

    def test_fixed_windows_do_not_credit_late_completions_to_the_offer_window(self):
        contract, origin = spec.ADMISSION_CURVE, 100
        selected = {item['id']: item for item in spec.calls(contract) if item['phase'] == 'low'}
        calls, offered = {}, {}
        snapshot = diagnostics.parse('v=1;reason=intake_data_requests_tenant;used=40;limit=40;requested=1', 'BACKPRESSURE')
        for key, item in selected.items():
            scheduled = origin + item['offset_ns']
            error = {'name': 'RemoteError', 'code': 'BACKPRESSURE'} if key == 'low-1' else None
            calls[key] = {'start': {'monotonic_ns': scheduled + 1},
                          'finish': {'monotonic_ns': scheduled + (5000000000 if key == 'low-0' else 200000000),
                                     'ok': error is None, 'error': error},
                          'rejection': snapshot if error else None}
            offered[key] = {'monotonic_ns': scheduled + 1, 'scheduled_ns': str(scheduled), 'active': 0}
        windows = oracle.windows(contract, 'low', origin, selected, calls, offered)
        self.assertEqual([row['offered_transactions'] for row in windows], [16, 16, 16, 16])
        self.assertEqual(sum(windows[0]['cohort_terminal_counts'].values()), 16)
        self.assertEqual(sum(windows[0]['terminal_counts_within_window'].values()), 15)
        self.assertEqual(windows[0]['unfinished_dispatched_transactions_at_window_end'], 1)
        self.assertEqual(sum(windows[1]['terminal_counts_within_window'].values()), 17)
        self.assertEqual(windows[0]['original_http_gate_observations']['intake_data_requests_tenant']['count'], 1)
        self.assertEqual(windows[0]['maximum_observed_active_before_offer'], 0)


if __name__ == '__main__':
    unittest.main()
