"""Independent negative controls for permanent startup-identity evidence."""
import copy
import hashlib
import unittest

import audit_wire as wire


def witness(worker='5001', role=None):
    value = b'SCAP-WORKER-INSTANCE-v1\0' + int(worker).to_bytes(8, 'big')
    digest = hashlib.sha256(value).hexdigest()
    empty = hashlib.sha256(b'').hexdigest()
    startup = {'worker': worker, 'role': role, 'start': 10, 'ready': 50}
    common = {'role': role, 'path': '/scap-test/scap-worker/v1/instances/' + worker,
              'status': 200, 'delivered': True, 'etag': '"original"', 'if_match': None}
    put = {**common, 'key': (worker, 1), 'method': 'PUT', 'start': 20, 'response': 22, 'end': 25,
           'if_none_match': '*', 'request_bytes': len(value), 'request_sha256': digest,
           'response_bytes': 0, 'response_sha256': empty}
    get = {**common, 'key': (worker, 2), 'method': 'GET', 'start': 30, 'response': 32, 'end': 35,
           'if_none_match': None, 'request_bytes': 0, 'request_sha256': empty,
           'response_bytes': len(value), 'response_sha256': digest}
    return startup, [put, get]


def owned_startup_events(*, role=None):
    # The child completes both exchanges at 32, while the parent is not
    # scheduled to observe the Popen result until 40. These are distinct clocks.
    identity = {'pid': 123, 'spawn_monotonic_ns': 40, 'pid_source': 'owned_Popen_child'}
    owner = {'owner_instance': 5001} if role is None else {'worker': role}
    return [{'event': 'service_started', **owner, 'identity': identity,
             'spawn_requested_ns': 10, 'monotonic_ns': 45},
            {'event': 'service_ready', **owner, 'identity': copy.deepcopy(identity),
             'monotonic_ns': 50}]


class OwnedStartupControls(unittest.TestCase):
    def test_child_claim_may_precede_parent_observation_for_both_service_adapters(self):
        for role in (None, 'A'):
            events = owned_startup_events(role=role)
            options = {} if role is None else {'workers': {'A': '5001'}}
            startups = wire.service_startups(events, **options)
            expected, rows = witness(role=role)
            self.assertEqual(startups, [expected])
            self.assertEqual(wire.worker_claims(startups, rows), {('5001', 1), ('5001', 2)})

    def test_request_before_pre_popen_bound_is_still_rejected(self):
        events = owned_startup_events()
        events[0]['spawn_requested_ns'] = 21
        _, rows = witness()
        with self.assertRaisesRegex(ValueError, 'before-ready'):
            wire.worker_claims(wire.service_startups(events), rows)

    def test_owned_interval_requires_original_typed_clocks_and_order(self):
        cases = (
            (0, (), 'spawn_requested_ns', None, 'spawn-clock'),
            (0, (), 'spawn_requested_ns', True, 'spawn-clock'),
            (0, (), 'spawn_requested_ns', '10', 'spawn-clock'),
            (0, (), 'spawn_requested_ns', 0, 'spawn-clock'),
            (0, (), 'spawn_requested_ns', 41, 'startup-order'),
            (0, ('identity',), 'spawn_monotonic_ns', 9, 'startup-order'),
            (0, ('identity',), 'spawn_monotonic_ns', '40', 'spawn-clock'),
            (0, ('identity',), 'spawn_monotonic_ns', True, 'spawn-clock'),
            (0, ('identity',), 'pid', 0, 'owned-spawn'),
            (0, ('identity',), 'pid', True, 'owned-spawn'),
            (0, ('identity',), 'pid_source', '/proc/guess', 'owned-spawn'),
            (0, (), 'monotonic_ns', 39, 'startup-order'),
            (1, (), 'monotonic_ns', 45, 'startup-order'),
            (1, (), 'monotonic_ns', '50', 'spawn-clock'),
        )
        for index, path, field, value, guard in cases:
            rows = owned_startup_events()
            target = rows[index]
            for component in path:
                target = target[component]
            target[field] = value
            with self.subTest(index=index, field=field, value=value), self.assertRaisesRegex(ValueError, guard):
                wire.owned_startup_interval(rows[0], rows[1])
        for field in ('identity', 'spawn_requested_ns', 'monotonic_ns'):
            rows = owned_startup_events()
            del rows[0][field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, 'owned-spawn|spawn-clock'):
                wire.owned_startup_interval(rows[0], rows[1])

    def test_service_ready_must_belong_to_the_unique_owned_start(self):
        cases = ('missing', 'duplicate-start', 'duplicate-ready', 'wrong-worker', 'wrong-child')
        for change in cases:
            rows = owned_startup_events()
            if change == 'missing':
                rows.pop()
            elif change == 'duplicate-start':
                rows.append(copy.deepcopy(rows[0]))
            elif change == 'duplicate-ready':
                rows.append(copy.deepcopy(rows[1]))
            elif change == 'wrong-worker':
                rows[1]['owner_instance'] = 5002
            else:
                rows[1]['identity']['pid'] += 1
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'readiness-denominator|owned-ready'):
                wire.service_startups(rows)
        rows = owned_startup_events()
        # Equal inventory sizes must not permit one ready row to be reused.
        rows += [copy.deepcopy(rows[0]), {**copy.deepcopy(rows[1]), 'owner_instance': 5002}]
        with self.assertRaisesRegex(ValueError, 'readiness-denominator'):
            wire.service_startups(rows)


class WorkerClaimControls(unittest.TestCase):
    def test_distinct_workers_may_start_concurrently_before_the_ready_log(self):
        first, rows = witness()
        second, more = witness('5002')
        self.assertEqual(wire.worker_claims([first, second], rows + more),
                         {('5001', 1), ('5001', 2), ('5002', 1), ('5002', 2)})
        self.assertEqual(wire.worker_claims([], []), set())

    def test_missing_extra_and_unbound_exchanges_cannot_be_ignored(self):
        startup, rows = witness()
        for changed in ([], rows[:1], rows + [copy.deepcopy(rows[0])]):
            with self.subTest(count=len(changed)), self.assertRaisesRegex(ValueError, 'request-denominator'):
                wire.worker_claims([startup], changed)
        with self.assertRaisesRegex(ValueError, 'request-denominator'):
            wire.worker_claims([], rows)

    def test_changed_identity_conditions_bytes_etag_or_lifetime_are_rejected(self):
        cases = [
            (0, 'role', 'other', 'exact-key'),
            (0, 'path', '/scap-test/scap-worker/v1/allocator', 'exact-key'),
            (1, 'path', '/scap-test/scap-worker/v1/instances/05001', 'exact-key'),
            (0, 'method', 'DELETE', 'create-readback'),
            (1, 'method', 'PUT', 'create-readback'),
            (0, 'start', 9, 'before-ready'),
            (1, 'start', 21, 'before-ready'),
            (1, 'response', 51, 'before-ready'),
            (0, 'status', 412, 'unambiguous-delivery'),
            (1, 'status', 404, 'unambiguous-delivery'),
            (0, 'delivered', False, 'unambiguous-delivery'),
            (1, 'delivered', False, 'unambiguous-delivery'),
            (0, 'if_none_match', None, 'absent-only'),
            (0, 'if_match', '"adopted"', 'absent-only'),
            (1, 'if_match', '"conditional-read"', 'absent-only'),
            (0, 'request_bytes', 31, 'exact-body'),
            (0, 'request_sha256', '0' * 64, 'exact-body'),
            (1, 'response_sha256', '0' * 64, 'exact-body'),
            (0, 'response_bytes', 1, 'exact-body'),
            (1, 'request_bytes', 1, 'exact-body'),
            (0, 'etag', '', 'same-etag'),
            (1, 'etag', '"later-object"', 'same-etag'),
        ]
        for index, key, value, boundary in cases:
            with self.subTest(index=index, field=key, value=value):
                startup, rows = witness()
                rows[index][key] = value
                with self.assertRaisesRegex(ValueError, boundary):
                    wire.worker_claims([startup], rows)

    def test_startup_must_use_a_unique_canonical_nonzero_u64(self):
        for worker in ('0', '05001', str(2**64), 5001):
            startup, rows = witness()
            startup['worker'] = worker
            with self.subTest(worker=worker), self.assertRaisesRegex(ValueError, 'identity-unique'):
                wire.worker_claims([startup], rows)
        startup, rows = witness()
        with self.assertRaisesRegex(ValueError, 'identity-unique'):
            wire.worker_claims([startup, copy.deepcopy(startup)], rows + copy.deepcopy(rows))

    def test_returned_keys_must_identify_distinct_wire_exchanges(self):
        first, rows = witness()
        second, more = witness('5002')
        more[0]['key'] = rows[0]['key']
        with self.assertRaisesRegex(ValueError, 'exchange-unique'):
            wire.worker_claims([first, second], rows + more)

    def test_late_delivery_callbacks_do_not_change_original_network_order(self):
        startup, rows = witness()
        rows[0]['end'] = 70
        rows[1]['end'] = 80
        self.assertEqual(wire.worker_claims([startup], rows), {('5001', 1), ('5001', 2)})
        rows[0]['response'] = rows[1]['start']
        with self.assertRaisesRegex(ValueError, 'before-ready'):
            wire.worker_claims([startup], rows)
        rows[0]['response'] = 22
        startup['ready'] = rows[1]['response']
        with self.assertRaisesRegex(ValueError, 'before-ready'):
            wire.worker_claims([startup], rows)


def raw_witness():
    value = b'SCAP-WORKER-INSTANCE-v1\0' + (5001).to_bytes(8, 'big')
    events = [{'event': 'child_started', 'id': 'service-A',
               'spawn_requested_ns': 5, 'monotonic_ns': 7,
               'identity': {'pid': 123, 'spawn_monotonic_ns': 6, 'pid_source': 'owned_Popen_child'}},
              {'event': 'service_ready', 'id': 'service-A', 'role': 'A',
               'worker': '5001', 'monotonic_ns': 60}]
    stages = ('s3_handler_started', 's3_request', 's3_forward_started',
              's3_backend_response', 's3_delivery_started',
              's3_delivery_finished', 's3_handler_finished')
    for serial, method, start in ((1, 'PUT', 10), (2, 'GET', 30)):
        request, response = (value, b'') if method == 'PUT' else (b'', value)
        for offset, stage in enumerate(stages):
            row = {'event': stage, 'role': 'A', 'serial': serial, 'phase': 'setup',
                   'path': '/scap-test/scap-worker/v1/instances/5001', 'method': method,
                   'monotonic_ns': start + offset}
            if stage == 's3_request':
                row.update(request=request, signature_valid=True, access_sha256='normal',
                           headers={'x-amz-content-sha256': hashlib.sha256(request).hexdigest(),
                                    'content-length': str(len(request)),
                                    **({'if-none-match': '*'} if method == 'PUT' else {})})
            elif stage == 's3_backend_response':
                row.update(response=response, status=200, headers={'etag': '"original"'})
            elif stage == 's3_delivery_started':
                row.update(response=response, status=200, origin='backend')
            elif stage == 's3_delivery_finished':
                row['complete'] = True
            events.append(row)
    return events


class ClosedRawWorkerClaims(unittest.TestCase):
    def test_complete_raw_lifetimes_bind_owned_startup(self):
        self.assertEqual(wire.closed_worker_claims(raw_witness(), lambda value: value, 'normal'),
                         {('A', 1), ('A', 2)})

    def test_child_claim_may_finish_before_parent_observes_the_owned_process(self):
        rows = raw_witness()
        rows[0]['identity']['spawn_monotonic_ns'] = 40
        rows[0]['monotonic_ns'] = 45
        self.assertEqual(wire.closed_worker_claims(rows, lambda value: value, 'normal'),
                         {('A', 1), ('A', 2)})

    def test_pre_spawn_claim_and_missing_original_request_clock_are_rejected(self):
        rows = raw_witness()
        rows[0]['spawn_requested_ns'] = 12  # The original PUT request is at 11.
        rows[0]['identity']['spawn_monotonic_ns'] = 40
        rows[0]['monotonic_ns'] = 45
        with self.assertRaisesRegex(ValueError, 'before-ready'):
            wire.closed_worker_claims(rows, lambda value: value, 'normal')
        rows = raw_witness()
        del rows[0]['spawn_requested_ns']
        with self.assertRaisesRegex(ValueError, 'spawn-clock'):
            wire.closed_worker_claims(rows, lambda value: value, 'normal')

    def test_raw_adapter_preserves_the_callers_rejection_type(self):
        class Rejected(Exception):
            pass
        def check(condition, rule):
            if not condition:
                raise Rejected(rule)
        rows = raw_witness()
        rows[0]['spawn_requested_ns'] = rows[0]['identity']['spawn_monotonic_ns'] + 1
        with self.assertRaisesRegex(Rejected, 'startup-order'):
            wire.raw_worker_claims(rows, [], 'normal', check=check)

    def test_missing_or_duplicate_stage_is_rejected(self):
        original = raw_witness()
        for stage in ('s3_handler_started', 's3_forward_started', 's3_backend_response',
                      's3_delivery_started', 's3_delivery_finished', 's3_handler_finished'):
            target = next(row for row in original if row['event'] == stage and row['serial'] == 1)
            for changed in ([row for row in original if row is not target], original + [copy.deepcopy(target)]):
                with self.subTest(stage=stage, count=len(changed)), self.assertRaisesRegex(ValueError, 'closed-stages'):
                    wire.closed_worker_claims(changed, lambda value: value, 'normal')

    def test_faulted_or_changed_raw_delivery_cannot_be_certified(self):
        cases = (
            ('s3_forward_started', 'path', '/wrong', 'original-exchange'),
            ('s3_delivery_finished', 'phase', 'database', 'original-exchange'),
            ('s3_forward_started', 'monotonic_ns', 1, 'stage-order'),
            ('s3_request', 'signature_valid', False, 'signed-request'),
            ('s3_request', 'request', b'wrong', 'signed-body'),
            ('s3_request', 'access_sha256', 'gc', 'normal-authority'),
            ('s3_delivery_started', 'origin', 'fixture', 'original-delivery'),
            ('s3_delivery_started', 'response', b'wrong', 'original-delivery'),
            ('s3_delivery_started', 'status', 412, 'original-delivery'),
            ('s3_delivery_finished', 'complete', False, 'unambiguous-delivery'),
        )
        for event, field, value, guard in cases:
            changed = raw_witness()
            next(row for row in changed if row['event'] == event and row['serial'] == 1)[field] = value
            with self.subTest(event=event, field=field), self.assertRaisesRegex(ValueError, guard):
                wire.closed_worker_claims(changed, lambda value: value, 'normal')
        changed = raw_witness() + [{'event': 'fault_suppressed', 'role': 'A', 'serial': 1}]
        with self.assertRaisesRegex(ValueError, 'no-fault'):
            wire.closed_worker_claims(changed, lambda value: value, 'normal')

    def test_readiness_cannot_borrow_another_owned_process(self):
        for change in ('missing', 'extra', 'duplicate', 'wrong-id', 'wrong-role', 'wrong-incarnation'):
            rows = raw_witness()
            ready = rows[1]
            if change == 'missing':
                rows.remove(ready)
            elif change == 'extra':
                rows.append({'event': 'child_started', 'id': 'service-B',
                             'identity': {'spawn_monotonic_ns': 1}})
            elif change == 'duplicate':
                rows.append(copy.deepcopy(ready))
                rows.append({'event': 'child_started', 'id': 'service-B',
                             'identity': {'spawn_monotonic_ns': 1}})
            elif change == 'wrong-id':
                ready['id'] = 'node-version'
            elif change == 'wrong-role':
                ready['role'] = 'B'
            else:
                ready['incarnation'] = 0
            guard = 'owned-role' if change in ('wrong-role', 'wrong-incarnation') else 'owned-readiness'
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, guard):
                wire.closed_worker_claims(rows, lambda value: value, 'normal')
        rows = raw_witness()
        rows[0]['id'] = rows[1]['id'] = 'service-A-1'
        rows[1]['incarnation'] = 1
        self.assertEqual(wire.closed_worker_claims(rows, lambda value: value, 'normal'), {('A', 1), ('A', 2)})


if __name__ == '__main__':
    unittest.main()
