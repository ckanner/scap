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
    put = {**common, 'key': (worker, 1), 'method': 'PUT', 'start': 20, 'end': 25,
           'if_none_match': '*', 'request_bytes': len(value), 'request_sha256': digest,
           'response_bytes': 0, 'response_sha256': empty}
    get = {**common, 'key': (worker, 2), 'method': 'GET', 'start': 30, 'end': 35,
           'if_none_match': None, 'request_bytes': 0, 'request_sha256': empty,
           'response_bytes': len(value), 'response_sha256': digest}
    return startup, [put, get]


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
            (1, 'start', 24, 'before-ready'),
            (1, 'end', 51, 'before-ready'),
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


if __name__ == '__main__':
    unittest.main()
