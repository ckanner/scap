"""Regress the real credential-order failure without weakening identity checks."""
import copy
import importlib.util
import itertools
from pathlib import Path
import sys
import unittest

# The standalone oracle imports shared audit modules from object-service.
# Restore its search-path setup so combined discovery still loads this
# directory's run.py for the observer tests.
_path = sys.path[:]
try:
    from oracle import PRINCIPALS, WORKERS, credential_audit, original_s3_exchanges, relay_counts
    from test_owner_oracle import signed_exchange_fixture
finally:
    sys.path[:] = _path


class PhysicalListenerInventory(unittest.TestCase):
    def test_foreign_daemon_control_preserves_complete_wire_checks(self):
        fixture = signed_exchange_fixture(WORKERS)
        fixture['phases'].add('reader_denied')
        serial = max(row['request_serial'] for row in fixture['history'])
        for row in fixture['history']:
            if row['request_serial'] == serial:
                row.update(worker='p', phase='reader_denied')
                row['signing']['host'] = fixture['endpoints']['p'].split('://', 1)[1]
        spec = importlib.util.spec_from_file_location('guarded_control_case_test', Path(__file__).with_name('controls.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.foreign_daemon_head({'history': fixture['history'], 'configuration': {'s3_endpoints': fixture['endpoints']}})
        net = original_s3_exchanges(**fixture)
        self.assertEqual(net['requests'][serial]['worker'], 'q')
        self.assertEqual(net['requests'][serial]['signing']['host'], fixture['endpoints']['q'].split('://', 1)[1])
        self.assertEqual(dict((case.__name__, rule) for case, rule in module.CASES)['foreign_daemon_head'],
                         'S3 came from wrong daemon instance')

    def test_every_authenticated_startup_stays_in_its_listener_denominator(self):
        net = original_s3_exchanges(**signed_exchange_fixture(WORKERS))
        self.assertEqual(relay_counts(net), {'sink': 0, 'http-s': 7, 'http-p': 22,
                                           's3-s': 3, 's3-p': 2, 's3-q': 2})
        self.assertEqual(len(net['physical_requests']), 7)
        self.assertEqual(len(net['requests']), 1)
        self.assertEqual(len(net['startup_requests']), 6)

    def test_unproven_marker_never_reaches_a_listener_allowance(self):
        data = signed_exchange_fixture(WORKERS)
        for row in data['history']:
            if row['request_serial'] == 1:
                row['path'] = '/scap-test/scap-worker/v1/instances/9999'
        with self.assertRaisesRegex(ValueError, 'worker-identity-exact-key'):
            original_s3_exchanges(**data)


class CredentialPartition(unittest.TestCase):
    def setUp(self):
        self.identities = {role: str(index) * 64
            for index, role in enumerate(PRINCIPALS, 1)}
        self.records = [{'sha256': self.identities[role], 'deployment': '1',
            'tenant': '8' if role == 'foreign' else '7', 'principal': principal,
            'provision': role == 'writer'} for role, principal in PRINCIPALS.items()]

    def reject(self, records):
        with self.assertRaisesRegex(ValueError, '^trusted credential partition changed$'):
            credential_audit(records, self.identities)

    def test_all_orders_preserve_the_same_trusted_partition(self):
        for order in itertools.permutations(self.records):
            with self.subTest(principals=[entry['principal'] for entry in order]):
                credential_audit(list(order), self.identities)

    def test_missing_extra_and_replaced_records_are_rejected(self):
        self.reject(self.records[:-1])
        self.reject(self.records + [self.records[0]])
        self.reject([*self.records[:-1], self.records[0]])

    def test_each_trusted_field_and_type_remains_exact(self):
        changes = {'sha256': '0' * 64, 'deployment': '2', 'tenant': '8',
            'principal': '12', 'provision': False}
        for field, value in changes.items():
            with self.subTest(field=field):
                records = copy.deepcopy(self.records)
                records[0][field] = value
                self.reject(records)
        for field in ('deployment', 'tenant', 'principal'):
            records = copy.deepcopy(self.records)
            records[0][field] = int(records[0][field])
            self.reject(records)
        records = copy.deepcopy(self.records)
        records[0]['provision'] = 1
        self.reject(records)

    def test_swapped_digests_do_not_reassign_credentials(self):
        records = copy.deepcopy(self.records)
        records[0]['sha256'], records[1]['sha256'] = records[1]['sha256'], records[0]['sha256']
        self.reject(records)

    def test_unknown_or_missing_fields_and_nonarray_shape_are_rejected(self):
        records = copy.deepcopy(self.records)
        records[0]['unexpected'] = False
        self.reject(records)
        del records[0]['unexpected']
        del records[0]['provision']
        self.reject(records)
        self.reject({entry['sha256']: entry for entry in self.records})


if __name__ == '__main__':
    unittest.main()
