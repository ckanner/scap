"""Regress the real credential-order failure without weakening identity checks."""
import copy
import itertools
import sys
import unittest

# The standalone oracle imports shared audit modules from object-service.
# Restore its search-path setup so combined discovery still loads this
# directory's run.py for the observer tests.
_path = sys.path[:]
try:
    from oracle import PRINCIPALS, credential_audit
finally:
    sys.path[:] = _path


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
