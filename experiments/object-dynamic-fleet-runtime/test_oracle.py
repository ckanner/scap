import copy
import unittest

import oracle


class Recipes(unittest.TestCase):
    def setUp(self):
        self.commitments = [{'nonces': {phase: str(index * 4 + offset + 1)
            for offset, phase in enumerate(('claim', 'cancel', 'activate', 'abort'))}} for index in range(4)]
        self.rows = []
        for index, target in enumerate(('9602', '9603', '9604'), 1):
            identity = str(index + 10)
            original = {'creator': '12', 'operation': identity, 'expected_head_serial': identity,
                'mode': 'takeover', 'target_worker': target, 'nonces': self.commitments[index]['nonces']}
            prepared = {'input': original, 'reference': {'creator': '12', 'operation': identity,
                        'descriptor_hash': str(index) * 64}, 'scope': {}}
            self.rows.append({'body': {'operation': 'owner_prepare', 'input': original},
                              'value': {'value': {'prepared': prepared}}})
            for operation in ('owner_claim', 'owner_abort' if index == 1 else 'owner_resume'):
                self.rows.append({'body': {'operation': operation, 'plan': copy.deepcopy(prepared['reference']),
                    'expected_worker_instance': target}, 'value': {'value': {'prepared': copy.deepcopy(prepared)}}})

    def test_fixed_original_recipes(self):
        self.assertEqual(set(oracle.fixed_owner_recipes(self.rows, self.commitments)), {'9602', '9603', '9604'})

    def test_rejects_new_guard_without_rewriting_original(self):
        self.rows[1]['body']['expected_worker_instance'] = '9604'
        with self.assertRaisesRegex(oracle.old.Rejected, '^original-target-guard$'):
            oracle.fixed_owner_recipes(self.rows, self.commitments)

    def test_rejects_resuming_retired_original_even_when_reference_matches(self):
        original = self.rows[0]['value']['value']['prepared']
        resumed = self.rows[5]
        resumed['body'].update(plan=copy.deepcopy(original['reference']), expected_worker_instance='9602')
        resumed['value']['value']['prepared'] = copy.deepcopy(original)
        with self.assertRaisesRegex(oracle.old.Rejected, '^retired-target-never-resumed$'):
            oracle.fixed_owner_recipes(self.rows, self.commitments)

    def test_rejects_policy_identity_or_nonce_rebase(self):
        for key, value in [('creator', '13'), ('operation', '99'), ('mode', 'activate'), ('target_worker', '9604'),
                           ('nonces', self.commitments[0]['nonces'])]:
            changed = copy.deepcopy(self.rows)
            changed[0]['body']['input'][key] = value
            with self.assertRaisesRegex(oracle.old.Rejected, '^prepare-exact-current-policy$'):
                oracle.fixed_owner_recipes(changed, self.commitments)

    def test_rejects_missing_or_rewritten_owner_step(self):
        with self.assertRaisesRegex(oracle.old.Rejected, '^fixed-owner-mutation-denominator$'):
            oracle.fixed_owner_recipes(self.rows[:-1], self.commitments)
        self.rows[2]['body']['plan']['descriptor_hash'] = 'f' * 64
        with self.assertRaisesRegex(oracle.old.Rejected, '^original-recipe-never-rebased$'):
            oracle.fixed_owner_recipes(self.rows, self.commitments)


class AuthorityRevocation(unittest.TestCase):
    def setUp(self):
        self.business = [{'event': 'controller_authority_revoked', 'revision': '13'}]
        self.calls = [{'body': {'operation': 'policy', 'permissions': [
            {'principal': '11', 'read': True, 'write': True, 'admin': True}]},
            'request': {'phase': 'authority-revoked'}, 'value': {'value': {'revision': '13'}}}]

    def test_uses_actual_sdk_policy_wire_operation(self):
        oracle.authority_revocation(self.calls, self.business)
        self.calls[0]['body']['operation'] = 'set_policy'
        with self.assertRaisesRegex(oracle.old.Rejected, '^real-controller-authority-revocation$'):
            oracle.authority_revocation(self.calls, self.business)

    def test_rejects_retained_controller_authority_or_fabricated_revision(self):
        changed = copy.deepcopy(self.calls)
        changed[0]['body']['permissions'].append({'principal': '12', 'read': True, 'write': True, 'admin': True})
        with self.assertRaisesRegex(oracle.old.Rejected, '^real-controller-authority-revocation$'):
            oracle.authority_revocation(changed, self.business)
        self.business[0]['revision'] = '14'
        with self.assertRaisesRegex(oracle.old.Rejected, '^real-controller-authority-revocation$'):
            oracle.authority_revocation(self.calls, self.business)


if __name__ == '__main__':
    unittest.main()
