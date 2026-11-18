"""Verifier rejection tests; these do not stand in for actual process acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import controls
import oracle


class OracleTests(unittest.TestCase):
    def rejected(self, guard, call):
        with self.assertRaisesRegex(oracle.Rejected, '^' + guard + '$'):
            call()

    def test_controller_cannot_disguise_sql_as_recovery(self):
        self.rejected('controller-never-sql', lambda: oracle.controllers([], [
            {'principal': '12', 'operation': 'execute'}], {}, None, 0))

    def test_claim_retry_is_not_another_accepted_step(self):
        calls = [{'principal': '12', 'operation': operation} for operation in
                 ('owner_prepare', 'owner_claim', 'owner_claim', 'owner_resume')]
        self.rejected('fixed-owner-mutations-no-replay', lambda: oracle.controllers([], calls, {}, None, 0))

    def owner_response(self):
        scope = {'deployment': '1', 'tenant': '7', 'database': '8601', 'incarnation': '1', 'generation': '1'}
        fixed = {'creator': '12', 'operation': '7', 'expected_revision': '6', 'expected_head_serial': '7',
                 'mode': 'takeover', 'target_worker': '9602',
                 'nonces': {'claim': '101', 'activate': '102', 'cancel': '103', 'abort': '104'}}
        reference = {'creator': '12', 'operation': '7', 'descriptor_hash': 'a' * 64}
        marker = {'reference': reference, 'admission': {'kind': 'claim', 'revision': '7', 'head_serial': '8'},
                  'phase': {'kind': 'active', 'nonce': '102', 'owner_epoch': '2', 'owner_instance': '9602',
                            'revision': '8', 'head_serial': '9'}}
        response = {'ok': True, 'value': {'state': 'active',
            'prepared': {'scope': scope, 'input': fixed, 'reference': reference},
            'accepted': copy.deepcopy(marker), 'status': {'active': True, 'scope': scope, 'owner_instance': '9602',
            'owner_epoch': '2', 'owner_plan': copy.deepcopy(marker), 'revision': '8', 'head_serial': '9',
            'sequence': '3', 'lifecycle': 'ready', 'transition': {'nonce': '102', 'revision': '8'}}}}
        return response, fixed, scope, reference

    def test_owner_observation_accepts_original_input_and_current_marker(self):
        response, fixed, scope, reference = self.owner_response()
        self.assertEqual(oracle.owner_observation(response, 200, fixed, scope, reference, 'active'), response['value'])

    def test_failed_resume_cannot_be_replaced_by_a_successful_cli_report(self):
        success, fixed, scope, reference = self.owner_response()
        for response, status in [({'ok': False, 'error': {'code': 'FENCED'}}, 200), (None, 200), (success, 503)]:
            with self.subTest(response=response, status=status):
                self.rejected('real-resume-success', lambda: oracle.owner_observation(
                    response, status, fixed, scope, reference, 'active'))

    def test_resume_observation_rejects_wrong_active_authority_and_plan(self):
        cases = [('state', 'real-resume-active-state'), ('inactive', 'resume-active-authority'),
                 ('owner', 'resume-active-authority'), ('plan', 'resume-original-plan'),
                 ('marker', 'resume-current-marker')]
        for case, guard in cases:
            with self.subTest(case=case):
                response, fixed, scope, reference = self.owner_response()
                value = response['value']
                if case == 'state': value['state'] = 'claimed'
                elif case == 'inactive': value['status']['active'] = False
                elif case == 'owner': value['status']['owner_instance'] = '9601'
                elif case == 'plan': value['accepted']['reference']['descriptor_hash'] = '0' * 64
                elif case == 'marker': value['status']['owner_plan']['phase']['kind'] = 'claimed'
                self.rejected(guard, lambda: oracle.owner_observation(response, 200, fixed, scope, reference, 'active'))

    def test_consistent_marker_still_requires_original_activation_nonce(self):
        response, fixed, scope, reference = self.owner_response()
        value = response['value']
        value['accepted']['phase']['nonce'] = '999'
        value['status']['owner_plan']['phase']['nonce'] = '999'
        value['status']['transition']['nonce'] = '999'
        self.rejected('resume-accepted-phase', lambda: oracle.owner_observation(
            response, 200, fixed, scope, reference, 'active'))

    def test_unsigned_actual_request_is_rejected(self):
        self.rejected('actual-s3-signatures', lambda: oracle.exchanges([
            {'event': 's3_request', 'signature_valid': False}], None))

    def test_unconditional_head_publication_is_rejected(self):
        events = []
        kinds = ['s3_handler_started', 's3_request', 's3_forward_started', 's3_backend_response',
                 's3_delivery_started', 's3_delivery_finished', 's3_handler_finished']
        for sequence, event in enumerate(kinds):
            events.append({'sequence': sequence, 'event': event, 'role': 'A', 'serial': 1,
                'signature_valid': True, 'complete': True, 'method': 'PUT', 'headers': {},
                'request': {}, 'response': {}})
        self.rejected('conditional-s3-put', lambda: oracle.exchanges(events, lambda _: b''))

    def test_immutable_put_alone_does_not_prove_head_cas(self):
        events = []
        kinds = ['s3_handler_started', 's3_request', 's3_forward_started', 's3_backend_response',
                 's3_delivery_started', 's3_delivery_finished', 's3_handler_finished']
        for sequence, event in enumerate(kinds):
            events.append({'sequence': sequence, 'event': event, 'role': 'A', 'serial': 1,
                'signature_valid': True, 'complete': True, 'method': 'PUT', 'path': '/objects/immutable',
                'headers': {'if-none-match': '*'}, 'request': {}, 'response': {}})
        self.rejected('head-cas-observed', lambda: oracle.exchanges(events, lambda _: b''))

    def test_raw_evidence_byte_changes_are_not_hidden_by_same_length(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'raw').mkdir()
            digest = oracle.sha(b'valid')
            path = root / 'raw' / digest
            path.write_bytes(b'valid')
            ref = {'file': 'raw/' + digest, 'bytes': 5, 'sha256': digest}
            self.assertEqual(oracle.raw_file(root, ref), b'valid')
            path.write_bytes(b'wrong')
            self.rejected('raw-hash', lambda: oracle.raw_file(root, ref))

    def test_targeted_control_preserves_shared_body_and_sibling_request(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'raw').mkdir()
            raw, changed = b'{"operation":"status"}', b'{"operation":"execute"}'
            digest = oracle.sha(raw)
            path = root / 'raw' / digest
            path.write_bytes(raw)
            original = {'file': 'raw/' + digest, 'bytes': len(raw), 'sha256': digest}
            target, sibling = {'request': dict(original)}, {'request': dict(original)}
            replacements = {}
            controls.replace_reference(target, 'request', changed, replacements)
            self.assertEqual(sibling['request'], original)
            self.assertEqual(oracle.raw_file(root, sibling['request']), raw)
            self.assertEqual(path.read_bytes(), raw)
            self.assertNotEqual(target['request'], original)
            self.assertEqual(target['request']['bytes'], len(changed))
            self.assertEqual(target['request']['sha256'], oracle.sha(changed))
            self.assertEqual(replacements, {oracle.sha(changed): changed})

    def test_partial_final_record_and_duplicate_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'events.jsonl'
            path.write_text('{"event":"x"}')
            self.rejected('complete-ledger', lambda: oracle.read_rows(path))
            path.write_text('{"event":"x","event":"y"}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                oracle.read_rows(path)
            path.write_text(json.dumps({'event': 'x'}) + '\n')
            self.assertEqual(oracle.read_rows(path), [{'event': 'x'}])


if __name__ == '__main__':
    unittest.main()
