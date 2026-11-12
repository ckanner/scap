"""Verifier rejection tests; these do not stand in for actual process acceptance."""
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
