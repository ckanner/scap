"""Boundary units for the new independent decoder and actual public SDK saves."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import audit_model as m
import audit_evidence as evidence
import spec

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOGICAL = {key: int(value) for key, value in spec.SCOPES['bulk'].items()}
KNOWN = {tuple(LOGICAL[key] for key in m.SCOPE)}


def base_head():
    return {'format': 6, 'scope': dict(LOGICAL), 'head_serial': 1,
        'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None},
        'revision': 1, 'transition': {'revision': 1, 'nonce': 901}, 'sequence': 0,
        'owner_epoch': 1, 'owner_instance': 9101, 'active': False, 'auth_epoch': 1,
        'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True},
                   {'principal': 12, 'read': True, 'write': True, 'admin': True}],
        'lifecycle': 'ready', 'creation': None, 'deletion': None, 'data_root': '1' * 64,
        'quota': {'max_bytes': 67108864}, 'retention': {'max_entries': 129, 'max_result_bytes': 268435456},
        'request_epoch': 1, 'windows': [{'epoch': 1, 'root': '2' * 64, 'count': 0, 'result_bytes': 0}]}


def original_descriptor():
    original = {'creator': 11, 'operation': 800101, 'expected_revision': 1, 'expected_head_serial': 1,
                'mode': 'takeover', 'target_worker': 9102,
                'nonces': {'claim': 8001011, 'cancel': 8001012, 'activate': 8001013, 'abort': 8001014}}
    base = {'head_hash': m.sha(m.canonical_head(base_head())), 'etag': '"original"',
            'revision': 1, 'head_serial': 1, 'owner_epoch': 1, 'owner_instance': 9101,
            'active': False, 'previous_marker': None}
    value = {'version': 1, 'scope': dict(LOGICAL), 'input': original, 'base': base,
             'input_digest': m.sha(m.encoded([1, LOGICAL, original, base]))}
    return value


def marked_head(kind='claimed'):
    descriptor = original_descriptor()
    terminal = kind in ('active', 'aborted')
    revision = 3 if terminal else 2
    nonce = descriptor['input']['nonces'][{'claimed': 'claim', 'cancelling': 'cancel', 'active': 'activate', 'aborted': 'abort'}[kind]]
    head = base_head()
    admission = 'cancel' if kind == 'cancelling' else 'claim'
    owner = (1, 9101) if admission == 'cancel' else (2, 9102)
    head.update(format=8, head_serial=revision, revision=revision, transition={'revision': revision, 'nonce': nonce},
                owner_epoch=owner[0], owner_instance=owner[1], active=kind == 'active', owner_plan={
                    'reference': m.reference(descriptor),
                    'admission': {'kind': admission, 'revision': 2, 'head_serial': 2},
                    'phase': {'kind': kind, 'revision': revision, 'head_serial': revision,
                              'nonce': nonce, 'owner_epoch': owner[0], 'owner_instance': owner[1]}})
    return head


class ModelBoundary(unittest.TestCase):
    def rejected(self, rule, function, *args):
        with self.assertRaises(m.Rejected) as caught:
            function(*args)
        self.assertEqual(rule, caught.exception.rule)

    def test_fixed_denominators(self):
        self.assertEqual(spec.validate()['owner_posts'], 200)
        self.assertEqual(spec.WARM_PLANS['claim_cancel'][1][0], 'takeover')

    def test_independent_original_descriptor(self):
        value = original_descriptor()
        self.assertEqual(m.descriptor(m.encoded(value)), value)
        m.descriptor_base(value, base_head(), '"original"')

    def test_typed_canonical_hash_ignores_json_key_order(self):
        value = base_head()
        reordered = json.loads(json.dumps(value, sort_keys=True, indent=2))
        self.assertEqual(m.canonical_head(value), m.canonical_head(reordered))
        m.descriptor_base(original_descriptor(), reordered, '"original"')

    def test_descriptor_original_etag(self):
        self.rejected('owner-exact-original-head', m.descriptor_base,
                      original_descriptor(), base_head(), '"new-observation"')

    def test_descriptor_original_head_hash(self):
        changed = base_head()
        changed['policy'][0]['write'] = False
        self.rejected('owner-exact-original-head', m.descriptor_base, original_descriptor(), changed, '"original"')

    def test_input_digest_includes_nonce_and_base(self):
        value = original_descriptor()
        value['input']['nonces']['abort'] += 9
        self.rejected('owner-original-input-digest', m.descriptor, m.encoded(value))

    def test_descriptor_scope_identity_key(self):
        value = original_descriptor()
        path = spec.owner_path('bulk', 'descriptor', '11', '800102')
        self.rejected('owner-descriptor-full-key', m.descriptor, m.encoded(value), path)

    def test_duplicate_nonce(self):
        value = original_descriptor()
        value['input']['nonces']['abort'] = value['input']['nonces']['claim']
        self.rejected('owner-distinct-nonces', m.descriptor, m.encoded(value))

    def test_present_null_owner_forbidden(self):
        value = marked_head()
        value['owner_plan'] = None
        self.rejected('owner-marker-shape', m.head, m.encoded(value), KNOWN)

    def test_head6_owner_field_forbidden(self):
        value = marked_head()
        value['format'] = 6
        self.rejected('head-owner-format-shape', m.head, m.encoded(value), KNOWN)

    def test_same_revision_requires_phase_nonce(self):
        value = marked_head('active')
        value['transition']['nonce'] += 10
        self.rejected('owner-same-revision-nonce', m.head, m.encoded(value), KNOWN)

    def test_later_business_nonce_is_history(self):
        value = marked_head('active')
        value.update(revision=4, head_serial=4, transition={'revision': 4, 'nonce': 9001})
        self.assertEqual(m.head(m.encoded(value), KNOWN)['owner_plan']['phase']['revision'], 3)

    def test_pending_cannot_claim_active_bit(self):
        value = marked_head()
        value['active'] = True
        self.rejected('owner-non-active-inactive', m.head, m.encoded(value), KNOWN)

    def test_pending_target_tuple_bound(self):
        value = marked_head()
        value['owner_instance'] = 9202
        self.rejected('owner-pending-current-tuple', m.head, m.encoded(value), KNOWN)

    def test_pending_no_technical_gap(self):
        value = marked_head()
        value['head_serial'] += 1
        self.rejected('owner-pending-business-only', m.head, m.encoded(value), KNOWN)

    def test_terminal_gap_is_business_only(self):
        value = marked_head('active')['owner_plan']
        value['phase']['head_serial'] += 1
        self.rejected('owner-no-technical-gap', m.owner_marker, value)

    def test_cancelling_preserves_original_owner(self):
        value = marked_head('cancelling')
        m.head(m.encoded(value), KNOWN)
        m.descriptor_marker(original_descriptor(), value['owner_plan'])
        value['owner_plan']['phase']['owner_instance'] = 9102
        self.rejected('owner-accepted-original-target', m.descriptor_marker, original_descriptor(), value['owner_plan'])

    def test_admission_and_terminal_single_steps(self):
        self.assertEqual(m.advance(base_head(), marked_head()), 'owner_claim')
        self.assertEqual(m.advance(marked_head(), marked_head('active')), 'owner_active')

    def test_terminal_tuple_cannot_be_rebased(self):
        value = marked_head('active')
        value['owner_instance'] = value['owner_plan']['phase']['owner_instance'] = 9202
        self.rejected('owner-terminal-keeps-tuple', m.advance, marked_head(), value)

    def test_recovery_cannot_change_sql_root(self):
        value = marked_head('active')
        value['data_root'] = 'f' * 64
        self.rejected('owner-phase-preserves-business', m.advance, marked_head(), value)

    def test_proof_cannot_be_pending(self):
        value = {'version': 1, 'scope': LOGICAL, 'marker': marked_head()['owner_plan']}
        self.rejected('owner-proof-terminal-only', m.proof, m.encoded(value))

    def test_terminal_storage_keeps_owner_history(self):
        value = marked_head('active')
        value.update(lifecycle='deleted', active=False, revision=4, head_serial=4,
                     transition={'revision': 4, 'nonce': 9001})
        sealed = deepcopy(value)
        sealed['head_serial'] = 5
        sealed['storage']['terminal'] = {'serial': 5}
        m.head(m.encoded(sealed), KNOWN)
        self.assertEqual(m.advance(value, sealed), 'terminal')
        self.assertEqual(sealed['owner_plan'], value['owner_plan'])

    def test_terminal_revision_must_precede_seal(self):
        value = marked_head('active')
        value.update(lifecycle='deleted', active=False, head_serial=4)
        value['storage']['terminal'] = {'serial': 3}
        self.rejected('terminal-after-business-revision', m.head, m.encoded(value), KNOWN)

    def test_public_booleans_are_not_native_u64(self):
        value = original_descriptor()
        value['input']['creator'] = True
        self.rejected('integer-shape', m.descriptor, m.encoded(value))

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):
            m.descriptor(b'{"version":1,"version":1}')


class PublicSDKOriginals(unittest.TestCase):
    def test_all_sql_and_owner_inputs_use_real_save_restore(self):
        with tempfile.TemporaryDirectory(prefix='scap-owner-sdk-unit-') as directory:
            root = Path(directory)
            (root / 'raw').mkdir()
            endpoints = {str(worker): f'http://127.0.0.1:{20000 + index}'
                for index, worker in enumerate(worker for values in spec.WORKERS.values() for worker in values)}
            configuration = {'source_root': str(ROOT), 'endpoint': endpoints['9103'], 'scopes': spec.SCOPES,
                'tokens': {'11': 'a' * 64, '12': 'b' * 64}, 'timeouts': spec.TIMEOUTS,
                'workerEndpoints': endpoints,
                'routes': [{'workerInstance': worker, 'endpoint': endpoint + '/v1'} for worker, endpoint in endpoints.items()]}
            config = root / 'configuration.json'
            config.write_text(json.dumps(configuration))
            commands = [{'id': 'sql-save', 'operation': 'prepare_sql', 'specs': spec.inputs()}]
            rows = list(spec.plans()) + spec.exceptional_plans()[:2]
            source = {row['name']: row for row in rows}
            for alias in spec.exceptional_plans()[2:]:
                rows.append({**source[alias['alias']], 'name': alias['name']})
            for index, row in enumerate(rows, 1):
                original = {key: row[key] for key in ('creator', 'operation', 'mode', 'target_worker', 'nonces')}
                original.update(expected_revision=str(index), expected_head_serial=str(index + 2))
                commands.append({'id': row['name'] + '-save', 'operation': 'owner_save', 'scope_name': row['scope_name'],
                                 'principal': row['creator'], 'intent': row['name'], 'input': original})
            command = [shutil.which('node') or 'node', str(HERE / 'client.mjs'), str(config), str(root), 'unit']
            result = subprocess.run(command, input=''.join(json.dumps(row) + '\n' for row in commands),
                                    text=True, capture_output=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            answers = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(answers[0], {'ready': True})
            self.assertEqual(len(answers), len(commands) + 1)
            self.assertTrue(all(row['ok'] for row in answers[1:]), answers)
            sql = json.loads((root / 'intents.json').read_text())
            self.assertEqual(len(sql), 297)
            for row in spec.inputs():
                saved = json.loads(sql[row['name']]['serialized'])
                self.assertEqual(set(saved), {'scope', 'request', 'statements'})
                self.assertEqual(saved['scope'], spec.SCOPES[row['scope_name']])
                self.assertEqual(saved['statements'], row['statements'])
                self.assertEqual(saved['request'], {'epoch': row['epoch'], 'id': row['request_id'],
                    'principal': '11', 'fingerprint': m.wire.fingerprint(row['statements'])})
            owners = [json.loads(line) for line in (root / 'owner-inputs.jsonl').read_text().splitlines()]
            self.assertEqual(len(owners), 50)
            expected = {row['intent']: row for row in commands[1:]}
            for row in owners:
                saved = json.loads(row['serialized'])
                self.assertEqual(set(saved), {'version', 'scope', 'input'})
                self.assertEqual(saved['version'], 1)
                self.assertEqual(saved['scope'], spec.SCOPES[row['scope_name']])
                self.assertEqual(saved['input'], expected[row['name']]['input'])
            events = [json.loads(line) for line in (root / 'sdk-unit.jsonl').read_text().splitlines()]
            self.assertFalse(any(row['event'] == 'http_request' for row in events))
            self.assertEqual(sum(row['event'] == 'owner_input_saved' for row in events), 50)
            self.assertTrue(all(row['attempts'] == 0 for row in events if row['event'] == 'command_finished'))
            # Feed the real public SDK's serialized bytes into the independent
            # reader too. The one catalogue row is a pure saved-input unit, not
            # an assertion that a named operation ran against the product.
            saved_name = {'version': 1, 'deployment': '1', 'tenant': '7', 'principal': '11',
                          'action': {'operation': 'resolve_name', 'name': 'owner-head8-history'}}
            (root / 'named-intents.jsonl').write_text(json.dumps({'name': 'unit-original-name',
                'scope_name': 'named_old', 'role': 'unit', 'principal': '11', 'serialized': json.dumps(saved_name)}) + '\n')
            parsed = evidence.original_inputs(root, {'specs': spec.inputs(), 'scopes': spec.SCOPES,
                'named': {name: spec.creation(name) for name in spec.NAMED}}, [])
            self.assertEqual(tuple(len(value) for value in parsed), (297, 297, 50, 1))


if __name__ == '__main__':
    unittest.main()
