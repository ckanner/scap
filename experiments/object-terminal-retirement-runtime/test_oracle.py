"""Independent protocol/observer boundaries and actual public SDK preparation."""
from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

import audit_evidence as evidence
import audit_model as model
import controls
from harness import Harness
import oracle
import spec
import support as io


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def fixture_head(terminal=False):
    value = {'format': 6, 'scope': {key: int(number) for key, number in spec.SCOPES['late'].items()},
        'head_serial': 5, 'revision': 3, 'transition': {'revision': 3, 'nonce': 31}, 'sequence': 1,
        'owner_epoch': 1, 'owner_instance': 8101, 'active': True, 'auth_epoch': 1,
        'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True}], 'lifecycle': 'deleted',
        'creation': None, 'deletion': None, 'data_root': 'a' * 64, 'quota': {'max_bytes': 67108864},
        'retention': {'max_entries': 129, 'max_result_bytes': 268435456}, 'request_epoch': 1,
        'windows': [{'epoch': 1, 'root': 'b' * 64, 'count': 1, 'result_bytes': 100}],
        'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None}}
    if terminal:
        value.update(format=7, head_serial=6, active=False)
        value['storage']['terminal'] = {'serial': 6}
    return value


def with_checkpoint():
    value = fixture_head(True)
    value['head_serial'] = 7
    digest = 'c' * 64
    value['storage']['sweep'] = {'serial': 7, 'generation': 1, 'next_after': None, 'exhausted': True,
        'entries': [{'key': model.prefix(value['scope'], 1).removeprefix('/scap-test/') + digest,
                     'hash': digest, 'etag': '"original-etag"', 'disposition': 'pending'}]}
    return value


def native_creation(name):
    original = spec.creation(name)
    return {key: int(value) if key in ('creator', 'operation') else
            {k: int(v) for k, v in value.items()} if key == 'scope' else
            None if value is None else int(value) if key == 'expected_name_revision' else value
            for key, value in original.items()}


def admin_only_history():
    names = ('bad-sweep-admin-only', 'bad-sweep-delete-status', 'bad-sweep-delete',
             'bad-sweep-seal-without-read-or-provision')
    calls = {name: {'request': {'principal': '11', 'monotonic_ns': 10 + 10 * index},
                    'done': {'monotonic_ns': 19 + 10 * index}, 'result': {'ok': True}}
             for index, name in enumerate(names)}
    policy, denied, deletion, _seal = (calls[name] for name in names)
    permissions = [{'principal': '11', 'read': False, 'write': False, 'admin': True}]
    policy.update(body={'permissions': permissions, 'scope': spec.SCOPES['bad_sweep']},
                  response_body={'value': {'revision': '5'}})
    denied['result'] = {'ok': False, 'error': {'code': 'DENIED'}}
    deletion['body'] = {'expected_revision': '5'}
    history = []
    for revision, serial, timestamp, terminal in ((5, 5, 15, False), (6, 6, 35, False), (6, 7, 45, True)):
        head = fixture_head(terminal)
        head.update(revision=revision, head_serial=serial)
        head['policy'] = [{**permissions[0], 'principal': 11}]
        if terminal:
            head['storage']['terminal']['serial'] = serial
        history.append({'head': head, 'exchange': {'backend': {'monotonic_ns': timestamp}}})
    return calls, {int(spec.SCOPES['bad_sweep']['database']): history}


class ModelBoundaries(unittest.TestCase):
    def parse(self, value):
        return model.head(encoded(value), {model.scope_key(value['scope'])})

    def rejected(self, rule, function, *args):
        with self.assertRaises(model.Rejected) as caught:
            function(*args)
        self.assertEqual(caught.exception.rule, rule)

    def test_head6_deleted_can_keep_historical_activation(self):
        value = fixture_head()
        self.assertTrue(self.parse(value)['active'])
        self.assertEqual(model.advance(value, fixture_head(True)), 'terminal')

    def test_head6_must_not_gain_public_null_field(self):
        value = fixture_head(); value['storage']['terminal'] = None
        self.rejected('exact-storage-version-shape', self.parse, value)

    def test_head7_missing_terminal_rejected(self):
        value = fixture_head(True); del value['storage']['terminal']
        self.rejected('exact-storage-version-shape', self.parse, value)

    def test_head7_explicit_null_rejected(self):
        value = fixture_head(True); value['storage']['terminal'] = None
        self.rejected('terminal-seal-shape', self.parse, value)

    def test_head7_active_rejected(self):
        value = fixture_head(True); value['active'] = True
        self.rejected('terminal-deleted-inactive', self.parse, value)

    def test_head7_live_lifecycle_rejected(self):
        value = fixture_head(True); value['lifecycle'] = 'ready'
        self.rejected('terminal-deleted-inactive', self.parse, value)

    def test_terminal_after_business_revision(self):
        value = fixture_head(True); value['storage']['terminal']['serial'] = value['revision']
        self.rejected('terminal-after-business-revision', self.parse, value)

    def test_terminal_after_allocated_generation(self):
        value = fixture_head(True); value['storage']['allocated_through'] = 6
        self.rejected('terminal-after-allocation', self.parse, value)

    def test_terminal_current_serial_is_bounded(self):
        value = fixture_head(True); value['storage']['terminal']['serial'] = 7
        self.rejected('integer-shape', self.parse, value)

    def test_seal_keeps_original_business_barrier(self):
        value = fixture_head(True); value['transition']['nonce'] += 1
        self.rejected('seal-business-preservation', model.advance, fixture_head(), self.parse(value))

    def test_seal_cannot_allocate(self):
        value = fixture_head(True); value['storage']['allocated_through'] += 1
        self.rejected('one-way-terminal-seal', model.advance, fixture_head(), self.parse(value))

    def test_terminal_cannot_change_on_later_checkpoint(self):
        value = with_checkpoint(); value['storage']['terminal']['serial'] = 5
        self.rejected('terminal-allocation-frozen', model.advance, fixture_head(True), self.parse(value))

    def test_terminal_checkpoint_can_delete_historical_active(self):
        value = self.parse(with_checkpoint())
        self.assertTrue(model.retired(value['storage'], 1))
        self.assertFalse(model.retired(value['storage'], 2))
        self.assertEqual(model.advance(fixture_head(True), value), 'prepare')

    def test_checkpoint_must_be_later_than_terminal(self):
        value = with_checkpoint(); value['storage']['sweep']['serial'] = 6
        self.rejected('checkpoint-after-terminal', self.parse, value)

    def test_unsealed_active_generation_is_not_retired(self):
        self.assertFalse(model.retired(fixture_head()['storage'], 1))

    def test_pending_checkpoint_cannot_clear(self):
        old = with_checkpoint(); new = copy.deepcopy(old)
        new['head_serial'] += 1; new['storage']['sweep'] = None
        self.rejected('pending-checkpoint-cleared', model.advance, old, new)

    def test_checkpoint_keeps_original_etag(self):
        old = with_checkpoint(); new = copy.deepcopy(old)
        new['head_serial'] += 1; new['storage']['sweep']['entries'][0].update(etag='"new"', disposition='applied')
        self.rejected('checkpoint-original-etag', model.advance, old, new)

    def test_checkpoint_full_scope_includes_incarnation(self):
        value = with_checkpoint()
        value['storage']['sweep']['entries'][0]['key'] = value['storage']['sweep']['entries'][0]['key'].replace('/inc/1/', '/inc/2/')
        self.rejected('checkpoint-full-scope-key', self.parse, value)

    def test_public_projection_has_null_on_unsealed_head6(self):
        value = oracle.projection(fixture_head())
        self.assertIsNone(value['storage']['terminal'])
        oracle.public_terminal(value)

    def test_public_terminal_revision_boundary(self):
        value = oracle.projection(fixture_head(True)); value['storage']['terminal']['serial'] = value['revision']
        self.rejected('public-terminal-after-business-revision', oracle.public_terminal, value)

    def test_public_terminal_checkpoint_boundary(self):
        value = oracle.projection(with_checkpoint()); value['storage']['sweep']['serial'] = value['storage']['terminal']['serial']
        self.rejected('public-checkpoint-after-terminal', oracle.public_terminal, value)

    def test_explicit_stale_barrier_can_be_static_valid(self):
        value = fixture_head(True); value['head_serial'] = 10; value['storage']['terminal']['serial'] = 5
        self.assertEqual(self.parse(value)['storage']['terminal']['serial'], 5)

    def test_named_scope_uses_all_64_bit_components(self):
        for name in spec.NAMED:
            model.native_creation(native_creation(name))
        value = native_creation('before'); value['scope']['incarnation'] += 1
        self.rejected('named-derived-full-scope', model.native_creation, value)

    def test_persisted_descriptor_kind_differs_from_http_mode(self):
        value = {'format': 1, 'creation': native_creation('before'),
                 'options': {'quota': {'kind': 'limited', 'max_bytes': 67108864}},
                 'initial_quota': {'max_bytes': 67108864},
                 'retention': {'max_entries': 129, 'max_result_bytes': 268435456}}
        self.assertEqual(model.catalogue(encoded(value), spec.catalogue_path('create', 'before'))[0], 'descriptor')
        value['options']['quota'] = {'mode': 'limited', 'max_bytes': 67108864}
        self.rejected('named-initial-quota', model.catalogue, encoded(value), spec.catalogue_path('create', 'before'))

    def test_duplicate_authority_field_is_not_discarded(self):
        raw = encoded(fixture_head(True)).replace(b'"format":7', b'"format":6,"format":7')
        with self.assertRaises(ValueError):
            model.head(raw, {model.scope_key(fixture_head()['scope'])})

    def test_immutable_frame_requires_full_scope(self):
        logical = fixture_head()['scope']
        metadata = {'format': 2, 'scope': logical, 'payload': {'kind': 'manifest', 'value': {'page_count': 0, 'root': None}}}
        payload = encoded(metadata)
        frame = b'SCAPOBJ2' + struct.pack('<IQ', len(payload), 0) + payload
        path = model.prefix(logical, 1) + model.sha(frame)
        self.assertEqual(model.envelope(frame, path)[0], 'manifest')
        self.rejected('immutable-full-scope', model.envelope, frame, path.replace('/inc/1/', '/inc/2/'))


class ObserverBoundaries(unittest.TestCase):
    def test_admin_only_retirement_preserves_denial_and_policy_revision(self):
        oracle.admin_only_retirement(*admin_only_history())

    def test_admin_only_delete_cannot_reuse_pre_policy_revision(self):
        calls, heads = admin_only_history()
        calls['bad-sweep-delete']['body']['expected_revision'] = '4'
        with self.assertRaises(model.Rejected) as error:
            oracle.admin_only_retirement(calls, heads)
        self.assertEqual(error.exception.rule, 'admin-only-delete-original-policy-revision')

    def test_admin_only_seal_cannot_restore_read_permission(self):
        calls, heads = admin_only_history()
        next(iter(heads.values()))[1]['head']['policy'][0]['read'] = True
        with self.assertRaises(model.Rejected) as error:
            oracle.admin_only_retirement(calls, heads)
        self.assertEqual(error.exception.rule, 'admin-only-policy-preserved-through-seal')

    def test_admin_only_observation_requires_real_denied_result(self):
        calls, heads = admin_only_history()
        calls['bad-sweep-delete-status']['result'] = {'ok': True}
        with self.assertRaises(model.Rejected) as error:
            oracle.admin_only_retirement(calls, heads)
        self.assertEqual(error.exception.rule, 'admin-only-read-denied')

    def test_original_name_read_filters_method_path_and_move_interval(self):
        values = []
        for serial, role, method, path, start in ((1, 'R', 'GET', '/name', 15),
                (2, 'R', 'PUT', '/name', 16), (3, 'R', 'GET', '/head', 17),
                (4, 'R', 'GET', '/name', 21), (1, 'C', 'GET', '/name', 14),
                (5, 'R', 'GET', '/name', 9)):
            values.append({'request': {'role': role, 'serial': serial, 'method': method,
                                      'path': path, 'monotonic_ns': start},
                           'backend': {'status': 200, 'monotonic_ns': start + 1}, 'delivered': True})
        index = evidence.ObservationIndex(sorted(values, key=lambda row: evidence.moment(row['request'])))
        found = oracle.name_reads_before_move(index,
            {'role': 'R', 'request': {'monotonic_ns': 10}}, {'request': {'path': '/name', 'monotonic_ns': 20}})
        self.assertEqual(found, values[:1])
        self.assertIs(found[0], values[0])

    def test_original_head_candidate_requires_same_call_exact_get(self):
        call = {'role': 'B', 'request': {'monotonic_ns': 20}}
        publication = {'request': {'role': 'B', 'path': '/head', 'monotonic_ns': 40,
                                   'headers': {'if-match': '"original"'}}}
        observation = {'request': {'role': 'B', 'serial': 1, 'path': '/head', 'method': 'GET', 'monotonic_ns': 21},
            'backend': {'monotonic_ns': 22, 'headers': {'etag': '"original"'}}, 'delivered': True,
            'read_head': {'head': {'identity': 'exact-original'}}, 'group': {'s3_delivery_finished': {'monotonic_ns': 23}}}
        values = evidence.ObservationIndex([observation])
        self.assertIs(evidence.candidate_basis(publication, call, values), observation['read_head'])
        observation['request']['monotonic_ns'] = 19
        with self.assertRaises(model.Rejected) as error:
            evidence.candidate_basis(publication, call, values)
        self.assertEqual(error.exception.rule, 'fresh-original-head-candidate')

    def test_observation_indexes_preserve_exact_rows_and_interval_edges(self):
        original = []
        for number, role, start, finish in ((1, 'B', 10, 11), (1, 'C', 12, 13),
                                            (2, 'B', 14, 30), (3, 'B', 15, None), (4, 'B', 20, 21)):
            original.append({'request': {'role': role, 'serial': number, 'path': '/a' if role == 'B' else '/b',
                                        'method': 'GET', 'monotonic_ns': start},
                             'backend': None if finish is None else {'monotonic_ns': finish}})
        index = evidence.ObservationIndex(original)
        call = {'role': 'B', 'request': {'monotonic_ns': 10}}
        for cutoff in (None, 10, 15, 20, 21, 22, 31):
            expected = [row for row in original if evidence.within(call, row, cutoff)]
            self.assertEqual(index.for_call(call, cutoff), expected)
            for actual in index.for_call(call, cutoff):
                self.assertTrue(any(actual is row for row in original))
        self.assertEqual(index.at_path('/a'), [row for row in original if row['request']['path'] == '/a'])
        self.assertIs(index.identities[('C', 1)], original[1])
        self.assertEqual(index.method('DELETE'), ())

    def test_closed_s3_serial_denominator(self):
        groups = {('B', number): {'s3_request': {'method': 'GET', 'path': '/key'}} for number in (1, 2)}
        evidence.exchange_integrity(groups, {'B': 2, 'O': 0})
        del groups[('B', 2)]
        with self.assertRaises(model.Rejected) as error:
            evidence.exchange_integrity(groups, {'B': 2, 'O': 0})
        self.assertEqual(error.exception.rule, 's3-closed-denominator')

    def test_each_stage_keeps_original_method_and_path(self):
        group = {('B', 1): {'s3_request': {'method': 'DELETE', 'path': '/a'},
                            's3_backend_response': {'method': 'DELETE', 'path': '/b'}}}
        with self.assertRaises(model.Rejected) as error:
            evidence.exchange_integrity(group, {'B': 1})
        self.assertEqual(error.exception.rule, 's3-original-method-path')

    def test_only_typed_no_such_key_is_absence(self):
        for code in ('NoSuchBucket', 'AccessDenied', 'Unknown'):
            self.assertFalse(oracle.no_such_key({'backend': {'status': 404}, 'bytes': f'<Error><Code>{code}</Code></Error>'.encode()}))
        self.assertTrue(oracle.no_such_key({'backend': {'status': 404}, 'bytes': b'<Error><Code>NoSuchKey</Code></Error>'}))
        self.assertFalse(oracle.no_such_key({'backend': {'status': 404}, 'bytes': b'broken'}))

    def test_raw_integrity_cannot_follow_a_different_file(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name); (directory / 'raw').mkdir()
            record = controls.put_raw(directory, b'original')
            self.assertEqual(evidence.raw(directory, record), b'original')
            bad = {**record, 'file': '../escaped'}
            with self.assertRaises(model.Rejected) as error:
                evidence.raw(directory, bad)
            self.assertEqual(error.exception.rule, 'raw-safe-path')

    def test_control_mutation_breaks_hardlinks(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name); original = directory / 'original'; changed = directory / 'changed'
            original.write_bytes(b'original'); os.link(original, changed)
            controls.replace_file(changed, b'counterfactual')
            self.assertEqual(original.read_bytes(), b'original')
            self.assertEqual(changed.read_bytes(), b'counterfactual')

    def test_all_control_cases_have_unique_named_boundaries(self):
        cases = controls.cases()
        self.assertEqual(len(cases), 25)
        self.assertEqual(len({name for name, _, _ in cases}), 25)
        self.assertTrue(all(boundary and callable(change) for _, boundary, change in cases))

    def test_real_sdk_prepares_all_original_sql_without_http(self):
        node = shutil.which('node')
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name); (directory / 'raw').mkdir()
            config = directory / 'config.json'
            config.write_bytes(encoded({'source_root': str(io.ROOT), 'endpoint': 'http://127.0.0.1:1',
                'scopes': spec.SCOPES, 'tokens': {'11': 'a' * 64, '12': 'b' * 64}}))
            command = {'id': 'prepare-test', 'operation': 'prepare', 'scope_name': 'late', 'specs': spec.inputs()}
            result = subprocess.run([node, str(io.HERE / 'client.mjs'), str(config), str(directory), 'A'],
                input=encoded(command) + b'\n', capture_output=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            answers = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(answers, [{'ready': True}, {'id': 'prepare-test', 'ok': True, 'value': {'prepared': 23}}])
            saved = json.loads((directory / 'intents.json').read_bytes())
            for original in spec.inputs():
                value = json.loads(saved[original['name']]['serialized'])
                self.assertEqual(set(value), {'scope', 'request', 'statements'})
                self.assertEqual(value['scope'], spec.SCOPES[original['scope_name']])
                self.assertEqual(value['statements'], original['statements'])
                self.assertEqual(value['request'], {'epoch': original['epoch'], 'id': original['request_id'],
                    'principal': '11', 'fingerprint': model.wire.fingerprint(original['statements'])})
            self.assertFalse([row for row in evidence.rows(directory / 'sdk-A.jsonl') if row['event'] == 'http_request'])
            catalogue = {'version': 1, 'deployment': '1', 'tenant': '7', 'principal': '11',
                         'action': {'operation': 'named_storage_status', 'creation': spec.creation('before')}}
            (directory / 'named-intents.jsonl').write_bytes(encoded({'name': 'catalogue-test',
                'principal': '11', 'serialized': json.dumps(catalogue)}) + b'\n')
            inputs = {'specs': spec.inputs(), 'scopes': spec.SCOPES,
                      'named': {name: spec.creation(name) for name in spec.NAMED}}
            specifications, decoded, named = evidence.original_inputs(directory, inputs)
            self.assertEqual(set(specifications), set(decoded))
            self.assertEqual(len(decoded), 23)
            self.assertEqual(set(named), {'catalogue-test'})
            extra = json.loads(saved['late-1']['serialized']); extra['version'] = 1
            saved['late-1']['serialized'] = json.dumps(extra)
            (directory / 'intents.json').write_bytes(encoded(saved))
            with self.assertRaises(model.Rejected) as error:
                evidence.original_inputs(directory, inputs)
            self.assertEqual(error.exception.rule, 'original-sql-fingerprint')

    def test_real_signed_operator_uses_nested_response_body_and_original_etag(self):
        for scope_name in ('stale', 'bad_sweep'):
            with self.subTest(scope=scope_name), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                value = fixture_head(True) if scope_name == 'stale' else with_checkpoint()
                value['scope'] = {key: int(number) for key, number in spec.SCOPES[scope_name].items()}
                if scope_name == 'stale':
                    value['head_serial'] = 10
                else:
                    entry = value['storage']['sweep']['entries'][0]
                    entry['key'] = model.prefix(value['scope'], 1).removeprefix('/scap-test/') + entry['hash']
                state = {'bytes': encoded(value), 'etag': '"initial"', 'requests': [], 'errors': []}
                access, secret = 'operator-test-access', 'operator-test-secret'

                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_args):
                        pass

                    def do_GET(self):
                        self.handle_request()

                    def do_PUT(self):
                        self.handle_request()

                    def handle_request(self):
                        try:
                            payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                            assert io.signing.verify_signature(self.command, self.path, dict(self.headers.items()), payload, access, secret)
                            assert self.path == spec.head_path(scope_name)
                            state['requests'].append((self.command, self.headers.get('If-Match'), payload))
                            if self.command == 'PUT':
                                assert self.headers.get('If-Match') == state['etag']
                                state['bytes'], state['etag'] = payload, '"changed"'
                            body = state['bytes'] if self.command == 'GET' else b''
                            self.send_response(200); self.send_header('ETag', state['etag'])
                            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
                        except BaseException as error:
                            state['errors'].append(repr(error))
                            self.send_error(500)

                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    suite = Harness.__new__(Harness)
                    suite.trace = io.Trace(directory)
                    suite.backend = SimpleNamespace(access=access, secret=secret)
                    suite.proxies = {'O': SimpleNamespace(server=server)}
                    mutation = {'terminal_serial': 5} if scope_name == 'stale' else {'sweep_serial': 'terminal_serial'}
                    suite.corrupt_only(scope_name, 'owned-loopback-boundary', mutation)
                    self.assertEqual(state['errors'], [])
                    self.assertEqual([row[0] for row in state['requests']], ['GET', 'PUT', 'GET'])
                    self.assertEqual(state['requests'][1][1], '"initial"')
                    result = json.loads(state['bytes'])
                    self.assertEqual(result['storage']['terminal']['serial'] if scope_name == 'stale' else result['storage']['sweep']['serial'],
                                     5 if scope_name == 'stale' else 6)
                finally:
                    server.shutdown(); server.server_close(); thread.join(5)
                    self.assertFalse(thread.is_alive())

    def test_real_sdk_prepares_and_restores_all_catalogue_action_shapes(self):
        actions = []
        for name in spec.NAMED:
            creation = spec.creation(name)
            actions.extend([
                {'operation': 'prepare_create', 'name': creation['name'], 'create_operation': creation['operation'],
                 'expected_name_revision': creation['expected_name_revision'],
                 'options': {'quota': {'mode': 'limited', 'max_bytes': '67108864'}}},
                {'operation': 'resume_create', 'creation': creation},
                {'operation': 'named_storage_status', 'creation': creation},
                {'operation': 'retire_named_storage', 'creation': creation, 'expected_head_serial': '20'},
                {'operation': 'abort_create', 'creation': creation, 'control_operation': '10001',
                 'expected_name_revision': '1', 'nonce': '20001'},
                {'operation': 'delete_name', 'creation': creation, 'control_operation': '10002',
                 'expected_name_revision': '2', 'expected_head_revision': '10', 'nonce': '20002'},
            ])
        program = r'''
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const { CatalogueClient } = await import(pathToFileURL(process.argv[1] + '/sdk/node/src/client.js'));
const client = new CatalogueClient({endpoint:'http://127.0.0.1:1/v1/catalogue',token:'a'.repeat(64),
  allowInsecureHttp:true,deployment:'1',tenant:'7',principal:'11',fetch:()=>{throw new Error('unexpected HTTP')}});
const actions = JSON.parse(readFileSync(0,'utf8'));
const restored = actions.map((action) => {
  const prepared = client.prepareIntent(action), saved = client.saveIntent(prepared);
  return JSON.parse(client.saveIntent(client.restoreIntent(saved)));
});
process.stdout.write(JSON.stringify(restored));
'''
        result = subprocess.run([shutil.which('node'), '--input-type=module', '-e', program, str(io.ROOT)],
            input=encoded(actions), capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        values = json.loads(result.stdout)
        self.assertEqual(len(values), 48)
        for value, action in zip(values, actions):
            self.assertEqual(value, {'version': 1, 'deployment': '1', 'tenant': '7', 'principal': '11', 'action': action})


if __name__ == '__main__':
    unittest.main()
