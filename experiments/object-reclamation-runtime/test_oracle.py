"""Deterministic observer/model boundaries, separate from actual acceptance."""
from __future__ import annotations

import copy
import base64
import http.server
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import subprocess
import select
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import os
import shutil

import audit_model as model
import controls
import oracle
import support
import spec
import harness


def base():
    return {'format': 6, 'scope': model.scope(4101), 'head_serial': 1,
        'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None},
        'revision': 1, 'transition': {'revision': 1, 'nonce': 91}, 'sequence': 0,
        'owner_epoch': 1, 'owner_instance': 4001, 'active': True, 'auth_epoch': 1,
        'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True}],
        'lifecycle': 'ready', 'creation': None, 'deletion': None, 'data_root': 'a' * 64,
        'quota': {'max_bytes': 67108864}, 'retention': {'max_entries': 129, 'max_result_bytes': 268435456},
        'request_epoch': 1, 'windows': [{'epoch': 1, 'root': 'b' * 64, 'count': 0, 'result_bytes': 0}]}


def begin(value):
    result = copy.deepcopy(value)
    result['head_serial'] += 1
    result['active'] = False
    result['storage']['allocated_through'] += 1
    result['storage']['plan'] = {'serial': result['head_serial'], 'source': value['storage']['active_generation'],
        'target': result['storage']['allocated_through'], 'phase': 'copying',
        'basis': {k: copy.deepcopy(value[k]) for k in model.BASIS}}
    return result


def advance(value, **storage):
    result = copy.deepcopy(value)
    result['head_serial'] += 1
    result['storage'].update(storage)
    return result


def frame(database, kind, value, payload=b''):
    metadata = json.dumps({'format': 2, 'scope': model.scope(database),
        'payload': {'kind': kind, 'value': value}}, separators=(',', ':')).encode()
    return b'SCAPOBJ2' + struct.pack('<IQ', len(metadata), len(payload)) + metadata + payload


def graph(nonce=1):
    values = {}

    def add(kind, value, raw=b''):
        data = frame(4101, kind, value, raw)
        name = model.sha(data)
        values[model.prefix(4101, 1) + name] = data
        return name

    data_root = add('manifest', {'page_count': 0, 'root': None})
    raw = b'SCAPRES1' + struct.pack('<I', 0)
    request = {'epoch': 1, 'id': 1, 'principal': 11, 'fingerprint': 'c' * 64}
    result = add('result', {'request': request, 'sequence': 1, 'transition': {'revision': 3, 'nonce': nonce},
                          'data_root': 'd' * 64, 'bytes': []}, raw)
    root = add('index', {'kind': 'leaf', 'epoch': 1, 'entries': [
        {'request': request, 'outcome': {'state': 'committed', 'result': result}, 'result_bytes': len(raw)}]})
    authority = {'data_root': data_root, 'sequence': 1, 'revision': 3,
                 'windows': [{'epoch': 1, 'root': root, 'count': 1, 'result_bytes': len(raw)}]}
    return values, authority


class SdkInputTests(unittest.TestCase):
    def test_real_sdk_prepares_all_original_native_inputs_without_network(self):
        directory = Path(__file__).resolve().parent
        originals = spec.inputs()
        self.assertEqual(len(originals), 267)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'raw').mkdir()
            config = root / 'client.private.json'
            config.write_text(json.dumps({'source_root': str(directory.parents[1]),
                'endpoint': 'http://127.0.0.1:1', 'token': 'unit-only-' * 4, 'scopes': spec.SCOPES}))
            command = {'id': 'prepare-inputs', 'operation': 'prepare', 'specs': originals}
            process = subprocess.run([shutil.which('node') or 'node', str(directory / 'client.mjs'),
                str(config), str(root), 'A'], input=json.dumps(command) + '\n',
                text=True, capture_output=True, timeout=15)
            self.assertEqual(process.returncode, 0, process.stderr)
            output = [json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual(output, [{'ready': True}, {'id': 'prepare-inputs', 'ok': True,
                'value': {'prepared': 267}}])
            saved = json.loads((root / 'intents.json').read_text())
            self.assertEqual(set(saved), {row['name'] for row in originals})
            for row in originals:
                restored = json.loads(saved[row['name']]['serialized'])
                self.assertEqual(restored['scope'], spec.SCOPES[row['scope_name']])
                self.assertEqual(restored['statements'], row['statements'])
                self.assertEqual(restored['request'], {'epoch': row['epoch'],
                    'id': row['request_id'], 'principal': '11',
                    'fingerprint': oracle.wire.fingerprint(row['statements'])})
            events = [json.loads(line) for line in (root / 'sdk-A.jsonl').read_text().splitlines()]
            self.assertFalse(any(row['event'].startswith('http_') for row in events))


class OperatorInputTests(unittest.TestCase):
    def test_real_http_helper_nested_body_and_multipart_adapter(self):
        data = b'\x00\xffunit-only original immutable bytes\x80\x00'
        key = '/scap-test/unit/objects/' + 'a' * 64
        absent = b'<Error><Code>NoSuchKey</Code></Error>'
        calls = []
        state = {'complete': False}
        access, secret = 'unit-only-access', 'unit-only-secret'

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.dispatch()

            def do_PUT(self):
                self.dispatch()

            def do_POST(self):
                self.dispatch()

            def dispatch(self):
                payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                calls.append((self.command, self.path, payload))
                valid = support.signing.verify_signature(self.command, self.path,
                    dict(self.headers), payload, access, secret)
                if not valid:
                    self.send_error(403)
                    return
                tag = None
                if self.command == 'GET':
                    status, body = (200, data) if state['complete'] else (404, absent)
                    if state['complete']:
                        tag = '"unit-multipart"'
                elif self.command == 'POST' and self.path.endswith('?uploads'):
                    status, body = 200, b'<InitiateMultipartUploadResult><UploadId>unit-upload</UploadId></InitiateMultipartUploadResult>'
                elif self.command == 'PUT':
                    status, body, tag = 200, b'', '"unit-part"'
                else:
                    state['complete'] = True
                    status, body = 200, b'<CompleteMultipartUploadResult/>'
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                if tag is not None:
                    self.send_header('ETag', tag)
                self.end_headers()
                self.wfile.write(body)

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                suite = harness.Harness.__new__(harness.Harness)
                suite.backend = SimpleNamespace(port=server.server_port, access=access, secret=secret)
                suite.trace = support.Trace(root)
                response = suite.operator('unit-absent', 'GET', key)
                self.assertEqual(response['status'], 404)
                self.assertEqual(support.signing.body_value(response['body']), absent)
                self.assertEqual(suite.multipart_recreate(key, data), '"unit-multipart"')
                recorded = oracle.rows(root / 'events.jsonl')
                responses = [row for row in recorded if row['event'] == 'operator_response']
                self.assertEqual(len(responses), 5)
                self.assertEqual([row['status'] for row in responses], [404, 200, 200, 200, 200])
                self.assertEqual(oracle.raw(root, responses[0]['response']), absent)
                self.assertEqual(oracle.raw(root, responses[1]['response']),
                    b'<InitiateMultipartUploadResult><UploadId>unit-upload</UploadId></InitiateMultipartUploadResult>')
                self.assertEqual(oracle.raw(root, responses[2]['response']), b'')
                self.assertEqual(responses[2]['headers']['etag'], '"unit-part"')
                self.assertEqual(oracle.raw(root, responses[3]['response']), b'<CompleteMultipartUploadResult/>')
                self.assertEqual(oracle.raw(root, responses[-1]['response']), data)
                self.assertEqual(responses[-1]['headers']['etag'], '"unit-multipart"')
            self.assertEqual([method for method, _, _ in calls], ['GET', 'POST', 'PUT', 'POST', 'GET'])
            self.assertEqual(calls[2], ('PUT', key + '?partNumber=1&uploadId=unit-upload', data))
            self.assertEqual(calls[3][2], b'<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"unit-part"</ETag></Part></CompleteMultipartUpload>')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())


class ModelTests(unittest.TestCase):
    def rejected(self, rule, function, *args):
        with self.assertRaises(model.Rejected) as raised:
            function(*args)
        self.assertEqual(raised.exception.rule, rule)

    def test_full_technical_lifecycle_and_permanent_allocation(self):
        old = base()
        frozen = begin(old)
        self.assertEqual(model.advance(old, frozen), 'begin')
        self.assertEqual(model.head(json.dumps(frozen).encode(), 4101), frozen)
        sealed = advance(frozen)
        sealed['storage']['plan']['phase'] = 'sealed'
        self.assertEqual(model.advance(frozen, sealed), 'seal')
        promoted = advance(sealed, active_generation=2, plan=None)
        self.assertEqual(model.advance(sealed, promoted), 'promote')
        checkpoint = {'serial': 5, 'generation': 1, 'next_after': None, 'exhausted': True,
            'entries': [{'key': model.prefix(4101, 1).removeprefix('/scap-test/') + 'e' * 64,
                         'hash': 'e' * 64, 'etag': '"old"', 'disposition': 'pending'}]}
        prepared = advance(promoted, sweep=checkpoint)
        self.assertEqual(model.head(json.dumps(prepared).encode(), 4101), prepared)
        self.assertEqual(model.advance(promoted, prepared), 'prepare')
        progressed = advance(prepared)
        progressed['storage']['sweep']['entries'][0]['disposition'] = 'condition_mismatch'
        self.assertEqual(model.advance(prepared, progressed), 'progress')
        cleared = advance(progressed, sweep=None)
        self.assertEqual(model.advance(progressed, cleared), 'clear')
        self.assertEqual(cleared['revision'], old['revision'])

    def test_aborted_target_is_retired_above_active(self):
        frozen = begin(base())
        aborted = advance(frozen, plan=None)
        self.assertEqual(model.advance(frozen, aborted), 'abort')
        self.assertTrue(model.retired(aborted['storage'], 2))
        self.assertFalse(model.retired(aborted['storage'], 1))
        self.assertFalse(model.retired(aborted['storage'], 3))
        again = begin(aborted)
        self.assertEqual(again['storage']['plan']['target'], 3)

    def test_promotion_requires_seal(self):
        frozen = begin(base())
        promoted = advance(frozen, active_generation=2, plan=None)
        self.rejected('promote-before-seal', model.advance, frozen, promoted)

    def test_technical_head_cannot_rewrite_business(self):
        old = base()
        candidate = begin(old)
        candidate['sequence'] = 1
        self.rejected('technical-business-preservation', model.advance, old, candidate)

    def test_original_copy_basis_is_exact(self):
        old = base()
        candidate = begin(old)
        candidate['storage']['plan']['basis']['data_root'] = 'f' * 64
        self.rejected('freeze-original-basis', model.advance, old, candidate)

    def test_policy_update_survives_technical_publication(self):
        frozen = begin(base())
        policy = copy.deepcopy(frozen)
        policy['head_serial'] += 1
        policy['revision'] += 1
        policy['transition'] = {'revision': policy['revision'], 'nonce': 123}
        policy['auth_epoch'] += 1
        policy['policy'].append({'principal': 12, 'read': True, 'write': False, 'admin': False})
        self.assertEqual(model.advance(frozen, policy), 'business')
        sealed = advance(policy)
        sealed['storage']['plan']['phase'] = 'sealed'
        sealed['policy'] = copy.deepcopy(frozen['policy'])
        self.rejected('technical-business-preservation', model.advance, policy, sealed)

    def checkpoint(self):
        value = base()
        value.update(head_serial=7, active=False)
        value['storage'] = {'active_generation': 2, 'allocated_through': 2, 'plan': None,
            'sweep': {'serial': 7, 'generation': 1, 'next_after': None, 'exhausted': True,
                'entries': [{'key': model.prefix(4101, 1).removeprefix('/scap-test/') + 'e' * 64,
                             'hash': 'e' * 64, 'etag': '"old"', 'disposition': 'pending'}]}}
        return value

    def test_pending_unknown_cannot_clear(self):
        old = self.checkpoint()
        self.rejected('pending-checkpoint-cleared', model.advance, old, advance(old, sweep=None))

    def test_checkpoint_etag_cannot_refresh(self):
        old = self.checkpoint()
        new = advance(old)
        new['storage']['sweep']['entries'][0].update(etag='"new"', disposition='applied')
        self.rejected('checkpoint-etag-refreshed', model.advance, old, new)

    def test_active_generation_cannot_be_swept(self):
        value = self.checkpoint()
        value['storage']['sweep']['generation'] = 2
        self.rejected('checkpoint-retirement', model.head, json.dumps(value).encode(), 4101)

    def test_current_target_is_not_retired(self):
        value = begin(base())
        self.assertFalse(model.retired(value['storage'], 1))
        self.assertFalse(model.retired(value['storage'], 2))

    def test_no_explicit_holds_are_admitted(self):
        value = base()
        value['storage']['holds'] = []
        self.rejected('storage-shape', model.head, json.dumps(value).encode(), 4101)

    def test_bool_is_not_scope_integer(self):
        value = base()
        value['scope']['deployment'] = True
        self.rejected('scope-integer-shape', model.head, json.dumps(value).encode(), 4101)

    def test_result_receipt_root_is_not_a_copy_edge(self):
        values, authority = graph()
        result = model.Graph(values, 4101, 1).closure(authority)
        self.assertEqual(len(result['dependencies']), 3)
        self.assertEqual(len(result['results']), 1)
        self.assertNotIn(model.prefix(4101, 1) + 'd' * 64, result['dependencies'])

    def test_missing_retained_result_fails_complete_graph(self):
        values, authority = graph()
        for key in list(values):
            if model.envelope(values[key], key)[0] == 'result':
                del values[key]
        self.rejected('complete-copy-dependency', model.Graph(values, 4101, 1).closure, authority)

    def test_valid_hash_wrong_nonce_is_semantic_failure(self):
        values, authority = graph(nonce=9)
        self.rejected('original-result-transition', model.Graph(values, 4101, 1).closure, authority)

    def test_actual_bytes_hash_and_scope_are_checked(self):
        values, _ = graph()
        key, value = next(iter(values.items()))
        self.rejected('immutable-bytes-key', model.envelope, value[:-1] + bytes([value[-1] ^ 1]), key)
        wrong = frame(4102, 'manifest', {'page_count': 0, 'root': None})
        self.rejected('frame-logical-scope', model.envelope, wrong, model.prefix(4101, 1) + model.sha(wrong))

    def test_complete_window_aggregate_is_checked(self):
        values, authority = graph()
        authority['windows'][0]['count'] = 2
        self.rejected('window-complete-aggregate', model.Graph(values, 4101, 1).closure, authority)

    def test_branch_checks_real_children_not_parent_summaries(self):
        values, authority = graph()
        children = []
        for first, last in ((1, 64), (65, 129)):
            entries = [{'request': {'epoch': 1, 'id': i, 'principal': 11, 'fingerprint': 'c' * 64},
                        'outcome': {'state': 'cancelled', 'transition': {'revision': i + 2, 'nonce': i}},
                        'result_bytes': 0} for i in range(first, last + 1)]
            raw = frame(4101, 'index', {'kind': 'leaf', 'epoch': 1, 'entries': entries})
            name = model.sha(raw)
            values[model.prefix(4101, 1) + name] = raw
            children.append({'hash': name, 'summary': {'first': first, 'last': last,
                                                       'count': len(entries), 'result_bytes': 0}})
        branch = {'kind': 'branch', 'epoch': 1, 'level': 1, 'children': children}
        raw = frame(4101, 'index', branch)
        name = model.sha(raw)
        values[model.prefix(4101, 1) + name] = raw
        authority.update(revision=200, windows=[{'epoch': 1, 'root': name, 'count': 129, 'result_bytes': 0}])
        result = model.Graph(values, 4101, 1).closure(authority)
        self.assertEqual(len(result['entries']), 129)
        self.assertIn(1, result['index_levels'])
        children[0]['summary']['count'] = 65
        changed = frame(4101, 'index', branch)
        changed_hash = model.sha(changed)
        values[model.prefix(4101, 1) + changed_hash] = changed
        authority['windows'][0]['root'] = changed_hash
        self.rejected('complete-index-aggregate', model.Graph(values, 4101, 1).closure, authority)


class ObserverTests(unittest.TestCase):
    def test_owned_child_can_run_before_parent_records_its_popen_observation(self):
        # A pipe handshake forces the child to run first; no scheduling sleep
        # or service timeout change is used to reproduce the observation race.
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            trace = support.Trace(directory)
            observed, handles = [], []
            original_identity = support.network.process_identity
            def parent_observes_after_child(process):
                handles.append(process)
                self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'child did not announce its clock')
                observed.append(int(process.stdout.readline()))
                return original_identity(process)
            child = None
            try:
                with patch.object(support.network, 'process_identity', parent_observes_after_child):
                    child = support.Child([sys.executable, '-u', '-c',
                        'import sys,time; print(time.monotonic_ns(),flush=True); sys.stdin.readline()'],
                        directory, os.environ.copy(), trace, 'service-A', directory, interactive=True)
                start = json.loads((directory / 'events.jsonl').read_text().splitlines()[0])
                self.assertLess(start['spawn_requested_ns'], observed[0])
                self.assertLess(observed[0], start['identity']['spawn_monotonic_ns'])
                ready = trace.emit('service_ready', id='service-A', role='A', worker='5001')
                self.assertEqual(model.wire.owned_startup_interval(start, ready),
                    {'start': start['spawn_requested_ns'], 'ready': ready['monotonic_ns']})
            finally:
                if child is not None:
                    child.close()
                else:
                    for process in handles:
                        process.kill()
                        support.network.wait_child(process, 5)
                        process.stdin.close()
                        process.stdout.close()
            stopped = json.loads((directory / 'events.jsonl').read_text().splitlines()[-1])
            self.assertEqual(stopped['status'], 0)
            self.assertEqual(stopped['usage']['source'], 'kernel_wait4_owned_child')

    def test_atomic_shared_raw_creation_and_integrity(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            trace = support.Trace(directory)
            value = b'independent raw bytes' * 4096
            with ThreadPoolExecutor(max_workers=8) as pool:
                outputs = list(pool.map(trace.raw, [value] * 32))
            self.assertTrue(all(row == outputs[0] for row in outputs))
            self.assertEqual(oracle.raw(directory, outputs[0]), value)
            self.assertEqual(len(list((directory / 'raw').iterdir())), 1)

    def test_raw_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(model.Rejected) as raised:
                oracle.raw(Path(name), {'file': '../other', 'bytes': 0, 'sha256': model.sha(b'')})
            self.assertEqual(raised.exception.rule, 'raw-path')

    def test_only_typed_no_such_key_is_missing(self):
        for code, expected in (('NoSuchKey', True), ('NoSuchBucket', False), ('AccessDenied', False)):
            exchange = {'backend': {'status': 404}, 'bytes': f'<Error><Code>{code}</Code></Error>'.encode()}
            self.assertEqual(oracle.no_such_key(exchange), expected)
        self.assertFalse(oracle.no_such_key({'backend': None}))

    def test_whole_exchange_omission_cannot_shrink_the_s3_denominator(self):
        def group(serial):
            request = {'role': 'B', 'serial': serial, 'method': 'GET', 'path': '/bucket/key'}
            return {'s3_request': request, 's3_handler_started': request.copy()}
        oracle.exchange_integrity({('B', 1): group(1), ('B', 2): group(2)}, {'B': 2})
        with self.assertRaises(model.Rejected) as raised:
            oracle.exchange_integrity({('B', 1): group(1), ('B', 3): group(3)}, {'B': 3})
        self.assertEqual(raised.exception.rule, 'original-s3-request-denominator')

    def test_missing_final_exchange_is_detected_by_closed_listener_count(self):
        request = {'role': 'B', 'serial': 1, 'method': 'GET', 'path': '/bucket/key'}
        with self.assertRaises(model.Rejected) as raised:
            oracle.exchange_integrity({('B', 1): {'s3_request': request}}, {'B': 2})
        self.assertEqual(raised.exception.rule, 'original-s3-request-denominator')

    def test_all_stages_keep_the_original_method_and_path(self):
        request = {'role': 'B', 'serial': 1, 'method': 'DELETE', 'path': '/retired/key'}
        for field, changed in (('method', 'GET'), ('path', '/active/key')):
            with self.subTest(field=field):
                group = {'s3_request': request, 's3_backend_response': {**request, field: changed}}
                with self.assertRaises(model.Rejected) as raised:
                    oracle.exchange_integrity({('B', 1): group}, {'B': 1})
                self.assertEqual(raised.exception.rule, 's3-stage-original-method-path')

    def test_public_signed_body_hash_is_recomputed(self):
        payload = b'actual bytes'
        headers = {'content-length': str(len(payload)), 'x-amz-content-sha256': model.sha(payload)}
        oracle.payload_integrity({'headers': headers}, payload)
        oracle.payload_integrity({'headers': {**headers, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD'}}, payload)
        with self.assertRaises(model.Rejected) as raised:
            oracle.payload_integrity({'headers': {**headers, 'x-amz-content-sha256': '0' * 64}}, payload)
        self.assertEqual(raised.exception.rule, 'public-signed-payload-hash')


class ControlConstructionTests(unittest.TestCase):
    def fixture(self, root):
        trace = support.Trace(root)
        command = {'id': 'aborted-delete-unknown', 'operation': 'gc_resume', 'scope_name': 'aborted',
                   'input': {'batchSerial': '7'}}
        request = {'version': 1, 'scope': {k: str(v) for k, v in model.scope(4103).items()},
                   'operation': 'gc_resume', 'batch_serial': '7'}
        result = {'id': command['id'], 'ok': False, 'error': {'name': 'UnknownError', 'code': 'UNKNOWN',
                  'reference': {'scope': request['scope'], 'operation': 'gc_resume', 'batchSerial': '7'}}}
        original = trace.raw(controls.encoded(command))
        output = trace.raw(controls.encoded(result))
        events = [{'sequence': 1, 'monotonic_ns': 1, 'event': 'child_input', 'id': 'sdk-B', 'raw': original},
                  {'sequence': 2, 'monotonic_ns': 5, 'event': 'child_output', 'id': 'sdk-B', 'raw': output}]
        (root / 'events.jsonl').write_bytes(b''.join(controls.encoded(row) for row in events))
        ledger = [{'sequence': 1, 'monotonic_ns': '2', 'event': 'command_started', 'command': command['id'], 'input': original},
                  {'sequence': 2, 'monotonic_ns': '3', 'event': 'http_request', 'command': command['id'], 'request': trace.raw(controls.encoded(request))},
                  {'sequence': 3, 'monotonic_ns': '4', 'event': 'command_finished', 'command': command['id'], 'result': result}]
        (root / 'sdk-B.jsonl').write_bytes(b''.join(controls.encoded(row) for row in ledger))
        for role in ('A', 'R'):
            (root / ('sdk-' + role + '.jsonl')).write_bytes(controls.encoded({'sequence': 1, 'monotonic_ns': '1', 'event': 'sdk_started'}))

    def test_bad_batch_control_preserves_all_original_input_mirrors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            value = controls.Copy(root)
            value.input('aborted-delete-unknown', 'batchSerial', '99')
            role, rows = value.call('aborted-delete-unknown')
            start = oracle.one(rows, 'command_started', command='aborted-delete-unknown')
            request = oracle.one(rows, 'http_request', command='aborted-delete-unknown')
            done = oracle.one(rows, 'command_finished', command='aborted-delete-unknown')
            self.assertEqual(value.body(start, 'input')['input']['batchSerial'], '99')
            self.assertEqual(value.body(request, 'request')['batch_serial'], '99')
            self.assertEqual(done['result']['error']['reference']['batchSerial'], '99')
            child_in = oracle.one(value.events, 'child_input', id='sdk-B')
            child_out = oracle.one(value.events, 'child_output', id='sdk-B')
            self.assertEqual(value.body(child_in, 'raw'), value.body(start, 'input'))
            self.assertEqual(value.body(child_out, 'raw'), done['result'])

    def test_mutation_breaks_links_without_touching_positive_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, changed = root / 'source', root / 'changed'
            source.mkdir()
            self.fixture(source)
            before = controls.inventory(source)
            shutil.copytree(source, changed, copy_function=os.link)
            value = controls.Copy(changed)
            controls.mutate(value, 'unknown_reference_lost')
            value.save()
            self.assertEqual(before, controls.inventory(source))
            self.assertNotEqual(before, controls.inventory(changed))

    def test_fixed_business_counter_offset_ignores_identical_blob_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            value = controls.Copy(root)
            blob = b'\x01' + struct.pack('<q', 260)
            raw = b'SCAPRES1' + struct.pack('<II', 1, 3)
            raw += b''.join(struct.pack('<I', len(name)) + name for name in (b'id', b'counter', b'payload'))
            raw += struct.pack('<I', 1) + b'\x01' + struct.pack('<q', 1) + b'\x01' + struct.pack('<q', 260)
            raw += b'\x04' + struct.pack('<I', len(blob)) + blob + struct.pack('<Qq', 0, 1)
            body = {'ok': True, 'value': {'result': base64.b64encode(raw).decode()}}
            value.sdk['B'].append({'sequence': 4, 'monotonic_ns': '6', 'event': 'http_response',
                                  'command': 'cold-query-main', 'response': value.artifact(controls.encoded(body))})
            controls.mutate(value, 'business_effect_replayed')
            row = oracle.one(value.sdk['B'], 'http_response', command='cold-query-main')
            decoded = model.wire.result(model.wire.b64(value.body(row, 'response')['value']['result']))
            self.assertEqual(decoded[0]['rows'], [[1, 261, blob]])

    def test_declared_control_scope_has_exact_unique_boundaries(self):
        self.assertEqual(len(controls.CASES), 23)
        self.assertTrue(all(isinstance(v, str) and v for v in controls.CASES.values()))


if __name__ == '__main__':
    unittest.main()
