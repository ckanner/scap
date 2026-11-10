"""Observer/input/oracle boundaries, never a simulated product throughput PASS."""
import array
import base64
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oracle
import resources
import spec
import support
import controls


class ContractTests(unittest.TestCase):
    def test_actual_public_sdk_prepares_all_185_originals_without_http(self):
        selected = [c for c in spec.calls() if c['operation'] == 'execute']
        for item in selected:
            item['statements'] = spec.statements(item, {str(row): {'bytes': item['blob_bytes']} for row in item.get('rows', [])})
        script = """
          import assert from 'node:assert/strict';
          import { readFileSync } from 'node:fs';
          import { Client } from './sdk/node/src/client.js';
          import { statements } from './experiments/object-load/input.mjs';
          const value = JSON.parse(readFileSync(0, 'utf8'));
          const observed = [];
          for (const item of value.calls) {
            const scope = value.scopes[item.scope];
            const client = new Client({ endpoint: 'http://127.0.0.1:1/v1', token: 'a'.repeat(32), scope,
              principal: scope.tenant === '7' ? '11' : '22', fetch() { throw new Error('unit sent HTTP'); } });
            const input = statements(item, descriptor => Buffer.alloc(descriptor.bytes, 0x6b));
            const prepared = client.prepare(input, { epoch: '1', id: item.request_id });
            const saved = client.save(prepared);
            assert.equal(client.save(client.restore(saved)), saved);
            assert(Buffer.byteLength(JSON.stringify({version: 1, ...prepared, operation: 'execute'})) <= value.maxBody);
            observed.push({id: item.id, request: prepared.request});
          }
          console.log(JSON.stringify({originals: observed, httpPosts: 0}));
        """
        result = subprocess.run(['node', '--input-type=module', '-e', script], input=json.dumps({
            'calls': selected, 'scopes': spec.SCOPES, 'maxBody': spec.ADMISSION['max_body_bytes']}),
            text=True, capture_output=True, cwd=HERE.parents[1], timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['httpPosts'], 0)
        self.assertEqual(len(observed['originals']), 185)
        for item, actual in zip(selected, observed['originals']):
            independent = [{'sql': statement['sql'], 'params': [
                {'type': 'integer', 'value': v['integer']} if 'integer' in v else
                {'type': 'blob', 'base64': base64.b64encode(b'k' * v['blob']['bytes']).decode()}
                for v in statement['params']]} for statement in item['statements']]
            self.assertEqual(actual, {'id': item['id'], 'request': {'epoch': '1', 'id': item['request_id'],
                'principal': '11' if spec.SCOPES[item['scope']]['tenant'] == '7' else '22',
                'fingerprint': oracle.wire.fingerprint(independent)}})

    def test_fixed_output_profile_can_hold_the_durable_maximum_result(self):
        # The fixture must satisfy the public profile's mandatory reservation,
        # even though this workload's ordinary replies are much smaller.
        maximum_result = 64 * 1024 * 1024
        minimum = ((maximum_result + 2) // 3 * 4) * 2 + 711 + 65536
        self.assertEqual(minimum, 179023223)
        self.assertEqual(spec.OUTPUT['bytes_per_tenant'], 192 * 1024 * 1024)
        for total, reserved in (('bytes', 'control_bytes'), ('bytes_per_tenant', 'control_bytes_per_tenant')):
            self.assertGreaterEqual(spec.OUTPUT[total] - spec.OUTPUT[reserved], minimum)

    def test_exact_workload_denominators_and_unique_originals(self):
        calls = spec.calls()
        self.assertEqual(len(calls), 871)
        self.assertEqual(len({c['id'] for c in calls}), 871)
        self.assertEqual(sum(c['operation'] == 'execute' for c in calls), 185)
        self.assertEqual(sum(c['phase'] in spec.MEASURED for c in calls), 288)
        identities = [(c['scope'], c['request_id']) for c in calls if c['operation'] == 'execute']
        self.assertEqual(len(identities), len(set(identities)))
        for phase, (count, cap) in spec.MEASURED.items():
            selected = [c for c in calls if c['phase'] == phase]
            self.assertEqual(len(selected), count)
            if phase.endswith('multi'):
                for lane in range(cap):
                    self.assertEqual({c['scope'] for c in selected[lane::cap]}, {'m' + str(lane)})
        self.assertEqual(sum(len(c.get('rows', [])) * c.get('blob_bytes', 0)
                             for c in calls if c['scope'] == 'cold'), 33554432)

    def test_nearest_rank_includes_all_slow_samples(self):
        value = oracle.percentiles(list(range(1, 65)))
        self.assertEqual(value, {'samples': 64, 'p50': 32, 'p95': 61, 'p99': 64, 'maximum': 64})
        for bad in ([], [-1], [float('nan')]):
            with self.assertRaisesRegex(oracle.Rejected, 'latency-values'):
                oracle.percentiles(bad)
        self.assertEqual(oracle.concurrent([(1, 4), (2, 3), (4, 6)]), 2)

    def test_raw_digest_and_paths_are_not_summary_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); store = support.RawStore(root)
            description = store.save(b'original')
            self.assertEqual(oracle.raw(root, description), b'original')
            self.assertEqual(store.save(b'original'), description)
            (root / description['file']).write_bytes(b'modified')
            with self.assertRaisesRegex(oracle.Rejected, 'raw-integrity'):
                oracle.raw(root, description)
            with self.assertRaisesRegex(oracle.Rejected, 'raw-path'):
                oracle.raw(root, dict(description, file='../secret'))

    def test_ledger_limit_precedes_unbounded_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'log'; path.write_bytes(b'x' * (1024 * 1024 + 1))
            with self.assertRaisesRegex(oracle.Rejected, 'ledger-framing'):
                oracle.rows(path)

    def test_shared_raw_budget_counts_all_writers_and_never_refunds_a_duplicate(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(spec.BOUNDS, raw_bytes=7):
            root = Path(temporary); first = support.RawStore(root); second = support.RawStore(root)
            first.save(b'1234'); second.save(b'1234'); second.save(b'567')
            self.assertEqual((root / 'raw-budget').read_text(), '7\n')
            with self.assertRaisesRegex(ValueError, 'budget exhausted'):
                first.save(b'x')
            self.assertFalse((root / 'raw-lock').exists())
            self.assertEqual(sum(p.stat().st_size for p in (root / 'raw').iterdir()), 7)

    def test_trace_budget_fails_without_silent_truncation(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(spec.BOUNDS, trace_rows=1):
            trace = support.Trace(Path(temporary) / 'events')
            trace.emit('first')
            with self.assertRaisesRegex(ValueError, 'trace evidence budget'):
                trace.emit('second')
            trace.close()
            self.assertEqual([r['event'] for r in oracle.rows(trace.path)], ['first'])

    def test_error_categories_keep_committed_deadline_and_transport_distinct(self):
        def row(name, code, outcome=None):
            return {'ok': False, 'error': {'name': name, 'code': code, 'outcome': outcome}}
        self.assertEqual(oracle.outcome({'ok': True}), 'success')
        self.assertEqual(oracle.outcome(row('RemoteError', 'RECOVERY_BUSY', 'unresolved')), 'rejected')
        self.assertEqual(oracle.outcome(row('UnknownError', 'UNKNOWN', 'unknown')), 'unknown')
        self.assertEqual(oracle.outcome(row('RemoteError', 'UNAVAILABLE', 'unresolved')), 'unknown')
        self.assertEqual(oracle.outcome(row('CommittedResultError', 'DEADLINE', 'committed')), 'committed_unavailable')
        self.assertEqual(oracle.outcome(row('ClientError', 'TRANSPORT')), 'transport_error')

    def test_later_lookup_ack_still_requires_earlier_original_publication(self):
        calls = {
            'original': {'item': {}, 'value': {'ok': False, 'error': {'code': 'UNKNOWN'}},
                         'terminal': {'monotonic_ns': 10}},
            'lookup': {'item': {'original': 'original'}, 'value': {'ok': True, 'value': {'state': 'committed'}},
                       'terminal': {'monotonic_ns': 30}},
            'cancel': {'item': {'original': 'original'},
                       'value': {'ok': False, 'error': {'code': 'COMMITTED_BUT_UNAVAILABLE', 'receipt': {}}},
                       'terminal': {'monotonic_ns': 40}}}
        oracle.publication_before_acks(calls, 'original', 20)
        for timestamp in (30, 35, 40):
            with self.assertRaisesRegex(oracle.Rejected, 'head-before-every-committed-ack'):
                oracle.publication_before_acks(calls, 'original', timestamp)

    def test_immutable_frame_requires_scope_length_and_actual_object_hash(self):
        scope = {k: int(v) for k, v in spec.SCOPES['cold'].items()}
        metadata = support.encoded({'format': 2, 'scope': scope,
                                    'payload': {'kind': 'chunk', 'value': {'first_page': 1, 'bytes': []}}})
        body = b'SCAPOBJ2' + struct.pack('<IQ', len(metadata), 4096) + metadata + b'x' * 4096
        path = '/objects/' + oracle.digest(body)
        self.assertEqual(oracle.frame(body, path, scope)[2], b'x' * 4096)
        with self.assertRaisesRegex(oracle.Rejected, 'immutable-frame'):
            oracle.frame(body[:-1] + b'y', path, scope)
        truncated = body[:-1]
        with self.assertRaisesRegex(oracle.Rejected, 'immutable-frame-length'):
            oracle.frame(truncated, '/objects/' + oracle.digest(truncated), scope)
        with self.assertRaisesRegex(oracle.Rejected, 'immutable-scope'):
            oracle.frame(body, path, dict(scope, tenant=999))

    def test_proc_parser_does_not_hide_missing_or_wrong_units(self):
        valid = 'Pid:\t12\nThreads:\t3\nVmRSS:\t11 kB\nVmHWM:\t20 kB\n'
        self.assertEqual(resources.fields(valid), {'Pid': 12, 'Threads': 3, 'VmRSS': 11264, 'VmHWM': 20480})
        for bad in (valid.replace('kB', 'B'), valid.replace('Threads:\t3\n', ''), valid + 'Pid:\t12\n'):
            with self.assertRaises(ValueError):
                resources.fields(bad)
        raw = '12 (name with spaces) ' + ' '.join(['S'] + ['0'] * 18 + ['123'])
        self.assertEqual(resources.stat_identity(raw), {'proc_pid': 12, 'start_ticks': 123})
        self.assertEqual(oracle.process_stat(raw), (12, 123))
        for bad in ('bad', '12 (name) S 0'):
            with self.assertRaises((ValueError, oracle.Rejected)):
                resources.stat_identity(bad)

    def test_proc_directory_handoff_binds_real_owned_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); events = []
            try:
                process, proc, identity, proof = resources.spawn_owned(
                    [str(Path(sys.executable).resolve()), '-c', 'import time; time.sleep(5)'],
                    dict(os.environ), path, path / 'process.log', lambda event, **fields: events.append((event, fields)))
            except BaseException as error:
                self.fail({'handoff_error': repr(error), 'events': events,
                           'child_stderr': (path / 'process.log').read_text()})
            try:
                self.assertEqual(resources.stat_identity(resources.read_at(proc, 'stat')),
                                 {k: identity[k] for k in ('proc_pid', 'start_ticks')})
                self.assertEqual(proof['source'], 'owned_pre_exec_proc_self_fd')
                until = time.monotonic() + 2
                while time.monotonic() < until:
                    actual = resources.executable(proc)
                    if actual['path'] == str(Path(sys.executable).resolve()): break
                    time.sleep(.01)
                self.assertEqual(actual['sha256'], hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
                self.assertGreater(resources.fields(resources.read_at(proc, 'status'))['VmRSS'], 0)
                self.assertTrue(resources.names_at(proc, 'fd'))
                self.assertTrue(resources.names_at(proc, 'task'))
            finally:
                os.close(proc)
                os.kill(process.pid, signal.SIGTERM)
                waited, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
            self.assertEqual(waited, process.pid)
            self.assertGreater(usage.ru_maxrss, 0)

    def test_handoff_rejects_wrong_nonce_and_closes_received_fd(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        proc = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
        try:
            child.sendmsg([b'{"nonce":"wrong","source":"owned_pre_exec_proc_self_fd"}'],
                          [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [proc]))])
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                resources.receive_proof(parent, 'expected')
        finally:
            os.close(proc); parent.close(); child.close()

    def test_signal_does_not_poll_or_reap_the_owned_child(self):
        child = SimpleNamespace(pid=12, returncode=None)
        with patch.object(resources.os, 'kill') as kill:
            self.assertTrue(resources.signal_owned(child, signal.SIGINT))
            kill.assert_called_once_with(12, signal.SIGINT)
        with patch.object(resources.os, 'kill', side_effect=ProcessLookupError):
            self.assertFalse(resources.signal_owned(child, signal.SIGINT))
            self.assertIsNone(child.returncode)
        child.returncode = 0
        with patch.object(resources.os, 'kill') as kill:
            self.assertFalse(resources.signal_owned(child, signal.SIGINT))
            kill.assert_not_called()

    def test_spawn_trace_failure_reaps_child_before_losing_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); events = []
            def emit(event, **fields):
                if event == 'service_spawned':
                    raise ValueError('injected trace failure')
                events.append((event, fields))
            with self.assertRaisesRegex(ValueError, 'injected trace failure'):
                resources.spawn_owned([str(Path(sys.executable).resolve()), '-c', 'import time; time.sleep(5)'],
                    dict(os.environ), path, path / 'process.log', emit)
            self.assertEqual(len(events), 1)
            name, value = events[0]
            self.assertEqual(name, 'service_launch_failed')
            self.assertEqual(value['waited_pid'], value['identity']['pid'])
            self.assertEqual(value['status'], -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.wait4(value['waited_pid'], os.WNOHANG)

    def test_sample_completion_covers_actual_disk_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); proc = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
            identity = resources.stat_identity(resources.read_at(proc, 'stat'))
            sampler = resources.Sampler(proc, identity, root, root, root / 'samples', lambda: 'test')
            original = resources.disk_tree
            def delayed(path):
                time.sleep(.01)
                return original(path)
            try:
                with patch.object(resources, 'disk_tree', side_effect=delayed):
                    value = sampler.sample()
                self.assertGreaterEqual(value['completed_ns'] - value['monotonic_ns'], 20000000)
                self.assertEqual(value['identity'], identity)
                self.assertGreater(value['metrics']['VmRSS'], 0)
            finally:
                os.close(proc)

    def test_disk_observer_counts_owned_files_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'data').write_bytes(b'a' * 4096)
            measured = resources.disk_tree(root)
            self.assertEqual(measured['logical_bytes'], 4096)
            self.assertEqual(measured['files'], 1)
            (root / 'escape').symlink_to('/tmp')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                resources.disk_tree(root)

    def test_real_proxy_gate_records_unmodified_bytes_and_explicit_release(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                received.append((self.path, self.headers.get('Authorization')))
                self.send_response(200); self.send_header('Content-Length', '7')
                self.send_header('ETag', '"original"'); self.end_headers(); self.wfile.write(b'payload')
        backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=backend.serve_forever); thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); proxy = support.Proxy(backend.server_port, root, support.RawStore(root))
                auth = ('AWS4-HMAC-SHA256 Credential=unit-access/20261110/us-east-1/s3/aws4_request, '
                        'SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=' + '0' * 64)
                headers = {'Authorization': auth, 'X-Amz-Date': '20261110T000000Z',
                           'X-Amz-Content-Sha256': hashlib.sha256(b'').hexdigest()}
                observed, errors = [], []
                def fetch():
                    client = http.client.HTTPConnection('127.0.0.1', proxy.server.server_port, timeout=3)
                    try:
                        client.request('GET', '/original', headers=headers)
                        response = client.getresponse(); observed.append((response.status, response.read()))
                    except BaseException as error:
                        errors.append(error)
                    finally: client.close()
                proxy.arm('/original'); request = threading.Thread(target=fetch); request.start()
                try:
                    self.assertTrue(proxy.arrived.wait(2)); self.assertEqual(received, [])
                    proxy.release_gate(); request.join(4)
                    self.assertFalse(request.is_alive()); self.assertEqual(errors, [])
                    self.assertEqual(observed, [(200, b'payload')]); self.assertEqual(received, [('/original', auth)])
                finally:
                    proxy.close(); request.join(4)
                events = oracle.rows(root / 's3.jsonl')
                self.assertEqual([r['event'] for r in events], ['gate_armed', 'request', 'gate_arrived',
                    'gate_released', 'forwarded', 'response', 'delivered'])
                response = next(r for r in events if r['event'] == 'response')
                self.assertEqual(oracle.raw(root, response['response']), b'payload')
                self.assertNotIn('unit-access', json.dumps(events))
        finally:
            backend.shutdown(); backend.server_close(); thread.join(3)

    def test_negative_control_atomic_replacement_does_not_mutate_original_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            original = b'{"tools":{"scapd":{"sha256":"original"}}}\n'
            (source / 'inputs.json').write_bytes(original)
            target = root / 'target'; shutil.copytree(source, target, copy_function=os.link)
            controls.mutate(target, 'wrong_binary')
            self.assertEqual((source / 'inputs.json').read_bytes(), original)
            self.assertNotEqual((target / 'inputs.json').read_bytes(), original)
        self.assertEqual(len(controls.CASES), 14)

    def test_oracle_imports_no_runner_sdk_or_product(self):
        import ast
        tree = ast.parse((HERE / 'oracle.py').read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        self.assertFalse({'run', 'support', 'resources'}.intersection(imports))
        self.assertNotIn('sdk/node', (HERE / 'oracle.py').read_text())


if __name__ == '__main__':
    unittest.main()
