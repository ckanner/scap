#!/usr/bin/env python3
"""Actual TCP/native/S3 resource contract with an explicit paused worker seam."""
from __future__ import annotations
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import build
from spec import CALLS, CHECK_SQL, LARGE_SQL, PLAN, PROFILE, SCOPES, SMALL_SQL, UNKNOWN_SQL

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SERVICE = ROOT / 'experiments/object-service'
sys.path.insert(0, str(SERVICE))
from isolation_proxy import Proxy  # noqa: E402


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


network = load('resource_network_fixture', ROOT / 'experiments/object-network/run.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


class Trace:
    def __init__(self, path):
        self.path, self.lock, self.sequence = path, threading.Lock(), 0

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {'schema': 1, 'sequence': self.sequence, 'event': event,
                   'monotonic_ns': time.monotonic_ns(), **fields}
            with self.path.open('a', encoding='utf-8') as output:
                output.write(json.dumps(row, sort_keys=True) + '\n')
                output.flush()
                os.fsync(output.fileno())
            return row


def configuration(port, cache, endpoint, tokens):
    admission = {
        'active_database_actors': 4, 'active_database_actors_per_tenant': 2,
        'actor_idle_timeout_ms': 60000, 'control_workers': 1,
        'queued_total': 16, 'queued_per_tenant': 8, 'queued_per_database': 4,
        'reserved_controls': 1, 'data_intake': 2, 'control_intake': 2, 'recovery_intake': 2,
        'max_body_bytes': PLAN['body_bytes'], 'timeout_ms': PLAN['timeout_ms'],
        'recovery_timeout_ms': PLAN['recovery_timeout_ms'],
        **{name: PROFILE for name in ('data_profile', 'control_profile', 'recovery_profile')},
    }
    credentials = [{'sha256': sha(tokens[name].encode()), 'deployment': '1', 'tenant': tenant,
                    'principal': principal, 'provision': True}
                   for name, tenant, principal in (('a', '7', '11'), ('rival', '7', '13'), ('b', '8', '22'))]
    return {'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': PLAN['worker_instance'],
            'lifecycle_diagnostics': {'version': 1, 'token_sha256': sha(secrets.token_hex(32).encode())},
            'cache_directory': str(cache), 'admission': admission,
            'cache': {'pages_per_actor': 65536, 'parallel_recoveries': 1},
            'execution': {'result_memory_bytes': 134217728}, 'credentials': credentials,
            's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
                   'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
                   'session_token_env': None, 'allow_http': True, 'timeout_ms': 10000}}


class Running:
    def __init__(self, binary, config, backend, evidence, trace):
        self.trace, self.events, self.condition = trace, [], threading.Condition()
        self.errors = []
        self.stderr = evidence / 'worker.stderr.log'
        self.binary = {'path': str(binary), 'sha256': build.digest(binary)}
        with self.stderr.open('wb') as errors:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen([str(binary), str(config)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=errors,
                env=dict(os.environ, SCAP_TEST_ACCESS=backend.access, SCAP_TEST_SECRET=backend.secret))
        self.identity = network.process_identity(self.process)
        trace.emit('worker_started', identity=self.identity, binary=self.binary,
                   spawn_requested_ns=spawn_requested_ns,
                   configuration_sha256=build.digest(config))
        assert build.digest(binary) == self.binary['sha256']
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        try:
            ready = self.wait('listening')
        except BaseException:
            self.process.kill()
            code, usage = network.wait_child(self.process, 10)
            self.reader.join(timeout=2)
            trace.emit('worker_stopped', identity=self.identity, wait_status=code, kernel_usage=usage,
                       stderr_sha256=build.digest(self.stderr), forced=True)
            raise
        self.port = int(ready['fields']['address'].rsplit(':', 1)[1])

    def read(self):
        try:
            for raw in self.process.stdout:
                assert len(raw) <= PLAN['max_worker_event_bytes']
                row = json.loads(raw)
                self.trace.emit('worker_event', raw=base64.b64encode(raw).decode(), sha256=sha(raw))
                with self.condition:
                    self.events.append(row)
                    self.condition.notify_all()
        except BaseException as error:
            self.errors.append(repr(error))
            with self.condition:
                self.condition.notify_all()

    def wait(self, event, predicate=lambda _row: True, timeout=15):
        bound = time.monotonic() + timeout
        with self.condition:
            while True:
                assert not self.errors, self.errors
                found = [row for row in self.events if row['event'] == event and predicate(row)]
                if found:
                    return found[-1]
                remaining = bound - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('worker observation: ' + event)
                self.condition.wait(remaining)

    def command(self, command, event):
        raw = encoded(command) + b'\n'
        self.trace.emit('operator_command', raw=base64.b64encode(raw).decode(), sha256=sha(raw))
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        return self.wait(event, lambda row: row['fields'].get('id') == command['id'])

    def observe_until(self, phase, available):
        # These are observation reads of the actual intake pool, not SQL
        # retries. Every offered observation has a recorded original identity.
        bound = time.monotonic() + 2
        for index in range(100):
            row = self.command({'operation': 'observe', 'id': f'{phase}-{index}'}, 'admission_observed')
            snapshot = row['fields']['lifecycle']
            lanes = {value['lane']: value for value in snapshot['lanes']}
            if (row['fields']['data_available'] == available and snapshot['valid'] is True
                    and lanes['data']['active'] == str(2 - available)
                    and all(lanes[name]['active'] == '0' for name in ('control', 'recovery', 'catalogue', 'restore'))):
                return row
            if time.monotonic() >= bound:
                break
            time.sleep(0.01)
        raise AssertionError('real transport did not reach the expected intake state: ' + phase)

    def stop(self):
        try:
            self.command({'operation': 'shutdown', 'id': 'shutdown'}, 'shutdown_requested')
            self.process.stdin.close()
            code, usage = network.wait_child(self.process, 10)
        except BaseException:
            self.process.kill()
            code, usage = network.wait_child(self.process, 10)
            self.trace.emit('worker_stopped', identity=self.identity, wait_status=code, kernel_usage=usage,
                            stderr_sha256=build.digest(self.stderr), forced=True)
            raise
        self.reader.join(timeout=2)
        self.trace.emit('worker_stopped', identity=self.identity, wait_status=code, kernel_usage=usage,
                        stderr_sha256=build.digest(self.stderr), forced=False)
        assert code == 0 and not self.reader.is_alive() and not self.errors


class Client:
    def __init__(self, worker, tokens, trace, proxy):
        self.worker, self.tokens, self.trace, self.proxy = worker, tokens, trace, proxy
        self.calls, self.pending = [], {}

    def begin(self, label, name, body, *, partial=False, slow=False):
        assert label not in self.calls
        self.calls.append(label)
        self.proxy.set_phase(label)
        admission = 'control' if body['operation'] in ('status', 'lookup', 'cancel') else (
            'recovery' if body['operation'] == 'activate' else 'data')
        raw = encoded(body)
        self.trace.emit('http_input', id=label, principal=name, admission=admission,
                        method='POST', path='/v1', credential_sha256=sha(self.tokens[name].encode()),
                        body=base64.b64encode(raw).decode(), sha256=sha(raw), partial=partial, slow=slow)
        connection = http.client.HTTPConnection('127.0.0.1', self.worker.port,
                                                timeout=PLAN['client_deadline_seconds'])
        connection.connect()
        if slow:
            connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, PLAN['socket_receive_buffer'])
            self.trace.emit('receive_buffer', id=label, configured=PLAN['socket_receive_buffer'],
                            observed=connection.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
        connection.putrequest('POST', '/v1')
        connection.putheader('Content-Type', 'application/json')
        connection.putheader('Authorization', 'Bearer ' + self.tokens[name])
        connection.putheader('X-SCAP-Admission', admission)
        connection.putheader('Content-Length', str(len(raw)))
        connection.putheader('Connection', 'close')
        sent = raw[:1] if partial else raw
        connection.endheaders(sent)
        self.trace.emit('http_body_sent', id=label, bytes=len(sent), total_bytes=len(raw), sha256=sha(sent))
        self.pending[label] = [connection, raw, None]

    def complete_body(self, label):
        connection, raw, _ = self.pending[label]
        self.proxy.set_phase(label)
        connection.send(raw[1:])
        self.trace.emit('http_body_completed', id=label, bytes=len(raw) - 1, sha256=sha(raw[1:]))

    def headers(self, label):
        connection, _, response = self.pending[label]
        assert response is None
        response = connection.getresponse()
        self.pending[label][2] = response
        self.trace.emit('http_headers', id=label, status=response.status, headers=response.getheaders())
        return response

    def finish(self, label):
        connection, _, response = self.pending[label]
        if response is None:
            response = self.headers(label)
        raw = response.read(32 * 1024 * 1024 + 1)
        assert len(raw) <= 32 * 1024 * 1024
        self.trace.emit('http_response', id=label, status=response.status,
                        body=base64.b64encode(raw).decode(), sha256=sha(raw))
        connection.close()
        del self.pending[label]
        return response.status, json.loads(raw)

    def call(self, label, name, body, expected=200):
        self.begin(label, name, body)
        status, value = self.finish(label)
        assert status == expected, (label, status, value)
        return value

    def close(self):
        for connection, _, response in self.pending.values():
            if response is not None:
                response.close()
            connection.close()
        self.pending.clear()


def action(name, operation, **fields):
    return {'version': 1, 'scope': SCOPES[name], 'operation': operation, **fields}


def query(name, sql=SMALL_SQL):
    return action(name, 'query', statements=[{'sql': sql, 'params': []}])


def intent(node, evidence, trace):
    original = encoded({'scope': SCOPES['a'], 'sql': UNKNOWN_SQL})
    argv = [str(node), str(HERE / 'prepare.mjs')]
    with (evidence / 'prepare.stderr.log').open('wb') as errors:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
    identity = network.process_identity(child)
    trace.emit('prepare_started', identity=identity, command=argv,
               binary={'path': str(node), 'sha256': build.digest(node)},
               input=base64.b64encode(original).decode(), input_sha256=sha(original))
    raw = b''
    try:
        child.stdin.write(original)
        child.stdin.close()
        bound = time.monotonic() + 10
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = bound - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    raise TimeoutError('SDK prepare output')
                piece = os.read(child.stdout.fileno(), 4097 - len(raw))
                if not piece:
                    break
                raw += piece
                assert len(raw) <= 4096, 'SDK prepare output exceeded bound'
        code, usage = network.wait_child(child, max(0.01, bound - time.monotonic()))
    except BaseException:
        child.kill()
        code, usage = network.wait_child(child, 10)
        trace.emit('prepare_stopped', identity=identity, wait_status=code, kernel_usage=usage,
                   stdout=base64.b64encode(raw).decode(), stdout_sha256=sha(raw), forced=True)
        raise
    finally:
        child.stdout.close()
    trace.emit('prepare_stopped', identity=identity, wait_status=code, kernel_usage=usage,
               stdout=base64.b64encode(raw).decode(), stdout_sha256=sha(raw), forced=False)
    assert code == 0
    result = json.loads(raw)
    build.save(evidence / 'original-intent.json', result)
    return result


def exercise(client, worker, original):
    for index, name in enumerate(('a', 'b')):
        created = client.call(name + '_create', name, action(name, 'create', nonce=str(501 + index * 10)))
        client.call(name + '_activate', name, action(name, 'activate', expected_revision=created['value']['revision'],
                                                    nonce=str(502 + index * 10)))
        client.call(name + '_warm', name, query(name))

    auth_path = '/scap-test/' + PLAN['pause_key']
    connection = http.client.HTTPConnection('127.0.0.1', client.proxy.backend_port, timeout=2)
    client.trace.emit('unsigned_backend_input', method='GET', path=auth_path, authorization_present=False)
    try:
        connection.request('GET', auth_path)
        response = connection.getresponse()
        raw = response.read(65537)
        client.trace.emit('unsigned_backend_response', status=response.status,
                          body=base64.b64encode(raw).decode(), sha256=sha(raw))
        assert response.status == 403 and len(raw) <= 65536
    finally:
        connection.close()

    client.begin('body_held', 'a', query('a'), partial=True)
    worker.observe_until('body-held', 1)
    client.call('body_same_tenant', 'rival', query('a'), 429)
    client.call('body_other_tenant', 'b', query('b'))
    client.call('body_control', 'a', action('a', 'status'))
    client.complete_body('body_held')
    assert client.finish('body_held')[0] == 200
    worker.observe_until('body-released', 2)
    client.call('body_after', 'a', query('a'))

    worker.command({'operation': 'arm', 'id': 'pause', 'key': PLAN['pause_key']}, 'pause_armed')
    client.begin('timeout_execute', 'a', action('a', 'execute', request=original['request'], statements=original['statements']))
    worker.wait('head_pause_entered')
    entered = worker.wait('worker_entered', lambda row: row['fields']['operation'] == 'execute')
    status, value = client.finish('timeout_execute')
    assert status == 503 and value['error']['code'] == 'UNKNOWN'
    worker.observe_until('after-http-timeout', 1)
    client.call('timeout_same_tenant', 'rival', query('a'), 429)
    client.call('timeout_other_tenant', 'b', query('b'))
    client.call('timeout_control', 'a', action('a', 'status'))
    worker.command({'operation': 'release', 'id': 'release'}, 'pause_released')
    worker.wait('worker_completed', lambda row: row['fields']['serial'] == entered['fields']['serial'])
    worker.observe_until('worker-released', 2)
    client.call('after_worker', 'a', query('a'))
    client.call('original_lookup', 'a', action('a', 'lookup', request=original['request']))
    client.call('original_cancel', 'a', action('a', 'cancel', request=original['request']))
    client.call('cancelled_lookup', 'a', action('a', 'lookup', request=original['request']))
    client.call('effect_check', 'a', query('a', CHECK_SQL))

    client.begin('response_held', 'a', query('a', LARGE_SQL), slow=True)
    assert client.headers('response_held').status == 200
    worker.observe_until('slow-response', 1)
    client.call('response_same_tenant', 'rival', query('a'), 429)
    client.call('response_other_tenant', 'b', query('b'))
    client.call('response_control', 'a', action('a', 'status'))
    assert client.finish('response_held')[0] == 200
    worker.observe_until('response-released', 2)
    client.call('response_after', 'a', query('a'))
    worker.observe_until('final', 2)
    assert tuple(client.calls) == CALLS


def main(args):
    evidence = args.evidence.resolve()
    assert not evidence.is_relative_to(ROOT)
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-resource-private-', dir=evidence.parent))
    trace = Trace(evidence / 'events.jsonl')
    backend = proxy = worker = client = None
    summary = {'schema': 1, 'status': 'failed', 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
               'private_directory': str(private), 'private_deleted': False}
    errors = []
    try:
        build.capture(args.build, args.worker, evidence)
        build.save(evidence / 'plan.json', PLAN)
        node = Path(shutil.which('node')).resolve()
        assert subprocess.check_output([node, '--version'], text=True).strip() == 'v22.16.0'
        original = intent(node, evidence, trace)
        backend = network.Backend(args.weed.resolve(), private / 'backend')
        backend.start()
        trace.emit('backend_started', processes=backend.identities(),
                   binary={'path': str(args.weed.resolve()), 'sha256': build.digest(args.weed)},
                   access_key_sha256=sha(backend.access.encode()))
        proxy = Proxy(backend.port, evidence)
        tokens = {name: secrets.token_hex(32) for name in ('a', 'rival', 'b')}
        cache = private / 'cache'
        cache.mkdir(mode=0o700)
        config = configuration(network.free_port(set()), cache, proxy.endpoint, tokens)
        path = private / 'worker.private.json'
        build.save(path, config)
        path.chmod(0o600)
        build.save(evidence / 'configuration.json', config)
        worker = Running(args.worker.resolve(), path, backend, evidence, trace)
        client = Client(worker, tokens, trace, proxy)
        exercise(client, worker, original)
        summary['contract_finished'] = True
    except BaseException as error:
        summary['error'] = repr(error)
    finally:
        if client:
            client.close()
        if worker:
            try:
                worker.stop()
            except BaseException as error:
                errors.append(repr(error))
        if proxy:
            try:
                proxy.close()
                errors.extend(proxy.errors)
                trace.emit('proxy_stopped', errors=proxy.errors)
            except BaseException as error:
                errors.append(repr(error))
        if backend:
            try:
                stopped = backend.stop()
                trace.emit('backend_stopped', processes=stopped)
                for role in ('master', 'volume', 'filer', 's3'):
                    shutil.copyfile(backend.directory / (role + '.private.log'), evidence / ('backend-' + role + '.log'))
            except BaseException as error:
                errors.append(repr(error))
        trace.emit('cleanup_finished', errors=errors)
        summary['cleanup_errors'] = errors
        try:
            build.verify(args.build, args.worker)
            summary['source_unchanged'] = True
        except BaseException as error:
            summary['source_unchanged'] = False
            summary['source_error'] = repr(error)
        if summary.get('contract_finished') and not errors and summary['source_unchanged']:
            shutil.rmtree(private)
            summary['private_deleted'] = not private.exists()
            summary['status'] = 'observed'
        build.save(evidence / 'summary.json', summary)
    if summary['status'] != 'observed':
        raise AssertionError(summary)
    oracle = load('resource_independent_oracle', HERE / 'oracle.py')
    try:
        checked = oracle.audit(evidence)
    except BaseException as error:
        summary['status'], summary['audit_error'] = 'failed', repr(error)
        build.save(evidence / 'summary.json', summary)
        raise
    build.save(evidence / 'oracle.json', checked)
    summary['status'] = 'passed'
    build.save(evidence / 'summary.json', summary)
    print(json.dumps(checked, indent=2, sort_keys=True))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('assertion-based contract requires Python without -O')
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--weed', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    main(parser.parse_args())
