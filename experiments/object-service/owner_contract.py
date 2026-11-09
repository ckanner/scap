#!/usr/bin/env python3
"""Fixed explicit-owner SDK contracts on real daemon/native/TCP/signed S3."""
from __future__ import annotations
import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time

import build
from owner_proxy import Hub, Trace, b64, sha
from owner_spec import COMMANDS, DEADLINES, PLAN, PRINCIPALS, SCOPES, WORKERS, head_path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
module_spec = importlib.util.spec_from_file_location('owner_network_fixture', ROOT / 'experiments/object-network/run.py')
network = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(network)
FAILURES = {
    'guard_reconcile': 'TARGET_MISMATCH', 'race_c': 'CONFLICT', 'late_write': 'CONFLICT',
    'claim_lost': 'UNKNOWN', 'claim_reuse': 'INTENT_USED', 'claim_restored_reuse': 'INTENT_USED',
    'activation_lost': 'UNKNOWN', 'corrupt_reconcile': 'CORRUPT', 'acl_reconcile': 'DENIED',
    'acl_reuse': 'INTENT_USED', 'lifecycle_reconcile': 'SUPERSEDED', 'lifecycle_write': 'LIFECYCLE',
    'reject_unknown_route': 'UNROUTABLE', 'reject_auth': 'UNAUTHENTICATED', 'reject_read': 'DENIED',
    'reject_busy': 'BACKPRESSURE', 'reject_redirect': 'TRANSPORT', 'reject_authority': 'UNKNOWN',
    'deadline_write': ('ABORTED', 'DEADLINE'), 'bootstrap_reuse': 'INTENT_USED',
    'bootstrap_changed_route': 'INVALID', 'bootstrap_wrong_scope': 'INVALID',
}


def encoded(value): return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def configuration(port, worker, cache, endpoint, tokens):
    body = 65536
    admission = {'active_database_actors': 20, 'active_database_actors_per_tenant': 16,
        'actor_idle_timeout_ms': DEADLINES['actor_idle_ms'], 'control_workers': 2,
        'queued_total': 64, 'queued_per_tenant': 32, 'queued_per_database': 8, 'reserved_controls': 2,
        'data_intake': 8, 'control_intake': 4, 'recovery_intake': 2, 'max_body_bytes': body,
        'timeout_ms': DEADLINES['ordinary_ms'], 'recovery_timeout_ms': DEADLINES['recovery_ms']}
    for name, count, tenant in (('data', 8, 4), ('control', 4, 1), ('recovery', 2, 1)):
        admission[name + '_profile'] = {'version': 1, 'requests_per_tenant': tenant,
            'body_bytes': count * body, 'body_bytes_per_tenant': tenant * body}
    return {'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': WORKERS[worker],
        'cache_directory': str(cache), 'admission': admission,
        'cache': {'pages_per_actor': 65536, 'parallel_recoveries': 1},
        'execution': {'result_memory_bytes': 134217728},
        'credentials': [{'sha256': sha(tokens[role].encode()), 'deployment': '1', 'tenant': '7',
            'principal': principal, 'provision': role == 'writer'} for role, principal in PRINCIPALS.items()],
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': DEADLINES['s3_ms']}}


class Service:
    def __init__(self, suite, worker, port):
        self.suite, self.worker, self.port, self.stopped = suite, worker, port, False
        self.cache = suite.private / ('cache-' + worker); self.cache.mkdir(mode=0o700)
        self.configuration = configuration(port, worker, self.cache, suite.s3_endpoints[worker], suite.tokens)
        self.path = suite.private / ('service-' + worker + '.private.json')
        build.save_receipt(self.path, self.configuration); self.path.chmod(0o600)
        shutil.copyfile(self.path, suite.evidence / ('service-' + worker + '.json'))
        self.log = suite.evidence / ('service-' + worker + '.log')
        binary = suite.args.server.resolve(); self.binary = {'path': str(binary), 'sha256': build.digest(binary)}
        with self.log.open('wb') as output:
            self.process = subprocess.Popen([str(binary), str(self.path)], cwd=ROOT, stdout=output, stderr=output,
                env=dict(os.environ, SCAP_TEST_ACCESS=suite.backend.access, SCAP_TEST_SECRET=suite.backend.secret))
        self.identity = network.process_identity(self.process)
        suite.events.emit('service_started', worker=worker, identity=self.identity, binary=self.binary,
            configuration_sha256=build.digest(self.path), cache_directory=str(self.cache),
            backend_endpoint=f'http://127.0.0.1:{port}', configuration_file='service-' + worker + '.json')
        try:
            assert build.digest(binary) == self.binary['sha256']
            bound = time.monotonic() + DEADLINES['ready_seconds']
            while time.monotonic() < bound:
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
                try:
                    connection.request('GET', '/healthz'); response = connection.getresponse(); raw = response.read(4097)
                    if response.status == 200 and json.loads(raw) == {'status': 'alive', 'protocol': 1}:
                        suite.events.emit('service_ready', worker=worker, identity=self.identity,
                                          status=response.status, body=b64(raw), sha256=sha(raw)); return
                except (OSError, ValueError, http.client.HTTPException): pass
                finally: connection.close()
                time.sleep(.02)
            raise TimeoutError('original daemon readiness deadline')
        except BaseException:
            self.stop('startup_failure', kill=True); raise

    def stop(self, reason='cleanup', kill=False):
        if self.stopped: return
        self.suite.events.emit('service_stop_requested', worker=self.worker, identity=self.identity, reason=reason,
                               signal='SIGKILL' if kill else 'SIGINT')
        try: os.kill(self.process.pid, signal.SIGKILL if kill else signal.SIGINT)
        except ProcessLookupError: pass
        termination_error = None
        try: code, usage = network.wait_child(self.process, 10)
        except TimeoutError as error:
            termination_error = repr(error)
            self.suite.events.emit('service_forced_cleanup', worker=self.worker, identity=self.identity, error=termination_error)
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            code, usage = network.wait_child(self.process, 10)
        self.stopped = True
        self.suite.events.emit('service_stopped', worker=self.worker, identity=self.identity, reason=reason,
            wait_status=code, kernel_usage=usage, stdout_sha256=build.digest(self.log), termination_error=termination_error)
        assert termination_error is None and code == (-9 if kill else 0), (self.worker, code, termination_error)


class Node:
    def __init__(self, suite, ordinal):
        self.suite, self.ordinal, self.condition = suite, ordinal, threading.Condition()
        self.rows, self.errors, self.stopped = [], [], False
        config = {'plan': PLAN, 'node': ordinal, 'endpoints': suite.endpoints, 'tokens': suite.tokens,
                  'evidence': str(suite.evidence)}
        path = suite.private / f'node-{ordinal}.private.json'; build.save_receipt(path, config); path.chmod(0o600)
        self.stderr = suite.evidence / f'node-{ordinal}.stderr.log'
        with self.stderr.open('wb') as errors:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen([suite.tools['node']['path'], str(HERE / 'owner_probe.mjs'), str(path)],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        self.identity = network.process_identity(self.process)
        suite.events.emit('node_started', node=ordinal, identity=self.identity, binary=suite.tools['node'],
                          configuration_sha256=build.digest(path), spawn_requested_ns=spawn_requested_ns)
        self.reader = threading.Thread(target=self.read, daemon=True); self.reader.start()
        try: self.wait('hello')
        except BaseException:
            self.stop(force=True); raise

    def read(self):
        try:
            for raw in self.process.stdout:
                assert len(raw) <= 1024 * 1024
                row = json.loads(raw)
                self.suite.events.emit('node_event', node=self.ordinal, raw=b64(raw), sha256=sha(raw))
                with self.condition: self.rows.append(row); self.condition.notify_all()
        except BaseException as error:
            self.errors.append(repr(error))
            with self.condition: self.condition.notify_all()

    def wait(self, event, command=None):
        bound = time.monotonic() + DEADLINES['child_seconds']
        with self.condition:
            while True:
                assert not self.errors, self.errors
                found = [r for r in self.rows if r['event'] == event and (command is None or r.get('command') == command)]
                if found: return found[-1]
                remaining = bound - time.monotonic()
                if remaining <= 0: raise TimeoutError('original SDK observation deadline: ' + str(command))
                self.condition.wait(remaining)

    def offer(self, identifier):
        raw = encoded({'id': identifier}) + b'\n'
        self.suite.events.emit('operator_command', node=self.ordinal, id=identifier, raw=b64(raw), sha256=sha(raw))
        self.process.stdin.write(raw); self.process.stdin.flush()

    def finish(self, identifier):
        row = self.wait('command_finished', identifier)
        if identifier in FAILURES:
            expected = FAILURES[identifier]
            assert row['ok'] is False and row['error']['code'] in (expected if isinstance(expected, tuple) else (expected,)), row
        else: assert row['ok'] is True, row
        return row

    def stop(self, force=False):
        if self.stopped: return
        self.suite.events.emit('node_stop_requested', node=self.ordinal, identity=self.identity, forced=force)
        termination_error = None
        if not force:
            try:
                self.offer('shutdown'); self.wait('finished'); self.process.stdin.close()
            except BaseException as error:
                termination_error, force = repr(error), True
        if force:
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        try: code, usage = network.wait_child(self.process, 10)
        except TimeoutError as error:
            termination_error, force = repr(error), True
            self.suite.events.emit('node_forced_cleanup', node=self.ordinal, identity=self.identity, error=termination_error)
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            code, usage = network.wait_child(self.process, 10)
        self.reader.join(timeout=3); self.stopped = True
        ledger = self.suite.evidence / f'node-{self.ordinal}.jsonl'
        self.suite.events.emit('node_stopped', node=self.ordinal, identity=self.identity, wait_status=code,
            kernel_usage=usage, forced=force, termination_error=termination_error,
            stderr_sha256=build.digest(self.stderr), ledger_sha256=build.digest(ledger) if ledger.exists() else None)
        self.process.stdout.close()
        if not self.process.stdin.closed: self.process.stdin.close()
        assert termination_error is None and code == (-9 if force else 0) and not self.reader.is_alive() and not self.errors


class Suite:
    def __init__(self, args, evidence, private, tools):
        self.args, self.evidence, self.private, self.tools = args, evidence, private, tools
        self.events = Trace(evidence / 'events.jsonl')
        info = private.stat(); self.private_identity = {'path': str(private), 'device': info.st_dev, 'inode': info.st_ino}
        self.events.emit('private_created', **self.private_identity)
        self.backend = self.hub = self.node = None
        self.services, self.nodes, self.offered, self.curls = {}, [], [], []
        self.tokens = {name: secrets.token_hex(32) for name in (*PRINCIPALS, 'invalid')}
        self.reservations = {}

    def start_service(self, worker):
        self.reservations.pop(worker).close()
        self.services[worker] = Service(self, worker, self.ports[worker])

    def setup(self):
        self.backend = network.Backend(Path(self.tools['weed']['path']), self.private / 'backend')
        self.backend.start()
        self.events.emit('backend_started', processes=self.backend.identities(), binary=self.tools['weed'],
                         access_key_sha256=sha(self.backend.access.encode()))
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=3)
        try:
            connection.request('GET', '/scap-test/fixture-ready')
            response = connection.getresponse(); raw = response.read(65537)
            self.events.emit('backend_unsigned_probe', endpoint=self.backend.endpoint, method='GET',
                path='/scap-test/fixture-ready', request_body=b64(b''), authorization=None,
                status=response.status, response_body=b64(raw), response_sha256=sha(raw))
            assert response.status == 403 and len(raw) <= 65536, 'real backend must enforce request signing'
        finally: connection.close()
        self.hub = Hub(self.backend.port, self.evidence, self.events)
        self.s3_endpoints = {worker: self.hub.s3(worker) for worker in WORKERS}
        self.fixture_endpoint = self.hub.s3('fixture')
        self.ports = {}
        for worker in WORKERS:
            reserved = socket.socket(); reserved.bind(('127.0.0.1', 0))
            self.reservations[worker] = reserved; self.ports[worker] = reserved.getsockname()[1]
        self.endpoints = {worker: self.hub.http(worker, self.ports[worker]) for worker in WORKERS}
        for worker in ('a', 'b', 'c'): self.start_service(worker)
        public = {'schema': 1, 'endpoints': self.endpoints, 'workers': WORKERS,
            'credential_sha256': {role: sha(token.encode()) for role, token in self.tokens.items()},
            'backend': {'endpoint': self.backend.endpoint, 'fixture_endpoint': self.fixture_endpoint,
                        'access_key_sha256': sha(self.backend.access.encode())},
            'services': {worker: {'configuration_file': f'service-{worker}.json',
                'backend_endpoint': f'http://127.0.0.1:{self.ports[worker]}', 'worker_instance': WORKERS[worker],
                'cache_directory': str(self.private / ('cache-' + worker))} for worker in WORKERS}}
        build.save_receipt(self.evidence / 'owner-configuration.json', public)
        self.node = Node(self, 1); self.nodes.append(self.node)

    def begin(self, identifier):
        assert identifier not in self.offered
        self.offered.append(identifier); self.hub.phase_to(COMMANDS[identifier]['phase']); self.node.offer(identifier)

    def call(self, identifier):
        self.begin(identifier); return self.node.finish(identifier)

    def snapshot(self, worker, label):
        cache = self.services[worker].cache
        files = [{'path': str(p.relative_to(cache)), 'bytes': p.stat().st_size, 'sha256': build.digest(p)}
                 for p in sorted(cache.rglob('*')) if p.is_file()]
        directories = [{'path': str(p.relative_to(cache)), 'device': p.stat().st_dev, 'inode': p.stat().st_ino}
                       for p in sorted(cache.rglob('*')) if p.is_dir()]
        self.events.emit('cache_observed', worker=worker, label=label, path=str(cache), files=files, directories=directories)
        return files

    def put_fixture(self, identifier, path, payload, etag, source_read_serial=None):
        target = self.private / (identifier + '.payload'); target.write_bytes(payload)
        headers = self.evidence / (identifier + '.headers'); response = self.evidence / (identifier + '.body')
        command = [self.tools['curl']['path'], '--silent', '--show-error', '--noproxy', '*', '--max-time', '8',
            '--aws-sigv4', 'aws:amz:us-east-1:s3', '--config', '-', '--request', 'PUT',
            '--header', 'x-amz-content-sha256: ' + sha(payload), '--header', 'If-Match: ' + etag,
            '--data-binary', '@' + str(target), '--dump-header', str(headers), '--output', str(response),
            '--write-out', '%{http_code}', self.fixture_endpoint + path]
        self.events.emit('fixture_put_started', id=identifier, path=path, body=b64(payload), sha256=sha(payload),
                         if_match=etag, source_read_serial=source_read_serial)
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        identity = network.process_identity(child); self.curls.append((child, identity))
        self.events.emit('fixture_process_started', id=identifier, identity=identity, binary=self.tools['curl'])
        child.stdin.write(f'user = "{self.backend.access}:{self.backend.secret}"\n'.encode()); child.stdin.close()
        code, usage = network.wait_child(child, 10)
        stdout, stderr = child.stdout.read(), child.stderr.read(); child.stdout.close(); child.stderr.close()
        self.curls.remove((child, identity))
        (self.evidence / (identifier + '.stdout')).write_bytes(stdout); (self.evidence / (identifier + '.stderr')).write_bytes(stderr)
        raw_headers, raw = headers.read_bytes(), response.read_bytes()
        etags = [line.split(b':', 1)[1].strip().decode() for line in raw_headers.splitlines() if line.lower().startswith(b'etag:')]
        self.events.emit('fixture_process_stopped', id=identifier, identity=identity, wait_status=code, kernel_usage=usage,
            status=int(stdout), body=b64(raw), sha256=sha(raw), etag=etags[-1] if etags else None,
            headers_sha256=sha(raw_headers), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
        assert code == 0 and stdout == b'200' and not stderr and etags
        return etags[-1]

    def http_fault(self, identifier, command, operation, kind='hold', **extra):
        self.hub.arm(identifier, channel='http', worker='b' if operation != 'status' else 'a', command=command,
                     operation=operation, kind=kind, stage='before_forward' if kind == 'redirect' else 'after_response', **extra)

    def run(self):
        self.setup(); seeded = self.call('seed')['value']
        for name in ('route_prepare', 'route_reconcile', 'route_write', 'route_lookup', 'route_query'): self.call(name)
        self.snapshot('c', 'before_target_guard')
        for name in ('guard_prepare', 'guard_reconcile', 'guard_inspect'): self.call(name)
        self.snapshot('c', 'after_target_guard')
        self.call('race_prepare_b'); self.call('race_prepare_c')
        for worker, nonce in (('b', '301'), ('c', '303')):
            self.hub.arm('race_' + worker, channel='s3', worker=worker, method='PUT', path=head_path('race'),
                         nonce=nonce, kind='hold', stage='before_forward')
        self.begin('race_b'); self.hub.wait('race_b'); self.begin('race_c'); self.hub.wait('race_c')
        self.hub.release('race_b'); self.node.finish('race_b'); self.hub.release('race_c'); self.node.finish('race_c')
        self.call('race_inspect_c')
        self.call('late_prepare')
        self.hub.arm('late_put', channel='s3', worker='a', method='PUT', path=head_path('late'), nonce='2', kind='hold', stage='before_forward')
        self.begin('late_write'); self.hub.wait('late_put'); self.call('late_reconcile')
        self.hub.release('late_put'); self.node.finish('late_write')
        for name in ('late_lookup', 'late_cancel', 'late_cancelled', 'late_query'): self.call(name)
        self.call('claim_prepare'); self.http_fault('lost_claim_response', 'claim_lost', 'takeover', 'drop')
        for name in ('claim_lost', 'claim_inspect', 'claim_reuse', 'claim_restored_reuse', 'claim_activation_prepare', 'claim_activation'): self.call(name)
        self.call('activation_prepare'); self.http_fault('lost_activation_response', 'activation_lost', 'activate', 'drop')
        for name in ('activation_lost', 'activation_advance', 'activation_inspect'): self.call(name)
        self.call('corrupt_prepare')
        before = {p for p in self.services['b'].cache.iterdir() if p.is_dir()}
        self.http_fault('corrupt_claim_received', 'corrupt_reconcile', 'takeover')
        self.begin('corrupt_reconcile'); self.hub.wait('corrupt_claim_received')
        root = seeded['corrupt']['receipt']['data_root']
        path = '/scap-test/scap-object/v1/1/7/' + SCOPES['corrupt']['database'] + '/inc/1/gen/1/storage/1/objects/' + root
        original = dict(self.hub.reads[path]); assert sha(original['body']) == root
        changed = bytes([original['body'][0] ^ 128]) + original['body'][1:]
        corrupted_etag = self.put_fixture('corrupt_manifest', path, changed, original['etag'], original['request_serial'])
        self.hub.release('corrupt_claim_received'); self.node.finish('corrupt_reconcile')
        created = {p for p in self.services['b'].cache.iterdir() if p.is_dir()} - before
        assert len(created) == 1, 'failed actor cache identity not observed'
        quarantined = created.pop(); stat = quarantined.stat()
        self.events.emit('quarantined_cache_observed', worker='b', path=str(quarantined), device=stat.st_dev, inode=stat.st_ino)
        self.call('corrupt_inspect'); self.put_fixture('restore_manifest', path, original['body'], corrupted_etag, original['request_serial'])
        bound = time.monotonic() + 10
        while quarantined.exists() and time.monotonic() < bound: time.sleep(.02)
        self.events.emit('quarantined_cache_removed', worker='b', path=str(quarantined), observed_absence=not quarantined.exists())
        assert not quarantined.exists(), 'quarantined Engine cache did not expire through ordinary idle retirement'
        for name in ('corrupt_activation_prepare', 'corrupt_activation', 'corrupt_query'): self.call(name)
        self.call('acl_prepare'); self.http_fault('acl_status_received', 'acl_reconcile', 'status')
        self.begin('acl_reconcile'); self.hub.wait('acl_status_received'); self.call('acl_revoke')
        self.hub.release('acl_status_received'); self.node.finish('acl_reconcile'); self.call('acl_reuse')
        for name in ('lifecycle_prepare', 'lifecycle_change', 'lifecycle_reconcile', 'lifecycle_inspect', 'lifecycle_write'): self.call(name)
        self.call('recovery_warm'); self.call('recovery_prepare')
        self.http_fault('recovery_claim_received', 'recovery_reconcile', 'takeover')
        self.begin('recovery_reconcile'); self.hub.wait('recovery_claim_received')
        root = seeded['recovery']['receipt']['data_root']
        path = '/scap-test/scap-object/v1/1/7/' + SCOPES['recovery']['database'] + '/inc/1/gen/1/storage/1/objects/' + root
        self.hub.arm('recovery_read', channel='s3', worker='b', method='GET', path=path, kind='hold', stage='before_forward')
        self.hub.release('recovery_claim_received'); self.hub.wait('recovery_read')
        self.call('recovery_hot'); self.call('recovery_control'); self.hub.release('recovery_read'); self.node.finish('recovery_reconcile')
        for name in ('reject_unknown_route', 'reject_auth', 'reject_read'): self.call(name)
        self.hub.arm('busy_read', channel='s3', worker='a', method='GET', path=head_path('rejects'), kind='hold', stage='before_forward')
        self.begin('busy_held'); self.hub.wait('busy_read'); self.call('reject_busy'); self.hub.release('busy_read'); self.node.finish('busy_held')
        self.http_fault('redirect_status', 'reject_redirect', 'status', 'redirect')
        self.call('reject_redirect')
        self.hub.arm('authority_blackhole', channel='s3', worker='a', method='GET', path=head_path('rejects'), kind='blackhole', stage='before_forward')
        self.call('reject_authority')
        self.http_fault('deadline_status_received', 'deadline_write', 'status', discard_after_release=True)
        self.begin('deadline_write'); self.hub.wait('deadline_status_received'); self.node.finish('deadline_write'); self.hub.release('deadline_status_received')
        self.call('cold_write'); self.node.stop()
        saved = [*self.evidence.glob('intent-*.json'), *self.evidence.glob('request-*.json')]
        self.events.emit('saved_files_observed', after_node=1, files={p.name: build.digest(p) for p in sorted(saved)})
        self.services['a'].stop('old_owner_loss', kill=True)
        old_cache = self.services['a'].cache; shutil.rmtree(old_cache)
        self.events.emit('cache_removed', worker='a', path=str(old_cache), observed_absence=not old_cache.exists())
        assert not old_cache.exists()
        self.start_service('d'); self.snapshot('d', 'new_worker_empty_cache')
        self.node = Node(self, 2); self.nodes.append(self.node)
        for name, command in COMMANDS.items():
            if command.get('node') == 2: self.call(name)
        self.node.stop()
        assert self.offered == list(COMMANDS), 'offered command denominator/order changed'
        assert not self.hub.errors

    def cleanup(self):
        errors = []
        if self.hub:
            for rule in self.hub.rules.values():
                if rule.entered.is_set() and rule.fields['kind'] == 'hold' and not rule.released.is_set():
                    self.events.emit('fault_cleanup_release', id=rule.id); rule.released.set()
        for node in self.nodes:
            if not node.stopped:
                try: node.stop(force=True)
                except BaseException as error: errors.append(repr(error))
        for child, identity in self.curls:
            try:
                os.kill(child.pid, signal.SIGKILL); code, usage = network.wait_child(child, 5)
                self.events.emit('unfinished_fixture_stopped', identity=identity, wait_status=code, kernel_usage=usage)
            except BaseException as error: errors.append(repr(error))
        for service in self.services.values():
            if not service.stopped:
                try: service.stop()
                except BaseException as error: errors.append(repr(error))
        for reserved in self.reservations.values(): reserved.close()
        if self.hub:
            try: self.hub.close(); errors.extend(self.hub.errors)
            except BaseException as error: errors.append(repr(error))
        if self.backend:
            try:
                stopped = self.backend.stop(); self.events.emit('backend_stopped', processes=stopped)
                for role in ('master', 'volume', 'filer', 's3'):
                    shutil.copyfile(self.backend.directory / (role + '.private.log'), self.evidence / ('backend-' + role + '.log'))
            except BaseException as error: errors.append(repr(error))
        self.events.emit('cleanup_finished', errors=errors)
        return errors


def main(args):
    evidence = args.evidence.resolve(); assert not evidence.is_relative_to(ROOT)
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-owner-private-', dir=evidence.parent))
    summary = {'schema': 1, 'status': 'failed', 'private_directory': str(private), 'private_deleted': False,
               'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}
    suite = None
    try:
        assert not any(os.environ.get(name) for name in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE', 'NODE_OPTIONS'))
        build.capture_receipt(args.build_record, args.server, evidence)
        tools = {}
        for name, path in (('node', Path(shutil.which('node')).resolve()), ('weed', args.weed.resolve()),
                           ('curl', Path(shutil.which('curl')).resolve())):
            version = subprocess.check_output([str(path), 'version' if name == 'weed' else '--version'], text=True).strip()
            tools[name] = {'path': str(path), 'sha256': build.digest(path), 'version': version}
        assert tools['node']['version'] == 'v22.16.0' and '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101' in tools['weed']['version']
        build.save_receipt(evidence / 'owner-plan.json', PLAN); build.save_receipt(evidence / 'owner-tools.json', tools)
        suite = Suite(args, evidence, private, tools); suite.run(); summary['contract_finished'] = True
    except BaseException as error:
        summary['error'] = repr(error)
    finally:
        summary['cleanup_errors'] = suite.cleanup() if suite else []
        try: build.verify(args.build_record, args.server); summary['source_unchanged'] = True
        except BaseException as error: summary['source_unchanged'] = False; summary['source_error'] = repr(error)
        if summary.get('contract_finished') and not summary['cleanup_errors'] and summary['source_unchanged']:
            suite.events.emit('private_remove_started', **suite.private_identity)
            shutil.rmtree(private)
            summary['private_deleted'] = not private.exists()
            suite.events.emit('private_removed', **suite.private_identity, observed_absence=summary['private_deleted'])
            assert summary['private_deleted']
            summary['status'] = 'observed'
        build.save_receipt(evidence / 'owner-summary.json', summary)
    assert summary['status'] == 'observed', summary
    import owner_oracle
    try:
        result = owner_oracle.audit(evidence)
        assert not private.exists(), 'current-run cleanup check failed'
        build.save_receipt(evidence / 'owner-oracle.json', result)
    except BaseException as error:
        summary['status'], summary['audit_error'] = 'failed', repr(error)
        build.save_receipt(evidence / 'owner-summary.json', summary)
        raise
    summary['status'] = 'passed'; build.save_receipt(evidence / 'owner-summary.json', summary)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    if not __debug__: raise RuntimeError('owner acceptance requires Python assertions')
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--weed', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    main(parser.parse_args())
