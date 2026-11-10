#!/usr/bin/env python3
"""Observe the fixed guarded-status protocol on real daemon/native/TCP/S3."""
from __future__ import annotations
import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import tempfile
import time

from support import (Backend, BoundedTrace, COMMANDS, DEADLINES, DeadlineConnection, HERE, Node,
    ObservedHub, PLAN, ROOT, Service, b64, build, sha, tool_version)


def fixture_sources():
    return {str(p.relative_to(ROOT)): build.digest(p) for p in sorted(HERE.iterdir()) if p.is_file()}


class Suite:
    def __init__(self, args, evidence, private, tools):
        self.args, self.evidence, self.private, self.tools = args, evidence, private, tools
        self.events = BoundedTrace(evidence / 'events.jsonl')
        self.backend = self.hub = self.node = None
        self.services, self.nodes, self.reservations, self.offered = {}, [], {}, []
        self.cleanup_failures = []
        self.tokens = {name: secrets.token_hex(32) for name in (*PLAN['principals'], 'invalid')}
        self.events.emit('private_created', path=str(private), device=private.stat().st_dev,
            inode=private.stat().st_ino)

    def setup(self):
        self.backend = Backend(self.tools['weed']['path'], self.private / 'backend', self.events)
        self.backend.start()
        connection = DeadlineConnection(self.backend.port, time.monotonic() + 3)
        try:
            connection.request('GET', '/scap-test/fixture-ready')
            response = connection.getresponse()
            raw = response.read(65537)
            self.events.emit('backend_unsigned_probe', status=response.status, body=b64(raw), sha256=sha(raw))
            assert response.status == 403 and len(raw) <= 65536, 'backend must enforce SigV4'
        finally:
            connection.close()
        self.hub = ObservedHub(self.backend.port, self.evidence, self.events, self)
        self.s3_endpoints = {worker: self.hub.s3(worker) for worker in PLAN['workers']}
        self.ports = {}
        for worker in ('s', 'p'):
            reserved = socket.socket()
            reserved.bind(('127.0.0.1', 0))
            self.reservations[worker] = reserved
            self.ports[worker] = reserved.getsockname()[1]
        self.ports['q'] = self.ports['p']
        self.endpoints = {worker: self.hub.http(worker, self.ports[worker]) for worker in ('s', 'p')}
        self.endpoints['q'] = self.endpoints['p']
        for worker in ('s', 'p'):
            self.start_service(worker)
        self.snapshot('p', 'initial_probe_cache')
        public = {'schema': 1, 'scope': PLAN['scope'], 'workers': PLAN['workers'],
            'endpoints': self.endpoints, 's3_endpoints': self.s3_endpoints, 'daemon_ports': self.ports,
            'sink': self.hub.sink_url, 'backend_endpoint': self.backend.endpoint,
            'credential_sha256': {name: sha(token.encode()) for name, token in self.tokens.items()},
            'access_key_sha256': sha(self.backend.access.encode())}
        build.save_receipt(self.evidence / 'configuration.json', public)
        self.node = Node(self, 1)

    def start_service(self, worker):
        reservation = self.reservations.pop(worker, None)
        if reservation is not None:
            reservation.close()
        self.services[worker] = Service(self, worker, self.ports[worker])

    def snapshot(self, worker, label):
        cache = self.services[worker].cache
        files = [{'path': str(p.relative_to(cache)), 'bytes': p.stat().st_size,
            'sha256': build.digest(p)} for p in sorted(cache.rglob('*')) if p.is_file()]
        self.events.emit('cache_snapshot', worker=worker, label=label, path=str(cache), files=files)
        assert files == [], 'metadata probe materialized private payload files'

    def call(self, command):
        identifier = command['id']
        assert identifier not in self.offered
        self.offered.append(identifier)
        self.hub.phase_to(identifier)
        fault = next((x for x in PLAN['faults'] if x['command'] == identifier), None)
        if fault is not None:
            fields = {k: v for k, v in fault.items() if k not in ('id', 'command')}
            if fields['channel'] == 'http':
                fields.update(command=identifier, operation='status')
            else:
                fields.update(path='/scap-test/scap-object/v1/1/7/3101/head', stage='before_forward')
            self.hub.arm(fault['id'], **fields)
        self.node.offer(identifier)
        if fault is not None and fault['kind'] == 'hold':
            self.hub.wait(fault['id'])
        self.node.finish(identifier)
        if fault is not None and fault['kind'] == 'hold':
            self.hub.release(fault['id'])

    def replace(self):
        self.snapshot('p', 'old_probe_before_kill')
        old = self.services['p']
        old.stop('instance_replaced', kill=True)
        shutil.rmtree(old.cache)
        self.events.emit('cache_removed', worker='p', path=str(old.cache),
            observed_absence=not old.cache.exists())
        assert not old.cache.exists()
        self.start_service('q')
        self.snapshot('q', 'replacement_empty_cache')

    def run(self):
        self.setup()
        for command in PLAN['commands']:
            self.call(command)
            if command['id'] == PLAN['replacement']['after']:
                self.replace()
        self.snapshot('q', 'replacement_after_probes')
        self.node.stop()
        assert self.offered == list(COMMANDS), 'fixed command denominator changed'
        assert not self.hub.errors, self.hub.errors

    def cleanup(self, failed=False):
        errors = list(self.cleanup_failures)
        if self.hub:
            for rule in self.hub.rules.values():
                if rule.entered.is_set() and rule.fields['kind'] == 'hold' and not rule.released.is_set():
                    rule.released.set()
                    self.events.cleanup_emit('fault_cleanup_release', id=rule.id)
        for node in self.nodes:
            if not node.stopped:
                try:
                    node.stop(force=True)
                except BaseException as error:
                    errors.append(repr(error))
        for service in self.services.values():
            if not service.stopped:
                try:
                    service.stop()
                except BaseException as error:
                    errors.append(repr(error))
        for reservation in self.reservations.values():
            try:
                reservation.close()
            except BaseException as error:
                errors.append(repr(error))
        traces = [self.events] + ([self.hub.history] if self.hub else [])
        stop_backend_first = self.backend is not None and (
            failed or errors or any(trace.failure is not None for trace in traces))
        if stop_backend_first:
            # Failed observers must not wait for a relay that is still reading
            # its backend. All owned daemons/SDK children were stopped above.
            try:
                self.backend.stop()
            except BaseException as error:
                errors.append(repr(error))
        if self.hub:
            try:
                self.hub.close()
                errors.extend(self.hub.errors)
            except BaseException as error:
                errors.append(repr(error))
        if self.backend and not stop_backend_first:
            try:
                self.backend.stop()
            except BaseException as error:
                errors.append(repr(error))
        errors.extend('trace failed: ' + trace.failure for trace in traces if trace.failure is not None)
        self.events.cleanup_emit('cleanup_finished', errors=errors, private_preserved=self.private.exists())
        for trace in traces:
            if trace.failure is not None and 'trace failed: ' + trace.failure not in errors:
                errors.append('trace failed: ' + trace.failure)
        return errors


def main(args):
    assert __debug__, 'acceptance requires assertions'
    evidence = args.evidence.resolve()
    assert not evidence.is_relative_to(ROOT)
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-guarded-private-', dir=evidence.parent))
    before = fixture_sources()
    summary = {'schema': 1, 'status': 'FAILED', 'private_directory': str(private),
        'private_deleted': False, 'fixture_sources_before': before, 'aws_standard': 'NOT_RUN',
        'production_slo': 'NOT_RUN', 'started_monotonic_ns': time.monotonic_ns()}
    suite = None
    def expired(_signal, _frame):
        raise TimeoutError('original whole-run deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, PLAN['bounds']['whole_run_seconds'])
    try:
        assert not any(os.environ.get(name) for name in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE', 'NODE_OPTIONS'))
        assert not any('instrument-coverage' in os.environ.get(name, '')
            for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        assert PLAN['deadlines'] == DEADLINES
        build.capture_receipt(args.build_record, args.server, evidence)
        tools = {name: tool_version(name, path, evidence) for name, path in
            (('node', Path(shutil.which('node')).resolve()), ('weed', args.weed.resolve()))}
        assert tools['node']['version'] == 'v22.16.0'
        assert '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101' in tools['weed']['version']
        build.save_receipt(evidence / 'tools.json', tools)
        shutil.copyfile(HERE / 'inputs.json', evidence / 'inputs.json')
        suite = Suite(args, evidence, private, tools)
        suite.run()
        summary['contract_finished'] = True
    except BaseException as error:
        summary['error'] = repr(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        try:
            summary['cleanup_errors'] = suite.cleanup(failed='error' in summary) if suite else []
        except BaseException as error:
            summary['cleanup_errors'] = [repr(error)]
        try:
            build.verify(args.build_record, args.server)
            summary['fixture_sources_after'] = fixture_sources()
            assert before == summary['fixture_sources_after'], 'fixture source changed during run'
            summary['source_unchanged'] = True
        except BaseException as error:
            summary['source_error'] = repr(error)
        summary['ended_monotonic_ns'] = time.monotonic_ns()
        summary['whole_run_within_original_bound'] = (
            summary['ended_monotonic_ns'] - summary['started_monotonic_ns']
            <= PLAN['bounds']['whole_run_seconds'] * 1_000_000_000)
        if (summary.get('contract_finished') and not summary['cleanup_errors']
                and summary.get('source_unchanged') and summary['whole_run_within_original_bound']):
            summary['status'] = 'OBSERVED_NOT_AUDITED'
        build.save_receipt(evidence / 'summary.json', summary)
    assert summary['status'] == 'OBSERVED_NOT_AUDITED', summary
    print(json.dumps({'status': summary['status'], 'evidence': str(evidence)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--weed', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    main(parser.parse_args())
