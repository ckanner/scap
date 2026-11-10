#!/usr/bin/env python3
"""Fixed real output-pool pressure contract; all database work uses scapd/SDK."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import tarfile
import threading
import time

if not __debug__:
    raise RuntimeError('contract requires Python assertions')

HERE = Path(__file__).resolve().parent


def module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(specification)
    sys.modules[name] = result
    specification.loader.exec_module(result)
    return result


io = module('scap_output_pool_io', HERE / 'io.py')


def encoded(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def fixture_inputs():
    return {p.name: io.sha(p.read_bytes()) for p in sorted(HERE.iterdir())
            if p.is_file() and p.suffix in ('.py', '.mjs', '.md')}


class Events:
    def __init__(self, directory):
        self.path = directory / 'events.jsonl'
        self.lock = threading.Lock()
        self.sequence = 0

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {'event': event, 'sequence': self.sequence, 'monotonic_ns': time.monotonic_ns(), **fields}
            with self.path.open('a') as stream:
                stream.write(json.dumps(row, sort_keys=True) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            return row


def configuration(port, cache, endpoint, tokens, profile):
    transport = {'version': 1, 'max_connections': 64, 'max_headers': 64,
                 'max_header_bytes': 16384, 'max_buffer_bytes': 32768, 'header_timeout_ms': 5000}
    if profile == 'bounded':
        transport.update(response_timeout_ms=120000, shutdown_timeout_ms=30000)
    return {'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': '5001',
        'cache_directory': str(cache), 'transport': transport,
        'output': {'version': 1, 'bytes': 256 * 1024 * 1024,
            'bytes_per_tenant': 192 * 1024 * 1024, 'control_bytes': 8 * 1024 * 1024,
            'control_bytes_per_tenant': 1024 * 1024},
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': 10000},
        'admission': {'active_database_actors': 4, 'active_database_actors_per_tenant': 2,
            'actor_idle_timeout_ms': 60000, 'control_workers': 2,
            'queued_total': 32, 'queued_per_tenant': 16, 'queued_per_database': 8,
            'reserved_controls': 2, 'data_intake': 16, 'control_intake': 8,
            'recovery_intake': 2, 'max_body_bytes': 1048576,
            'timeout_ms': 60000, 'recovery_timeout_ms': 60000},
        'cache': {'pages_per_actor': 65536, 'parallel_recoveries': 2},
        'execution': {'result_memory_bytes': 134217728},
        'credentials': [
            {'sha256': io.sha(tokens[role].encode()), 'deployment': '1', 'tenant': tenant,
             'principal': principal, 'provision': role != 'a_reader'}
            for role, tenant, principal in (('a', '7', '11'), ('a_reader', '7', '12'), ('b', '8', '22'))]}


class Suite:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.events = Events(evidence)
        self.source = args.source_root.resolve()
        self.build = module('scap_output_runtime_build', self.source / 'experiments/object-service/build.py')
        self.network = module('scap_output_runtime_network', self.source / 'experiments/object-network/run.py')
        self.backend = self.proxy = self.process = None
        self.held = []
        self.tokens = {name: secrets.token_hex(32) for name in ('a', 'a_reader', 'b')}
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.fixture = fixture_inputs()
        self.tools = {name: {'path': str(path.resolve()), 'sha256': self.build.digest(path)}
                      for name, path in (('node', self.node), ('weed', args.weed), ('scapd', args.server))}

    def setup(self):
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(k, '') for k in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        assert subprocess.check_output([str(self.node), '--version'], text=True).strip() == 'v22.16.0'
        record = self.build.verify(self.args.build_record, self.args.server)
        (self.evidence / 'runtime-build').mkdir()
        self.build.capture_receipt(self.args.build_record, self.args.server, self.evidence / 'runtime-build')
        with tarfile.open(self.evidence / 'fixture-source.tar', 'w') as archive:
            for name in self.fixture:
                archive.add(HERE / name, arcname=name, recursive=False)
        self.build.save_receipt(self.evidence / 'inputs.json', {
            'fixture': self.fixture, 'fixture_root': str(HERE), 'runtime_source_root': str(self.source),
            'runtime_source_commit': record['source_commit'], 'runtime_inputs': record['inputs'],
            'runtime_build_sha256': self.build.digest(self.args.build_record),
            'fixture_archive_sha256': self.build.digest(self.evidence / 'fixture-source.tar'),
            'tools': self.tools, 'profile': self.args.transport_profile,
            'plan_sha256': self.fixture['PLAN.md']})
        self.backend = self.network.Backend(self.args.weed.resolve(), self.private / 'backend',
                                             volume_size_mib=128, max_volumes=4)
        self.backend.start()
        self.events.emit('backend_started', processes=self.backend.identities(), binary=self.tools['weed'])
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            connection.request('GET', '/scap-test/fixture-ready')
            response = connection.getresponse()
            raw = response.read(65537)
            self.events.emit('unsigned_probe', status=response.status, body_sha256=io.sha(raw))
            assert response.status == 403 and len(raw) <= 65536
        finally:
            connection.close()
        self.proxy = self.network.Proxy(self.backend.port, self.evidence)
        self.proxy.capture = True
        self.port = self.network.free_port(set())
        self.endpoint = f'http://127.0.0.1:{self.port}'
        cache = self.private / 'cache'
        cache.mkdir(mode=0o700)
        config = configuration(self.port, cache, self.proxy.endpoint, self.tokens, self.args.transport_profile)
        self.build.save_receipt(self.evidence / 'service-config.json', config)
        path = self.private / 'service.private.json'
        self.build.save_receipt(path, config)
        self.log = self.private / 'service.private.log'
        with self.log.open('wb') as out:
            self.process = subprocess.Popen([str(self.args.server.resolve()), str(path)],
                cwd=self.source, stdout=out, stderr=out,
                env=dict(os.environ, SCAP_TEST_ACCESS=self.backend.access, SCAP_TEST_SECRET=self.backend.secret))
        self.identity = self.network.process_identity(self.process)
        self.events.emit('service_started', identity=self.identity, binary=self.tools['scapd'], endpoint=self.endpoint)
        bound = time.monotonic() + 20
        while time.monotonic() < bound:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=.5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read(4097)) == {'status': 'alive', 'protocol': 1}:
                    self.events.emit('service_ready', identity=self.identity)
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('real daemon readiness deadline; private log retained')
        self.client_config = self.private / 'client.private.json'
        self.build.save_receipt(self.client_config, {'endpoint': self.endpoint, 'tokens': self.tokens,
                                                   'source_root': str(self.source)})

    def phase(self, phase):
        self.proxy.set_phase(phase)
        self.events.emit('phase_started', phase=phase)
        with (self.evidence / (phase + '.stdout')).open('wb') as out, \
                (self.evidence / (phase + '.stderr')).open('wb') as err:
            process = subprocess.Popen([str(self.node), str(HERE / 'probe.mjs'), phase,
                                        str(self.client_config), str(self.evidence)], stdout=out, stderr=err)
        identity = self.network.process_identity(process)
        self.events.emit('node_started', phase=phase, identity=identity)
        try:
            status, usage = self.network.wait_child(process, 75)
        except BaseException:
            process.kill()
            status, usage = self.network.wait_child(process, 10)
            self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=True)
            raise
        self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=False)
        assert status == 0, 'SDK phase failed: ' + phase
        self.events.emit('phase_finished', phase=phase)

    def hold(self, role, identifier):
        self.proxy.set_phase(identifier)
        scope = {'deployment': '1', 'tenant': '8' if role == 'b' else '7',
                 'database': '202' if role == 'b' else '101', 'incarnation': '1', 'generation': '1'}
        columns = ', '.join(f'zeroblob(2097152) AS b{i}' for i in range(16))
        body = encoded({'version': 1, 'scope': scope, 'operation': 'query',
                        'statements': [{'sql': 'SELECT ' + columns, 'params': []}]})
        value = io.SlowResponse(self.endpoint, self.tokens[role], body, self.evidence,
                                identifier, self.events.emit)
        self.held.append(value)
        assert value.status == 200 and value.length > 42 * 1024 * 1024

    def run(self):
        self.phase('setup')
        for identifier in ('a1', 'a2', 'a3'):
            self.hold('a', identifier)
        self.phase('tenant-limit')
        self.hold('b', 'b1')
        self.phase('global-limit')
        self.phase('control')
        self.phase('insert')
        self.held[0].disconnect()
        # Closing the real socket wakes the server; no product count is read.
        # A fixed bounded settling interval is part of this observation, not a retry.
        time.sleep(.1)
        self.phase('after-disconnect')
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(value.drain) for value in self.held[1:]]
            for future in futures:
                future.result()
        self.phase('lookup')
        self.phase('count')
        assert not self.proxy.errors, self.proxy.errors
        self.build.verify(self.args.build_record, self.args.server)
        assert fixture_inputs() == self.fixture, 'fixture changed during real run'
        assert all(self.build.digest(Path(value['path'])) == value['sha256'] for value in self.tools.values())

    def close(self):
        errors = []
        for value in self.held:
            try:
                value.disconnect()
            except BaseException as error:
                errors.append(repr(error))
        if self.process is not None:
            try:
                self.events.emit('service_stop_requested', identity=self.identity, signal='SIGINT')
                self.process.send_signal(signal.SIGINT)
                status, usage = self.network.wait_child(self.process, 40)
                self.events.emit('service_stopped', identity=self.identity, status=status, usage=usage)
                assert status == 0
            except BaseException as error:
                errors.append(repr(error))
                try:
                    self.process.kill()
                    status, usage = self.network.wait_child(self.process, 10)
                    self.events.emit('service_forced_stop', status=status, usage=usage)
                except BaseException as cleanup:
                    errors.append(repr(cleanup))
        if self.proxy is not None:
            try:
                self.proxy.clear()
                self.proxy.server.shutdown()
                self.proxy.server.server_close()
                self.proxy.thread.join(timeout=5)
                assert not self.proxy.thread.is_alive()
                self.events.emit('proxy_stopped', errors=list(self.proxy.errors), joined=True)
            except BaseException as error:
                errors.append(repr(error))
        if self.backend is not None:
            try:
                self.events.emit('backend_stopped', processes=self.backend.stop())
            except BaseException as error:
                errors.append(repr(error))
        return errors


def main(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-output-private-', dir=evidence.parent))
    suite = Suite(args, evidence, private)
    summary = {'status': 'FAILED', 'aws_standard': 'NOT_RUN', 'production_slo_passed': False,
               'private_path': str(private), 'private_removed': False}
    try:
        suite.setup()
        suite.run()
        summary['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        summary['error'] = repr(error)
    finally:
        summary['cleanup_errors'] = suite.close()
        if summary['cleanup_errors']:
            summary['status'] = 'FAILED'
        if summary['status'] == 'OBSERVED_NOT_AUDITED':
            shutil.rmtree(private)
            summary['private_removed'] = True
        suite.build.save_receipt(evidence / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--weed', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--node', default='node')
    parser.add_argument('--transport-profile', choices=('baseline', 'bounded'), default='bounded')
    parser.add_argument('--evidence', type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
