#!/usr/bin/env python3
"""Real daemon/S3 response deadlines; never joins LLVM unit profiles."""
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
import subprocess
import sys
import tarfile
import tempfile
import time

if not __debug__:
    raise RuntimeError('contract requires Python assertions')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


shared = module('scap_response_output_helpers', ROOT / 'experiments/output-pool/run.py')
io = shared.io


def fixture_paths():
    own = {p.name: p for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py', '.mjs', '.md')}
    return {**own, **{'shared/' + name: ROOT / 'experiments/output-pool' / name
                     for name in ('run.py', 'io.py', 'oracle.py')}}


def fixture_inputs():
    return {name: io.sha(path.read_bytes()) for name, path in sorted(fixture_paths().items())}


class Suite:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.events = shared.Events(evidence)
        self.source = args.source_root.resolve()
        self.build = module('scap_response_build', self.source / 'experiments/object-service/build.py')
        self.network = module('scap_response_network', self.source / 'experiments/object-network/run.py')
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
            for name, path in sorted(fixture_paths().items()):
                archive.add(path, arcname=name, recursive=False)
        self.build.save_receipt(self.evidence / 'inputs.json', {
            'fixture': self.fixture, 'runtime_source_root': str(self.source),
            'runtime_source_commit': record['source_commit'], 'runtime_inputs': record['inputs'],
            'runtime_build_sha256': self.build.digest(self.args.build_record),
            'fixture_archive_sha256': self.build.digest(self.evidence / 'fixture-source.tar'),
            'tools': self.tools, 'profile': self.args.transport_profile,
            'plan_sha256': self.fixture['PLAN.md']})
        self.backend = self.network.Backend(self.args.weed.resolve(), self.private / 'backend',
                                             volume_size_mib=64, max_volumes=2)
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
        config = shared.configuration(self.port, cache, self.proxy.endpoint, self.tokens, self.args.transport_profile)
        config['transport']['max_connections'] = 8
        if self.args.transport_profile == 'bounded':
            config['transport'].update(response_timeout_ms=2000, shutdown_timeout_ms=500)
        self.build.save_receipt(self.evidence / 'service-config.json', config)
        path = self.private / 'service.private.json'
        self.build.save_receipt(path, config)
        with (self.private / 'service.private.log').open('wb') as out:
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
            raise TimeoutError('real daemon readiness deadline')
        self.client_config = self.private / 'client.private.json'
        self.build.save_receipt(self.client_config, {'endpoint': self.endpoint, 'token': self.tokens['a'],
                                                   'source_root': str(self.source)})

    def phase(self, phase):
        self.proxy.set_phase(phase)
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

    def hold(self, identifier):
        self.proxy.set_phase(identifier)
        if identifier == 'committed':
            intent = json.loads(json.loads((self.evidence / 'intent.json').read_text())['serialized'])
            body = {'version': 1, 'operation': 'execute', **intent}
        else:
            columns = ', '.join(f'zeroblob(2097152) AS b{i}' for i in range(8))
            body = {'version': 1, 'operation': 'query',
                'scope': {'deployment': '1', 'tenant': '7', 'database': '101', 'incarnation': '1', 'generation': '1'},
                'statements': [{'sql': 'SELECT ' + columns, 'params': []}]}
        response = io.SlowResponse(self.endpoint, self.tokens['a'], shared.encoded(body),
                                   self.evidence, identifier, self.events.emit, timeout=60)
        self.held.append(response)
        assert response.status == 200 and response.length > 21 * 1024 * 1024
        return response

    @staticmethod
    def until(when):
        time.sleep(max(0, when - time.monotonic()))

    def expire(self, identifier, drip=False):
        response = self.hold(identifier)
        origin = time.monotonic()
        if drip:
            for index, offset in enumerate((.5, 1, 1.5), 1):
                self.until(origin + offset)
                byte = response.socket.recv(1)
                assert len(byte) == 1
                self.events.emit('slow_drip', id=identifier, ordinal=index,
                    response=io.save(self.evidence / f'{identifier}.drip-{index}', byte))
        self.until(origin + 2.3)
        result = response.drain(allow_truncated=True)
        assert result['bytes'] + (3 if drip else 0) < response.length, 'peer did not expire its stalled response'

    def run(self):
        self.phase('setup')
        self.expire('stalled')
        self.phase('after-stalled')
        self.expire('drip', drip=True)
        self.phase('after-drip')
        self.expire('committed')
        self.phase('lookup')
        response = self.hold('shutdown')
        self.events.emit('service_stop_requested', identity=self.identity, signal='SIGINT')
        self.process.send_signal(signal.SIGINT)
        status, usage = self.network.wait_child(self.process, 4)
        self.events.emit('service_stopped', identity=self.identity, status=status, usage=usage)
        assert status == 0
        result = response.drain(allow_truncated=True)
        assert result['bytes'] < response.length
        assert not self.proxy.errors, self.proxy.errors
        self.build.verify(self.args.build_record, self.args.server)
        assert fixture_inputs() == self.fixture, 'fixture changed during real run'
        assert all(self.build.digest(Path(v['path'])) == v['sha256'] for v in self.tools.values())

    def close(self):
        errors = []
        for value in self.held:
            try:
                value.disconnect()
            except BaseException as error:
                errors.append(repr(error))
        if self.process is not None and self.process.returncode is None:
            try:
                self.process.kill()
                status, usage = self.network.wait_child(self.process, 10)
                self.events.emit('service_forced_stop', status=status, usage=usage)
            except BaseException as error:
                errors.append(repr(error))
        if self.proxy is not None:
            try:
                self.proxy.close()
                assert not self.proxy.thread.is_alive()
                self.events.emit('proxy_stopped', joined=True, errors=list(self.proxy.errors))
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
    private = Path(tempfile.mkdtemp(prefix='scap-response-private-', dir=evidence.parent))
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
