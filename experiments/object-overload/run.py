#!/usr/bin/env python3
"""Run the fixed offered workload against the ordinary release daemon and SDK."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

import shared
import spec

HERE = Path(__file__).resolve().parent
support, resources = shared.observers()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_inputs():
    return {path.relative_to(shared.ROOT).as_posix(): digest(path)
            for path in shared.fixture_files()}


class Suite:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.source = args.source_root.resolve()
        self.build = shared.module('overload_runtime_build', self.source / 'experiments/object-service/build.py')
        self.network = shared.module('overload_backend', self.source / 'experiments/object-network/run.py')
        self.events, self.raw = support.Trace(evidence / 'events.jsonl'), support.RawStore(evidence)
        self.backend = self.proxy = self.process = self.sampler = self.proc = None
        self.tokens = {tenant: secrets.token_hex(32) for tenant in ('7', '8')}
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.fixture, self.children = fixture_inputs(), []
        self.until, self.phase = time.monotonic() + spec.DEADLINES['run_seconds'], 'setup'

    def remaining(self, maximum):
        value = min(maximum, self.until - time.monotonic())
        if value <= 0:
            raise TimeoutError('original complete-run deadline')
        return value

    def setup(self):
        if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
            raise ValueError('assertions required by original evidence adapters')
        if any(key in os.environ for key in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE')):
            raise ValueError('runtime evidence cannot use coverage instrumentation')
        if any('instrument-coverage' in os.environ.get(key, '') for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')):
            raise ValueError('runtime coverage flags forbidden')
        space = shutil.disk_usage(self.private).free
        self.events.emit('startup_space', filesystem_free_bytes=space,
                         required_bytes=spec.BOUNDS['startup_free_bytes'])
        if space < spec.BOUNDS['startup_free_bytes']:
            raise ValueError('startup disk-space guard')
        if subprocess.check_output([str(self.node), '--version'], text=True).strip() != 'v22.16.0':
            raise ValueError('Node differs from fixed toolchain')
        receipt = self.build.verify(self.args.build_record, self.args.server)
        (self.evidence / 'runtime-build').mkdir()
        self.build.capture_receipt(self.args.build_record, self.args.server, self.evidence / 'runtime-build')
        self.tools = {name: {'path': str(path.resolve()), 'sha256': digest(path)} for name, path in (
            ('scapd', self.args.server), ('node', self.node), ('weed', self.args.weed))}
        with tarfile.open(self.evidence / 'fixture-source.tar', 'w') as archive:
            for name in self.fixture:
                archive.add(shared.ROOT / name, arcname=name, recursive=False)
        support.save_json(self.evidence / 'inputs.json', {
            'fixture': self.fixture, 'fixture_archive_sha256': digest(self.evidence / 'fixture-source.tar'),
            'fixture_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=HERE, text=True).strip(),
            'fixture_source_root': str(shared.ROOT), 'runtime_source_root': str(self.source),
            'runtime_source_commit': receipt['source_commit'], 'runtime_inputs': receipt['inputs'],
            'runtime_build_sha256': digest(self.args.build_record), 'tools': self.tools})
        calls = spec.calls()
        for call in calls:
            statements = spec.statements(call)
            if statements is not None:
                call['statements'] = statements
        row_numbers = {row for call in calls for row in call.get('rows', [])}
        payloads = {str(row): self.raw.save(spec.payload(row)) for row in sorted(row_numbers)}
        support.save_json(self.evidence / 'workload.json', {'plan': spec.PLAN, 'calls': calls, 'payloads': payloads})
        self.backend = self.network.Backend(self.args.weed.resolve(), self.private / 'backend',
                                            volume_size_mib=256, max_volumes=8)
        self.backend.start()
        self.events.emit('backend_started', processes=self.backend.identities(), binary=self.tools['weed'])
        self.proxy = support.Proxy(self.backend.port, self.evidence, self.raw)
        self.port = self.network.free_port(set())
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.client_config = self.private / 'client.private.json'
        support.save_json(self.client_config, {'endpoint': self.endpoint, 'tokens': self.tokens,
                                              'source_root': str(self.source)})
        self.start_daemon()

    def start_daemon(self):
        self.phase = 'startup'
        self.proxy.set_phase(self.phase)
        self.cache, temporary = self.private / 'cache', self.private / 'tmp'
        self.cache.mkdir(mode=0o700); temporary.mkdir(mode=0o700)
        config = {'version': 1, 'listen': f'127.0.0.1:{self.port}',
            'worker_instance': str(spec.WORKER), 'cache_directory': str(self.cache),
            'admission': spec.ADMISSION, 'cache': spec.CACHE, 'transport': spec.TRANSPORT,
            'output': spec.OUTPUT, 'execution': {'result_memory_bytes': 134217728},
            's3': {'endpoint': self.proxy.endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
                'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
                'session_token_env': None, 'allow_http': True, 'timeout_ms': spec.DEADLINES['s3_ms']},
            'credentials': [{'sha256': hashlib.sha256(self.tokens[tenant].encode()).hexdigest(),
                'deployment': '1', 'tenant': tenant, 'principal': principal, 'provision': True}
                for tenant, principal in (('7', '11'), ('8', '22'))]}
        support.save_json(self.evidence / 'service-config.json', config)
        path = self.private / 'service.private.json'
        support.save_json(path, config)
        self.events.emit('service_start_requested', worker_instance=str(spec.WORKER),
                         cache=str(self.cache), initial_cache=resources.disk_tree(self.cache))
        environment = dict(os.environ, TMPDIR=str(temporary), SCAP_TEST_ACCESS=self.backend.access,
                           SCAP_TEST_SECRET=self.backend.secret)
        self.process, self.proc, self.identity, proof = resources.spawn_owned(
            [str(self.args.server.resolve()), str(path)], environment, self.source,
            self.private / 'service.private.log', self.events.emit)
        bound = time.monotonic() + self.remaining(20)
        while time.monotonic() < bound:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=.5)
            try:
                actual = resources.executable(self.proc)
                if actual != self.tools['scapd']:
                    time.sleep(.01)
                    continue
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                body = response.read(4097)
                self.events.emit('readiness_probe', status=response.status, response=self.raw.save(body))
                if response.status == 200 and json.loads(body) == {'status': 'alive', 'protocol': 1}:
                    break
            except (OSError, ValueError, http.client.HTTPException) as error:
                self.events.emit('readiness_failure', error=repr(error))
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('original service startup deadline')
        self.events.emit('service_started', identity=self.identity, proof=proof, binary=actual,
                         endpoint=self.endpoint, cache=str(self.cache), worker_instance=str(spec.WORKER))
        self.sampler = resources.Sampler(self.proc, self.identity, self.cache, self.private / 'backend',
            self.evidence / 'resources.jsonl', lambda: self.phase)
        self.proc = None
        self.sampler.start()

    def phase_run(self, phase):
        if self.sampler.errors:
            raise RuntimeError(self.sampler.errors)
        self.phase = phase
        self.proxy.set_phase(phase)
        self.events.emit('phase_started', phase=phase)
        command = [str(self.node), str(HERE / 'probe.mjs'), phase, str(self.client_config), str(self.evidence)]
        with (self.evidence / f'{phase}.stdout').open('xb') as out, (self.evidence / f'{phase}.stderr').open('xb') as err:
            before = time.monotonic_ns()
            process = subprocess.Popen(command, stdout=out, stderr=err, cwd=HERE)
        identity = self.network.process_identity(process)
        self.children.append((process, identity, phase))
        self.events.emit('node_started', phase=phase, identity=identity, spawn_requested_ns=before,
                         binary=self.tools['node'])
        try:
            status, usage = self.network.wait_child(process, self.remaining(spec.DEADLINES['phase_seconds']))
        except BaseException:
            resources.signal_owned(process, signal.SIGKILL)
            status, usage = self.network.wait_child(process, 10)
            self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=True)
            raise
        self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=False)
        if status != 0:
            raise RuntimeError('SDK phase failed: ' + phase)
        self.events.emit('phase_finished', phase=phase)

    def run(self):
        for phase in spec.PHASES:
            self.phase_run(phase)
            if phase == 'seed':
                connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
                try:
                    path = '/scap-test/scap-object/v1/1/7/1101/head'
                    connection.request('GET', path)
                    response = connection.getresponse()
                    body = response.read(65537)
                    self.events.emit('unsigned_probe', path=path, status=response.status, response=self.raw.save(body))
                    if response.status != 403 or len(body) > 65536:
                        raise ValueError('existing authority allowed unsigned read')
                finally:
                    connection.close()
        if self.proxy.errors or self.sampler.errors:
            raise RuntimeError({'proxy': self.proxy.errors, 'sampler': self.sampler.errors})
        self.build.verify(self.args.build_record, self.args.server)
        if fixture_inputs() != self.fixture:
            raise ValueError('frozen fixture source changed')
        for tool in self.tools.values():
            if digest(tool['path']) != tool['sha256']:
                raise ValueError('actual tool changed')

    def close(self):
        errors = []
        for process, identity, phase in self.children:
            if process.returncode is not None:
                continue
            try:
                resources.signal_owned(process, signal.SIGKILL)
                status, usage = self.network.wait_child(process, 10)
                self.events.emit('node_stopped', phase=phase, identity=identity,
                                 status=status, usage=usage, forced=True)
            except BaseException as error:
                errors.append(repr(error))
        if self.sampler is not None:
            try:
                self.sampler.close()
            except BaseException as error:
                errors.append(repr(error))
        if self.proc is not None:
            os.close(self.proc)
        if self.process is not None:
            self.events.emit('service_stop_requested', identity=self.identity)
            resources.signal_owned(self.process, signal.SIGINT)
            forced = False
            try:
                status, usage = self.network.wait_child(self.process, 40)
            except BaseException as error:
                errors.append(repr(error)); forced = True
                resources.signal_owned(self.process, signal.SIGKILL)
                status, usage = self.network.wait_child(self.process, 10)
            self.events.emit('service_stopped', identity=self.identity, status=status, usage=usage, forced=forced)
            if status != 0 or forced:
                errors.append('formal daemon did not stop normally')
        if self.proxy is not None:
            try:
                self.proxy.close()
                self.events.emit('proxy_stopped', joined=True, errors=self.proxy.errors, request_count=self.proxy.serial)
            except BaseException as error:
                errors.append(repr(error))
        if self.backend is not None:
            try:
                self.events.emit('backend_stopped', processes=self.backend.stop())
            except BaseException as error:
                errors.append(repr(error))
        self.events.close()
        return errors


def main(args):
    os.umask(0o077)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-overload-private-', dir=evidence.parent))
    suite = Suite(args, evidence, private)
    summary = {'status': 'FAILED', 'private_path': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo_passed': False}
    suite.events.emit('private_created', path=str(private), device=private.stat().st_dev, inode=private.stat().st_ino)
    try:
        suite.setup(); suite.run()
        summary['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        summary['error'] = repr(error)
    finally:
        summary['cleanup_errors'] = suite.close()
        if summary['cleanup_errors']:
            summary['status'] = 'FAILED'
        if summary['status'] == 'OBSERVED_NOT_AUDITED':
            before = private.stat()
            shutil.rmtree(private)
            suite.events.emit('private_removed', path=str(private), device=before.st_dev,
                              inode=before.st_ino, exists=private.exists())
            summary['private_removed'] = True
        suite.events.close()
        support.save_json(evidence / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for option in ('source-root', 'server', 'weed', 'build-record', 'evidence'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--node', default='node')
    raise SystemExit(main(parser.parse_args()))
