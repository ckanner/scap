#!/usr/bin/env python3
"""One bounded local run of the frozen workload through the actual daemon/SDK."""
from __future__ import annotations

import argparse
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
import tarfile
import tempfile
import time

import resources
import spec
from support import Proxy, RawStore, Trace, encoded, save_json, select_chunk, sha

HERE = Path(__file__).resolve().parent


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


def fixture_inputs():
    return {p.name: sha(p.read_bytes()) for p in sorted(HERE.iterdir())
            if p.is_file() and p.suffix in ('.py', '.mjs', '.md')}


class Suite:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.source = args.source_root.resolve()
        self.events, self.raw = Trace(evidence / 'events.jsonl'), RawStore(evidence)
        self.build = module('load_runtime_build', self.source / 'experiments/object-service/build.py')
        self.network = module('load_runtime_network', self.source / 'experiments/object-network/run.py')
        self.fixture = fixture_inputs()
        self.fixture_commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=HERE, text=True).strip()
        self.tokens = {tenant: secrets.token_hex(32) for tenant in ('7', '8')}
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.backend = self.proxy = self.process = self.sampler = None
        self.proc = None
        self.clients, self.round, self.phase = [], 0, 'setup'
        self.until = time.monotonic() + spec.DEADLINES['run_seconds']

    def remaining(self, maximum):
        value = min(maximum, self.until - time.monotonic())
        if value <= 0:
            raise TimeoutError('original complete-run deadline')
        return value

    def setup(self):
        if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
            raise ValueError('assertions required for imported evidence adapters')
        if any(key in os.environ for key in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE')):
            raise ValueError('runtime evidence cannot use coverage instrumentation')
        if any('instrument-coverage' in os.environ.get(key, '') for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')):
            raise ValueError('runtime coverage flags are forbidden')
        free = shutil.disk_usage(self.private).free
        self.events.emit('startup_space', filesystem_free_bytes=free,
                         required_bytes=spec.BOUNDS['startup_free_bytes'])
        if free < spec.BOUNDS['startup_free_bytes']:
            raise ValueError('startup disk space guard')
        if subprocess.check_output([str(self.node), '--version'], text=True).strip() != 'v22.16.0':
            raise ValueError('Node version differs from fixed toolchain')
        receipt = self.build.verify(self.args.build_record, self.args.server)
        (self.evidence / 'runtime-build').mkdir()
        self.build.capture_receipt(self.args.build_record, self.args.server, self.evidence / 'runtime-build')
        with tarfile.open(self.evidence / 'fixture-source.tar', 'w') as archive:
            for name in self.fixture:
                archive.add(HERE / name, arcname=name, recursive=False)
        self.tools = {name: {'path': str(path.resolve()), 'sha256': self.build.digest(path)}
                      for name, path in (('scapd', self.args.server), ('node', self.node), ('weed', self.args.weed))}
        save_json(self.evidence / 'inputs.json', {'fixture': self.fixture,
            'fixture_archive_sha256': self.build.digest(self.evidence / 'fixture-source.tar'),
            'fixture_commit': self.fixture_commit, 'fixture_source_root': str(HERE),
            'plan_sha256': self.fixture['PLAN.md'], 'runtime_source_root': str(self.source),
            'runtime_source_commit': receipt['source_commit'], 'runtime_inputs': receipt['inputs'],
            'runtime_build_sha256': self.build.digest(self.args.build_record), 'tools': self.tools})
        calls = spec.calls()
        for call in calls:
            payloads = {str(row): self.raw.save(secrets.token_bytes(call['blob_bytes']))
                        for row in call.get('rows', [])}
            if payloads:
                call['payloads'] = payloads
            statements = spec.statements(call, payloads)
            if statements is not None:
                call['statements'] = statements
        save_json(self.evidence / 'workload.json', {'plan': spec.PLAN, 'calls': calls})
        self.backend = self.network.Backend(self.args.weed.resolve(), self.private / 'backend',
                                            volume_size_mib=256, max_volumes=8)
        self.backend.start()
        self.events.emit('backend_started', processes=self.backend.identities(), binary=self.tools['weed'])
        self.proxy = Proxy(self.backend.port, self.evidence, self.raw)
        self.port = self.network.free_port(set())
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.client_config = self.private / 'client.private.json'
        save_json(self.client_config, {'endpoint': self.endpoint, 'tokens': self.tokens, 'source_root': str(self.source)})
        self.start_daemon()

    def configuration(self, cache):
        return {'version': 1, 'listen': f'127.0.0.1:{self.port}',
            'worker_instance': str(spec.WORKER_INSTANCES[self.round - 1]),
            'cache_directory': str(cache), 'transport': spec.TRANSPORT, 'output': spec.OUTPUT,
            's3': {'endpoint': self.proxy.endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
                'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
                'session_token_env': None, 'allow_http': True, 'timeout_ms': spec.DEADLINES['s3_ms']},
            'admission': spec.ADMISSION, 'cache': spec.CACHE, 'execution': {'result_memory_bytes': 134217728},
            'credentials': [{'sha256': sha(self.tokens[tenant].encode()), 'deployment': '1', 'tenant': tenant,
                'principal': principal, 'provision': True} for tenant, principal in (('7', '11'), ('8', '22'))]}

    def start_daemon(self):
        self.round += 1
        if self.round > len(spec.WORKER_INSTANCES):
            raise ValueError('fixed daemon startup count exceeded')
        self.phase = f'startup-{self.round}'
        self.proxy.set_phase(self.phase)
        self.cache = self.private / f'cache-{self.round}'
        self.cache.mkdir(mode=0o700)
        empty_cache = resources.disk_tree(self.cache)
        temporary = self.private / f'tmp-{self.round}'
        temporary.mkdir(mode=0o700)
        config = self.configuration(self.cache)
        save_json(self.evidence / f'service-config-{self.round}.json', config)
        path = self.private / f'service-{self.round}.private.json'
        save_json(path, config)
        self.events.emit('service_start_requested', instance=self.round,
                         worker_instance=config['worker_instance'], cache=str(self.cache))
        environment = dict(os.environ, TMPDIR=str(temporary), SCAP_TEST_ACCESS=self.backend.access,
                           SCAP_TEST_SECRET=self.backend.secret)
        self.process, self.proc, self.identity, proof = resources.spawn_owned(
            [str(self.args.server.resolve()), str(path)], environment, self.source,
            self.private / f'service-{self.round}.private.log', self.events.emit)
        expected = self.tools['scapd']
        deadline = time.monotonic() + self.remaining(20)
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=.5)
            issued = False
            try:
                actual = resources.executable(self.proc)
                if actual != expected:
                    time.sleep(.01)
                    continue
                connection.request('GET', '/healthz')
                issued = True
                response = connection.getresponse()
                raw = response.read(4097)
                self.events.emit('readiness_probe', instance=self.round, method='GET', path='/healthz',
                                 status=response.status, response=self.raw.save(raw))
                if response.status == 200 and json.loads(raw) == {'status': 'alive', 'protocol': 1}:
                    break
            except (OSError, ValueError, http.client.HTTPException) as error:
                self.events.emit('readiness_failure', instance=self.round, issued=issued, error=repr(error))
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('owned formal daemon startup deadline')
        self.events.emit('service_started', instance=self.round, identity=self.identity,
                         proof=proof, binary=actual, endpoint=self.endpoint, cache=str(self.cache),
                         initial_cache=empty_cache, worker_instance=config['worker_instance'])
        self.sampler = resources.Sampler(self.proc, self.identity, self.cache, self.private / 'backend',
            self.evidence / f'resources-{self.round}.jsonl', lambda: self.phase)
        self.proc = None  # Sampler owns the passed directory fd until close.
        self.sampler.start()

    def stop_daemon(self):
        errors = []
        if self.sampler is not None:
            try:
                self.sampler.close()
            except BaseException as error:
                errors.append(repr(error))
            self.sampler = None
        if self.proc is not None:
            os.close(self.proc)
            self.proc = None
        if self.process is not None:
            self.events.emit('service_stop_requested', instance=self.round, identity=self.identity, signal='SIGINT')
            forced = False
            resources.signal_owned(self.process, signal.SIGINT)
            try:
                status, usage = self.network.wait_child(self.process, 40)
            except BaseException as error:
                errors.append(repr(error)); forced = True
                resources.signal_owned(self.process, signal.SIGKILL)
                status, usage = self.network.wait_child(self.process, 10)
            self.events.emit('service_stopped', instance=self.round, identity=self.identity,
                             status=status, usage=usage, forced=forced)
            self.process = None
            if status != 0 or forced:
                errors.append('formal daemon did not stop normally')
        if errors:
            raise RuntimeError(errors)

    def start_phase(self, phase):
        self.remaining(1)
        if self.sampler is not None and self.sampler.errors:
            raise RuntimeError(self.sampler.errors)
        self.phase = phase
        self.proxy.set_phase(phase)
        self.events.emit('phase_started', phase=phase)
        with (self.evidence / f'{phase}.stdout').open('xb') as out, (self.evidence / f'{phase}.stderr').open('xb') as err:
            process = subprocess.Popen([str(self.node), str(HERE / 'probe.mjs'), phase,
                str(self.client_config), str(self.evidence)], stdout=out, stderr=err, cwd=HERE)
        identity = self.network.process_identity(process)
        self.clients.append((process, identity, phase))
        self.events.emit('node_started', phase=phase, identity=identity, binary=self.tools['node'])
        return process, identity, phase

    def finish_phase(self, child, maximum=None):
        process, identity, phase = child
        timeout = self.remaining(spec.DEADLINES['phase_seconds'] if maximum is None else maximum)
        try:
            status, usage = self.network.wait_child(process, timeout)
        except BaseException:
            resources.signal_owned(process, signal.SIGKILL)
            status, usage = self.network.wait_child(process, 10)
            self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=True)
            raise
        self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=False)
        if status != 0:
            raise RuntimeError('SDK phase failed: ' + phase)
        self.events.emit('phase_finished', phase=phase)

    def run_phase(self, phase):
        self.finish_phase(self.start_phase(phase))

    def unsigned_probe(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            path = '/scap-test/scap-object/v1/1/7/101/head'
            connection.request('GET', path)
            response = connection.getresponse()
            raw = response.read(65537)
            self.events.emit('unsigned_probe', path=path, status=response.status, response=self.raw.save(raw))
            if response.status != 403 or len(raw) > 65536:
                raise ValueError('existing authority allowed an unsigned read')
        finally:
            connection.close()

    def run(self):
        self.run_phase('seed')
        self.unsigned_probe()
        for phase in spec.MEASURED:
            self.run_phase(phase)
        self.stop_daemon()
        removed = str(self.cache)
        shutil.rmtree(self.cache)
        self.events.emit('compute_cache_removed', instance=self.round, path=removed, exists=self.cache.exists())
        self.start_daemon()
        self.run_phase('hot-open')
        gate = select_chunk(self.evidence, self.proxy.objects, '/scap-test/scap-object/v1/1/7/501/head')
        self.proxy.arm(gate)
        cold = self.start_phase('cold-open')
        if not self.proxy.arrived.wait(self.remaining(5)):
            raise TimeoutError('cold chunk GET did not reach actual gate')
        probes = self.start_phase('cold-probes')
        self.finish_phase(probes, spec.DEADLINES['probe_ms'] / 1000)
        self.proxy.release_gate()
        self.finish_phase(cold)
        self.run_phase('cold-warm')
        self.run_phase('verify')
        if self.proxy.errors:
            raise RuntimeError(self.proxy.errors)
        self.build.verify(self.args.build_record, self.args.server)
        if fixture_inputs() != self.fixture:
            raise ValueError('fixture source changed during run')
        for value in self.tools.values():
            if self.build.digest(Path(value['path'])) != value['sha256']:
                raise ValueError('actual tool binary changed during run')

    def close(self):
        errors = []
        if self.proxy is not None:
            self.proxy.release.set()
        for process, identity, phase in self.clients:
            if process.returncode is not None:
                continue
            try:
                resources.signal_owned(process, signal.SIGKILL)
                status, usage = self.network.wait_child(process, 10)
                self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage, forced=True)
            except BaseException as error:
                errors.append(repr(error))
        try:
            self.stop_daemon()
        except BaseException as error:
            errors.append(repr(error))
        if self.proxy is not None:
            try:
                self.proxy.close()
                self.events.emit('proxy_stopped', joined=True, errors=self.proxy.errors,
                                 request_count=self.proxy.serial)
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
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-load-private-', dir=evidence.parent))
    suite = Suite(args, evidence, private)
    summary = {'status': 'FAILED', 'private_path': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo_passed': False}
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
            shutil.rmtree(private)
            summary['private_removed'] = True
        save_json(evidence / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for option in ('source-root', 'server', 'weed', 'build-record', 'evidence'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--node', default='node')
    raise SystemExit(main(parser.parse_args()))
