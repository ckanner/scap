#!/usr/bin/env python3
"""Four fresh local S3 runs; instrumentation is observation, never a queue gate."""
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

support, resources = shared.observers()
build = shared.module('group_load_build', shared.ROOT / 'experiments/object-service/build.py')
network = shared.module('group_load_backend', shared.ROOT / 'experiments/object-network/run.py')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture():
    return {path.relative_to(shared.ROOT).as_posix(): sha(path) for path in shared.fixture_files()}


class Round:
    def __init__(self, args, name, enabled, until):
        self.args, self.enabled, self.until = args, enabled, until
        self.directory = args.evidence / name
        self.directory.mkdir(mode=0o700)
        self.temporary = tempfile.TemporaryDirectory(prefix='scap-group-load-', dir=args.evidence.parent)
        self.private = Path(self.temporary.name)
        self.events, self.raw = support.Trace(self.directory / 'events.jsonl'), support.RawStore(self.directory)
        self.backend = self.proxy = self.service = self.sampler = self.proc = self.child = None
        self.phase = 'startup'

    def remaining(self, maximum):
        value = min(maximum, self.until - time.monotonic())
        if value <= 0:
            raise TimeoutError('frozen complete paired-run deadline')
        return value

    def setup(self):
        if shutil.disk_usage(self.private).free < spec.BOUNDS['startup_free_bytes']:
            raise ValueError('startup free-space bound')
        calls = spec.calls()
        support.save_json(self.directory / 'workload.json', {
            'plan': spec.PLAN, 'calls': calls, 'final_sql': spec.ALL_ROWS,
            'payloads': {str(call['row']): self.raw.save(spec.payload(call['row']))
                         for call in calls if 'row' in call}})
        self.backend = network.Backend(self.args.weed, self.private / 'backend',
                                       volume_size_mib=256, max_volumes=8)
        self.backend.start()
        self.events.emit('backend_started', identities=self.backend.identities(), binary_sha256=sha(self.args.weed))
        self.proxy = support.Proxy(self.backend.port, self.directory, self.raw)
        self.port = network.free_port(set())
        self.cache, temporary = self.private / 'cache', self.private / 'tmp'
        self.cache.mkdir(mode=0o700); temporary.mkdir(mode=0o700)
        token = secrets.token_hex(32)
        config = spec.configuration(f'127.0.0.1:{self.port}', self.cache, self.proxy.endpoint,
                                    hashlib.sha256(token.encode()).hexdigest(), self.enabled)
        support.save_json(self.directory / 'service-config.json', config)
        config_path = self.private / 'service.json'
        support.save_json(config_path, config)
        self.client = self.private / 'client.json'
        support.save_json(self.client, {'endpoint': f'http://127.0.0.1:{self.port}',
                                        'token': token, 'source_root': str(shared.ROOT)})
        self.proxy.set_phase('startup')
        self.events.emit('service_start_requested', empty_cache=not list(self.cache.iterdir()),
                         group_commit=self.enabled, configuration_sha256=sha(config_path))
        env = dict(os.environ, TMPDIR=str(temporary), SCAP_TEST_ACCESS=self.backend.access,
                   SCAP_TEST_SECRET=self.backend.secret)
        self.service, self.proc, self.identity, proof = resources.spawn_owned(
            [str(self.args.binary), str(config_path)], env, shared.ROOT,
            self.private / 'service.log', self.events.emit)
        deadline = time.monotonic() + self.remaining(20)
        expected = {'path': str(self.args.binary), 'sha256': sha(self.args.binary)}
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=.5)
            try:
                actual = resources.executable(self.proc)
                if actual != expected:
                    time.sleep(.01)
                    continue
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                body = response.read(4097)
                self.events.emit('readiness_probe', status=response.status, response=self.raw.save(body))
                if response.status == 200 and json.loads(body) == {'status': 'alive', 'protocol': 1}:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('frozen startup deadline')
        self.events.emit('service_started', identity=self.identity, proof=proof, binary=actual)
        self.sampler = resources.Sampler(self.proc, self.identity, self.cache, self.private / 'backend',
            self.directory / 'resources.jsonl', lambda: self.phase)
        self.proc = None
        self.sampler.start()

    def observe(self):
        for phase in ('seed', *spec.PHASES, 'verify'):
            self.phase = phase
            self.proxy.set_phase(phase)
            self.events.emit('phase_started', phase=phase)
            command = [str(self.args.node), str(shared.HERE / 'probe.mjs'), phase,
                       str(self.client), str(self.directory)]
            with (self.directory / (phase + '.stdout')).open('xb') as out, \
                 (self.directory / (phase + '.stderr')).open('xb') as err:
                requested = time.monotonic_ns()
                self.child = subprocess.Popen(command, stdout=out, stderr=err, cwd=shared.HERE)
            identity = network.process_identity(self.child)
            self.events.emit('node_started', phase=phase, identity=identity,
                             spawn_requested_ns=requested, binary_sha256=sha(self.args.node))
            status, usage = network.wait_child(self.child, self.remaining(spec.DEADLINES['phase_seconds']))
            self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage)
            self.child = None
            if status != 0:
                raise RuntimeError('SDK phase failed: ' + phase)
            if self.proxy.errors or self.sampler.errors:
                raise RuntimeError({'proxy': self.proxy.errors, 'sampler': self.sampler.errors})
            self.events.emit('phase_finished', phase=phase)

    def close(self):
        errors = []
        if self.child is not None:
            resources.signal_owned(self.child, signal.SIGKILL)
            status, usage = network.wait_child(self.child, 10)
            self.events.emit('node_forced_stop', status=status, usage=usage)
            errors.append('unfinished SDK phase')
        if self.sampler is not None:
            try:
                self.sampler.close()
            except BaseException as error:
                errors.append(repr(error))
        if self.proc is not None:
            os.close(self.proc)
        if self.service is not None:
            resources.signal_owned(self.service, signal.SIGINT)
            try:
                status, usage = network.wait_child(self.service, 40)
            except BaseException as error:
                errors.append(repr(error))
                resources.signal_owned(self.service, signal.SIGKILL)
                status, usage = network.wait_child(self.service, 10)
            self.events.emit('service_stopped', identity=self.identity, status=status, usage=usage,
                             cache_empty=not list(self.cache.iterdir()))
            if status != 0:
                errors.append('service did not stop normally')
        if self.proxy is not None:
            try:
                self.proxy.close()
                self.events.emit('proxy_stopped', errors=self.proxy.errors, request_count=self.proxy.serial)
            except BaseException as error:
                errors.append(repr(error))
        if self.backend is not None:
            try:
                self.events.emit('backend_stopped', processes=self.backend.stop(verify=True))
            except BaseException as error:
                errors.append(repr(error))
        log = self.private / 'service.log'
        if log.exists():
            (self.directory / 'service.log').write_bytes(log.read_bytes())
        if not errors:
            self.temporary.cleanup()
        self.events.close()
        return errors


def run(args):
    if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
        raise ValueError('assertions required by source-bound observer helpers')
    if any(name in os.environ for name in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE')) or any(
            'instrument-coverage' in os.environ.get(name, '') for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')):
        raise ValueError('runtime evidence must not use coverage instrumentation')
    for name in ('binary', 'node', 'weed', 'build_record', 'evidence'):
        setattr(args, name, getattr(args, name).resolve())
    args.evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    before = fixture()
    report = {'status': 'FAILED', 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'rounds': []}
    until = time.monotonic() + spec.DEADLINES['run_seconds']
    try:
        if subprocess.check_output([str(args.node), '--version'], text=True).strip() != 'v22.16.0':
            raise ValueError('Node must be exactly 22.16.0')
        build.verify(args.build_record, args.binary)
        (args.evidence / 'build').mkdir()
        receipt = build.capture_receipt(args.build_record, args.binary, args.evidence / 'build')
        with tarfile.open(args.evidence / 'fixture-source.tar', 'w') as archive:
            for name in before:
                archive.add(shared.ROOT / name, arcname=name, recursive=False)
        inputs = {'fixture': before, 'fixture_archive_sha256': sha(args.evidence / 'fixture-source.tar'),
                  'fixture_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=shared.ROOT, text=True).strip(),
                  'build_source_commit': receipt['source_commit'],
                  'tools': {name: {'path': str(path), 'sha256': sha(path)} for name, path in (
                      ('scapd', args.binary), ('node', args.node), ('weed', args.weed))}}
        support.save_json(args.evidence / 'inputs.json', inputs)
        support.save_json(args.evidence / 'plan.json', spec.PLAN)
        for name, enabled in spec.ROUNDS:
            observed = {'name': name, 'group_commit': enabled, 'status': 'FAILED'}
            report['rounds'].append(observed)
            instance = Round(args, name, enabled, until)
            try:
                instance.setup()
                instance.observe()
                observed['status'] = 'OBSERVED_NOT_AUDITED'
            finally:
                observed['cleanup_errors'] = instance.close()
                if observed['cleanup_errors']:
                    raise RuntimeError(observed['cleanup_errors'])
            print(json.dumps(observed), flush=True)
        build.verify(args.build_record, args.binary)
        if fixture() != before or any(sha(item['path']) != item['sha256'] for item in inputs['tools'].values()):
            raise ValueError('frozen source/tool changed during paired run')
        support.save_json(args.evidence / 'fixture-after.json', fixture())
        report['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        support.save_json(args.evidence / 'result.json', report)
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'build-record', 'weed', 'node', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
