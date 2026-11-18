#!/usr/bin/env python3
"""One diagnostic sample; reuses the original backend and evidence proxy.

Rust owns service/native/allocator counters. These Python counters measure only
the optional existing evidence observer. No formal acceptance rule is replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import subprocess
import sys
import threading
import time


PHASES = ('write_seq', 'write_multi', 'write_same', 'read_multi')


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


class Counters:
    """Inclusive wall/thread CPU, not additive elapsed time or kernel I/O time."""
    def __init__(self):
        self.lock, self.values = threading.Lock(), {}

    def record(self, name, start, cpu, size=0):
        value = (1, time.monotonic_ns() - start, time.thread_time_ns() - cpu, size)
        with self.lock:
            previous = self.values.setdefault(name, [0, 0, 0, 0])
            for index, amount in enumerate(value):
                previous[index] += amount

    def wrap(self, owner, name, stage, body=False):
        original = getattr(owner, name)
        def measured(*args, **kwargs):
            start, cpu = time.monotonic_ns(), time.thread_time_ns()
            try:
                return original(*args, **kwargs)
            finally:
                self.record(stage, start, cpu, len(args[0]) if body else 0)
        setattr(owner, name, measured)

    def snapshot(self, proxy):
        with self.lock:
            values = {name: value.copy() for name, value in sorted(self.values.items())}
        return {'monotonic_ns': time.monotonic_ns(), 'process_cpu_ns': time.process_time_ns(),
                'columns': ['calls', 'inclusive_wall_ns', 'caller_thread_cpu_ns', 'input_bytes'],
                'stages': values, 's3_requests': proxy.serial if proxy else 0}


class MeasuredLock:
    def __init__(self, lock, counters, name):
        self.lock, self.counters, self.name = lock, counters, name

    def __enter__(self):
        start, cpu = time.monotonic_ns(), time.thread_time_ns()
        self.lock.acquire()
        self.counters.record(self.name, start, cpu)
        return self

    def __exit__(self, *_):
        self.lock.release()


def observer(backend, output, support, counters):
    raw = support.RawStore(output)
    raw.lock = MeasuredLock(raw.lock, counters, 'raw_lock_wait')
    counters.wrap(raw, 'save', 'raw_save', body=True)
    proxy = support.Proxy(backend.port, output, raw)
    proxy.trace.lock = MeasuredLock(proxy.trace.lock, counters, 'trace_lock_wait')
    counters.wrap(proxy.trace, 'emit', 'trace_emit')
    counters.wrap(os, 'fsync', 'fsync')
    counters.wrap(http.client.HTTPConnection, 'endheaders', 'upstream_send')
    counters.wrap(http.client.HTTPConnection, 'getresponse', 'upstream_headers')
    counters.wrap(http.client.HTTPResponse, 'read', 'upstream_body')
    return proxy


def probe(args, root, config, output, proxy, counters):
    command = [str(args.node), str(root / 'experiments/service-profile/probe.mjs'),
               str(config), str(output / 'profile.json')]
    expected = [(phase, edge) for phase in PHASES for edge in ('before', 'after')]
    messages, seen = [], []
    with (output / 'probe.stderr.log').open('xb') as error:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=error, text=True, bufsize=1)
        try:
            deadline = time.monotonic() + 240
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('original diagnostic probe deadline')
                if not select.select([process.stdout], [], [], .25)[0]:
                    continue
                line = process.stdout.readline(65537)
                if not line:
                    break
                if len(line) > 65536:
                    raise ValueError('diagnostic message bound')
                message = json.loads(line)
                if 'diagnostic_observer' in message:
                    item = message['diagnostic_observer']
                    value = (item['phase'], item['edge'])
                    if len(seen) >= len(expected) or value != expected[len(seen)]:
                        raise ValueError('diagnostic phase handshake')
                    seen.append(value)
                    if proxy and item['edge'] == 'before':
                        proxy.set_phase(item['phase'])
                    captured = counters.snapshot(proxy)
                    messages.append({'phase': item, 'snapshot': captured})
                    if proxy and item['edge'] == 'after':
                        proxy.set_phase('audit')
                    process.stdin.write(json.dumps(captured) + '\n')
                    process.stdin.flush()
                else:
                    messages.append(message)
            code = process.wait(timeout=5)
            if code != 0 or seen != expected or messages[-1] != {
                    'ok': True, 'phases': 4, 'measured_calls': 144,
                    'original_lookups': 112, 'final_databases': 6}:
                raise ValueError('diagnostic SDK outcome or denominator')
            value = json.loads((output / 'profile.json').read_text())
            if len(value['observations']) != 280 or not all(call['ok'] for call in value['calls']):
                raise ValueError('diagnostic request denominator')
            return messages
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            save(output / 'observer-messages.json', messages)


def run(args):
    os.umask(0o077)
    root, output = args.source_root.resolve(), args.evidence.resolve()
    output.mkdir(mode=0o700)
    private = output / 'private'
    private.mkdir(mode=0o700)
    manifests = module('causal_manifest', Path(__file__).resolve().parents[2] / 'scripts/source_manifest.py')
    expected = manifests.load(args.source_manifest)
    if manifests.capture(root) != expected:
        raise ValueError('frozen diagnostic source changed')
    receipt = json.loads(args.build_record.read_text())
    if receipt['source_manifest_sha256'] != sha(args.source_manifest) or receipt['binary_sha256'] != sha(args.server):
        raise ValueError('diagnostic build identity')
    if subprocess.check_output([str(args.node), '--version'], text=True).strip() != 'v22.16.0':
        raise ValueError('fixed Node version')
    network = module('causal_network', root / 'experiments/object-network/run.py')
    spec = module('spec', root / 'experiments/object-load/spec.py')
    support = module('causal_support', root / 'experiments/object-load/support.py')
    counters, service, proxy = Counters(), None, None
    backend = network.Backend(args.weed.resolve(), private / 'backend', volume_size_mib=64, max_volumes=2)
    record = {'schema': 1, 'diagnostic_only': True, 'mode': args.mode, 'status': 'STARTED',
              'source': expected, 'build': receipt, 'observer_source_sha256': sha(Path(__file__)),
              'tools': {name: {'path': str(path.resolve()), 'sha256': sha(path)}
                        for name, path in (('scapd', args.server), ('node', args.node), ('weed', args.weed))},
              'start_monotonic_ns': time.monotonic_ns()}
    save(output / 'inputs.json', record)
    try:
        backend.start()
        if args.mode == 'evidence':
            proxy = observer(backend, output, support, counters)
        port = network.free_port(set())
        endpoint = f'http://127.0.0.1:{port}'
        tokens = {tenant: secrets.token_hex(32) for tenant in ('7', '8')}
        cache, temporary = private / 'cache', private / 'tmp'
        cache.mkdir(); temporary.mkdir()
        configuration = {'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': '5001',
            'cache_directory': str(cache), 'transport': spec.TRANSPORT, 'output': spec.OUTPUT,
            's3': {'endpoint': proxy.endpoint if proxy else backend.endpoint, 'region': 'us-east-1',
                'bucket': 'scap-test', 'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
                'session_token_env': None, 'allow_http': True, 'timeout_ms': 15000},
            'admission': spec.ADMISSION, 'cache': spec.CACHE, 'execution': {'result_memory_bytes': 134217728},
            'credentials': [{'sha256': hashlib.sha256(tokens[t].encode()).hexdigest(), 'deployment': '1',
                'tenant': t, 'principal': p, 'provision': True} for t, p in (('7', '11'), ('8', '22'))]}
        config, client = private / 'service.json', private / 'client.json'
        save(config, configuration)
        save(client, {'endpoint': endpoint, 'tokens': tokens, 'source_root': str(root), 'observer_pipe': True})
        environment = dict(os.environ, TMPDIR=str(temporary), SCAP_TEST_ACCESS=backend.access,
                           SCAP_TEST_SECRET=backend.secret)
        with (output / 'service.private.log').open('xb') as log:
            service = subprocess.Popen([str(args.server), str(config)], stdout=log, stderr=log,
                                       env=environment, cwd=root)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if service.poll() is not None:
                raise RuntimeError('owned diagnostic daemon exited before readiness')
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read()) == {'status': 'alive', 'protocol': 1}:
                    break
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.05)
        else:
            raise TimeoutError('owned diagnostic daemon readiness deadline')
        record['probe_summary'] = probe(args, root, client, output, proxy, counters)[-1]
        record['status'] = 'PASSED_DIAGNOSTIC_OUTCOMES'
    except BaseException as error:
        record['status'], record['failure'] = 'FAILED', repr(error)
        raise
    finally:
        errors = []
        if service is not None and service.returncode is None:
            service.send_signal(signal.SIGINT)
            try:
                code, usage = network.wait_child(service, 10)
                record['service_exit'] = {'code': code, 'usage': usage}
                if code != 0:
                    errors.append('service exit was not normal')
            except BaseException as error:
                service.kill(); service.wait(timeout=5)
                errors.append(repr(error))
        if proxy:
            try:
                proxy.close()
                record['proxy'] = {'requests': proxy.serial, 'errors': proxy.errors, 'joined': True}
            except BaseException as error:
                errors.append(repr(error))
        record['backend_stop'] = backend.stop()
        record['observer_total'] = counters.snapshot(proxy)
        record['source_unchanged'] = manifests.capture(root) == expected
        record['finish_monotonic_ns'] = time.monotonic_ns()
        record['cleanup_errors'] = errors
        if errors or not record['source_unchanged']:
            record['status'] = 'FAILED'
        save(output / 'run.json', record)
        if record['status'] == 'PASSED_DIAGNOSTIC_OUTCOMES':
            shutil.rmtree(private)
        if errors or not record['source_unchanged']:
            raise RuntimeError('diagnostic cleanup or source identity failed')
    print(json.dumps({'status': record['status'], 'mode': args.mode, **record['probe_summary']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'source-manifest', 'build-record', 'server', 'node', 'weed', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mode', choices=('direct', 'evidence'), required=True)
    run(parser.parse_args())
