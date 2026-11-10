"""Lifecycle adapters; product logic stays in the real service and SDK."""
from __future__ import annotations
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'experiments/object-service'))
import build
from owner_proxy import Hub, Trace, b64, sha
from owner_spec import DEADLINES
PLAN = json.loads((HERE / 'inputs.json').read_text())
assert PLAN['deadlines'] == DEADLINES
WORKERS = PLAN['workers']
COMMANDS = {c['id']: c for c in PLAN['commands']}
module_spec = importlib.util.spec_from_file_location('guarded_backend_fixture', ROOT / 'experiments/object-network/run.py')
network = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(network)


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


class DeadlineSocket(socket.socket):
    """Keep one absolute deadline across every buffered header/body read."""
    def __init__(self, owned, deadline):
        family, kind, protocol = owned.family, owned.type, owned.proto
        self.io_timeout = owned.gettimeout()
        super().__init__(family, kind, protocol, fileno=owned.detach())
        self.deadline = deadline

    def settimeout(self, value):
        self.io_timeout = value
        return super().settimeout(value)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('original HTTP request deadline')
        super().settimeout(remaining if self.io_timeout is None else min(remaining, self.io_timeout))

    def recv_into(self, *args):
        self.remaining()
        return super().recv_into(*args)

    def sendall(self, *args):
        self.remaining()
        return super().sendall(*args)


class DeadlineConnection(http.client.HTTPConnection):
    def __init__(self, port, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('original HTTP request deadline')
        self.deadline = deadline
        super().__init__('127.0.0.1', port, timeout=remaining)

    def connect(self):
        super().connect()
        self.sock = DeadlineSocket(self.sock, self.deadline)


def configuration(port, worker, cache, endpoint, tokens):
    body = PLAN['bounds']['request_bytes']
    admission = {'active_database_actors': 4, 'active_database_actors_per_tenant': 4,
        'actor_idle_timeout_ms': DEADLINES['actor_idle_ms'], 'control_workers': 2,
        'queued_total': 32, 'queued_per_tenant': 16, 'queued_per_database': 8,
        'reserved_controls': 2, 'data_intake': 8, 'control_intake': 4, 'recovery_intake': 2,
        'max_body_bytes': body, 'timeout_ms': DEADLINES['ordinary_ms'],
        'recovery_timeout_ms': DEADLINES['recovery_ms']}
    for name, count, tenant in (('data', 8, 4), ('control', 4, 2), ('recovery', 2, 1)):
        admission[name + '_profile'] = {'version': 1, 'requests_per_tenant': tenant,
            'body_bytes': count * body, 'body_bytes_per_tenant': tenant * body}
    return {'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': WORKERS[worker],
        'cache_directory': str(cache), 'admission': admission,
        'cache': {'pages_per_actor': 65536, 'parallel_recoveries': 1},
        'execution': {'result_memory_bytes': 134217728},
        'credentials': [{'sha256': sha(tokens[role].encode()), 'deployment': '1',
            'tenant': '8' if role == 'foreign' else '7', 'principal': principal,
            'provision': role == 'writer'} for role, principal in PLAN['principals'].items()],
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': DEADLINES['s3_ms']}}


class BoundedTrace(Trace):
    def __init__(self, path):
        super().__init__(path)
        self.bytes = 0
        self.failure = None

    def emit(self, event, **fields):
        with self.lock:
            if self.failure is not None:
                raise RuntimeError('trace previously failed: ' + self.failure)
            try:
                row = {'schema': 1, 'sequence': self.sequence + 1, 'event': event,
                       'monotonic_ns': time.monotonic_ns(), **fields}
                raw = (json.dumps(row, sort_keys=True) + '\n').encode()
                size = len(raw)
                assert self.sequence < PLAN['bounds']['event_count'], 'trace event limit'
                assert self.bytes + size <= PLAN['bounds']['trace_bytes'], 'trace byte limit'
                with self.path.open('ab') as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                self.sequence += 1
                self.bytes += size
                return row
            except BaseException as error:
                self.failure = repr(error)
                raise

    def cleanup_emit(self, event, **fields):
        try:
            return self.emit(event, **fields)
        except BaseException:
            # Recording failure remains sticky, but cannot prevent owned cleanup.
            return None


class ObservedHub(Hub):
    def __init__(self, backend_port, evidence, events, suite):
        self.listener_names = []
        self.next_listener = 'sink'
        self.backend_port, self.events = backend_port, events
        self.history = BoundedTrace(evidence / 'history.jsonl')
        self.lock, self.http_serial, self.s3_serial = threading.RLock(), 0, 0
        self.rules, self.servers, self.errors, self.reads = {}, [], [], {}
        self.phase = 'setup'
        suite.hub = self
        self.sink_url = self.start_sink()

    def server(self, handler):
        owner, name = self, self.next_listener

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False

            def __init__(self):
                self.gate = threading.BoundedSemaphore(PLAN['bounds']['handlers_active_per_listener'])
                self.count, self.count_lock = 0, threading.Lock()
                super().__init__(('127.0.0.1', 0), handler)

            def process_request(self, request, client_address):
                with self.count_lock:
                    self.count += 1
                    allowed = self.count <= PLAN['bounds']['handlers_total_per_listener']
                if not allowed or not self.gate.acquire(blocking=False):
                    owner.errors.append('bounded listener admission exceeded: ' + name)
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self.gate.release()
                    raise

            def get_request(self):
                request, address = super().get_request()
                limit = DEADLINES['s3_ms'] if name.startswith('s3-') else DEADLINES['owner_ms']
                return DeadlineSocket(request, time.monotonic() + limit / 1000), address

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.gate.release()

        server = Server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.servers.append((server, thread))
        self.listener_names.append(name)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}'
        self.events.emit('listener_started', name=name, url=url, descriptor=server.fileno())
        return url

    def s3(self, worker):
        self.next_listener = 's3-' + worker
        return super().s3(worker)

    def http(self, worker, backend_port):
        self.next_listener = 'http-' + worker
        return super().http(worker, backend_port)

    def close(self):
        errors = []
        for name, (server, thread) in zip(self.listener_names, self.servers):
            try:
                if thread.ident is not None:
                    server.shutdown()
                server.server_close()
                if thread.ident is not None:
                    thread.join(timeout=3)
                assert not thread.is_alive(), 'listener thread did not join'
                self.events.cleanup_emit('listener_closed', name=name, descriptor=server.fileno(),
                    thread_joined=True, handlers_joined=True, accepted_handlers=server.count)
            except BaseException as error:
                errors.append(repr(error))
        self.errors.extend(errors)
        self.events.cleanup_emit('proxy_stopped', errors=self.errors,
            http_requests=self.http_serial, s3_requests=self.s3_serial)
        assert not errors, errors


class Backend:
    """Real pinned backend; all children and provisioning calls are observed here."""
    def __init__(self, binary, directory, events):
        self.binary, self.directory, self.events = Path(binary), directory, events
        directory.mkdir(mode=0o700)
        self.access, self.secret = secrets.token_hex(16), secrets.token_hex(32)
        identity = directory / 'identity.private.json'
        identity.write_text(json.dumps({'identities': [{'name': 'guarded-contract',
            'credentials': [{'accessKey': self.access, 'secretKey': self.secret}],
            'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging']}]}))
        identity.chmod(0o600)
        used = set()
        ports = {name: (network.free_port(used), network.free_port(used))
            for name in ('master', 'volume', 'filer', 's3')}
        self.port = ports['s3'][0]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        for name in ('master', 'volume', 'filer'):
            (directory / name).mkdir(mode=0o700)
        def listen(name):
            return ['-ip=127.0.0.1', '-ip.bind=127.0.0.1', f'-port={ports[name][0]}',
                f'-port.grpc={ports[name][1]}']
        master = '127.0.0.1:%d.%d' % ports['master']
        filer = '127.0.0.1:%d.%d' % ports['filer']
        self.commands = [
            ('master', ['master', *listen('master'), f'-mdir={directory / "master"}',
                '-peers=none', '-telemetry=false', '-volumeSizeLimitMB=64', '-volumePreallocate=false']),
            ('volume', ['volume', *listen('volume'), f'-dir={directory / "volume"}', f'-master={master}', '-max=2']),
            ('filer', ['filer', *listen('filer'), f'-defaultStoreDir={directory / "filer"}', f'-master={master}']),
            ('s3', ['s3', *listen('s3'), f'-filer={filer}', f'-config={identity}', '-port.iceberg=0', '-port.lance=0']),
        ]
        self.children = []
        self.readiness_serial = 0

    def signed(self, method, path, payload, deadline):
        assert deadline > time.monotonic(), 'original backend readiness deadline'
        request_deadline = min(deadline, time.monotonic() + PLAN['bounds']['readiness_request_seconds'])
        now = datetime.now(timezone.utc)
        stamp, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
        host, digest = f'127.0.0.1:{self.port}', sha(payload)
        names = 'host;x-amz-content-sha256;x-amz-date'
        canonical_headers = f'host:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{stamp}\n'
        canonical = f'{method}\n{path}\n\n{canonical_headers}\n{names}\n{digest}'
        scope = f'{day}/us-east-1/s3/aws4_request'
        signable = f'AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{sha(canonical.encode())}'
        key = ('AWS4' + self.secret).encode()
        for part in (day, 'us-east-1', 's3', 'aws4_request'):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, signable.encode(), hashlib.sha256).hexdigest()
        headers = {'Host': host, 'X-Amz-Date': stamp, 'X-Amz-Content-Sha256': digest,
            'Authorization': f'AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={names}, Signature={signature}'}
        self.readiness_serial += 1
        number = self.readiness_serial
        self.events.emit('readiness_request', serial=number, method=method, path=path,
            payload_sha256=digest, access_key_sha256=sha(self.access.encode()))
        connection = None
        try:
            connection = DeadlineConnection(self.port, request_deadline)
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read(65537)
            assert len(raw) <= 65536, 'readiness response bound'
            self.events.emit('readiness_response', serial=number, status=response.status,
                body_sha256=sha(raw), body_bytes=len(raw))
            return response.status == 200
        except (OSError, http.client.HTTPException) as error:
            self.events.emit('readiness_error', serial=number, error_type=type(error).__name__)
            return False
        finally:
            if connection is not None:
                connection.close()

    def start(self):
        for name, arguments in self.commands:
            with (self.directory / (name + '.private.log')).open('wb') as output:
                process = subprocess.Popen([str(self.binary), *arguments], cwd=self.directory,
                    stdout=output, stderr=output)
            child = {'name': name, 'process': process, 'identity': None}
            self.children.append(child)
            child['identity'] = network.process_identity(process)
            self.events.emit('backend_child_started', role=name, identity=child['identity'],
                binary_sha256=build.digest(self.binary))
        deadline = time.monotonic() + PLAN['bounds']['readiness_seconds']
        for _ in range(PLAN['bounds']['readiness_rounds']):
            if time.monotonic() >= deadline:
                break
            if self.signed('HEAD', '/scap-test', b'', deadline) or self.signed('PUT', '/scap-test', b'', deadline):
                if self.signed('PUT', '/scap-test/fixture-ready', b'ready', deadline):
                    self.events.emit('backend_ready', endpoint=self.endpoint, requests=self.readiness_serial)
                    return
            time.sleep(min(PLAN['bounds']['readiness_pause_seconds'], max(0, deadline - time.monotonic())))
        raise TimeoutError('original bounded backend readiness')

    def stop(self):
        errors = []
        for child in reversed(self.children):
            try:
                os.kill(child['process'].pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as error:
                errors.append(repr(error))
        for child in self.children:
            name, process, identity = child['name'], child['process'], child['identity']
            try:
                code, usage = network.wait_child(process, 10)
                self.events.cleanup_emit('backend_child_stopped', role=name, identity=identity,
                    wait_status=code, kernel_usage=usage,
                    log_sha256=build.digest(self.directory / (name + '.private.log')))
                assert code == -signal.SIGKILL and usage['available'], (name, code, usage)
            except BaseException as error:
                errors.append(repr(error))
        self.children.clear()
        assert not errors, errors


def tool_version(name, path, evidence):
    output = evidence / (name + '-version.log')
    with output.open('wb') as stream:
        process = subprocess.Popen([str(path), 'version' if name == 'weed' else '--version'],
            stdout=stream, stderr=stream)
    identity = None
    code, usage = None, {'available': False, 'reason': 'owned child has not been reaped'}
    try:
        identity = network.process_identity(process)
        code, usage = network.wait_child(process, 10)
    except BaseException:
        try:
            os.kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code, usage = network.wait_child(process, 10)
        raise
    finally:
        record = {'identity': identity, 'end_monotonic_ns': time.monotonic_ns(),
            'wait_status': code, 'kernel_usage': usage, 'path': str(path),
            'sha256': build.digest(path), 'log_sha256': build.digest(output)}
        build.save_receipt(evidence / (name + '-version-process.json'), record)
    assert code == 0 and usage['available'] and output.stat().st_size <= 8192
    record['version'] = output.read_text().strip()
    return record


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
        self.identity = None
        suite.services[worker] = self
        try:
            self.identity = network.process_identity(self.process)
            suite.events.emit('service_started', worker=worker, identity=self.identity, binary=self.binary,
                configuration_sha256=build.digest(self.path), cache_directory=str(self.cache),
                backend_endpoint=f'http://127.0.0.1:{port}', configuration_file='service-' + worker + '.json')
            assert build.digest(binary) == self.binary['sha256']
            bound = time.monotonic() + DEADLINES['ready_seconds']
            while time.monotonic() < bound:
                connection = None
                try:
                    connection = DeadlineConnection(port, min(bound, time.monotonic() + .5))
                    connection.request('GET', '/healthz'); response = connection.getresponse(); raw = response.read(4097)
                    if response.status == 200 and json.loads(raw) == {'status': 'alive', 'protocol': 1}:
                        suite.events.emit('service_ready', worker=worker, identity=self.identity,
                                          status=response.status, body=b64(raw), sha256=sha(raw)); return
                except (OSError, ValueError, http.client.HTTPException): pass
                finally:
                    if connection is not None:
                        connection.close()
                time.sleep(.02)
            raise TimeoutError('original daemon readiness deadline')
        except BaseException:
            try:
                self.stop('startup_failure', kill=True)
            except BaseException as error:
                suite.cleanup_failures.append(repr(error))
            raise

    def stop(self, reason='cleanup', kill=False):
        if self.stopped: return
        self.suite.events.cleanup_emit('service_stop_requested', worker=self.worker, identity=self.identity, reason=reason,
                               signal='SIGKILL' if kill else 'SIGINT')
        try: os.kill(self.process.pid, signal.SIGKILL if kill else signal.SIGINT)
        except ProcessLookupError: pass
        termination_error = None
        try: code, usage = network.wait_child(self.process, 10)
        except TimeoutError as error:
            termination_error = repr(error)
            self.suite.events.cleanup_emit('service_forced_cleanup', worker=self.worker, identity=self.identity, error=termination_error)
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            code, usage = network.wait_child(self.process, 10)
        self.stopped = True
        self.suite.events.cleanup_emit('service_stopped', worker=self.worker, identity=self.identity, reason=reason,
            wait_status=code, kernel_usage=usage, stdout_sha256=build.digest(self.log), termination_error=termination_error)
        assert termination_error is None and code == (-9 if kill else 0), (self.worker, code, termination_error)

class Node:
    def __init__(self, suite, ordinal):
        self.suite, self.ordinal, self.condition = suite, ordinal, threading.Condition()
        self.rows, self.errors, self.stopped = [], [], False
        config = {'plan': PLAN, 'node': ordinal, 'endpoints': suite.endpoints, 'tokens': suite.tokens,
                  'evidence': str(suite.evidence), 'sink': suite.hub.sink_url}
        path = suite.private / f'node-{ordinal}.private.json'; build.save_receipt(path, config); path.chmod(0o600)
        self.stderr = suite.evidence / f'node-{ordinal}.stderr.log'
        with self.stderr.open('wb') as errors:
            spawn_requested_ns = time.monotonic_ns()
            self.process = subprocess.Popen([suite.tools['node']['path'], str(HERE / 'client.mjs'), str(path)],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        self.identity, self.reader = None, None
        suite.nodes.append(self)
        try:
            self.identity = network.process_identity(self.process)
            suite.events.emit('node_started', node=ordinal, identity=self.identity, binary=suite.tools['node'],
                              configuration_sha256=build.digest(path), spawn_requested_ns=spawn_requested_ns)
            self.reader = threading.Thread(target=self.read, daemon=True)
            self.reader.start()
            self.wait('hello')
        except BaseException:
            try:
                self.stop(force=True)
            except BaseException as error:
                suite.cleanup_failures.append(repr(error))
            raise

    def read(self):
        try:
            while True:
                raw = self.process.stdout.readline(PLAN['bounds']['node_response_bytes'] + 1)
                if not raw:
                    break
                assert len(raw) <= PLAN['bounds']['node_response_bytes'] and raw.endswith(b'\n')
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
        command = COMMANDS[identifier]
        if command['kind'] == 'raw_status':
            assert row['ok'] is True and row['value']['status'] == command['http_status'], row
            assert row['value']['body']['error']['code'] == command['error_code'], row
        elif command['error_code'] is None:
            assert row['ok'] is True, row
        else:
            assert row['ok'] is False and row['error']['code'] == command['error_code'], row
        self.suite.events.emit('sdk_completion_observed', command=identifier, ok=row['ok'])
        return row

    def stop(self, force=False):
        if self.stopped: return
        self.suite.events.cleanup_emit('node_stop_requested', node=self.ordinal, identity=self.identity, forced=force)
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
            self.suite.events.cleanup_emit('node_forced_cleanup', node=self.ordinal, identity=self.identity, error=termination_error)
            try: os.kill(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            code, usage = network.wait_child(self.process, 10)
        if self.reader is not None and self.reader.ident is not None:
            self.reader.join(timeout=3)
        joined = self.reader is None or not self.reader.is_alive()
        self.stopped = True
        ledger = self.suite.evidence / 'node.jsonl'
        self.suite.events.cleanup_emit('node_stopped', node=self.ordinal, identity=self.identity, wait_status=code,
            kernel_usage=usage, forced=force, termination_error=termination_error, reader_joined=joined,
            stderr_sha256=build.digest(self.stderr), ledger_sha256=build.digest(ledger) if ledger.exists() else None)
        self.process.stdout.close()
        if not self.process.stdin.closed: self.process.stdin.close()
        assert termination_error is None and code == (-9 if force else 0) and joined and not self.errors
