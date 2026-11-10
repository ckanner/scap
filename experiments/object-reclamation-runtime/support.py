"""Owned process and raw TCP/S3 observation for the reclamation experiment."""
from __future__ import annotations

import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import threading
import time
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_RAW = 64 * 1024 * 1024


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


network = module('reclamation_owned_network', ROOT / 'experiments/object-network/run.py')
signing = module('reclamation_signing', ROOT / 'experiments/object-gc-store/support.py')
service_build = module('reclamation_service_build', ROOT / 'experiments/object-service/build.py')
seed_build = module('reclamation_seed_build', ROOT / 'experiments/object-network/build.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def save(path, raw):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class Trace:
    def __init__(self, evidence):
        self.evidence, self.lock, self.sequence = Path(evidence), threading.RLock(), 0
        (self.evidence / 'raw').mkdir()

    def raw(self, value):
        assert isinstance(value, bytes) and len(value) <= MAX_RAW
        digest = sha(value)
        path = self.evidence / 'raw' / digest
        with self.lock:
            if path.exists():
                assert path.stat().st_size == len(value) and sha(path.read_bytes()) == digest
            else:
                descriptor, name = tempfile.mkstemp(prefix='.raw-', dir=path.parent)
                try:
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(value)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.link(name, path)
                    except FileExistsError:
                        assert path.stat().st_size == len(value) and sha(path.read_bytes()) == digest
                finally:
                    os.unlink(name)
        return {'file': 'raw/' + digest, 'bytes': len(value), 'sha256': digest}

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {'sequence': self.sequence, 'monotonic_ns': time.monotonic_ns(),
                   'event': event, **fields}
            with (self.evidence / 'events.jsonl').open('ab') as stream:
                stream.write(encoded(row))
                stream.flush()
                os.fsync(stream.fileno())
            return row


class Gate:
    def __init__(self, identifier, method, prefix, mode, stage='before_forward', occurrence=1):
        assert mode in ('hold', 'drop', 'no_such_bucket')
        assert stage in ('before_forward', 'after_response')
        assert type(occurrence) is int and occurrence > 0
        self.id, self.method, self.prefix = identifier, method, prefix
        self.mode, self.stage, self.occurrence = mode, stage, occurrence
        self.seen = self.used = 0
        self.arrived, self.released, self.finished = (threading.Event() for _ in range(3))
        self.observed = None
        self.aborted = False


class Proxy:
    """One service's real S3 listener, with explicit, one-shot transport gates."""
    def __init__(self, backend, role, trace, credentials):
        self.backend, self.role, self.trace = backend, role, trace
        self.credentials = credentials
        self.lock, self.gate = threading.Lock(), None
        self.gates, self.errors = [], []
        self.serial, self.phase, self.active = 0, 'setup', 0
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def __getattr__(self, name):
                if name.startswith('do_'):
                    return self.dispatch
                raise AttributeError(name)

            def dispatch(self):
                connection = None
                selected = None
                self.close_connection = True
                with owner.lock:
                    owner.serial += 1
                    serial, phase = owner.serial, owner.phase
                    owner.active += 1
                fields = {'role': role, 'serial': serial, 'phase': phase,
                          'method': self.command, 'path': self.path}
                trace.emit('s3_handler_started', **fields)
                try:
                    self.connection.settimeout(10)
                    assert self.command in ('GET', 'PUT', 'DELETE'), 'unplanned production S3 method'
                    assert self.headers.get('Transfer-Encoding') is None
                    length = int(self.headers.get('Content-Length', '0'))
                    assert 0 <= length <= MAX_RAW
                    payload = self.rfile.read(length)
                    assert len(payload) == length
                    headers = dict(self.headers.items())
                    authorization = self.headers.get('Authorization', '')
                    access = re.match(r'AWS4-HMAC-SHA256 Credential=([^/]+)/', authorization)
                    assert access and access.group(1) in credentials, 'unconfigured S3 principal'
                    key = access.group(1)
                    assert signing.verify_signature(self.command, self.path, headers, payload,
                                                    key, credentials[key]), 'invalid actual SigV4'
                    public = {k.lower(): v for k, v in headers.items()
                              if k.lower() not in ('authorization', 'x-amz-security-token')}
                    trace.emit('s3_request', request=trace.raw(payload), headers=public,
                               access_sha256=sha(key.encode()), authorization_sha256=sha(authorization.encode()),
                               signature_valid=True, **fields)
                    with owner.lock:
                        selected = owner.gate
                        if selected and (selected.method != self.command
                                         or not self.path.startswith(selected.prefix)):
                            selected = None
                        if selected:
                            selected.seen += 1
                            if selected.seen != selected.occurrence:
                                selected = None
                        if selected:
                            selected.used += 1
                            owner.gate = None
                    if selected and selected.stage == 'before_forward':
                        if not owner.reached(selected, fields, payload):
                            return
                        if selected.mode == 'no_such_bucket':
                            body = b'<Error><Code>NoSuchBucket</Code><Message>fixture</Message></Error>'
                            owner.deliver(self, fields, 404, {}, body, 'fixture_no_such_bucket')
                            return
                    connection = http.client.HTTPConnection('127.0.0.1', backend.port, timeout=15)
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in headers.items():
                        connection.putheader(name, value)
                    trace.emit('s3_forward_started', **fields)
                    connection.endheaders(payload)
                    response = connection.getresponse()
                    body = response.read(MAX_RAW + 1)
                    assert len(body) <= MAX_RAW
                    received_headers = {k.lower(): v for k, v in response.getheaders()}
                    trace.emit('s3_backend_response', status=response.status, headers=received_headers,
                               response=trace.raw(body), **fields)
                    if selected and selected.stage == 'after_response':
                        if not owner.reached(selected, fields, payload):
                            return
                    owner.deliver(self, fields, response.status, received_headers, body, 'backend')
                except BaseException as error:
                    owner.errors.append({'role': role, 'serial': serial, 'error': repr(error)})
                    trace.emit('s3_fixture_error', error=repr(error), **fields)
                finally:
                    if connection:
                        connection.close()
                    if selected:
                        selected.finished.set()
                    with owner.lock:
                        owner.active -= 1
                    trace.emit('s3_handler_finished', **fields)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = False
        self.endpoint = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        trace.emit('s3_proxy_started', role=role, endpoint=self.endpoint)

    def deliver(self, handler, fields, status, headers, body, origin):
        self.trace.emit('s3_delivery_started', status=status, origin=origin,
                        response=self.trace.raw(body), **fields)
        sent, failure = False, None
        try:
            handler.send_response_only(status)
            for name, value in headers.items():
                if name.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    handler.send_header(name, value)
            handler.send_header('Content-Length', str(len(body)))
            handler.send_header('Connection', 'close')
            handler.end_headers()
            handler.wfile.write(body)
            handler.wfile.flush()
            sent = True
        except (BrokenPipeError, ConnectionResetError) as error:
            failure = type(error).__name__
        self.trace.emit('s3_delivery_finished', complete=sent, failure=failure, **fields)

    def reached(self, gate, fields, payload):
        gate.observed = dict(fields, request=self.trace.raw(payload))
        self.trace.emit('fault_arrived', id=gate.id, mode=gate.mode, stage=gate.stage, **fields)
        gate.arrived.set()
        if gate.mode == 'no_such_bucket':
            return True
        if gate.mode == 'hold':
            assert gate.released.wait(180), 'fixed gate release deadline'
        if gate.aborted or gate.mode == 'drop':
            self.trace.emit('fault_suppressed', id=gate.id, aborted=gate.aborted, **fields)
            return False
        self.trace.emit('fault_forward_resumed', id=gate.id, **fields)
        return True

    def phase_to(self, phase):
        with self.lock:
            self.phase = phase
        self.trace.emit('phase_started', role=self.role, phase=phase)

    def arm(self, identifier, method, prefix, mode, stage='before_forward', occurrence=1):
        gate = Gate(identifier, method, prefix, mode, stage, occurrence)
        with self.lock:
            assert self.gate is None
            self.gate = gate
            self.gates.append(gate)
        self.trace.emit('fault_armed', role=self.role, id=identifier, method=method,
                        prefix=prefix, mode=mode, stage=stage, occurrence=occurrence)
        return gate

    def release(self, gate):
        assert gate.arrived.is_set() and not gate.released.is_set()
        self.trace.emit('fault_release_requested', role=self.role, id=gate.id)
        gate.released.set()

    def close(self):
        with self.lock:
            for gate in self.gates:
                if not gate.finished.is_set():
                    gate.aborted = True
                    gate.released.set()
            self.gate = None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        assert not self.thread.is_alive() and self.active == 0
        self.trace.emit('s3_proxy_stopped', role=self.role, errors=self.errors, joined=True)


class Child:
    def __init__(self, command, cwd, environment, trace, identifier, private, interactive=False):
        self.trace, self.id, self.pending = trace, identifier, b''
        self.interactive = interactive
        self.log = Path(private) / (identifier + '.stderr')
        with self.log.open('wb') as errors:
            self.process = subprocess.Popen(command, cwd=cwd, env=environment,
                stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
                stdout=subprocess.PIPE if interactive else errors, stderr=errors)
        self.identity = network.process_identity(self.process)
        trace.emit('child_started', id=identifier, identity=self.identity,
                   command=command, executable_sha256=service_build.digest(Path(command[0])))

    def send(self, value):
        raw = encoded(value)
        self.trace.emit('child_input', id=self.id, raw=self.trace.raw(raw))
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def read(self, seconds=30):
        deadline = time.monotonic() + seconds
        while b'\n' not in self.pending:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.process.stdout], [], [], left)[0]:
                raise TimeoutError('original child output deadline')
            part = os.read(self.process.stdout.fileno(), 65536)
            if not part:
                raise EOFError('child output ended before complete line')
            self.pending += part
            assert len(self.pending) <= 4 * 1024 * 1024
        raw, self.pending = self.pending.split(b'\n', 1)
        raw += b'\n'
        self.trace.emit('child_output', id=self.id, raw=self.trace.raw(raw))
        return json.loads(raw)

    def close(self, crash=False):
        if self.process.returncode is not None:
            return
        self.trace.emit('child_stop_requested', id=self.id, identity=self.identity, crash=crash)
        if crash:
            self.process.kill()
        elif self.interactive:
            self.process.stdin.close()
        else:
            self.process.send_signal(signal.SIGINT)
        forced = False
        try:
            status, usage = network.wait_child(self.process, 35)
        except TimeoutError:
            self.process.kill()
            forced = True
            status, usage = network.wait_child(self.process, 10)
        if self.interactive:
            self.process.stdout.close()
        self.trace.emit('child_stopped', id=self.id, identity=self.identity,
                        status=status, usage=usage, crash=crash, forced=forced,
                        stderr=self.trace.raw(self.log.read_bytes()))
        assert not forced and status == (-signal.SIGKILL if crash else 0)
