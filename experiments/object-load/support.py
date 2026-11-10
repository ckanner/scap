"""Bounded byte capture and S3 forwarding. No database decisions are made here."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import struct
import threading
import time

from spec import BOUNDS, DEADLINES


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def save_json(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


class RawStore:
    def __init__(self, evidence):
        self.directory = Path(evidence) / 'raw'
        self.directory.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.budget = self.directory.parent / 'raw-budget'
        self.process_lock = self.directory.parent / 'raw-lock'
        if not self.budget.exists():
            with self.budget.open('x') as stream:
                stream.write(str(sum(p.stat().st_size for p in self.directory.iterdir())) + '\n')
                stream.flush(); os.fsync(stream.fileno())

    @contextmanager
    def exclusive(self):
        until = time.monotonic() + 10
        while True:
            try:
                self.process_lock.mkdir(mode=0o700)
                break
            except FileExistsError:
                if time.monotonic() >= until:
                    raise TimeoutError('original raw evidence lock deadline') from None
                time.sleep(.005)
        try:
            yield
        finally:
            self.process_lock.rmdir()

    def save(self, raw):
        if len(raw) > BOUNDS['body_bytes']:
            raise ValueError('raw body exceeded bound')
        digest = sha(raw)
        path = self.directory / digest
        with self.lock, self.exclusive():
            if not path.exists():
                total = int(self.budget.read_text())
                if total < 0 or total + len(raw) > BOUNDS['raw_bytes']:
                    raise ValueError('raw evidence byte budget exhausted')
                with self.budget.open('w') as stream:
                    stream.write(str(total + len(raw)) + '\n')
                    stream.flush(); os.fsync(stream.fileno())
                with path.open('xb') as stream:
                    stream.write(raw)
                    stream.flush(); os.fsync(stream.fileno())
            if path.stat().st_size != len(raw):
                raise ValueError('content-addressed evidence changed')
        return {'file': 'raw/' + digest, 'bytes': len(raw), 'sha256': digest}


class Trace:
    def __init__(self, path):
        self.path = Path(path)
        self.lock, self.sequence, self.bytes = threading.Lock(), 0, 0

    def emit(self, event, **fields):
        with self.lock:
            row = {'event': event, 'sequence': self.sequence + 1,
                   'monotonic_ns': time.monotonic_ns(), **fields}
            value = encoded(row) + b'\n'
            if self.sequence >= BOUNDS['trace_rows'] or self.bytes + len(value) > BOUNDS['trace_bytes']:
                raise ValueError('trace evidence budget exhausted')
            with self.path.open('ab') as stream:
                stream.write(value)
                stream.flush()
            self.sequence += 1
            self.bytes += len(value)
            return row

    def close(self):
        if self.path.exists():
            with self.path.open('rb') as stream:
                os.fsync(stream.fileno())


def signing(headers):
    value = headers.get('Authorization', '')
    match = re.fullmatch(r'AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]{64})', value)
    if match is None:
        raise ValueError('unsigned or malformed product S3 request')
    access, scope, names, signature = match.groups()
    names = names.split(';')
    if names != sorted(set(names)) or not {'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(names):
        raise ValueError('incomplete S3 signature fields')
    return {'access_key_sha256': sha(access.encode()), 'credential_scope': scope,
            'signed_headers': names, 'signature_sha256': sha(signature.encode()),
            'host': headers['Host'], 'date': headers['X-Amz-Date'],
            'payload_sha256': headers['X-Amz-Content-Sha256']}


class Proxy:
    def __init__(self, backend_port, evidence, raw):
        self.backend_port, self.raw = backend_port, raw
        self.trace = Trace(Path(evidence) / 's3.jsonl')
        self.lock, self.serial, self.phase = threading.Lock(), 0, 'setup'
        self.objects, self.errors = {}, []
        self.gate_path, self.gate_serial = None, None
        self.arrived, self.release = threading.Event(), threading.Event()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.dispatch()

            def do_PUT(self):
                self.dispatch()

            def dispatch(self):
                self.close_connection = True
                try:
                    self.forward()
                except BaseException as error:
                    with owner.lock:
                        owner.errors.append(repr(error))
                    owner.trace.emit('proxy_error', error=repr(error))

            def forward(self):
                self.connection.settimeout(DEADLINES['s3_ms'] / 1000)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= BOUNDS['body_bytes']:
                    raise ValueError('S3 request body bound')
                payload = self.rfile.read(length)
                if len(payload) != length:
                    raise ValueError('S3 request body truncated')
                with owner.lock:
                    if owner.serial >= BOUNDS['s3_requests']:
                        raise ValueError('S3 request count bound')
                    owner.serial += 1
                    serial, phase = owner.serial, owner.phase
                    gated = self.command == 'GET' and self.path == owner.gate_path and owner.gate_serial is None
                    if gated:
                        owner.gate_serial = serial
                common = {'request_serial': serial, 'phase': phase, 'method': self.command,
                          'path': self.path, 'request': owner.raw.save(payload),
                          'if_match': self.headers.get('If-Match'),
                          'if_none_match': self.headers.get('If-None-Match'), 'signing': signing(self.headers)}
                owner.trace.emit('request', **common)
                if gated:
                    owner.trace.emit('gate_arrived', **common)
                    owner.arrived.set()
                    if not owner.release.wait(DEADLINES['gate_hold_ms'] / 1000):
                        raise TimeoutError('frozen original GET gate deadline')
                connection = http.client.HTTPConnection('127.0.0.1', owner.backend_port, timeout=10)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items():
                        connection.putheader(name, value)
                    connection.endheaders(payload)
                    owner.trace.emit('forwarded', **common)
                    response = connection.getresponse()
                    body = response.read(BOUNDS['body_bytes'] + 1)
                    description = owner.raw.save(body)
                    received = {'status': response.status, 'response': description, 'etag': response.getheader('ETag')}
                    owner.trace.emit('response', **common, **received)
                    if response.status == 200:
                        with owner.lock:
                            owner.objects[self.path] = common['request'] if self.command == 'PUT' else description
                    self.send_response_only(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ('connection', 'content-length', 'transfer-encoding'):
                            self.send_header(name, value)
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(body)
                    owner.trace.emit('delivered', **common, **received)
                finally:
                    connection.close()

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False

            def __init__(self):
                self.permits = threading.BoundedSemaphore(BOUNDS['handlers'])
                super().__init__(('127.0.0.1', 0), Handler)

            def process_request(self, request, address):
                if not self.permits.acquire(blocking=False):
                    owner.errors.append('proxy handler bound exceeded')
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except BaseException:
                    self.permits.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self.permits.release()

        self.server = Server()
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, name='load-s3-proxy')
        self.thread.start()

    def set_phase(self, phase):
        with self.lock:
            self.phase = phase

    def arm(self, path):
        with self.lock:
            if self.gate_path is not None:
                raise ValueError('duplicate GET gate')
            self.gate_path = path
        self.trace.emit('gate_armed', path=path, hold_ms=DEADLINES['gate_hold_ms'])

    def release_gate(self):
        self.trace.emit('gate_released', path=self.gate_path, request_serial=self.gate_serial)
        self.release.set()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.errors.append('S3 listener did not join')
        self.trace.close()
        if self.errors:
            raise RuntimeError(self.errors)


def select_chunk(evidence, objects, head_path):
    """Locate the gate using actually recorded current metadata, not test-created data."""
    head = json.loads((Path(evidence) / objects[head_path]['file']).read_bytes())
    scope = head['scope']
    prefix = ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}'
              '/gen/{generation}/storage/').format(**scope) + str(head['storage']['active_generation']) + '/objects/'
    root = head['data_root']
    for _ in range(7):
        raw = (Path(evidence) / objects[prefix + root]['file']).read_bytes()
        if raw[:8] != b'SCAPOBJ2' or len(raw) < 20:
            raise ValueError('gate metadata frame')
        size, = struct.unpack('<I', raw[8:12])
        payload = json.loads(raw[20:20 + size])['payload']
        if payload['kind'] == 'chunk':
            return prefix + root
        if payload['kind'] == 'manifest':
            root = payload['value']['root']
        elif payload['kind'] == 'node':
            root = payload['value']['children'][0]
        else:
            raise ValueError('unexpected gate metadata kind')
    raise ValueError('gate metadata depth')
