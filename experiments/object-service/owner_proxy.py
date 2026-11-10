"""Observed real HTTP/S3 relays with named, one-shot operator fault boundaries."""
from __future__ import annotations
import base64
import hashlib
import http.client
import http.server
import json
import os
import socket
import threading
import time

from isolation_proxy import signing
from owner_spec import DEADLINES


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode()


class Trace:
    def __init__(self, path):
        self.path, self.sequence, self.lock = path, 0, threading.RLock()

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            row = {'schema': 1, 'sequence': self.sequence, 'event': event,
                   'monotonic_ns': time.monotonic_ns(), **fields}
            with self.path.open('a') as output:
                output.write(json.dumps(row, sort_keys=True) + '\n')
                output.flush(); os.fsync(output.fileno())
            return row


class Rule:
    def __init__(self, identifier, fields):
        self.id, self.fields, self.used = identifier, fields, False
        self.entered, self.released = threading.Event(), threading.Event()
        self.witness = None

    def matches(self, channel, values, payload):
        if self.used or self.fields['channel'] != channel:
            return False
        for key in ('worker', 'command', 'method', 'path'):
            if key in self.fields and self.fields[key] != values.get(key):
                return False
        if 'operation' in self.fields and json.loads(payload)['operation'] != self.fields['operation']:
            return False
        if 'nonce' in self.fields and str(json.loads(payload)['transition']['nonce']) != self.fields['nonce']:
            return False
        return True


class Hub:
    def __init__(self, backend_port, evidence, events):
        self.backend_port, self.events = backend_port, events
        self.history = Trace(evidence / 'history.jsonl')
        self.lock, self.http_serial, self.s3_serial = threading.RLock(), 0, 0
        self.rules, self.servers, self.errors, self.reads = {}, [], [], {}
        self.phase = 'setup'
        self.sink_url = self.start_sink()

    def phase_to(self, phase):
        with self.lock:
            self.phase = phase
            self.history.emit('phase_started', phase=phase)

    def arm(self, identifier, **fields):
        with self.lock:
            assert identifier not in self.rules
            self.rules[identifier] = Rule(identifier, fields)
            self.events.emit('fault_armed', id=identifier, **fields)

    def select(self, channel, values, payload):
        with self.lock:
            matches = [rule for rule in self.rules.values() if rule.matches(channel, values, payload)]
            assert len(matches) <= 1, 'ambiguous one-shot fault'
            if not matches:
                return None
            rule = matches[0]; rule.used = True
            return rule

    def enter(self, rule, **witness):
        rule.witness = witness
        self.events.emit('fault_entered', id=rule.id, **rule.fields, **witness)
        rule.entered.set()

    def hold(self, rule):
        if not rule.released.wait(DEADLINES['gate_seconds']):
            self.events.emit('fault_expired', id=rule.id)
            raise TimeoutError('original owner fixture gate expired: ' + rule.id)

    def wait(self, identifier):
        rule = self.rules[identifier]
        assert rule.entered.wait(DEADLINES['gate_seconds']), 'fault not entered: ' + identifier
        return rule.witness

    def release(self, identifier):
        rule = self.rules[identifier]
        assert rule.entered.is_set() and not rule.released.is_set()
        self.events.emit('fault_released', id=identifier, **rule.witness)
        rule.released.set()

    def server(self, handler):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.daemon_threads = False
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.servers.append((server, thread))
        return f'http://127.0.0.1:{server.server_port}'

    def start_sink(self):
        owner = self
        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args): pass
            def do_POST(self):
                token = self.headers.get('Authorization', '').removeprefix('Bearer ')
                owner.events.emit('unexpected_sink_request', path=self.path, credential_sha256=sha(token.encode()))
                self.send_response(400); self.send_header('Content-Length', '0'); self.end_headers()
        url = self.server(Sink) + '/v1'
        self.events.emit('redirect_sink_started', url=url)
        return url

    def s3(self, worker):
        owner = self
        class Relay(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_args): pass
            def do_GET(self): self.dispatch()
            def do_PUT(self): self.dispatch()
            def dispatch(self):
                try: self.forward()
                except BaseException as error:
                    owner.errors.append(repr(error)); owner.history.emit('transport_fixture_failed', worker=worker, error=repr(error))
                finally: self.close_connection = True
            def forward(self):
                self.connection.settimeout(DEADLINES['s3_ms'] / 1000)
                length = int(self.headers.get('Content-Length', '0'))
                assert 0 <= length <= 4 * 1024 * 1024
                payload = self.rfile.read(length); assert len(payload) == length
                with owner.lock:
                    owner.s3_serial += 1
                    fields = {'request_serial': owner.s3_serial, 'worker': worker, 'phase': owner.phase,
                              'method': self.command, 'path': self.path,
                              'request_body': b64(payload), 'request_bytes': len(payload), 'request_sha256': sha(payload),
                              'if_match': self.headers.get('If-Match'), 'if_none_match': self.headers.get('If-None-Match'),
                              'signing': signing(self.headers)}
                if self.path.endswith('/head'): fields['head_request_bytes'] = list(payload)
                owner.history.emit('object_request', **fields)
                rule = owner.select('s3', fields, payload)
                if rule:
                    owner.enter(rule, request_serial=fields['request_serial'])
                    owner.history.emit('transport_fault_observed', mode=rule.fields['kind'], stage='before_forward', **fields)
                    if rule.fields['kind'] == 'blackhole':
                        owner.events.emit('s3_request_suppressed', id=rule.id, request_serial=fields['request_serial'])
                        return
                    owner.hold(rule)
                connection = http.client.HTTPConnection('127.0.0.1', owner.backend_port, timeout=8)
                try:
                    connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in self.headers.items(): connection.putheader(name, value)
                    connection.endheaders(payload); owner.history.emit('object_forwarded', **fields)
                    response = connection.getresponse(); raw = response.read(4 * 1024 * 1024 + 1)
                    assert len(raw) <= 4 * 1024 * 1024
                    received = {'status': response.status, 'response_body': b64(raw), 'response_bytes': len(raw),
                                'response_sha256': sha(raw), 'etag': response.getheader('ETag')}
                    if self.path.endswith('/head'): received['head_response_bytes'] = list(raw)
                    owner.history.emit('object_response', response_origin='backend', suppressed=False, **fields, **received)
                    if self.command == 'GET' and response.status == 200:
                        with owner.lock:
                            owner.reads[self.path] = {'body': raw, 'etag': received['etag'], 'request_serial': fields['request_serial']}
                    self.send_response_only(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ('connection', 'transfer-encoding', 'content-length'): self.send_header(name, value)
                    self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close'); self.end_headers()
                    self.wfile.write(raw); owner.history.emit('object_response_delivered', **fields, **received)
                finally: connection.close()
        return self.server(Relay)

    def http(self, worker, backend_port):
        owner = self
        class Relay(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_args): pass
            def do_POST(self):
                try: self.forward()
                except BaseException as error:
                    owner.errors.append(repr(error)); owner.events.emit('http_fixture_failed', worker=worker, error=repr(error))
                finally: self.close_connection = True
            def forward(self):
                self.connection.settimeout(DEADLINES['child_seconds'])
                length = int(self.headers.get('Content-Length', '0')); assert 0 <= length <= 65536
                payload = self.rfile.read(length); assert len(payload) == length and self.path == '/v1'
                token = self.headers.get('Authorization', '').removeprefix('Bearer ')
                with owner.lock:
                    owner.http_serial += 1
                    fields = {'http_serial': owner.http_serial, 'worker': worker,
                              'command': self.headers.get('X-SCAP-Fixture-Command'), 'method': 'POST', 'path': self.path,
                              'request_body': b64(payload), 'request_sha256': sha(payload), 'credential_sha256': sha(token.encode())}
                owner.events.emit('http_request', **fields)
                rule = owner.select('http', fields, payload)
                connection = None
                try:
                    if rule and rule.fields['kind'] == 'redirect':
                        owner.enter(rule, http_serial=fields['http_serial'])
                        status, raw, headers, origin = 307, b'', [('Location', owner.sink_url)], 'fault_redirect'
                    else:
                        connection = http.client.HTTPConnection('127.0.0.1', backend_port, timeout=DEADLINES['child_seconds'])
                        connection.putrequest('POST', self.path)
                        for name, value in self.headers.items():
                            if name.lower() not in ('host', 'connection'): connection.putheader(name, value)
                        connection.putheader('Connection', 'close'); connection.endheaders(payload)
                        owner.events.emit('http_forwarded', **fields)
                        response = connection.getresponse(); raw = response.read(4 * 1024 * 1024 + 1)
                        assert len(raw) <= 4 * 1024 * 1024
                        status, headers, origin = response.status, response.getheaders(), 'service'
                    received = {'status': status, 'response_body': b64(raw), 'response_sha256': sha(raw),
                                'headers': headers, 'origin': origin, 'suppressed': bool(rule and rule.fields['kind'] == 'drop')}
                    owner.events.emit('http_response', **fields, **received)
                    if rule and rule.fields['kind'] != 'redirect':
                        owner.enter(rule, http_serial=fields['http_serial'])
                        if rule.fields['kind'] == 'drop':
                            owner.events.emit('http_response_suppressed', id=rule.id, reason='explicit_response_loss', **fields)
                            return
                        owner.hold(rule)
                        if rule.fields.get('discard_after_release'):
                            owner.events.emit('http_response_suppressed', id=rule.id, reason='original_client_deadline', **fields)
                            return
                    self.send_response_only(status)
                    for name, value in headers:
                        if name.lower() not in ('connection', 'transfer-encoding', 'content-length'): self.send_header(name, value)
                    self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close'); self.end_headers()
                    self.wfile.write(raw); owner.events.emit('http_delivered', **fields, **received)
                finally:
                    if connection: connection.close()
        return self.server(Relay) + '/v1'

    def close(self):
        for rule in self.rules.values():
            if rule.entered.is_set() and rule.fields['kind'] == 'hold' and not rule.released.is_set():
                self.events.emit('fault_cleanup_release', id=rule.id); rule.released.set()
        for server, thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
            assert not thread.is_alive()
        self.events.emit('proxy_stopped', errors=self.errors, http_requests=self.http_serial, s3_requests=self.s3_serial)
