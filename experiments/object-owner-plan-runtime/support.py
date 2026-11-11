"""Raw owned process/SigV4 observer; no product or acceptance algorithm."""
from __future__ import annotations

import http.client
import http.server
import importlib.util
import json
from pathlib import Path
import re
import sys
import threading

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_spec = importlib.util.spec_from_file_location('owner_original_transport',
    HERE.parent / 'object-reclamation-runtime/support.py')
shared = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = shared
_spec.loader.exec_module(shared)
Child = shared.Child
network, signing = shared.network, shared.signing
service_build, seed_build = shared.service_build, shared.seed_build
sha, encoded, save, module = shared.sha, shared.encoded, shared.save, shared.module
MAX_RAW = shared.MAX_RAW


class Trace(shared.Trace):
    """Wake a runner only after an existing observer has durably logged an event."""
    def __init__(self, evidence):
        super().__init__(evidence)
        self.watches = []

    def watch(self, event, **fields):
        observed = threading.Event()
        with self.lock:
            assert len(self.watches) < 16
            self.watches.append((event, fields, observed))
        return observed

    def emit(self, event, **fields):
        with self.lock:
            row = super().emit(event, **fields)
            for expected, matching, observed in tuple(self.watches):
                if event == expected and all(row.get(key) == value for key, value in matching.items()):
                    self.watches.remove((expected, matching, observed))
                    observed.set()
            return row


class Gate:
    def __init__(self, identifier, method, prefix, mode, stage='before_forward', occurrence=1,
                 uses=1, mutation=None):
        assert mode in ('hold', 'drop', 'no_such_key', 'replace_body')
        assert stage in ('before_forward', 'after_response')
        assert type(occurrence) is int and occurrence > 0
        assert type(uses) is int and uses in (1, 2)
        assert (mode == 'replace_body') == (mutation is not None)
        assert mode != 'replace_body' or stage == 'after_response'
        assert mode != 'no_such_key' or stage == 'before_forward'
        assert uses == 1 or mode == 'no_such_key' or mode == 'replace_body' and mutation['kind'] == 'same_id_hash'
        self.id, self.method, self.prefix = identifier, method, prefix
        self.mode, self.stage, self.occurrence = mode, stage, occurrence
        self.uses, self.mutation = uses, mutation
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
                            if not selected.occurrence <= selected.seen < selected.occurrence + selected.uses:
                                selected = None
                        if selected:
                            selected.used += 1
                            if selected.used == selected.uses:
                                owner.gate = None
                    if selected and selected.stage == 'before_forward':
                        if not owner.reached(selected, fields, payload):
                            return
                        if selected.mode == 'no_such_key':
                            body = b'<Error><Code>NoSuchKey</Code><Message>fixture</Message></Error>'
                            owner.deliver(self, fields, 404, {}, body, 'fixture_no_such_key')
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
                    origin = 'backend'
                    if selected and selected.mode == 'replace_body':
                        assert response.status == 200
                        original = body
                        body = owner.mutate(selected, body)
                        origin = 'fixture_metadata_mutation'
                        trace.emit('fault_body_replaced', id=selected.id, mutation=selected.mutation,
                                   original=trace.raw(original), replacement=trace.raw(body), **fields)
                    owner.deliver(self, fields, response.status, received_headers, body, origin)
                except BaseException as error:
                    owner.errors.append({'role': role, 'serial': serial, 'error': repr(error)})
                    trace.emit('s3_fixture_error', error=repr(error), **fields)
                finally:
                    if connection:
                        connection.close()
                    if selected and selected.used == selected.uses:
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
        self.trace.emit('s3_delivery_started', status=status, origin=origin, headers=headers,
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
        self.trace.emit('fault_arrived', id=gate.id, mode=gate.mode, stage=gate.stage,
                        use=gate.used, uses=gate.uses, **fields)
        gate.arrived.set()
        if gate.mode in ('no_such_key', 'replace_body'):
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

    @staticmethod
    def mutate(gate, raw):
        value = json.loads(raw)
        mutation = gate.mutation
        if mutation['kind'] == 'same_id_hash':
            reference = value['owner_plan']['reference']
            assert reference['creator'] == mutation['creator'] and reference['operation'] == mutation['operation']
            assert reference['descriptor_hash'] != mutation['descriptor_hash']
            reference['descriptor_hash'] = mutation['descriptor_hash']
        elif mutation['kind'] == 'proof_at_admission':
            value['marker']['phase']['revision'] = mutation['revision']
            value['marker']['phase']['head_serial'] = mutation['head_serial']
        else:
            raise ValueError('unplanned metadata delivery mutation')
        return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()

    def arm(self, identifier, method, prefix, mode, stage='before_forward', occurrence=1,
            uses=1, mutation=None):
        gate = Gate(identifier, method, prefix, mode, stage, occurrence, uses, mutation)
        with self.lock:
            assert self.gate is None
            self.gate = gate
            self.gates.append(gate)
        self.trace.emit('fault_armed', role=self.role, id=identifier, method=method,
                        prefix=prefix, mode=mode, stage=stage, occurrence=occurrence,
                        uses=uses, mutation=mutation)
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
        self.trace.emit('s3_proxy_stopped', role=self.role, errors=self.errors, joined=True,
                        request_count=self.serial)
