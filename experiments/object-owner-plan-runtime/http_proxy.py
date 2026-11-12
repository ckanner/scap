"""Bounded, owned HTTP observation and transport faults for the owner fixture.

Only the caller's shared Trace writes evidence. A backend response, a successful
socket write, and an SDK acknowledgement are three different observations. The
proxy never retries, redirects, fabricates a product response, or cancels a
forwarded operation when the original caller disconnects.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import secrets
import socket
import socketserver
import threading
import time


MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 64 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADERS = 64
MAX_HANDLERS = 16
MAX_REQUESTS = 10000
MAX_GATES = 128
INPUT_SECONDS = 10
OUTPUT_SECONDS = 10
BACKEND_SECONDS = 330
HOLD_SECONDS = 180
CLOSE_SECONDS = 10
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
HOP = frozenset(('connection', 'proxy-connection', 'keep-alive', 'te', 'trailer',
                 'upgrade', 'transfer-encoding', 'content-length', 'host'))
PRIVATE = frozenset(('authorization', 'proxy-authorization', 'cookie',
                     'set-cookie', 'x-api-key', 'x-amz-security-token'))


class ProxyError(Exception):
    """A fixed, non-secret fixture error code; never contains a header value."""


class Closing(Exception):
    pass


class Gate:
    def __init__(self, identifier, operation, mode, stage, occurrence):
        self.id, self.operation = identifier, operation
        self.mode, self.stage, self.occurrence = mode, stage, occurrence
        self.seen = self.used = 0
        self.arrived, self.released, self.finished = (threading.Event() for _ in range(3))
        self.observed = None
        self.aborted = False


class Connection:
    def __init__(self, identifier, client, phase):
        self.id, self.client, self.phase = identifier, client, phase
        self.thread = self.backend_socket = self.gate = None
        self.serial = None
        self.fields = None
        self.stage = 'input'
        self.deadline = self.absolute = time.monotonic() + INPUT_SECONDS
        self.interrupted = None
        self.finished = False


class Server(socketserver.TCPServer):
    allow_reuse_address = False
    request_queue_size = MAX_HANDLERS

    def process_request(self, request, client_address):
        self.owner._accept(request, client_address)

    def service_actions(self):
        self.owner._expire()
        self.owner._reap()


class Handler(socketserver.StreamRequestHandler):
    def __init__(self, request, address, server, owner, connection):
        self.owner, self.owned = owner, connection
        super().__init__(request, address, server)

    def handle(self):
        self.owner._dispatch(self, self.owned)


class HTTPProxy:
    """One incarnation's listener forwarding to one fixed loopback daemon port.

    Each connection accepts at most one POST. The listener owns at most sixteen
    handlers and one watchdog/listener thread. Response byte caps bound the
    captured representation, not the Python process's total RSS or kernel memory.
    """

    def __init__(self, role, target_port, trace, tokens):
        if not isinstance(role, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', role):
            raise ValueError('invalid proxy role')
        if type(target_port) is not int or not 1 <= target_port <= 65535:
            raise ValueError('invalid loopback target port')
        if not isinstance(tokens, dict) or not 1 <= len(tokens) <= 16:
            raise ValueError('invalid principal configuration')
        for principal, token in tokens.items():
            if (not isinstance(principal, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', principal)
                    or int(principal) > 2**64 - 1 or not isinstance(token, str)
                    or not 1 <= len(token) <= 4096
                    or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                raise ValueError('invalid principal configuration')
        if len(set(tokens.values())) != len(tokens):
            raise ValueError('ambiguous principal configuration')
        self.role, self.target_port, self.trace = role, target_port, trace
        self.tokens = dict(tokens)
        self.lock = threading.RLock()
        self.phase, self.serial, self.connection_count = 'setup', 0, 0
        self.connections, self.gates, self.errors = {}, [], []
        self.gate = None
        self.closing = self.closed = False
        self.server = Server(('127.0.0.1', 0), socketserver.BaseRequestHandler)
        self.server.owner = self
        self.endpoint = 'http://127.0.0.1:' + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval': 0.02}, name='owner-http-' + role, daemon=False)
        try:
            self.thread.start()
            trace.emit('http_proxy_started', role=role, endpoint=self.endpoint,
                target_port=target_port, limits={'request_bytes': MAX_REQUEST,
                'response_bytes': MAX_RESPONSE, 'header_bytes': MAX_HEADER_BYTES,
                'headers': MAX_HEADERS, 'handlers': MAX_HANDLERS, 'requests': MAX_REQUESTS,
                'gates': MAX_GATES, 'input_seconds': INPUT_SECONDS,
                'output_seconds': OUTPUT_SECONDS, 'backend_seconds': BACKEND_SECONDS,
                'hold_seconds': HOLD_SECONDS, 'close_seconds': CLOSE_SECONDS})
        except BaseException:
            try:
                if self.thread.ident is None:
                    self.server.server_close()
                else:
                    self.close()
            except BaseException:
                pass
            raise

    @staticmethod
    def _shutdown(sock):
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _error(self, code, connection=None, error=None):
        fields = {'role': self.role, 'code': code}
        if connection:
            fields.update(connection.fields or {'connection': connection.id,
                          'phase': connection.phase, 'serial': connection.serial})
        if error is not None:
            fields['error_type'] = type(error).__name__
        with self.lock:
            self.errors.append(fields)
        try:
            self.trace.emit('http_proxy_fixture_error', **fields)
        except BaseException:
            # Evidence failure cannot skip socket/thread ownership cleanup.
            with self.lock:
                self.errors.append({'role': self.role, 'code': 'trace_failed'})

    def _accept(self, client, address):
        self._reap()
        with self.lock:
            self.connection_count += 1
            identifier = self.connection_count
            if self.closing or len(self.connections) >= MAX_HANDLERS:
                try:
                    self.trace.emit('http_proxy_connection_rejected', role=self.role,
                        connection=identifier, reason='closing' if self.closing else 'capacity')
                    if not self.closing:
                        self._error('handler_capacity')
                finally:
                    self._shutdown(client)
                    client.close()
                return
            connection = Connection(identifier, client, self.phase)
            self.connections[identifier] = connection
            try:
                self.trace.emit('http_proxy_connection_started', role=self.role,
                    connection=identifier, phase=connection.phase)
                connection.thread = threading.Thread(target=self._serve,
                    args=(connection, address), name=f'owner-http-{self.role}-{identifier}',
                    daemon=False)
                connection.thread.start()
            except BaseException as error:
                del self.connections[identifier]
                self._shutdown(client)
                client.close()
                self._error('handler_start', connection, error)

    def _serve(self, connection, address):
        try:
            connection.client.settimeout(INPUT_SECONDS)
            Handler(connection.client, address, self.server, self, connection)
        except BaseException as error:
            self._error('handler_unhandled', connection, error)
        finally:
            self._shutdown(connection.backend_socket)
            self._shutdown(connection.client)
            connection.client.close()
            try:
                self.trace.emit('http_proxy_connection_finished', role=self.role,
                    connection=connection.id, serial=connection.serial)
            except BaseException as error:
                self._error('connection_finish_trace', connection, error)
            finally:
                with self.lock:
                    connection.finished = True

    def _reap(self):
        # A handler marking itself finished is not yet proof that its thread
        # exited. Retain ownership until an external join observes completion.
        with self.lock:
            ended = [c for c in self.connections.values()
                     if c.finished and not c.thread.is_alive()]
            for connection in ended:
                connection.thread.join(0)
                del self.connections[connection.id]

    def _remaining(self, connection):
        with self.lock:
            if self.closing or connection.interrupted == 'closing':
                raise Closing()
            remaining = connection.deadline - time.monotonic()
            if connection.interrupted or remaining <= 0:
                raise TimeoutError('proxy absolute deadline')
            return remaining

    def _stage(self, connection, stage, seconds):
        with self.lock:
            self._remaining(connection)
            connection.stage = stage
            connection.deadline = min(connection.absolute, time.monotonic() + seconds)

    def _expire(self):
        with self.lock:
            expired = [c for c in self.connections.values()
                       if not c.finished and c.interrupted is None and time.monotonic() >= c.deadline]
            for connection in expired:
                connection.interrupted = 'deadline'
                if connection.gate and not connection.gate.finished.is_set():
                    connection.gate.aborted = True
                    connection.gate.released.set()
        for connection in expired:
            self._shutdown(connection.client)
            self._shutdown(connection.backend_socket)
            if connection.stage.startswith('hold_'):
                self._error('gate_deadline', connection)
            try:
                self.trace.emit('http_proxy_deadline', role=self.role,
                    connection=connection.id, serial=connection.serial, stage=connection.stage)
            except BaseException as error:
                self._error('deadline_trace', connection, error)

    def _headers(self, stream):
        used, result = 0, {}
        while True:
            raw = stream.readline(MAX_HEADER_BYTES - used + 1)
            used += len(raw)
            if used > MAX_HEADER_BYTES or not raw.endswith(b'\r\n'):
                raise ProxyError('request_headers')
            if raw == b'\r\n':
                return result
            if len(result) >= MAX_HEADERS or b':' not in raw:
                raise ProxyError('request_headers')
            name, value = raw[:-2].split(b':', 1)
            name = name.decode('ascii').lower()
            value = value.decode('latin-1').strip(' \t')
            if (not TOKEN.fullmatch(name) or name in result
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ProxyError('request_headers')
            result[name] = value

    def _request(self, handler, connection):
        line = handler.rfile.readline(MAX_HEADER_BYTES + 1)
        if line == b'':
            self.trace.emit('http_proxy_connection_empty', role=self.role, connection=connection.id)
            return None
        if len(line) > MAX_HEADER_BYTES or not line.endswith(b'\r\n'):
            raise ProxyError('request_line')
        parts = line[:-2].decode('ascii').split(' ')
        if len(parts) != 3:
            raise ProxyError('request_line')
        method, path, version = parts
        with self.lock:
            if self.serial >= MAX_REQUESTS:
                raise ProxyError('request_count_limit')
            self.serial += 1
            connection.serial = self.serial
        fields = connection.fields = {'role': self.role, 'connection': connection.id,
            'serial': connection.serial, 'phase': connection.phase,
            'method': method, 'path': path, 'operation': None}
        if method != 'POST' or path not in ('/v1', '/v1/catalogue') or version != 'HTTP/1.1':
            raise ProxyError('request_target')
        headers = self._headers(handler.rfile)
        if ('transfer-encoding' in headers or 'expect' in headers
                or not re.fullmatch(r'0|[1-9][0-9]*', headers.get('content-length', ''))):
            raise ProxyError('request_framing')
        length = int(headers['content-length'])
        if length > MAX_REQUEST:
            raise ProxyError('request_size')
        authorization = headers.get('authorization', '')
        principal, token = None, ''
        if authorization.startswith('Bearer '):
            token = authorization[7:]
            for identity, configured in self.tokens.items():
                if secrets.compare_digest(token.encode('latin-1'), configured.encode('ascii')):
                    principal = identity
        if principal is None:
            raise ProxyError('request_authorization')
        payload = handler.rfile.read(length)
        if len(payload) != length:
            raise ProxyError('request_incomplete')
        value = json.loads(payload)
        operation = value.get('operation') if isinstance(value, dict) else None
        if not isinstance(operation, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', operation):
            raise ProxyError('request_operation')
        fields['operation'] = operation
        self.trace.emit('http_proxy_handler_started', **fields)
        raw = self.trace.raw(payload)
        public = {k: v for k, v in headers.items() if k not in PRIVATE}
        self.trace.emit('http_proxy_request', request=raw, headers=public,
            principal=principal, token_sha256=hashlib.sha256(token.encode('ascii')).hexdigest(), **fields)
        with self.lock:
            self._remaining(connection)
            connection.absolute = time.monotonic() + HOLD_SECONDS + BACKEND_SECONDS + OUTPUT_SECONDS
            connection.deadline = connection.absolute
        return headers, payload, raw

    def _select(self, connection):
        with self.lock:
            gate = self.gate
            if gate is None or gate.operation != connection.fields['operation']:
                return None
            gate.seen += 1
            if gate.seen != gate.occurrence:
                return None
            gate.used += 1
            self.gate = None
            connection.gate = gate
            return gate

    def _reached(self, connection, gate, request):
        gate.observed = {**connection.fields, 'request': request}
        self.trace.emit('http_proxy_fault_arrived', id=gate.id, mode=gate.mode,
            stage=gate.stage, **connection.fields)
        gate.arrived.set()
        if gate.mode == 'hold':
            self._stage(connection, 'hold_' + gate.stage, HOLD_SECONDS)
            if not gate.released.wait(self._remaining(connection)):
                gate.aborted = True
                raise ProxyError('gate_deadline')
        if gate.aborted or gate.mode == 'drop':
            self.trace.emit('http_proxy_delivery_suppressed', id=gate.id,
                stage=gate.stage, mode=gate.mode, aborted=gate.aborted, **connection.fields)
            self._shutdown(connection.client)
            return False
        self.trace.emit('http_proxy_fault_released', id=gate.id, stage=gate.stage, **connection.fields)
        return True

    def _forward(self, connection, headers, payload, request):
        self._stage(connection, 'backend', BACKEND_SECONDS)
        backend = http.client.HTTPConnection('127.0.0.1', self.target_port,
                                             timeout=self._remaining(connection))
        response = None
        fields = connection.fields
        try:
            outgoing = {k: v for k, v in headers.items() if k not in HOP}
            outgoing.update({'host': '127.0.0.1:' + str(self.target_port),
                'content-length': str(len(payload)), 'connection': 'close'})
            self.trace.emit('http_proxy_forward_started', request=request,
                headers={k: v for k, v in outgoing.items() if k not in PRIVATE},
                target_port=self.target_port, **fields)
            backend.connect()
            with self.lock:
                connection.backend_socket = backend.sock
                self._remaining(connection)
            backend.putrequest('POST', fields['path'], skip_host=True, skip_accept_encoding=True)
            for name, value in outgoing.items():
                backend.putheader(name, value)
            backend.endheaders(payload)
            self.trace.emit('http_proxy_forward_finished', **fields)
            response = backend.getresponse()
            received = {}
            total = 0
            for name, value in response.getheaders():
                name = name.lower()
                total += len(name) + len(value) + 4
                if (name in received or not TOKEN.fullmatch(name)
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                    raise ProxyError('backend_headers')
                received[name] = value
            if total > MAX_HEADER_BYTES or len(received) > MAX_HEADERS:
                raise ProxyError('backend_headers')
            if not 200 <= response.status <= 599:
                raise ProxyError('backend_status')
            declared = received.get('content-length')
            transfer = received.get('transfer-encoding')
            if ((declared is not None and (not re.fullmatch(r'0|[1-9][0-9]*', declared)
                                          or int(declared) > MAX_RESPONSE))
                    or (transfer is not None and (transfer.lower() != 'chunked' or declared is not None))):
                raise ProxyError('backend_framing')
            body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise ProxyError('backend_size')
            raw = self.trace.raw(body)
            public = {k: v for k, v in received.items() if k not in PRIVATE}
            if declared is not None and len(body) != int(declared):
                self.trace.emit('http_proxy_backend_failure', failure='IncompleteBody',
                    status=response.status, headers=public, response=raw, **fields)
                return None
            self.trace.emit('http_proxy_backend_response', status=response.status,
                headers=public, response=raw, **fields)
            return response.status, received, body, raw
        except (OSError, http.client.HTTPException, Closing) as error:
            partial = error.partial if isinstance(error, http.client.IncompleteRead) else None
            extra = {'response': self.trace.raw(partial)} if partial is not None and len(partial) <= MAX_RESPONSE else {}
            self.trace.emit('http_proxy_backend_failure', failure=type(error).__name__,
                closing=self.closing, **extra, **fields)
            return None
        finally:
            if response:
                response.close()
            backend.close()
            with self.lock:
                connection.backend_socket = None

    def _deliver(self, connection, status, headers, body, raw):
        self._stage(connection, 'output', OUTPUT_SECONDS)
        self.trace.emit('http_proxy_delivery_started', status=status, response=raw,
                        **connection.fields)
        complete, failure = False, None
        try:
            lines = [f'HTTP/1.1 {status} {http.client.responses.get(status, "")}\r\n']
            lines.extend(f'{k}: {v}\r\n' for k, v in headers.items() if k not in HOP)
            lines.extend((f'Content-Length: {len(body)}\r\n', 'Connection: close\r\n', '\r\n'))
            connection.client.settimeout(self._remaining(connection))
            connection.client.sendall(''.join(lines).encode('latin-1'))
            connection.client.sendall(body)
            complete = True
        except (OSError, Closing) as error:
            failure = type(error).__name__
        self.trace.emit('http_proxy_delivery_finished', complete=complete, failure=failure,
                        **connection.fields)

    def _dispatch(self, handler, connection):
        selected = None
        try:
            request = self._request(handler, connection)
            if request is None:
                return
            headers, payload, raw = request
            selected = self._select(connection)
            if selected and selected.stage == 'before_forward' and not self._reached(connection, selected, raw):
                return
            result = self._forward(connection, headers, payload, raw)
            if result is None:
                self.trace.emit('http_proxy_delivery_skipped', reason='backend_failure', **connection.fields)
                return
            if selected and selected.stage == 'after_response' and not self._reached(connection, selected, raw):
                return
            self._deliver(connection, *result)
        except Closing:
            self.trace.emit('http_proxy_handler_aborted', reason='closing',
                            **(connection.fields or {'role': self.role, 'connection': connection.id}))
        except BaseException as error:
            if self.closing:
                self.trace.emit('http_proxy_handler_aborted', reason='closing',
                    **(connection.fields or {'role': self.role, 'connection': connection.id}))
            else:
                self._error(str(error) if isinstance(error, ProxyError) else 'handler_error', connection, error)
        finally:
            try:
                if connection.serial is not None:
                    self.trace.emit('http_proxy_handler_finished', **connection.fields)
            except BaseException as error:
                self._error('handler_finish_trace', connection, error)
            finally:
                if selected:
                    selected.finished.set()

    def arm(self, identifier, operation, mode='drop', stage='after_response', occurrence=1):
        if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identifier)
                or not isinstance(operation, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', operation)
                or mode not in ('hold', 'drop') or stage not in ('before_forward', 'after_response')
                or (mode == 'drop' and stage != 'after_response')
                or type(occurrence) is not int or not 1 <= occurrence <= MAX_REQUESTS):
            raise ValueError('invalid HTTP fault')
        gate = Gate(identifier, operation, mode, stage, occurrence)
        with self.lock:
            if self.closing or self.gate or len(self.gates) >= MAX_GATES or any(g.id == identifier for g in self.gates):
                raise ValueError('HTTP fault unavailable')
            self.trace.emit('http_proxy_fault_armed', role=self.role, id=identifier,
                operation=operation, mode=mode, stage=stage, occurrence=occurrence)
            self.gate = gate
            self.gates.append(gate)
        return gate

    def release(self, gate):
        with self.lock:
            if (gate not in self.gates or gate.mode != 'hold' or not gate.arrived.is_set()
                    or gate.released.is_set() or gate.aborted):
                raise ValueError('HTTP gate cannot be released')
            self.trace.emit('http_proxy_release_requested', role=self.role, id=gate.id)
            gate.released.set()

    def phase_to(self, phase):
        if not isinstance(phase, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', phase):
            raise ValueError('invalid HTTP phase')
        with self.lock:
            if self.closing:
                raise ValueError('HTTP proxy closing')
            self.trace.emit('http_proxy_phase', role=self.role, phase=phase)
            self.phase = phase

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closing = True
            for gate in self.gates:
                if not gate.finished.is_set():
                    gate.aborted = True
                    gate.released.set()
                    if not gate.arrived.is_set():
                        gate.finished.set()
            self.gate = None
            for connection in self.connections.values():
                connection.interrupted = 'closing'
                self._shutdown(connection.client)
                self._shutdown(connection.backend_socket)
        deadline = time.monotonic() + CLOSE_SECONDS
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(max(0, deadline - time.monotonic()))
        with self.lock:
            remaining = list(self.connections.values())
        for connection in remaining:
            connection.thread.join(max(0, deadline - time.monotonic()))
        self._reap()
        with self.lock:
            joined = not self.thread.is_alive() and not self.connections
            self.closed = joined
        self.trace.emit('http_proxy_closed', role=self.role, joined=joined,
            request_count=self.serial, connection_count=self.connection_count,
            errors=list(self.errors))
        if not joined:
            raise RuntimeError('owned HTTP proxy did not stop within fixed close deadline')
