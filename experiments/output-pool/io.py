"""Real slow TCP consumers and bounded raw observations; no product internals."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time
from urllib.parse import urlsplit


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    with Path(path).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'file': Path(path).name, 'bytes': len(raw), 'sha256': sha(raw)}


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('original slow-response deadline')
    return value


class SlowResponse:
    """Read only headers, then explicitly drain or reset the actual connection.

    Constructor timeout is one absolute deadline covering header and body reads.
    Reads never consume body bytes before drain(); peer truncation is separate
    from the explicit client disconnect event. emit accepts (event, **fields).
    """

    def __init__(self, endpoint, token, body, evidence, identifier, emit, timeout=180):
        parsed = urlsplit(endpoint)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1':
            raise ValueError('fixture only permits local HTTP')
        self.evidence, self.identifier, self.emit = Path(evidence), identifier, emit
        self.deadline = time.monotonic() + timeout
        self.body_prefix = b''
        self.closed = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.receive_buffer = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        request = save(self.evidence / (identifier + '.request.json'), body)
        emit('http_request', id=identifier, client='slow', request=request,
             token_sha256=sha(token.encode()), method='POST', path='/v1')
        try:
            self.socket.settimeout(remaining(self.deadline))
            self.socket.connect((parsed.hostname, parsed.port))
            header = (f'POST /v1 HTTP/1.1\r\nHost: 127.0.0.1:{parsed.port}\r\n'
                      f'Authorization: Bearer {token}\r\nContent-Type: application/json\r\n'
                      f'X-Scap-Admission: data\r\nContent-Length: {len(body)}\r\n'
                      'Connection: close\r\n\r\n').encode('ascii')
            self.socket.sendall(header + body)
            raw = bytearray()
            while not raw.endswith(b'\r\n\r\n'):
                if len(raw) >= 65536:
                    raise ValueError('response headers exceed fixture limit')
                self.socket.settimeout(remaining(self.deadline))
                byte = self.socket.recv(1)
                if not byte:
                    raise EOFError('peer closed before complete response headers')
                raw.extend(byte)
            lines = bytes(raw).decode('latin1').split('\r\n')
            self.status = int(lines[0].split(' ')[1])
            self.headers = {}
            for line in lines[1:]:
                if not line:
                    continue
                key, value = line.split(':', 1)
                key = key.lower()
                if key in self.headers:
                    raise ValueError('duplicate response header')
                self.headers[key] = value.strip()
            if 'transfer-encoding' in self.headers:
                raise ValueError('expected exact Content-Length response')
            self.length = int(self.headers['content-length'])
            if not 0 <= self.length <= 96 * 1024 * 1024:
                raise ValueError('response body exceeds fixture limit')
            self.header_file = save(self.evidence / (identifier + '.headers'), bytes(raw))
            emit('slow_headers', id=identifier, status=self.status, headers=self.header_file,
                 content_length=self.length, receive_buffer=self.receive_buffer,
                 body_bytes_read=0, socket_local=list(self.socket.getsockname()),
                 socket_peer=list(self.socket.getpeername()))
        except BaseException:
            self.socket.close()
            self.closed = True
            raise

    def drain(self, allow_truncated=False):
        if self.closed:
            raise ValueError('slow socket already closed')
        self.emit('slow_drain_started', id=self.identifier, body_bytes_read=0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        path = self.evidence / (self.identifier + '.response.json')
        count, digest, peer_eof, failure = 0, hashlib.sha256(), False, None
        try:
            with path.open('xb') as stream:
                while count < self.length:
                    self.socket.settimeout(remaining(self.deadline))
                    try:
                        raw = self.socket.recv(min(1024 * 1024, self.length - count))
                    except (ConnectionResetError, BrokenPipeError) as error:
                        failure = type(error).__name__
                        break
                    if not raw:
                        peer_eof = True
                        break
                    count += len(raw)
                    digest.update(raw)
                    stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            self.socket.close()
            self.closed = True
        record = {'file': path.name, 'bytes': count, 'sha256': digest.hexdigest()}
        self.emit('http_response', id=self.identifier, client='slow', status=self.status,
                  response=record, complete=count == self.length, peer_eof=peer_eof,
                  peer_failure=failure, expected_bytes=self.length)
        if count != self.length and not allow_truncated:
            raise EOFError('slow response was truncated by peer')
        return record

    def disconnect(self):
        if self.closed:
            return
        self.emit('slow_disconnect_requested', id=self.identifier, body_bytes_read=0,
                  method='TCP_RST')
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self.socket.close()
        self.closed = True
        self.emit('slow_disconnected', id=self.identifier, body_bytes_read=0,
                  method='TCP_RST')
