/** Fixture-only observation of the original Fetch; never dispatch, retry or alter a socket. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { subscribe, unsubscribe } from 'node:diagnostics_channel';

export const LIMITS = Object.freeze({ callEvents: 64, callRequests: 8, callConnections: 8,
  connectionEvents: 16, activeConnections: 128, pendingEvents: 1024 });
const NAMES = new Set(['Error', 'TypeError', 'RangeError', 'SyntaxError', 'AbortError',
  'TimeoutError', 'AggregateError', 'SocketError', 'ConnectTimeoutError', 'HeadersTimeoutError',
  'BodyTimeoutError', 'ClientClosedError', 'ClientDestroyedError', 'RequestAbortedError']);
const CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'ENETUNREACH',
  'EHOSTUNREACH', 'EAI_AGAIN', 'ENOTFOUND', 'EMFILE', 'ENFILE', 'ENOBUFS', 'ENOMEM',
  'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_CLOSED', 'UND_ERR_DESTROYED', 'UND_ERR_ABORTED', 'UND_ERR_INFO',
  'UND_ERR_REQ_CONTENT_LENGTH_MISMATCH', 'UND_ERR_RES_CONTENT_LENGTH_MISMATCH',
  'HPE_INVALID_HEADER_TOKEN', 'HPE_INVALID_CONTENT_LENGTH', 'HPE_UNEXPECTED_CONTENT_LENGTH',
  'HPE_INVALID_EOF_STATE']);
const object = (value) => value !== null && (typeof value === 'object' || typeof value === 'function');
const now = () => process.hrtime.bigint().toString();
function field(value, name) {
  try { return object(value) ? value[name] : undefined; } catch { return undefined; }
}
const allowed = (value, choices) => typeof value === 'string' && choices.has(value) ? value : 'UNKNOWN';

/** Do not retain arbitrary messages, stacks, URLs, headers, addresses or unknown code strings. */
export function safeError(error) {
  return { error_name: allowed(field(error, 'name'), NAMES),
    error_code: allowed(field(error, 'code'), CODES),
    cause_code: allowed(field(field(error, 'cause'), 'code'), CODES) };
}

export function createObservation(writeRows) {
  const context = new AsyncLocalStorage(), requests = new WeakMap(), sockets = new WeakMap();
  const activeSockets = new Map(), subscriptions = [];
  let pending = [], overflow = null, sequence = 0, connectionSerial = 0;
  let closed = false, incomplete = false;

  function enqueue(event, fields = {}) {
    if (closed) return false;
    const row = { sequence: ++sequence, monotonic_ns: now(), event, ...fields };
    if (pending.length < LIMITS.pendingEvents) { pending.push(row); return true; }
    incomplete = true;
    overflow ??= { sequence: row.sequence, monotonic_ns: row.monotonic_ns,
      event: 'observation_incomplete', scope: 'observer', reason: 'pending_event_limit' };
    return false;
  }
  function mark(scope, reason, call) {
    incomplete = true;
    if (call) {
      call.incomplete = true;
      if (call.marked) return;
      call.marked = true;
    }
    enqueue('observation_incomplete', { scope, reason, ...(call ? { call_id: call.id } : {}) });
  }
  function callEvent(call, event, fields = {}) {
    if (call.events >= LIMITS.callEvents) { mark('call', 'call_event_limit', call); return; }
    call.events++;
    if (!enqueue(event, { call_id: call.id, ...fields })) call.incomplete = true;
  }
  function connectionEvent(info, event, fields = {}) {
    if (info.events >= LIMITS.connectionEvents) {
      incomplete = true;
      if (!info.marked) {
        info.marked = true;
        enqueue('observation_incomplete', { scope: 'connection', connection_id: info.id,
          reason: 'connection_event_limit' });
      }
      return;
    }
    info.events++;
    enqueue(event, { connection_id: info.id, ...fields });
  }
  function detach(socket) {
    const tracked = activeSockets.get(socket);
    if (!tracked) return;
    for (const [name, handler] of tracked.handlers) socket.removeListener(name, handler);
    activeSockets.delete(socket);
  }
  function socketIdentity(socket, call) {
    if (!object(socket) || typeof field(socket, 'on') !== 'function' ||
        typeof field(socket, 'removeListener') !== 'function') {
      mark('call', 'socket_identity_unavailable', call); return 'UNKNOWN';
    }
    const known = sockets.get(socket);
    if (known) {
      if (known.closed) { mark('call', 'closed_socket_identity_reused', call); return 'UNKNOWN'; }
      return known.id;
    }
    if (activeSockets.size >= LIMITS.activeConnections) {
      mark('call', 'active_connection_limit', call); return 'UNKNOWN';
    }
    const info = { id: `${process.pid}:connection:${++connectionSerial}`, events: 0, marked: false, closed: false };
    const handlers = [
      ['end', () => connectionEvent(info, 'socket_end')],
      ['error', (error) => connectionEvent(info, 'socket_error', safeError(error))],
      ['close', (hadError) => {
        info.closed = true;
        connectionEvent(info, 'socket_close', { had_error: typeof hadError === 'boolean' ? hadError : 'UNKNOWN' });
        detach(socket);
      }],
    ];
    sockets.set(socket, info);
    activeSockets.set(socket, { handlers });
    for (const [name, handler] of handlers) socket.on(name, handler);
    connectionEvent(info, 'socket_observed');
    return info.id;
  }
  function binding(data) {
    const request = field(data, 'request');
    return object(request) ? requests.get(request) : undefined;
  }
  function watch(name, handler) {
    const callback = (data) => {
      if (closed) return;
      // A diagnostics subscriber must never throw into Undici's network path.
      try { handler(data); } catch { mark('observer', 'diagnostic_callback_error'); }
    };
    subscribe(name, callback);
    subscriptions.push([name, callback]);
  }

  watch('undici:request:create', (data) => {
    const call = context.getStore();
    if (!call) return; // No temporal/last-call inference for unrelated diagnostics.
    const request = field(data, 'request');
    if (!object(request)) { mark('call', 'request_identity_unavailable', call); return; }
    if (requests.has(request)) { mark('call', 'request_identity_reused', call); return; }
    if (call.requests.length >= LIMITS.callRequests) { mark('call', 'call_request_limit', call); return; }
    const id = `${call.id}:request:${call.requests.length + 1}`;
    call.requests.push(id);
    requests.set(request, { call, id });
    callEvent(call, 'request_created', { request_id: id });
  });
  watch('undici:client:sendHeaders', (data) => {
    const request = binding(data);
    if (!request) return;
    const id = socketIdentity(field(data, 'socket'), request.call);
    if (id !== 'UNKNOWN' && !request.call.connections.has(id)) {
      if (request.call.connections.size >= LIMITS.callConnections) {
        mark('call', 'call_connection_limit', request.call);
        callEvent(request.call, 'request_send_headers', { request_id: request.id, connection_id: 'UNKNOWN' });
        return;
      }
      request.call.connections.add(id);
    }
    callEvent(request.call, 'request_send_headers', { request_id: request.id, connection_id: id });
  });
  watch('undici:request:headers', (data) => {
    const request = binding(data);
    if (!request) return;
    const status = field(field(data, 'response'), 'statusCode');
    callEvent(request.call, 'request_response_headers', { request_id: request.id,
      status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : 'UNKNOWN' });
  });
  watch('undici:request:trailers', (data) => {
    const request = binding(data);
    if (request) callEvent(request.call, 'request_body_complete', { request_id: request.id });
  });
  watch('undici:request:error', (data) => {
    const request = binding(data);
    if (request) callEvent(request.call, 'request_error', { request_id: request.id, ...safeError(field(data, 'error')) });
  });

  function flush() {
    if (pending.length === 0 && overflow === null) return;
    // One reserved overflow marker beyond the fixed queue; failed writes cannot grow it.
    const rows = overflow ? [...pending, overflow] : pending;
    // Keep the batch until the synchronous evidence writer has succeeded.
    writeRows(rows);
    pending = []; overflow = null;
  }
  function begin(id) {
    const known = typeof id === 'string' && /^[a-zA-Z0-9_:.-]{1,256}$/.test(id);
    const call = { id: known ? id : 'UNKNOWN', events: 0, requests: [], connections: new Set(), incomplete: false, marked: false };
    if (!known) mark('call', 'call_identifier_unavailable', call);
    callEvent(call, 'fetch_started');
    return call;
  }
  function finish(call, outcome, stage) {
    callEvent(call, 'call_observation_finished', { outcome, stage,
      observation_status: call.incomplete ? 'INCOMPLETE' : 'RECORDED',
      request_identity: call.requests.length ? 'OBSERVED' : 'UNKNOWN',
      connection_identity: call.connections.size ? 'OBSERVED' : 'UNKNOWN',
      request_ids: [...call.requests], connection_ids: [...call.connections] });
    flush();
  }
  function close() {
    if (closed) return;
    for (const [name, handler] of subscriptions) unsubscribe(name, handler);
    const remaining = activeSockets.size;
    for (const socket of activeSockets.keys()) detach(socket);
    enqueue('observer_stopped', { observation_status: incomplete ? 'INCOMPLETE' : 'RECORDED',
      remaining_connections: remaining });
    flush(); closed = true;
    context.disable();
  }
  enqueue('observer_started', { limits: LIMITS });
  return { begin, run: (call, operation) => context.run(call, operation), event: callEvent,
    finish, flush, close };
}
