/** One owned Node HTTP attempt; no redirect, retry, idle pool, or admission queue. */
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { Buffer } from 'node:buffer';
import { ClientError } from './errors.js';
import { record, requireValue } from './wire.js';

const REQUEST_BYTES = 16 * 1024;
const RESPONSE_BYTES = 64 * 1024;
const HEADER_BYTES = 16 * 1024;
const HEADER_COUNT = 64;
// Complete Node 22.16 X509 verification codes, excluding OUT_OF_MEM below,
// plus EPROTO emitted when a TLS write encounters an incompatible peer.
// Certificate rejection and an incompatible TLS endpoint do not establish that
// the owner died; counting them as TRANSPORT can consume the finite rank chain.
const TLS_ERRORS = new Set(['UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_CRL',
  'UNABLE_TO_DECRYPT_CERT_SIGNATURE', 'UNABLE_TO_DECRYPT_CRL_SIGNATURE',
  'UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY', 'CERT_SIGNATURE_FAILURE', 'CRL_SIGNATURE_FAILURE',
  'CERT_NOT_YET_VALID', 'CERT_HAS_EXPIRED', 'CRL_NOT_YET_VALID', 'CRL_HAS_EXPIRED',
  'ERROR_IN_CERT_NOT_BEFORE_FIELD', 'ERROR_IN_CERT_NOT_AFTER_FIELD',
  'ERROR_IN_CRL_LAST_UPDATE_FIELD', 'ERROR_IN_CRL_NEXT_UPDATE_FIELD',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_CHAIN_TOO_LONG', 'CERT_REVOKED', 'INVALID_CA',
  'PATH_LENGTH_EXCEEDED', 'INVALID_PURPOSE', 'CERT_UNTRUSTED', 'CERT_REJECTED', 'HOSTNAME_MISMATCH', 'EPROTO']);

function failure(code) {
  return new ClientError(code, 'The bounded controller HTTP attempt did not complete');
}

function networkCode(error) {
  if (error?.code === 'HPE_HEADER_OVERFLOW' || error?.code === 'OUT_OF_MEM') return 'LIMIT';
  return TLS_ERRORS.has(error?.code) || /^(?:HPE_|ERR_TLS_|ERR_SSL_)/.test(error?.code) ? 'INVALID' : 'TRANSPORT';
}

function argumentsFor(input, init) {
  record(init, ['method', 'body', 'signal', 'headers'],
    ['redirect', 'cache', 'credentials', 'referrerPolicy']);
  requireValue(init.method === 'POST' && init.signal instanceof AbortSignal,
    'Controller HTTP requires POST and the original AbortSignal');
  for (const [name, expected] of [['redirect', 'error'], ['cache', 'no-store'],
    ['credentials', 'omit'], ['referrerPolicy', 'no-referrer']]) {
    requireValue(init[name] === undefined || init[name] === expected, 'Unsupported controller HTTP option');
  }
  requireValue(typeof input === 'string' || input instanceof URL, 'Expected an HTTP URL');
  const spelling = typeof input === 'string' ? input : input.href;
  requireValue(Buffer.byteLength(spelling) <= 2048, 'Controller HTTP URL is too large');
  let url;
  try { url = new URL(spelling); } catch { throw failure('INVALID'); }
  requireValue(['http:', 'https:'].includes(url.protocol) && url.username === '' && url.password === '' &&
    url.search === '' && url.hash === '' && url.port !== '0', 'Invalid controller HTTP URL');
  const value = init.body;
  requireValue(typeof value === 'string' ||
    (value instanceof Uint8Array && !(value.buffer instanceof SharedArrayBuffer)), 'Expected bounded request bytes');
  const length = typeof value === 'string' ? Buffer.byteLength(value) : value.byteLength;
  if (length > REQUEST_BYTES) throw failure('LIMIT');
  const body = Buffer.from(value);
  requireValue(init.headers !== null && typeof init.headers === 'object', 'Expected explicit request headers');
  const names = Reflect.ownKeys(init.headers);
  record(init.headers, [], names);
  requireValue(names.length <= HEADER_COUNT - 4, 'Too many controller request headers');
  const headers = Object.create(null);
  for (const name of names) {
    requireValue(typeof name === 'string' && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name), 'Invalid header name');
    const key = name.toLowerCase(), content = init.headers[name];
    requireValue(!Object.hasOwn(headers, key) && !['host', 'connection', 'content-length',
      'transfer-encoding', 'expect', 'upgrade', 'proxy-authorization', 'accept-encoding'].includes(key),
    'Unsupported or duplicate controller request header');
    requireValue(typeof content === 'string' && /^[\x20-\x7e]*$/.test(content), 'Invalid header value');
    headers[key] = content;
  }
  headers['content-length'] = String(length);
  headers.connection = 'close';
  headers['accept-encoding'] = 'identity';
  const bytes = Object.entries(headers).reduce((total, [key, content]) => total + key.length + content.length + 4,
    url.host.length + url.pathname.length + 32);
  if (bytes > HEADER_BYTES) throw failure('LIMIT');
  return { url, body, headers, signal: init.signal };
}

function responseHeaders(response) {
  const pairs = response.rawHeaders;
  if (pairs.length > HEADER_COUNT * 2) throw failure('LIMIT');
  const headers = new Headers();
  let bytes = 0;
  for (let index = 0; index < pairs.length; index += 2) {
    const name = pairs[index], value = pairs[index + 1];
    bytes += name.length + value.length + 4;
    if (name.toLowerCase() === 'x-scap-rejection') {
      // This optional diagnostic has no framing or outcome authority. Preserve
      // duplicates as a combined value for the SDK to discard, while retaining
      // the original total header budgets and all other duplicate checks.
      headers.append(name, value);
    } else {
      requireValue(!headers.has(name), 'Duplicate controller response header');
      headers.set(name, value);
    }
  }
  if (bytes > HEADER_BYTES) throw failure('LIMIT');
  const length = headers.get('content-length');
  requireValue(length === null || /^(0|[1-9][0-9]*)$/.test(length), 'Invalid response length');
  if (length !== null && BigInt(length) > BigInt(RESPONSE_BYTES)) throw failure('LIMIT');
  const encoding = headers.get('content-encoding'), transfer = headers.get('transfer-encoding');
  requireValue(encoding === null || encoding.toLowerCase() === 'identity', 'Compressed controller response');
  requireValue(transfer === null || (length === null && transfer.toLowerCase() === 'chunked'),
    'Ambiguous controller response framing');
  return { headers, length: length === null ? null : Number(length) };
}

export class ControllerHttp {
  #maximum;
  #entries = new Set();
  #closed = false;
  #closing;
  #finishClose;
  #quiescing;
  #finishQuiesce;
  #paused = false;
  #started = 0;
  #completed = 0;
  #peak = 0;

  constructor(options = {}) {
    record(options, [], ['maxRequests']);
    const { maxRequests = 8 } = options;
    requireValue(Number.isSafeInteger(maxRequests) && maxRequests >= 1 && maxRequests <= 8,
      'Controller HTTP admission must be between one and eight');
    this.#maximum = maxRequests;
    this.fetch = this.fetch.bind(this);
  }

  snapshot() {
    return Object.freeze({ closed: this.#closed, active: this.#entries.size, peak: this.#peak,
      started: this.#started, completed: this.#completed });
  }

  async fetch(input, init) {
    if (this.#closed) throw failure('CLOSED');
    if (this.#paused) throw failure('LIMIT');
    const { url, body, headers, signal } = argumentsFor(input, init);
    if (signal.aborted) throw failure('ABORTED');
    if (this.#entries.size >= this.#maximum) throw failure('LIMIT');
    const entry = { request: null, response: null, sockets: new Set(), lookups: 0,
      constructing: true, requestClosed: true, stopped: false, stop: null };
    this.#entries.add(entry);
    ++this.#started;
    this.#peak = Math.max(this.#peak, this.#entries.size);
    return new Promise((resolve, reject) => {
      let settled = false;
      const release = () => {
        if (!entry.constructing && entry.requestClosed && entry.sockets.size === 0 && entry.lookups === 0 &&
            this.#entries.delete(entry)) {
          signal.removeEventListener('abort', abort);
          ++this.#completed;
          if (this.#closed && this.#entries.size === 0) this.#finishClose();
          if (this.#paused && this.#entries.size === 0) this.#finishQuiesce();
        }
      };
      const stop = (code) => {
        entry.stopped = true;
        if (!settled) { settled = true; reject(failure(code)); }
        entry.response?.destroy();
        entry.request?.destroy();
        for (const socket of entry.sockets) socket.destroy();
      };
      entry.stop = stop;
      const abort = () => stop('ABORTED');
      const socket = (value) => {
        if (entry.sockets.has(value) || value.closed) return;
        entry.sockets.add(value);
        value.once('close', () => { entry.sockets.delete(value); release(); });
        if (entry.stopped) value.destroy();
      };
      // getaddrinfo is not withdrawn by ClientRequest.destroy(). Keep this
      // same admission lease until the actual lookup callback has completed.
      const lookup = (hostname, options, callback) => {
        ++entry.lookups;
        let completed = false;
        const done = (...args) => {
          if (completed) return;
          completed = true;
          try { callback(...args); } finally { --entry.lookups; release(); }
        };
        try {
          if (entry.stopped) done(failure('ABORTED'));
          else dns.lookup(hostname, options, done);
        } catch (error) { done(error); }
      };
      const received = (response) => {
        entry.response = response;
        response.on('error', (error) => stop(networkCode(error)));
        response.on('aborted', () => stop('TRANSPORT'));
        response.on('close', () => { if (!settled) stop('TRANSPORT'); });
        if (entry.stopped) { response.destroy(); return; }
        let parsed, storage, size = 0;
        try {
          requireValue(response.statusCode >= 200 && response.statusCode <= 599 &&
            !(response.statusCode >= 300 && response.statusCode < 400) &&
            ![204, 205].includes(response.statusCode), 'Invalid or redirected controller response');
          parsed = responseHeaders(response);
          storage = Buffer.alloc(RESPONSE_BYTES);
        } catch (error) { stop(error instanceof ClientError ? error.code : 'INVALID'); return; }
        response.on('data', (chunk) => {
          if (settled) return;
          if (size + chunk.length > RESPONSE_BYTES) { stop('LIMIT'); return; }
          chunk.copy(storage, size);
          size += chunk.length;
        });
        response.on('end', () => {
          if (settled) return;
          if (!response.complete || (parsed.length !== null && size !== parsed.length)) {
            stop('TRANSPORT'); return;
          }
          try {
            const result = new Response(storage.subarray(0, size), { status: response.statusCode, headers: parsed.headers });
            settled = true;
            resolve(result);
          } catch { stop('INVALID'); }
        });
      };
      signal.addEventListener('abort', abort, { once: true });
      try {
        if (signal.aborted) { stop('ABORTED'); return; }
        const implementation = url.protocol === 'https:' ? https : http;
        entry.request = implementation.request(url, { method: 'POST', headers, agent: false,
          maxHeaderSize: HEADER_BYTES, autoSelectFamily: false, rejectUnauthorized: true, lookup }, received);
        entry.requestClosed = false;
        entry.request.maxHeadersCount = HEADER_COUNT + 1;
        entry.request.on('error', (error) => stop(networkCode(error)));
        entry.request.once('close', () => {
          entry.requestClosed = true;
          if (!settled) stop('TRANSPORT');
          release();
        });
        entry.request.on('socket', socket);
        entry.request.on('information', () => stop('INVALID'));
        const upgraded = (_response, value) => { socket(value); stop('INVALID'); };
        entry.request.on('upgrade', upgraded);
        entry.request.on('connect', upgraded);
        if (entry.request.socket) socket(entry.request.socket);
        if (entry.stopped) entry.request.destroy();
        else entry.request.end(body);
      } catch (error) { stop(networkCode(error)); }
      finally { entry.constructing = false; release(); }
    });
  }

  /** Stop admission, abort old attempts and join every socket and DNS callback.
   * Unlike close, successful quiescence permits the next trusted fleet snapshot.
   */
  quiesce() {
    if (this.#closed) return this.close();
    if (this.#quiescing !== undefined) return this.#quiescing;
    this.#paused = true;
    const joined = new Promise((resolve) => { this.#finishQuiesce = resolve; });
    this.#quiescing = joined.then(() => { this.#paused = false; this.#quiescing = undefined; });
    for (const entry of this.#entries) entry.stop('ABORTED');
    if (this.#entries.size === 0) this.#finishQuiesce();
    return this.#quiescing;
  }

  close() {
    if (this.#closing !== undefined) return this.#closing;
    this.#closed = true;
    this.#closing = new Promise((resolve) => { this.#finishClose = resolve; });
    for (const entry of this.#entries) entry.stop('CLOSED');
    if (this.#entries.size === 0) this.#finishClose();
    return this.#closing;
  }
}
