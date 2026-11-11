/** One bounded HTTP attempt. No retries, redirects, or deadline renewal. */
import { Buffer, isUtf8 } from 'node:buffer';
import { performance } from 'node:perf_hooks';
import { CodecError } from '../../node-codec/src/codec.js';
import { ClientError, RemoteError, UnknownError, CommittedResultError } from './errors.js';
import { record, requireValue, parseJson, envelope } from './wire.js';

const MAX_WIRE_BYTES = 96 * 1024 * 1024;
const RECOVERY = new Set(['open', 'activate', 'compact_copy', 'gc_prepare', 'gc_resume', 'owner_resume']);
const DATA = new Set(['create', 'execute', 'query']);
const CATALOGUE = new Set(['prepare_create', 'resume_create', 'abort_create',
  'inspect_create_operation', 'resolve_name', 'delete_name', 'named_storage_status', 'retire_named_storage']);
const DISCOVERY = new Set(['list_names', 'deployment_inventory']);
const READ = new Set(['status', 'query', 'open', 'storage_status', 'named_storage_status',
  'inspect_create_operation', 'resolve_name', 'owner_inspect', 'snapshot_inspect', 'snapshot_list', ...DISCOVERY]);

export function duration(value) {
  requireValue(Number.isSafeInteger(value) && value > 0 && value <= 2147483647,
    'Timeout must be a positive bounded millisecond integer');
  return value;
}

function byteLimit(value) {
  requireValue(Number.isSafeInteger(value) && value > 0 && value <= MAX_WIRE_BYTES,
    'HTTP byte budget must be a positive integer at most 96 MiB');
  return value;
}

function endpoint(value, allowInsecureHttp) {
  requireValue(typeof value === 'string', 'Expected an HTTP endpoint URL');
  let url;
  try { url = new URL(value); } catch { throw new ClientError('INVALID', 'Invalid HTTP endpoint URL'); }
  requireValue(url.username === '' && url.password === '' && url.search === '' && url.hash === '',
    'Endpoint must not include credentials, a query or a fragment');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  requireValue(url.protocol === 'https:' || (url.protocol === 'http:' && (loopback || allowInsecureHttp)),
    'Use HTTPS or an explicitly allowed HTTP endpoint');
  requireValue(url.pathname !== '/', 'Endpoint must include the API path, normally /v1');
  return url.href;
}

export class Transport {
  #endpoint;
  #token;
  #fetch;
  #timeout;
  #recoveryTimeout;
  #requestLimit;
  #responseLimit;

  constructor(options) {
    record(options, ['endpoint', 'token'], ['fetch', 'timeoutMs', 'recoveryTimeoutMs',
      'maxRequestBytes', 'maxResponseBytes', 'allowInsecureHttp']);
    const { token, allowInsecureHttp = false, fetch: fetcher = globalThis.fetch,
      timeoutMs = 30000, recoveryTimeoutMs = 1800000,
      maxRequestBytes = MAX_WIRE_BYTES, maxResponseBytes = MAX_WIRE_BYTES } = options;
    requireValue(typeof allowInsecureHttp === 'boolean', 'Expected explicit HTTP permission');
    this.#endpoint = endpoint(options.endpoint, allowInsecureHttp);
    requireValue(typeof token === 'string' && /^[\x21-\x7e]{32,1024}$/.test(token), 'Expected a bounded bearer credential');
    requireValue(typeof fetcher === 'function', 'Expected a fetch implementation');
    this.#token = token;
    this.#fetch = fetcher;
    this.#timeout = duration(timeoutMs);
    this.#recoveryTimeout = duration(recoveryTimeoutMs);
    this.#requestLimit = byteLimit(maxRequestBytes);
    this.#responseLimit = byteLimit(maxResponseBytes);
  }

  async call(body, reference, decode, options = {}) {
    record(options, [], ['timeoutMs', 'signal']);
    const recovery = RECOVERY.has(body.operation);
    const timeout = duration(options.timeoutMs === undefined ?
      (recovery ? this.#recoveryTimeout : this.#timeout) : options.timeoutMs);
    const signal = options.signal;
    requireValue(signal === undefined || signal instanceof AbortSignal, 'Expected an AbortSignal');
    if (signal?.aborted) throw new ClientError('ABORTED', 'The call was aborted before transport');
    const encoded = JSON.stringify(body);
    if (Buffer.byteLength(encoded) > this.#requestLimit) {
      throw new ClientError('LIMIT', 'HTTP request exceeds the client byte budget');
    }
    const deadline = performance.now() + timeout;
    const controller = new AbortController();
    let abortCode, rejectAbort, reader, result, failure;
    const aborted = new Promise((_, reject) => { rejectAbort = reject; });
    const stop = (code) => {
      abortCode = code;
      controller.abort();
      rejectAbort(new ClientError(code, 'The original HTTP deadline or abort ended this call'));
    };
    const onAbort = () => stop('ABORTED');
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => stop('DEADLINE'), timeout);
    // Promise handlers are attached before the fetch/reader callback runs. Even
    // a synchronous injected failure or abort cannot leave an unhandled reject.
    const wait = (operation) => Promise.race([aborted, Promise.resolve().then(operation)]);
    try {
      const response = await wait(() => this.#fetch(this.#endpoint, {
        method: 'POST', body: encoded, redirect: 'error', cache: 'no-store', credentials: 'omit',
        referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.#token}`,
          'x-scap-admission': DISCOVERY.has(body.operation) ? 'discovery' : CATALOGUE.has(body.operation) ? 'catalogue' :
            recovery ? 'recovery' : DATA.has(body.operation) ? 'data' : 'control' },
      }));
      requireValue(response instanceof Response && !response.redirected, 'Invalid or redirected HTTP response');
      const contentType = response.headers.get('content-type');
      requireValue(contentType !== null && contentType.split(';')[0].trim().toLowerCase() === 'application/json',
        'Expected a JSON API response');
      const length = response.headers.get('content-length');
      if (length !== null) {
        requireValue(/^(0|[1-9][0-9]*)$/.test(length), 'Invalid response length');
        if (BigInt(length) > BigInt(this.#responseLimit)) throw new ClientError('LIMIT', 'HTTP response exceeds byte budget');
      }
      requireValue(response.body !== null, 'Expected a response body');
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      for (;;) {
        const { done, value } = await wait(() => reader.read());
        if (done) break;
        requireValue(value instanceof Uint8Array, 'Expected response bytes');
        size += value.byteLength;
        if (size > this.#responseLimit) throw new ClientError('LIMIT', 'HTTP response exceeds byte budget');
        chunks.push(Buffer.from(value));
      }
      const bytes = Buffer.concat(chunks, size);
      requireValue(isUtf8(bytes), 'Response is not valid UTF-8');
      const value = envelope(parseJson(bytes.toString('utf8')), response.status, reference);
      const decoded = decode(value);
      // Synchronous parsing/materialization also consumes the original budget.
      if (performance.now() >= deadline) {
        if (decoded.state === 'committed') {
          throw new CommittedResultError('DEADLINE', decoded.receipt, decoded.rawResult);
        }
        throw new ClientError('DEADLINE', 'The response exceeded the original deadline');
      }
      result = decoded;
    } catch (error) {
      if (error instanceof RemoteError || error instanceof UnknownError || error instanceof CommittedResultError) {
        failure = error;
      } else {
        // Neither untrusted server text nor arbitrary fetch exceptions are kept:
        // both can include tokens or raw requests. Preserve only a bounded code.
        const code = abortCode ?? (error instanceof ClientError || error instanceof CodecError ? error.code : 'TRANSPORT');
        const cause = new ClientError(code, 'HTTP transport or response validation failed');
        failure = READ.has(body.operation) ? new ClientError(code, 'The read call did not return a verified result', cause) :
          new UnknownError(reference, cause);
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      controller.abort();
      if (reader !== undefined) reader.releaseLock();
    }
    if (failure !== undefined) throw failure;
    return result;
  }
}
