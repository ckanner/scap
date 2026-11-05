import { createClient as createLibsqlClient } from "@libsql/client/http";
import type { Config, InStatement, InValue, ResultSet, TransactionMode } from "@libsql/client";

export interface ClientConfig {
  /** Replica origins. Every endpoint must serve the same immutable database. */
  endpoints: readonly string[];
  database: string;
  authToken: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export interface RequestOptions {
  /** Reuse only for the exact original operation, never a different SQL input. */
  requestId?: string;
  /** Original request generation; omitted values always mean legacy epoch one. */
  requestEpoch?: bigint;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface RequestIdentity {
  requestId: string;
  /** Old saved identities without this field remain in epoch one. */
  requestEpoch?: bigint;
  statements: readonly InStatement[];
}

export interface TrackedResult<T> {
  request: RequestIdentity & { requestEpoch: bigint };
  result: T;
}

export class ScapError extends Error {
  constructor(message: string, public readonly code: string, public readonly request: RequestIdentity) {
    super(message);
    this.name = "ScapError";
  }
}

export interface RetainedResult {
  columns: string[];
  rows: Array<Array<null | string | number | bigint | ArrayBuffer>>;
  rowsAffected: number;
  lastInsertRowid: bigint | null;
}

export interface RequestPosition { term: bigint; index: bigint }

export type TerminalOutcome = { state: "cancelled"; position: RequestPosition | null; acknowledged: boolean }
  | { state: "committed"; sequence: bigint; results: RetainedResult[]; acknowledged: boolean };

export type RequestOutcome = { state: "unknown" }
  | { state: "retired"; currentEpoch: bigint }
  | TerminalOutcome;

export interface DatabaseStatus {
  revision: bigint;
  /** Null when a legacy service does not expose the retention protocol. */
  requestEpoch: bigint | null;
  retainedRequests: bigint | null;
  unacknowledgedRequests: bigint | null;
  retiredRevision: bigint | null;
  /** Null only when the connected legacy service exposes no physical watermarks. */
  baseRevision: bigint | null;
  tailEntries: bigint | null;
  tailBytes: bigint | null;
  suspended: boolean;
  cold: boolean;
  ownerActive: boolean;
  archivedRevision: bigint | null;
}

export interface Driver {
  execute(statement: InStatement): Promise<ResultSet>;
  batch(statements: InStatement[], mode: TransactionMode): Promise<ResultSet[]>;
  close(): void;
}

/** Narrow dependency ports; defaults always use the actual pinned libSQL SDK. */
export interface Runtime {
  fetch: typeof globalThis.fetch;
  now: () => number;
  monotonic: () => number;
  requestId: () => string;
  createClient: (config: Config) => Driver;
}

const defaultRuntime: Runtime = {
  fetch: (...args) => globalThis.fetch(...args),
  now: () => Date.now(),
  monotonic: () => performance.now(),
  requestId: () => crypto.randomUUID().replaceAll("-", ""),
  createClient: (config) => createLibsqlClient(config),
};

type Normalized = { sql: string; args: InValue[] };

function normalize(statement: InStatement): Normalized {
  const input = typeof statement === "string" ? { sql: statement } : statement;
  if (typeof input.sql !== "string" || input.sql.length === 0) throw new TypeError("SQL text is required");
  const args = input.args ?? [];
  if (!Array.isArray(args)) throw new TypeError("Named arguments are not supported by this protocol subset");
  return { sql: input.sql, args: args.map((value) => {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (value instanceof ArrayBuffer) return value.slice(0);
    if (value instanceof Date) return value.valueOf();
    if (typeof value === "boolean") return value ? 1n : 0n;
    return value;
  }) };
}

function wireStatement(statement: InStatement): unknown {
  const input = normalize(statement);
  return { sql: input.sql, args: input.args.map((value) => {
    if (value === null) return { type: "null" };
    if (typeof value === "bigint") return { type: "integer", value: value.toString() };
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new TypeError("Only finite numeric parameters are supported");
      return { type: "float", value };
    }
    if (typeof value === "string") return { type: "text", value };
    return { type: "blob", base64: Buffer.from(value as ArrayBuffer).toString("base64") };
  }) };
}

function positive(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) throw new RangeError("Invalid request budget");
  return value;
}

function requestId(value: string): string {
  if (!/^[0-9a-f]{32}$/i.test(value) || /^0+$/.test(value)) throw new TypeError("Request ID must be nonzero 128-bit hexadecimal");
  return value.toLowerCase();
}

function requestEpoch(value: bigint): bigint {
  if (typeof value !== "bigint" || value <= 0n || value > (1n << 64n) - 1n) throw new TypeError("Request epoch must be a positive u64 bigint");
  return value;
}

async function boundedResponse(response: Response, maximum: number): Promise<Response> {
  const reader = response.body?.getReader();
  if (!reader) return response;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > maximum) { await reader.cancel(); throw new Error("Response exceeded configured byte limit"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return new Response(Buffer.concat(chunks), { status: response.status, headers: response.headers });
}

function integer(value: unknown, signed: boolean, allowZero = false): bigint {
  if (typeof value !== "string" || !/^-?[0-9]{1,20}$/.test(value)) throw new Error("Invalid retained integer");
  const integer = BigInt(value);
  if (integer < (signed ? -(1n << 63n) : allowZero ? 0n : 1n) || integer > (signed ? (1n << 63n) - 1n : (1n << 64n) - 1n)) throw new Error("Retained integer outside range");
  return integer;
}

function retainedValue(value: any): null | string | number | bigint | ArrayBuffer {
  if (value === null || typeof value !== "object") throw new Error("Invalid retained value object");
  switch (value.type) {
    case "null": return null;
    case "integer": return integer(value.value, true);
    case "float":
      if (typeof value.value !== "number" || !Number.isFinite(value.value)) throw new Error("Invalid retained float");
      return value.value;
    case "text":
      if (typeof value.value !== "string") throw new Error("Invalid retained text");
      return value.value;
    case "blob": {
      if (typeof value.base64 !== "string") throw new Error("Invalid retained blob");
      const bytes = Buffer.from(value.base64, "base64");
      if (bytes.toString("base64") !== value.base64) throw new Error("Invalid retained base64");
      return Uint8Array.from(bytes).buffer;
    }
    default: throw new Error("Invalid retained SQLite value");
  }
}

function retainedOutcome(value: any): RequestOutcome {
  if (value === null || typeof value !== "object") throw new Error("Invalid outcome object");
  if (value.state === "unknown") return { state: "unknown" };
  if (value.state === "retired") return { state: "retired", currentEpoch: integer(value.current_epoch, false) };
  const acknowledged = value.acknowledged ?? false;
  if (typeof acknowledged !== "boolean" || value.acknowledged === null) throw new Error("Invalid acknowledgement state");
  if (value.state === "cancelled") {
    let position: RequestPosition | null = null;
    if (Object.hasOwn(value, "position")) {
      if (value.position === null || typeof value.position !== "object") throw new Error("Invalid cancellation position");
      position = { term: integer(value.position.term, false), index: integer(value.position.index, false) };
    }
    return { state: "cancelled", position, acknowledged };
  }
  if (value.state !== "committed") throw new Error("Invalid request outcome");
  if (!Array.isArray(value.results)) throw new Error("Invalid retained results");
  return { state: "committed", sequence: integer(value.sequence, false), acknowledged, results: value.results.map((result: any) => {
    if (!Array.isArray(result.cols) || !Array.isArray(result.rows) || !Number.isSafeInteger(result.affected_row_count) || result.affected_row_count < 0) throw new Error("Invalid retained result");
    const columns = result.cols.map((column: any) => {
      if (typeof column.name !== "string") throw new Error("Invalid retained column");
      return column.name;
    });
    return {
      columns,
      rows: result.rows.map((row: any[]) => {
        if (!Array.isArray(row) || row.length !== columns.length) throw new Error("Invalid retained row");
        return row.map(retainedValue);
      }),
      rowsAffected: result.affected_row_count,
      lastInsertRowid: result.last_insert_rowid === null ? null : integer(result.last_insert_rowid, true),
    };
  }) };
}

function terminalProof(value: any): unknown {
  if (value === null || typeof value !== "object") throw new TypeError("Acknowledgement requires a known terminal outcome");
  if (value.state === "committed") return { state: "committed", sequence: requestEpoch(value.sequence).toString() };
  if (value.state !== "cancelled" || value.position === null || typeof value.position !== "object") throw new TypeError("Acknowledgement requires an exact terminal receipt");
  return { state: "cancelled", position: { term: requestEpoch(value.position.term).toString(), index: requestEpoch(value.position.index).toString() } };
}

function acknowledgement(value: any): void {
  if (value === null || typeof value !== "object" || value.state !== "acknowledged") throw new Error("Invalid acknowledgement response");
}

function rotatedEpoch(value: any, expected: bigint): bigint {
  if (value === null || typeof value !== "object" || value.state !== "rotated") throw new Error("Invalid request rotation response");
  const epoch = integer(value.request_epoch, false);
  if (epoch !== expected + 1n) throw new Error("Request rotation epoch mismatch");
  return epoch;
}

function databaseStatus(value: any): DatabaseStatus {
  if (value === null || typeof value !== "object" || typeof value.suspended !== "boolean"
    || typeof value.cold !== "boolean" || typeof value.owner_active !== "boolean") throw new Error("Invalid database status");
  const physicalFields = ["base_revision", "tail_entries", "tail_bytes"].filter((field) => Object.hasOwn(value, field)).length;
  if (physicalFields !== 0 && physicalFields !== 3) throw new Error("Incomplete physical recovery status");
  const retentionFields = ["request_epoch", "retained_requests", "unacknowledged_requests", "retired_revision"].filter((field) => Object.hasOwn(value, field)).length;
  if (retentionFields !== 0 && retentionFields !== 4) throw new Error("Incomplete request retention status");
  return { revision: integer(value.revision, false, true), suspended: value.suspended, cold: value.cold,
    requestEpoch: retentionFields === 0 ? null : integer(value.request_epoch, false),
    retainedRequests: retentionFields === 0 ? null : integer(value.retained_requests, false, true),
    unacknowledgedRequests: retentionFields === 0 ? null : integer(value.unacknowledged_requests, false, true),
    retiredRevision: retentionFields === 0 ? null : integer(value.retired_revision, false, true),
    baseRevision: physicalFields === 0 ? null : integer(value.base_revision, false, true),
    tailEntries: physicalFields === 0 ? null : integer(value.tail_entries, false, true),
    tailBytes: physicalFields === 0 ? null : integer(value.tail_bytes, false, true),
    ownerActive: value.owner_active, archivedRevision: value.archived_revision === null ? null : integer(value.archived_revision, false, true) };
}

export class ScapClient {
  readonly #endpoints: URL[];
  readonly #config: Required<ClientConfig>;
  readonly #runtime: Runtime;
  #closed = false;

  constructor(config: ClientConfig, runtime: Runtime = defaultRuntime) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(config.database)) throw new TypeError("Invalid database route");
    if (!config.authToken || config.authToken.length > 8192) throw new TypeError("A bounded database credential is required");
    if (config.endpoints.length === 0 || config.endpoints.length > 16) throw new RangeError("Provide between one and sixteen replica endpoints");
    this.#endpoints = config.endpoints.map((endpoint) => {
      const url = new URL(endpoint);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
        throw new TypeError("Replica endpoints must be plain HTTP(S) origins without credentials, query or path");
      }
      return new URL(`/db/${config.database}/`, url);
    });
    this.#config = { ...config, endpoints: [...config.endpoints],
      timeoutMs: positive(config.timeoutMs ?? 2000, 3_600_000),
      maxResponseBytes: positive(config.maxResponseBytes ?? 4 * 1024 * 1024, 128 * 1024 * 1024) };
    this.#runtime = runtime;
  }

  execute(statement: InStatement, options: RequestOptions = {}): Promise<ResultSet> {
    return this.#run([statement], undefined, "write", options) as Promise<ResultSet>;
  }

  /** Preserve the successful operation's identity; acknowledgement stays explicit. */
  executeTracked(statement: InStatement, options: RequestOptions = {}): Promise<TrackedResult<ResultSet>> {
    return this.#run([statement], undefined, "write", options, undefined, true) as Promise<TrackedResult<ResultSet>>;
  }

  /** A new ReadIndex-backed, read-only SQLite transaction; no SQL write fallback. */
  query(statement: InStatement, options: RequestOptions = {}): Promise<ResultSet> {
    return this.#run([statement], undefined, "read", options) as Promise<ResultSet>;
  }

  batch(statements: InStatement[], mode: TransactionMode = "deferred", options: RequestOptions = {}): Promise<ResultSet[]> {
    return this.#run(statements, mode, mode === "read" ? "read" : "write", options) as Promise<ResultSet[]>;
  }

  batchTracked(statements: InStatement[], mode: TransactionMode = "deferred", options: RequestOptions = {}): Promise<TrackedResult<ResultSet[]>> {
    return this.#run(statements, mode, mode === "read" ? "read" : "write", options, undefined, true) as Promise<TrackedResult<ResultSet[]>>;
  }

  lookup(request: RequestIdentity, options: RequestOptions = {}): Promise<RequestOutcome> {
    return this.#run(request.statements, undefined, "lookup", { ...options, requestId: request.requestId, requestEpoch: request.requestEpoch === undefined ? 1n : request.requestEpoch }) as Promise<RequestOutcome>;
  }

  resolveOrCancel(request: RequestIdentity, options: RequestOptions = {}): Promise<RequestOutcome> {
    return this.#run(request.statements, undefined, "resolve_or_cancel", { ...options, requestId: request.requestId, requestEpoch: request.requestEpoch === undefined ? 1n : request.requestEpoch }) as Promise<RequestOutcome>;
  }

  /** Release only a known terminal result after the application has durably handled it. */
  acknowledge(request: RequestIdentity, terminal: TerminalOutcome, options: RequestOptions = {}): Promise<void> {
    return this.#run(request.statements, undefined, "acknowledge", { ...options, requestId: request.requestId, requestEpoch: request.requestEpoch === undefined ? 1n : request.requestEpoch }, terminal) as Promise<void>;
  }

  /** ADMIN operation: all retained outcomes must already be acknowledged. */
  rotateRequests(expectedEpoch: bigint, options: RequestOptions = {}): Promise<bigint> {
    return this.#run([], undefined, "rotate", { ...options, requestEpoch: expectedEpoch }) as Promise<bigint>;
  }

  /** Fresh authorized metadata, without acquiring or waking a SQLite writer. */
  status(options: RequestOptions = {}): Promise<DatabaseStatus> {
    return this.#run([], undefined, "status", options) as Promise<DatabaseStatus>;
  }

  close(): void { this.#closed = true; }

  async #run(input: readonly InStatement[], batchMode: TransactionMode | undefined, operation: string, options: RequestOptions, terminal?: TerminalOutcome, tracked = false): Promise<ResultSet | ResultSet[] | RequestOutcome | DatabaseStatus | bigint | void | TrackedResult<ResultSet | ResultSet[]>> {
    // Capture identity and budget before any probe, SDK queue or HTTP operation.
    const started = this.#runtime.monotonic();
    const timeout = positive(options.timeoutMs ?? this.#config.timeoutMs, this.#config.timeoutMs);
    const deadline = this.#runtime.now() + timeout;
    const identity = { requestId: requestId(options.requestId ?? this.#runtime.requestId()), requestEpoch: requestEpoch(options.requestEpoch === undefined ? 1n : options.requestEpoch), statements: input.map(normalize) };
    const expected = operation === "acknowledge" ? terminalProof(terminal) : undefined;
    const cancelled = new AbortController();
    const timer = setTimeout(() => cancelled.abort(), timeout);
    const abort = () => cancelled.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    let attempted = false;
    const check = () => {
      if (this.#closed) throw new ScapError("Client is closed", "CLIENT_CLOSED", identity);
      if (cancelled.signal.aborted || this.#runtime.monotonic() - started >= timeout) {
        throw new ScapError("Original request deadline or cancellation reached", attempted ? "COMMIT_UNKNOWN" : "EXPIRED", identity);
      }
    };
    try {
      for (const endpoint of this.#endpoints) {
        check();
        let ready: Response;
        try {
          ready = await this.#runtime.fetch(new URL("/readyz", endpoint), { redirect: "manual", signal: cancelled.signal });
          await ready.body?.cancel();
        } catch { check(); continue; }
        if (ready.status !== 200) continue;
        check();
        const fetch: typeof globalThis.fetch = async (input, init) => {
          check();
          const request = new Request(input, init);
          const target = new URL(request.url);
          if (target.origin !== endpoint.origin || !target.pathname.startsWith(endpoint.pathname)) throw new Error("SDK attempted an unconfigured origin or database");
          request.headers.set("x-scap-request-id", identity.requestId);
          request.headers.set("x-scap-request-epoch", identity.requestEpoch.toString());
          request.headers.set("x-scap-deadline-unix-ms", String(deadline));
          request.headers.set("x-scap-mode", operation === "read" ? "read" : "write");
          attempted = true;
          const response = await this.#runtime.fetch(request, { redirect: "manual", signal: cancelled.signal });
          const returnedId = response.headers.get("x-scap-request-id");
          if (returnedId !== null && returnedId !== identity.requestId) throw new Error("Response identity mismatch");
          const returnedEpoch = response.headers.get("x-scap-request-epoch");
          if (returnedEpoch === null) {
            if (identity.requestEpoch !== 1n) throw new Error("Response omitted the original request epoch");
          } else if (returnedEpoch !== identity.requestEpoch.toString()) throw new Error("Response request epoch mismatch");
          return boundedResponse(response, this.#config.maxResponseBytes);
        };
        let driver: Driver | undefined;
        let output: ResultSet | ResultSet[] | RequestOutcome | DatabaseStatus | bigint | void;
        try {
          if (identity.requestEpoch !== 1n && (operation === "write" || operation === "resolve_or_cancel" || operation === "acknowledge" || operation === "rotate")) {
            // An old endpoint silently ignores the epoch header. Before any
            // scoped mutation, prove this exact endpoint understands retention,
            // using the original identity/deadline and never caching capability
            // across restarts. Status is metadata-only and cannot execute SQL.
            const capability = await fetch(new URL("v1/status", endpoint), {
              method: "GET", headers: { authorization: `Bearer ${this.#config.authToken}` },
            });
            const value = await capability.json();
            if (!capability.ok) throw new ScapError(String(value.message), String(value.code), identity);
            check();
            if (databaseStatus(value).requestEpoch === null) throw new Error("Endpoint does not support request retention epochs");
          }
          if (operation === "lookup" || operation === "resolve_or_cancel" || operation === "acknowledge" || operation === "rotate" || operation === "status") {
            const status = operation === "status";
            const path = status ? "v1/status" : operation === "rotate" ? "v1/request-epoch" : `v1/requests/${identity.requestId}`;
            const body = operation === "rotate" ? { action: "rotate", expected_epoch: identity.requestEpoch.toString() }
              : { action: operation, statements: identity.statements.map(wireStatement), ...(expected === undefined ? {} : { expected }) };
            const response = await fetch(new URL(path, endpoint), {
              method: status ? "GET" : "POST", headers: { authorization: `Bearer ${this.#config.authToken}`, "content-type": "application/json" },
              body: status ? undefined : JSON.stringify(body),
            });
            const value = await response.json();
            if (!response.ok) throw new ScapError(String(value.message), String(value.code), identity);
            check();
            output = status ? databaseStatus(value) : operation === "rotate" ? rotatedEpoch(value, identity.requestEpoch)
              : operation === "acknowledge" ? acknowledgement(value) : retainedOutcome(value);
          } else {
            driver = this.#runtime.createClient({ url: endpoint.href, authToken: this.#config.authToken, intMode: "bigint", fetch });
            output = batchMode === undefined ? await driver.execute(identity.statements[0]) : await driver.batch(identity.statements, batchMode);
            check();
          }
        } catch (error: any) {
          // Only an authoritative before-proposal routing rejection permits a
          // second SQL attempt. Network/timeout/UNKNOWN never permit this retry.
          const code = error !== null && typeof error === "object" ? error.code : undefined;
          if (code === "NOT_LEADER") { attempted = false; continue; }
          if (error instanceof ScapError) throw error;
          throw new ScapError(error instanceof Error ? error.message : "Database operation failed", typeof code === "string" ? code : "COMMIT_UNKNOWN", identity);
        } finally { driver?.close(); }
        return tracked ? { request: identity, result: output as ResultSet | ResultSet[] } : output;
      }
      check();
      throw new ScapError("No configured replica is ready", "NO_LEADER", identity);
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}

export function createClient(config: ClientConfig, runtime?: Runtime): ScapClient { return new ScapClient(config, runtime); }
