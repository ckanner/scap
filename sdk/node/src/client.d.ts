/** Canonical nonzero u64 decimal string; runtime validation is mandatory. */
export type Decimal = string;

export interface Scope {
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly database: Decimal;
  readonly incarnation: Decimal;
  readonly generation: Decimal;
}

export type SqlValue = null | bigint | number | string | Uint8Array;
export interface Statement { readonly sql: string; readonly parameters: readonly SqlValue[] }
export interface RequestIdentity {
  readonly epoch: Decimal;
  readonly id: Decimal;
  readonly principal: Decimal;
  readonly fingerprint: string;
}
export interface Transition { readonly revision: Decimal; readonly nonce: Decimal }
export interface Receipt {
  readonly scope: Scope;
  readonly request: RequestIdentity;
  readonly sequence: Decimal;
  readonly transition: Transition;
  readonly data_root: string;
  readonly result_hash: string;
}

declare const preparedRequest: unique symbol;
/** Obtain only through Client.prepare or Client.restore; do not construct it. */
export interface TrackedRequest {
  readonly [preparedRequest]: true;
  readonly scope: Scope;
  readonly request: RequestIdentity;
  readonly statements: readonly unknown[];
}
export interface StatementResult {
  columns: string[];
  rows: SqlValue[][];
  affectedRows: bigint;
  lastInsertRowid: bigint;
}
export interface TransactionResult { statements: StatementResult[] }
export interface Committed {
  readonly state: 'committed';
  readonly receipt: Receipt;
  /** A Node Buffer at runtime, with independent retained bytes. */
  readonly rawResult: Uint8Array;
  readonly result: TransactionResult;
}
export type Resolution = Committed |
  { readonly state: 'cancelled'; readonly transition: Transition } |
  { readonly state: 'unknown' | 'closed' | 'retired' };

export type Lifecycle = 'ready' | 'maintenance' | 'deleted';
export interface DatabaseStatus {
  readonly scope: Scope;
  readonly revision: Decimal;
  readonly sequence: Decimal;
  readonly owner_epoch: Decimal;
  readonly owner_instance: Decimal;
  readonly active: boolean;
  readonly auth_epoch: Decimal;
  readonly lifecycle: Lifecycle;
  readonly request_epoch: Decimal;
  readonly max_bytes: Decimal | null;
  readonly transition: Transition;
  readonly retention: {
    readonly max_entries: number;
    readonly max_result_bytes: Decimal;
    readonly oldest_epoch: Decimal;
  };
}
export interface Permission {
  readonly principal: Decimal;
  readonly read: boolean;
  readonly write: boolean;
  readonly admin: boolean;
}
export interface AdministrativeInput { readonly expectedRevision: Decimal; readonly nonce: Decimal }
export interface CallOptions { readonly timeoutMs?: number; readonly signal?: AbortSignal }
export interface ResultLimits {
  readonly maxStatements?: number;
  readonly maxSqlBytes?: number;
  readonly maxParameters?: number;
  readonly maxColumns?: number;
  readonly maxRows?: number;
  readonly maxResultBytes?: number;
  readonly maxValueBytes?: number;
  readonly maxInputBytes?: number;
}
export interface AllocationLimits {
  readonly maxRows?: number;
  readonly maxValues?: number;
  readonly maxColumns?: number;
}
export interface ClientOptions {
  readonly endpoint: string;
  readonly token: string;
  readonly scope: Scope;
  readonly principal: Decimal;
  readonly timeoutMs?: number;
  readonly recoveryTimeoutMs?: number;
  readonly maxRequestBytes?: number;
  readonly maxResponseBytes?: number;
  readonly resultLimits?: ResultLimits;
  readonly allocation?: AllocationLimits;
  readonly allowInsecureHttp?: boolean;
  /** Trusted transport injection; it must preserve standard Fetch semantics. */
  readonly fetch?: typeof globalThis.fetch;
}

export interface OperationReference {
  readonly scope: Scope;
  readonly operation?: string;
  readonly request?: RequestIdentity;
  readonly nonce?: Decimal;
  readonly expectedRevision?: Decimal;
}

export type QuotaChoice =
  { readonly mode: 'default' | 'unlimited'; readonly max_bytes?: never } |
  { readonly mode: 'limited'; readonly max_bytes: Decimal };
export interface Creation {
  readonly creator: Decimal;
  /** The original create operation, including when another ADMIN deletes it. */
  readonly operation: Decimal;
  readonly name: string;
  readonly scope: Scope;
  readonly expected_name_revision: Decimal | null;
}
export interface PrepareCreateInput {
  readonly name: string;
  readonly create_operation: Decimal;
  /** Required: null for a never-bound name, or the exact observed tombstone revision. */
  readonly expected_name_revision: Decimal | null;
  readonly options: { readonly quota: QuotaChoice };
}
export interface AbortCreateInput {
  readonly creation: Creation;
  readonly control_operation: Decimal;
  readonly expected_name_revision: Decimal;
  readonly nonce: Decimal;
}
export interface DeleteNameInput extends AbortCreateInput {
  readonly expected_head_revision: Decimal;
}
export type CatalogueAction =
  ({ readonly operation: 'prepare_create' } & PrepareCreateInput) |
  { readonly operation: 'resume_create'; readonly creation: Creation } |
  ({ readonly operation: 'abort_create' } & AbortCreateInput) |
  { readonly operation: 'inspect_create_operation'; readonly create_operation: Decimal } |
  { readonly operation: 'resolve_name'; readonly name: string } |
  ({ readonly operation: 'delete_name' } & DeleteNameInput);

declare const preparedCatalogueIntent: unique symbol;
type FrozenCatalogueValue<T> = T extends object ? { readonly [K in keyof T]: FrozenCatalogueValue<T[K]> } : T;
/** Obtain through prepareIntent/restoreIntent; persist saveIntent before sending. */
export interface CatalogueIntent<A extends CatalogueAction = CatalogueAction> {
  readonly [preparedCatalogueIntent]: true;
  readonly version: 1;
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly principal: Decimal;
  readonly action: FrozenCatalogueValue<A>;
}
export interface CatalogueReference {
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly principal: Decimal;
  readonly operation: CatalogueAction['operation'];
  readonly intent: CatalogueIntent;
}
export type RequestReference = OperationReference | CatalogueReference;

export interface PreparedCreate {
  readonly creation: Creation;
  /** Immutable initial policy, not the current HEAD quota. */
  readonly initial_quota: { readonly max_bytes: Decimal | null };
  readonly retention: { readonly max_entries: number; readonly max_result_bytes: Decimal };
}
export type CreationPhase = 'not_reserved' | 'reserved' | 'provisioning' | 'bound' | 'ready' |
  'aborting' | 'aborted' | 'deleting' | 'deleted' | 'name_conflict' | 'identity_conflict';
export interface CreationProgress extends PreparedCreate {
  readonly phase: CreationPhase;
  readonly binding_revision: Decimal | null;
  readonly head_revision: Decimal | null;
}
export interface AbortProgress {
  readonly creation: Creation;
  /** The control operation; creation.operation remains the original create ID. */
  readonly operation: Decimal;
  readonly nonce: Decimal;
  readonly phase: 'not_reserved' | 'cannot_abort_bound' | 'aborting' | 'aborted';
  readonly binding_revision: Decimal | null;
  readonly head_revision: Decimal | null;
}
export interface DeletionProgress extends Omit<AbortProgress, 'phase'> {
  readonly phase: 'not_deleted' | 'deleting' | 'deleted';
}
export interface Named {
  readonly creation: Creation;
  readonly binding_revision: Decimal;
  readonly head: DatabaseStatus;
}
export type CatalogueResult<A extends CatalogueAction = CatalogueAction> =
  A extends { readonly operation: 'prepare_create' } ? PreparedCreate :
  A extends { readonly operation: 'resume_create' | 'inspect_create_operation' } ? CreationProgress :
  A extends { readonly operation: 'abort_create' } ? AbortProgress :
  A extends { readonly operation: 'delete_name' } ? DeletionProgress : Named;
export interface CatalogueClientOptions extends Omit<ClientOptions, 'scope' | 'resultLimits' | 'allocation'> {
  /** Expected server authority, used locally and never sent as caller-supplied authorization. */
  readonly deployment: Decimal;
  readonly tenant: Decimal;
}

export class CatalogueClient {
  constructor(options: CatalogueClientOptions);
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly principal: Decimal;
  prepareIntent<A extends CatalogueAction>(action: A): CatalogueIntent<A>;
  saveIntent(intent: CatalogueIntent): string;
  restoreIntent(serialized: string): CatalogueIntent;
  /** One HTTP POST; no automatic lookup, refresh, condition change or retry. */
  submit<A extends CatalogueAction>(intent: CatalogueIntent<A>, options?: CallOptions): Promise<CatalogueResult<A>>;
  prepareCreate(input: PrepareCreateInput, options?: CallOptions): Promise<PreparedCreate>;
  resumeCreate(creation: Creation, options?: CallOptions): Promise<CreationProgress>;
  abortCreate(input: AbortCreateInput, options?: CallOptions): Promise<AbortProgress>;
  inspectCreateOperation(createOperation: Decimal, options?: CallOptions): Promise<CreationProgress>;
  resolveName(name: string, options?: CallOptions): Promise<Named>;
  deleteName(input: DeleteNameInput, options?: CallOptions): Promise<DeletionProgress>;
}

export class ClientError extends Error {
  readonly code: string;
  constructor(code: string, message: string, cause?: unknown);
}
export class RemoteError extends ClientError {
  readonly outcome: 'unresolved';
  readonly reference: RequestReference;
  constructor(code: string, message: string, reference: RequestReference);
}
export class UnknownError extends ClientError {
  readonly code: 'UNKNOWN';
  readonly outcome: 'unknown';
  readonly reference: RequestReference;
  constructor(reference: RequestReference, cause?: unknown);
}
export class CommittedResultError extends ClientError {
  readonly outcome: 'committed';
  readonly receipt: Receipt;
  readonly rawResult?: Uint8Array;
  constructor(code: string, receipt: Receipt, rawResult?: Uint8Array, cause?: unknown);
}

export class Client {
  constructor(options: ClientOptions);
  readonly scope: Scope;
  readonly principal: Decimal;
  prepare(statements: readonly Statement[], request: { readonly epoch: Decimal; readonly id: Decimal }): TrackedRequest;
  save(request: TrackedRequest): string;
  restore(serialized: string): TrackedRequest;
  status(options?: CallOptions): Promise<DatabaseStatus>;
  open(options?: CallOptions): Promise<DatabaseStatus>;
  create(input: { readonly nonce: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  query(statements: readonly Statement[], options?: CallOptions): Promise<TransactionResult>;
  execute(request: TrackedRequest, options?: CallOptions): Promise<Committed>;
  lookup(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
  cancel(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
  activate(input: AdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  takeover(input: AdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  closeFull(input: AdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  setQuota(input: AdministrativeInput & { readonly maxBytes: Decimal | null }, options?: CallOptions): Promise<DatabaseStatus>;
  setPolicy(input: AdministrativeInput & { readonly permissions: readonly Permission[] }, options?: CallOptions): Promise<DatabaseStatus>;
  setLifecycle(input: AdministrativeInput & { readonly lifecycle: Lifecycle }, options?: CallOptions): Promise<DatabaseStatus>;
}

export function validateResult(bytes: Uint8Array, overrides?: ResultLimits): void;
export function decodeResult(bytes: Uint8Array, overrides?: ResultLimits, allocation?: AllocationLimits): TransactionResult;
