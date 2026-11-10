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
export interface CopyPlanStatus {
  readonly serial: Decimal;
  readonly source: Decimal;
  readonly target: Decimal;
  readonly phase: 'copying' | 'sealed';
}
export interface SweepStatus {
  readonly serial: Decimal;
  readonly generation: Decimal;
  readonly next_after: string | null;
  readonly exhausted: boolean;
  readonly pending: number;
  readonly applied: number;
  readonly observed_absent: number;
  readonly condition_mismatch: number;
}
export interface StorageStatus {
  readonly active_generation: Decimal;
  readonly allocated_through: Decimal;
  readonly plan: CopyPlanStatus | null;
  readonly sweep: SweepStatus | null;
}
export interface DatabaseStatus {
  readonly scope: Scope;
  readonly revision: Decimal;
  readonly head_serial: Decimal;
  readonly storage: StorageStatus;
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
export interface SweepReport {
  readonly status: DatabaseStatus;
  readonly generation: Decimal;
  readonly scanned: number;
  readonly next_after: string | null;
  readonly exhausted: boolean;
}
export interface Permission {
  readonly principal: Decimal;
  readonly read: boolean;
  readonly write: boolean;
  readonly admin: boolean;
}
export interface AdministrativeInput { readonly expectedRevision: Decimal; readonly nonce: Decimal }
export interface OwnerAdministrativeInput extends AdministrativeInput {
  /** Reject a misbound or restarted destination before authority or recovery effects. */
  readonly expectedWorkerInstance?: Decimal;
}
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
  readonly expectedWorkerInstance?: Decimal;
  readonly expectedHeadSerial?: Decimal;
  readonly planSerial?: Decimal;
  readonly batchSerial?: Decimal;
  readonly storageGeneration?: Decimal;
  readonly after?: string | null;
}

export interface OwnerRoute { readonly workerInstance: Decimal; readonly endpoint: string }
export interface RoutedClientOptions extends Omit<ClientOptions, 'endpoint'> {
  readonly bootstrapEndpoint: string;
  /** Static credential destinations; one endpoint per worker, at most 256 entries. */
  readonly routes: readonly OwnerRoute[];
}
export class RoutedClient {
  constructor(options: RoutedClientOptions);
  readonly scope: Scope;
  readonly principal: Decimal;
  prepare(statements: readonly Statement[], request: { readonly epoch: Decimal; readonly id: Decimal }): TrackedRequest;
  save(request: TrackedRequest): string;
  restore(serialized: string): TrackedRequest;
  status(options?: CallOptions): Promise<DatabaseStatus>;
  query(statements: readonly Statement[], options?: CallOptions): Promise<TransactionResult>;
  execute(request: TrackedRequest, options?: CallOptions): Promise<Committed>;
  lookup(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
  cancel(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
}
declare const ownerIntent: unique symbol;
export interface OwnerIntent {
  readonly [ownerIntent]: true;
  readonly version: 1;
  readonly scope: Scope;
  readonly principal: Decimal;
  readonly registryDigest: string;
  readonly mode: 'takeover' | 'activate';
  readonly baseRevision: Decimal;
  readonly baseOwnerEpoch: Decimal;
  readonly baseOwnerInstance: Decimal;
  readonly baseActive: boolean;
  readonly targetWorker: Decimal;
  readonly takeoverNonce: Decimal | null;
  readonly activateNonce: Decimal;
}
export interface OwnerInspection {
  readonly state: 'activation_accepted' | 'takeover_accepted' | 'base_observed' | 'blocked' |
    'unresolved' | 'target_active' | 'target_inactive' | 'superseded';
  readonly intent: OwnerIntent;
  readonly status: DatabaseStatus;
}
export interface ActiveOwner {
  readonly state: 'active';
  readonly intent: OwnerIntent;
  readonly status: DatabaseStatus;
}
export class OwnerClient {
  /** Reconciliation needs READ+ADMIN; observation/probes need READ. This client never sends SQL. */
  constructor(options: RoutedClientOptions);
  readonly scope: Scope;
  readonly principal: Decimal;
  observe(options?: CallOptions): Promise<DatabaseStatus>;
  /** One fresh READ on a trusted worker route; the returned owner may be another worker. */
  probe(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>;
  prepareTakeover(observed: DatabaseStatus, input: {
    readonly targetWorker: Decimal; readonly takeoverNonce: Decimal; readonly activateNonce: Decimal;
  }): OwnerIntent;
  prepareActivation(observed: DatabaseStatus, input: { readonly activateNonce: Decimal }): OwnerIntent;
  /** Pure serialization. The application must durably save and sync before reconcile. */
  saveIntent(intent: OwnerIntent): string;
  /** Restored intents can be inspected, but never dispatched by reconcile. */
  restoreIntent(serialized: string): OwnerIntent;
  /** Consumes a fresh intent once, even if observation fails before a transition. */
  reconcile(intent: OwnerIntent, options?: CallOptions): Promise<ActiveOwner>;
  inspect(intent: OwnerIntent, options?: CallOptions): Promise<OwnerInspection>;
}
export class RouteError extends ClientError {
  readonly outcome: 'not_sent';
  constructor(error: unknown);
}
export class OwnerReconcileError extends ClientError {
  readonly intent: OwnerIntent;
  readonly phase: 'observe' | 'takeover' | 'activate';
  readonly lastConfirmed: DatabaseStatus | null;
  readonly outcome: 'unknown' | 'active' | 'partial' | 'unresolved' | 'not_sent';
  constructor(intent: OwnerIntent, phase: 'observe' | 'takeover' | 'activate',
    lastConfirmed: DatabaseStatus | null, dispatched: boolean, uncertain: boolean, error: unknown);
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
export interface DiscoveryReference {
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly principal: Decimal;
  readonly operation: 'list_names' | 'deployment_inventory';
}
export type RequestReference = OperationReference | CatalogueReference | DiscoveryReference;

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

export type DiscoveryStop = 'INVALID' | 'DENIED' | 'LIMIT' | 'CONFLICT' | 'UNKNOWN' | 'CORRUPT' | 'SNAPSHOT_EXPIRED' | null;
export interface VisibleName {
  readonly creation: Creation;
  readonly binding_revision: Decimal;
  readonly head_revision: Decimal;
}
export interface NamePage {
  readonly names: readonly VisibleName[];
  /** Opaque, caller-bound and short-lived. A restart requires beginning again. */
  readonly cursor: string | null;
  readonly traversal_exhausted: boolean;
  readonly stopped: DiscoveryStop;
}
export interface InventoryRecord {
  readonly key: string;
  readonly kind: 'name' | 'create' | 'control' | 'abort_proof' | 'head' | 'orphan_prefix';
  readonly state: 'descriptor_only' | 'reserved' | 'provisioning' | 'bound' | 'ready' | 'maintenance' |
    'aborting' | 'aborted' | 'deleting' | 'deleted' | 'name_conflict' | 'identity_conflict' | 'control_admitted' | 'orphan';
  readonly creation: Creation | null;
  readonly scope: Scope | null;
  readonly control: ObservedControl | null;
  readonly binding_revision: Decimal | null;
  readonly head_revision: Decimal | null;
}
export type ObservedControl = {
  readonly principal: Decimal;
  readonly operation: Decimal;
  readonly expected_name_revision: Decimal;
  readonly nonce: Decimal;
} & ({ readonly kind: 'abort'; readonly expected_head_revision: null } |
  { readonly kind: 'delete'; readonly expected_head_revision: Decimal });
export interface InventoryPage {
  readonly records: readonly InventoryRecord[];
  readonly cursor: string | null;
  readonly stopped: DiscoveryStop;
  readonly completion: {
    readonly traversal_exhausted: boolean;
    readonly preexisting_slots_covered: boolean;
    readonly metadata_classified: Decimal;
    readonly data_recovery: 'not_run';
    readonly recovery_complete: false;
  };
  readonly usage: { readonly list_pages: number; readonly candidates: number; readonly exact_gets: number;
    readonly list_bytes: number; readonly metadata_bytes: number };
}
export class DiscoveryClient {
  /** Use the /v1/discovery endpoint. Enabled only by trusted server configuration. */
  constructor(options: CatalogueClientOptions);
  readonly deployment: Decimal;
  readonly tenant: Decimal;
  readonly principal: Decimal;
  /** One page with fresh READ checks; no automatic retries or continuation. */
  listNames(cursor?: string | null, options?: CallOptions): Promise<NamePage>;
  /** Requires the explicit deployment_inventory credential capability; metadata only. */
  deploymentInventory(cursor?: string | null, options?: CallOptions): Promise<InventoryPage>;
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
  /** Guard the receiving service instance without requiring it to own the database. */
  guardedStatus(workerInstance: Decimal, options?: CallOptions): Promise<DatabaseStatus>;
  open(options?: CallOptions): Promise<DatabaseStatus>;
  create(input: { readonly nonce: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  query(statements: readonly Statement[], options?: CallOptions): Promise<TransactionResult>;
  execute(request: TrackedRequest, options?: CallOptions): Promise<Committed>;
  lookup(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
  cancel(request: TrackedRequest, options?: CallOptions): Promise<Resolution>;
  activate(input: OwnerAdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  takeover(input: OwnerAdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  closeFull(input: AdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  setQuota(input: AdministrativeInput & { readonly maxBytes: Decimal | null }, options?: CallOptions): Promise<DatabaseStatus>;
  setPolicy(input: AdministrativeInput & { readonly permissions: readonly Permission[] }, options?: CallOptions): Promise<DatabaseStatus>;
  setLifecycle(input: AdministrativeInput & { readonly lifecycle: Lifecycle }, options?: CallOptions): Promise<DatabaseStatus>;
  /** Freeze a closure at the exact physical HEAD; does not retry an uncertain begin. */
  compactBegin(input: { readonly expectedHeadSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  compactCopy(input: { readonly planSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  /** Publishes the new generation inactive; never activates or replays SQL. */
  compactPromote(input: { readonly planSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  compactAbort(input: { readonly planSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  /** Install at most one bounded checkpoint; no deletion occurs in this call. */
  gcPrepare(input: { readonly expectedHeadSerial: Decimal; readonly generation: Decimal; readonly after: string | null }, options?: CallOptions): Promise<SweepReport>;
  /** Resume only the persisted batch identity and original candidate ETags. */
  gcResume(input: { readonly batchSerial: Decimal }, options?: CallOptions): Promise<SweepReport>;
}

export function validateResult(bytes: Uint8Array, overrides?: ResultLimits): void;
export function decodeResult(bytes: Uint8Array, overrides?: ResultLimits, allocation?: AllocationLimits): TransactionResult;
