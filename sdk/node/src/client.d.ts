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
  readonly terminal: { readonly serial: Decimal } | null;
}
export interface DatabaseStatus {
  readonly scope: Scope;
  readonly revision: Decimal;
  readonly head_serial: Decimal;
  readonly storage: StorageStatus;
  /** Historical durable owner marker; null only before the first accepted plan. */
  readonly owner_plan: OwnerPlan | null;
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
  readonly ownerInput?: PrepareOwnerInput;
  readonly ownerIdentity?: OwnerIdentity;
  readonly ownerPlan?: OwnerPlanRef;
  readonly snapshotInput?: PrepareSnapshotInput;
  readonly snapshotIdentity?: SnapshotIdentity;
  readonly snapshotReference?: SnapshotRef;
  readonly snapshotLimits?: SnapshotLimits;
}

export interface SnapshotIdentity { readonly creator: Decimal; readonly operation: Decimal }
export interface SnapshotRef extends SnapshotIdentity {
  readonly capture_serial: Decimal;
  readonly descriptor_hash: string;
}
export interface PrepareSnapshotInput extends SnapshotIdentity {
  readonly expected_revision: Decimal;
  readonly expected_head_serial: Decimal;
  /** Nonempty, at most 128 UTF-8 bytes, without control characters. */
  readonly label: string;
}
export interface SnapshotPoint {
  readonly data_root: string;
  readonly page_count: number;
  readonly sequence: Decimal;
  readonly source_revision: Decimal;
}
export interface SnapshotEntry {
  readonly reference: SnapshotRef;
  readonly label: string;
  readonly point: SnapshotPoint;
}
export interface SnapshotLimits {
  /** Zero disables new retained points. The persisted format allows at most 64. */
  readonly max_points: number;
  /** Gross logical bytes, counted once per point even when roots share objects. */
  readonly max_logical_bytes: Decimal;
}
declare const savedSnapshotInput: unique symbol;
export interface SavedSnapshotInput {
  readonly [savedSnapshotInput]: true;
  readonly version: 1;
  readonly scope: Scope;
  readonly input: PrepareSnapshotInput;
}
export interface SnapshotRecord {
  readonly scope: Scope;
  readonly input: PrepareSnapshotInput;
  readonly reference: SnapshotRef;
  readonly point: SnapshotPoint;
}
declare const preparedSnapshot: unique symbol;
/** SDK misuse guard; current server ADMIN/READ checks remain authoritative. */
export interface PreparedSnapshot extends SnapshotRecord { readonly [preparedSnapshot]: true }
export interface SnapshotObservation<P extends SnapshotRecord = SnapshotRecord> {
  /** Current observation. ReleasedObserved does not manufacture a past ACK. */
  readonly state: 'prepared' | 'retained' | 'released_observed' | 'fenced';
  readonly status: DatabaseStatus;
  readonly prepared: P;
  readonly accepted: SnapshotEntry | null;
}
export interface SnapshotListing {
  readonly status: DatabaseStatus;
  readonly snapshots: readonly SnapshotEntry[];
  /** Null before this database first adopts the retained-snapshot format. */
  readonly limits: SnapshotLimits | null;
}

export interface OwnerIdentity { readonly creator: Decimal; readonly operation: Decimal }
export interface OwnerPlanRef extends OwnerIdentity { readonly descriptor_hash: string }
export interface OwnerNonces {
  readonly claim: Decimal;
  readonly cancel: Decimal;
  readonly activate: Decimal;
  readonly abort: Decimal;
}
export interface PrepareOwnerInput extends OwnerIdentity {
  readonly expected_revision: Decimal;
  readonly expected_head_serial: Decimal;
  readonly mode: 'takeover' | 'activate';
  readonly target_worker: Decimal;
  readonly nonces: OwnerNonces;
}
export interface OwnerPlan {
  readonly reference: OwnerPlanRef;
  readonly admission: {
    readonly kind: 'claim' | 'cancel';
    readonly revision: Decimal;
    readonly head_serial: Decimal;
  };
  readonly phase: {
    readonly kind: 'claimed' | 'cancelling' | 'active' | 'aborted';
    readonly revision: Decimal;
    readonly head_serial: Decimal;
    readonly nonce: Decimal;
    readonly owner_epoch: Decimal;
    readonly owner_instance: Decimal;
  };
}
declare const savedOwnerInput: unique symbol;
export interface SavedOwnerInput {
  readonly [savedOwnerInput]: true;
  readonly version: 1;
  readonly scope: Scope;
  readonly input: PrepareOwnerInput;
}
/** Public immutable history; identity-only observation cannot authorize SDK mutation. */
export interface OwnerRecord {
  readonly scope: Scope;
  readonly input: PrepareOwnerInput;
  readonly reference: OwnerPlanRef;
}
declare const preparedOwner: unique symbol;
/** SDK misuse guard, not a credential. The server verifies current ADMIN on every call. */
export interface PreparedOwner extends OwnerRecord { readonly [preparedOwner]: true }
export type OwnerPreparation =
  { readonly state: 'prepared'; readonly prepared: PreparedOwner } |
  { readonly state: 'pending'; readonly reference: OwnerPlanRef };
export interface OwnerObservation<P extends OwnerRecord = OwnerRecord> {
  /** Historical phase; Active does not assert today's active owner or a native Session. */
  readonly state: 'prepared' | 'claimed' | 'cancelling' | 'active' | 'aborted' | 'fenced';
  readonly status: DatabaseStatus;
  readonly prepared: P;
  /** Fenced with null accepted means past outcome unknown, never proven NotApplied. */
  readonly accepted: OwnerPlan | null;
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
export class OwnerPlanClient {
  /** Current ADMIN only. No network method sends SQL or automatically retries a phase. */
  constructor(options: RoutedClientOptions);
  readonly scope: Scope;
  readonly principal: Decimal;
  /** Pure, deep immutable snapshot. Durably save it before the first prepare POST. */
  prepareInput(input: PrepareOwnerInput): SavedOwnerInput;
  saveInput(input: SavedOwnerInput): string;
  restoreInput(serialized: string): SavedOwnerInput;
  prepare(input: SavedOwnerInput, options?: CallOptions): Promise<OwnerPreparation>;
  /** Identity-only wire read followed by full original input and Scope comparison. */
  inspect(input: SavedOwnerInput, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  /** Pure history read; its OwnerRecord cannot be supplied to claim/resume/abort. */
  observe(identity: OwnerIdentity, options?: CallOptions): Promise<OwnerObservation>;
  /** Uses only the immutable target's locally configured route and mandatory worker guard. */
  claim(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  /** Uses recoveryTimeoutMs under one original deadline; no automatic second POST. */
  resume(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  /** May be sent by a current ADMIN through the metadata bootstrap, without a live target. */
  abort(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
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
export interface RetireNamedStorageInput {
  readonly creation: Creation;
  readonly expected_head_serial: Decimal;
}
export interface PrepareRestoreInput extends Omit<PrepareCreateInput, 'create_operation'> {
  readonly restore_operation: Decimal;
  readonly source_scope: Scope;
  readonly snapshot: SnapshotRef;
}
export interface RestoreRef {
  readonly creation: Creation;
  readonly descriptor_hash: string;
}
export interface AbortRestoreInput extends Omit<AbortCreateInput, 'creation'> {
  readonly reference: RestoreRef;
}
export interface PreparedRestore extends Omit<PreparedCreate, 'creation'> {
  readonly reference: RestoreRef;
  readonly input: PrepareRestoreInput;
  readonly point: SnapshotPoint;
}
export interface RestoreProgress {
  readonly prepared: PreparedRestore;
  readonly phase: 'not_reserved' | 'reserved' | 'copying' | 'copied' | 'bound' | 'ready' |
    'aborting' | 'aborted' | 'deleting' | 'deleted' | 'name_conflict' | 'identity_conflict';
  readonly binding_revision: Decimal | null;
  readonly head_revision: Decimal | null;
}
export type CatalogueAction =
  ({ readonly operation: 'prepare_create' } & PrepareCreateInput) |
  { readonly operation: 'resume_create'; readonly creation: Creation } |
  ({ readonly operation: 'abort_create' } & AbortCreateInput) |
  { readonly operation: 'inspect_create_operation'; readonly create_operation: Decimal } |
  ({ readonly operation: 'prepare_restore' } & PrepareRestoreInput) |
  { readonly operation: 'resume_restore'; readonly reference: RestoreRef } |
  { readonly operation: 'inspect_restore'; readonly creator: Decimal; readonly restore_operation: Decimal } |
  ({ readonly operation: 'abort_restore' } & AbortRestoreInput) |
  { readonly operation: 'resolve_name'; readonly name: string } |
  ({ readonly operation: 'delete_name' } & DeleteNameInput) |
  { readonly operation: 'named_storage_status'; readonly creation: Creation } |
  ({ readonly operation: 'retire_named_storage' } & RetireNamedStorageInput);

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
  A extends { readonly operation: 'prepare_restore' } ? PreparedRestore :
  A extends { readonly operation: 'resume_restore' | 'inspect_restore' } ? RestoreProgress :
  A extends { readonly operation: 'prepare_create' } ? PreparedCreate :
  A extends { readonly operation: 'resume_create' | 'inspect_create_operation' } ? CreationProgress :
  A extends { readonly operation: 'abort_create' | 'abort_restore' } ? AbortProgress :
  A extends { readonly operation: 'delete_name' } ? DeletionProgress :
  A extends { readonly operation: 'named_storage_status' | 'retire_named_storage' } ? DatabaseStatus : Named;
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
  prepareRestore(input: PrepareRestoreInput, options?: CallOptions): Promise<PreparedRestore>;
  /** One transition; copying uses the independently bounded recovery class. */
  resumeRestore(reference: RestoreRef, options?: CallOptions): Promise<RestoreProgress>;
  inspectRestore(restoreOperation: Decimal, options?: CallOptions): Promise<RestoreProgress>;
  abortRestore(input: AbortRestoreInput, options?: CallOptions): Promise<AbortProgress>;
  resolveName(name: string, options?: CallOptions): Promise<Named>;
  deleteName(input: DeleteNameInput, options?: CallOptions): Promise<DeletionProgress>;
  /** Deleted metadata only; verifies the original named deletion or abort intent. */
  storageStatus(creation: Creation, options?: CallOptions): Promise<DatabaseStatus>;
  /** One original-serial CAS; does not require or grant physical DELETE credentials. */
  retireStorage(input: RetireNamedStorageInput, options?: CallOptions): Promise<DatabaseStatus>;
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
  readonly state: 'descriptor_only' | 'reserved' | 'provisioning' | 'restore_copying' | 'restore_copied' | 'bound' | 'ready' | 'maintenance' |
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
  ownerPrepare(input: PrepareOwnerInput, options?: CallOptions): Promise<OwnerPreparation>;
  ownerInspect(input: PrepareOwnerInput, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  ownerObserve(identity: OwnerIdentity, options?: CallOptions): Promise<OwnerObservation>;
  ownerClaim(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  ownerResume(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  ownerAbort(prepared: PreparedOwner, options?: CallOptions): Promise<OwnerObservation<PreparedOwner>>;
  prepareSnapshotInput(input: PrepareSnapshotInput): SavedSnapshotInput;
  /** Persist this string before the first prepare RPC. It contains no bearer token. */
  saveSnapshotInput(input: SavedSnapshotInput): string;
  restoreSnapshotInput(serialized: string): SavedSnapshotInput;
  snapshotPrepare(saved: SavedSnapshotInput, options?: CallOptions): Promise<PreparedSnapshot>;
  snapshotInspect(saved: SavedSnapshotInput, options?: CallOptions): Promise<SnapshotObservation<PreparedSnapshot>>;
  /** Identity-only observations cannot authorize SDK capture or release. */
  snapshotObserve(identity: SnapshotIdentity, options?: CallOptions): Promise<SnapshotObservation>;
  snapshotCapture(prepared: PreparedSnapshot, options?: CallOptions): Promise<SnapshotObservation<PreparedSnapshot>>;
  snapshotRelease(prepared: PreparedSnapshot, options?: CallOptions): Promise<SnapshotObservation<PreparedSnapshot>>;
  snapshotList(options?: CallOptions): Promise<SnapshotListing>;
  setSnapshotLimits(input: { readonly expectedRevision: Decimal; readonly nonce: Decimal;
    readonly limits: SnapshotLimits }, options?: CallOptions): Promise<SnapshotListing>;
  closeFull(input: AdministrativeInput, options?: CallOptions): Promise<DatabaseStatus>;
  setQuota(input: AdministrativeInput & { readonly maxBytes: Decimal | null }, options?: CallOptions): Promise<DatabaseStatus>;
  setPolicy(input: AdministrativeInput & { readonly permissions: readonly Permission[] }, options?: CallOptions): Promise<DatabaseStatus>;
  setLifecycle(input: AdministrativeInput & { readonly lifecycle: Lifecycle }, options?: CallOptions): Promise<DatabaseStatus>;
  /** Freeze a closure at the exact physical HEAD; does not retry an uncertain begin. */
  compactBegin(input: { readonly expectedHeadSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
  /** Direct Deleted databases only; ordinary status and lookup remain lifecycle errors. */
  storageStatus(options?: CallOptions): Promise<DatabaseStatus>;
  /** Permanently retire every allocated physical generation; never deletes the HEAD. */
  retireStorage(input: { readonly expectedHeadSerial: Decimal }, options?: CallOptions): Promise<DatabaseStatus>;
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

export interface ControllerWorker {
  readonly workerInstance: Decimal;
  readonly endpoint: string;
  readonly rank: number;
}
export interface ControllerPolicyOptions {
  readonly scope: Scope;
  readonly authorityId: string;
  /** Dedicated READ+ADMIN creator; its owner operation domain is reserved for this controller. */
  readonly principal: Decimal;
  readonly metadataEndpoints: readonly string[];
  readonly workers: readonly ControllerWorker[];
  readonly modes: { readonly takeover: boolean; readonly activate: boolean; readonly cancel: boolean };
  readonly allowInsecureHttp?: boolean;
  readonly recoveryTimeoutMs?: number;
  /** Explicit irreversible deployment retirement; old identities remain in workers. */
  readonly retiredWorkers?: readonly Decimal[];
}
declare const controllerPolicy: unique symbol;
export interface ControllerPolicy {
  readonly [controllerPolicy]: true;
  readonly version: 1;
  readonly scope: Scope;
  readonly authorityId: string;
  readonly principal: Decimal;
  readonly metadataEndpoints: readonly string[];
  readonly workers: readonly ControllerWorker[];
  readonly retiredWorkers?: readonly Decimal[];
  readonly modes: ControllerPolicyOptions['modes'];
  readonly allowInsecureHttp: boolean;
  readonly canonical: string;
  readonly digest: string;
  readonly nonces: OwnerNonces;
  readonly limits: Readonly<Record<'scopes' | 'workers' | 'metadataEndpoints' | 'policyBytes' | 'ticks' |
    'tenantTicks' | 'recoveries' | 'httpCalls' | 'mutations' | 'requestBytes' | 'responseBytes' | 'headerBytes' |
    'timeoutMs' | 'recoveryTimeoutMs' | 'probeTimeoutMs' | 'tickIntervalMs' | 'failureCount' | 'failureIntervalMs' |
    'failureSpanMs', number> & { backoffMs: readonly number[] }>;
}
export function createControllerPolicy(options: ControllerPolicyOptions): ControllerPolicy;
export interface ControllerReport {
  readonly version: 1;
  readonly scope: Scope;
  readonly policyDigest: string;
  readonly state: 'healthy' | 'waiting' | 'prepared' | 'claimed' | 'cancelling' | 'aborted' | 'active_observed' |
    'fenced' | 'blocked' | 'unknown';
  readonly reason: string;
  readonly currentAuthority: DatabaseStatus | null;
  readonly acceptedPhase: OwnerPlan['phase']['kind'] | null;
  readonly httpCalls: number;
  readonly mutations: number;
  readonly recoveryBudget: boolean;
  readonly pastUnknown: boolean;
  /** Latest uncertain original call only; pastUnknown is not reset by later observations. */
  readonly lastUncertainCall: { readonly operation: string; readonly request?: string; readonly reference?: string } | null;
  readonly nativeSession: 'NOT_CERTIFIED';
  /** Process-local monotonic milliseconds, not a lease or durable timestamp. */
  readonly nextTickAt: number;
}
export class OwnerController {
  /** Injected fetch must honor the owned-resource contract; the default fleet transport supplies it. */
  constructor(options: { readonly policy: ControllerPolicy; readonly token: string; readonly fetch: typeof globalThis.fetch;
    readonly previousPolicies?: readonly ControllerPolicy[] });
  readonly policy: ControllerPolicy;
  readonly needsRecovery: boolean;
  readonly nextTickAt: number;
  readonly lastReport: ControllerReport | null;
  tick(options?: CallOptions): Promise<ControllerReport>;
  close(): Promise<void>;
}

export interface OwnedControllerTransport {
  readonly fetch: typeof globalThis.fetch;
  /** Join every original request, socket and DNS callback owned by this transport. */
  close(): Promise<void>;
  /** Required by dynamic fleets: stop admission and join old resources, then allow reuse. */
  quiesce?(): Promise<void>;
}
export interface ControllerHttpSnapshot {
  readonly closed: boolean;
  readonly active: number;
  readonly peak: number;
  readonly started: number;
  readonly completed: number;
}
export class ControllerHttp implements OwnedControllerTransport {
  constructor(options?: { readonly maxRequests?: number });
  readonly fetch: typeof globalThis.fetch;
  snapshot(): ControllerHttpSnapshot;
  quiesce(): Promise<void>;
  /** Aborts attempts and joins resources; a system DNS callback has no fixed shutdown bound. */
  close(): Promise<void>;
}
export interface ControllerFleetSnapshot {
  readonly closed: boolean;
  readonly scopes: number;
  readonly active: number;
  readonly recoveries: number;
  readonly pendingReports: number;
}
export interface ControllerFailureReport {
  readonly version: 1;
  readonly scope: Scope;
  readonly policyDigest: string;
  readonly state: 'blocked';
  readonly reason: 'CONTROLLER_FAILURE';
  readonly nativeSession: 'NOT_CERTIFIED';
}
export class OwnerControllerFleet {
  constructor(options: {
    readonly entries: readonly ControllerEntry[];
    readonly transport?: OwnedControllerTransport;
    readonly revision?: Decimal;
  });
  readonly revision: Decimal | null;
  readonly updating: boolean;
  /** One monotonic trusted snapshot, installed only after every old tick joins. */
  replace(configuration: { readonly revision: Decimal; readonly entries: readonly ControllerEntry[] }):
    Promise<{ readonly revision: Decimal; readonly scopes: number }>;
  snapshot(): ControllerFleetSnapshot;
  /** Admit eligible ticks into free slots; never queue another round for a busy Scope. */
  poll(): ControllerFleetSnapshot & { readonly started: number };
  /** Latest completed report per Scope only, not a durable or complete event log. */
  takeReports(): readonly (ControllerReport | ControllerFailureReport)[];
  close(): Promise<void>;
}
export interface ControllerEntry {
  readonly policy: ControllerPolicy;
  readonly token: string;
  readonly previousPolicies?: readonly ControllerPolicy[];
}
export interface ControllerConfiguration {
  readonly revision: Decimal | null;
  readonly entries: readonly ControllerEntry[];
}
export function readControllerEntries(path: string, environment?: Readonly<Record<string, string | undefined>>):
  readonly ControllerEntry[];
export function readControllerConfiguration(path: string, environment?: Readonly<Record<string, string | undefined>>): ControllerConfiguration;
/** Runs bounded polling and joins the fleet on shutdown; synchronous output has no logging queue. */
export function runControllerFleet(fleet: OwnerControllerFleet,
  options: { readonly signal: AbortSignal; readonly outputFd?: number;
    readonly reload?: () => ControllerConfiguration | null }): Promise<void>;
