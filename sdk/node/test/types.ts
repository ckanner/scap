/** Compile-only public API contract; it never supplies runtime coverage. */
import { CatalogueClient, DiscoveryClient, Client, RoutedClient, OwnerClient, OwnerPlanClient, OwnerController, OwnerControllerFleet, ControllerHttp, readControllerEntries, readControllerConfiguration, runControllerFleet, createControllerPolicy, RouteError, OwnerReconcileError, UnknownError, RemoteError,
  type SavedOwnerInput, type PreparedOwner, type OwnerPreparation, type OwnerObservation, type OwnerPlan,
  type SavedSnapshotInput, type PreparedSnapshot, type SnapshotObservation, type SnapshotListing,
  type DatabaseStatus, type SweepReport, type OwnerIntent, type ActiveOwner, type OwnerInspection, type NamePage, type InventoryPage, type Creation, type PreparedCreate,
  type CreationProgress, type AbortProgress, type DeletionProgress, type Named, type PreparedRestore, type RestoreProgress,
  type CatalogueIntent, type CatalogueResult, type ResourceRejection } from '../src/client.js';

const scope = { deployment: '1', tenant: '2', database: '3', incarnation: '1', generation: '1' };
const creation: Creation = { creator: '7', operation: '11', name: 'notes', scope, expected_name_revision: null };

async function contract() {
  const remote = new RemoteError('BACKPRESSURE', 'synthetic', { scope });
  const rejection: ResourceRejection | undefined = remote.resourceRejection;
  if (rejection !== undefined && 'used' in rejection) {
    const used: string = rejection.used;
    // @ts-expect-error Capacity observations remain exact decimal strings.
    const numeric: number = rejection.limit;
    // @ts-expect-error Diagnostic snapshots are immutable.
    rejection.requested = '1';
    void used; void numeric;
  }
  // @ts-expect-error The server's optional observation cannot be replaced.
  remote.resourceRejection = undefined;
  const sourceOnly: ResourceRejection = { version: 1, reason: 'native_recovery_busy' };
  // @ts-expect-error Native semaphore observations have no fabricated occupancy.
  sourceOnly.used;
  const policy = createControllerPolicy({ scope, authorityId: 'production-example', principal: '7',
    metadataEndpoints: ['https://example.invalid/v1'],
    workers: [{ workerInstance: '10', endpoint: 'https://example.invalid/v1', rank: 0 }],
    modes: { takeover: true, activate: true, cancel: true } });
  const controller = new OwnerController({ policy, token: 'synthetic-typecheck-only-credential', fetch });
  const controllerReport = await controller.tick({ timeoutMs: 1000 });
  const noNativeClaim: 'NOT_CERTIFIED' = controllerReport.nativeSession;
  // @ts-expect-error Controllers do not execute or replay business SQL.
  controller.execute({ sql: 'SELECT 1' });
  // @ts-expect-error A controller cannot change its fixed policy after construction.
  policy.workers[0].rank = 3;
  await controller.close(); void noNativeClaim;
  const transport = new ControllerHttp({ maxRequests: 8 });
  const fleet = new OwnerControllerFleet({ entries: [{ policy, token: 'synthetic-typecheck-only-credential' }], transport });
  const activeTicks: number = fleet.poll().active;
  const activeRequests: number = transport.snapshot().active;
  const fleetReports = fleet.takeReports();
  const notCertified: 'NOT_CERTIFIED' | undefined = fleetReports[0]?.nativeSession;
  // @ts-expect-error A fleet never accepts SQL or a dynamic untrusted routing callback.
  new OwnerControllerFleet({ entries: [], route: () => 'https://example.invalid/v1' });
  // @ts-expect-error Resource ownership requires a joinable close, not fetch alone.
  new OwnerControllerFleet({ entries: [], transport: { fetch } });
  await fleet.close(); void activeTicks; void activeRequests; void notCertified;
  const entries = readControllerEntries('/example/controller.json', { SCAP_OWNER_CONTROLLER_TOKEN: undefined });
  const configured = new OwnerControllerFleet({ entries });
  await runControllerFleet(configured, { signal: AbortSignal.abort(), outputFd: 1 });
  // @ts-expect-error A process loop always requires an explicit shutdown signal.
  runControllerFleet(configured, {});
  const nextPolicy = createControllerPolicy({ scope, authorityId: 'production-example', principal: '7',
    metadataEndpoints: ['https://example.invalid/v1'],
    workers: [{ workerInstance: '10', endpoint: 'https://example.invalid/v1', rank: 0 },
      { workerInstance: '11', endpoint: 'https://example.invalid/v1', rank: 1 }],
    retiredWorkers: ['10'], modes: { takeover: true, activate: true, cancel: true } });
  const dynamic = new OwnerControllerFleet({ entries, revision: '1' });
  const installed = await dynamic.replace({ revision: '2', entries: [{ policy: nextPolicy,
    previousPolicies: [policy], token: 'synthetic-typecheck-only-credential' }] });
  const revision: string | null = dynamic.revision;
  const updating: boolean = dynamic.updating;
  await runControllerFleet(dynamic, { signal: AbortSignal.abort(),
    reload: () => readControllerConfiguration('/example/controller-v2.json') });
  // @ts-expect-error A deployment revision must be a lossless decimal string.
  dynamic.replace({ revision: 3, entries });
  // @ts-expect-error Retirement is immutable configuration, never an editable server suggestion.
  nextPolicy.retiredWorkers!.push('11');
  void installed; void revision; void updating;
  const client = new CatalogueClient({ endpoint: 'https://example.invalid/v1/catalogue',
    token: 'synthetic-typecheck-only-credential', deployment: '1', tenant: '2', principal: '7' });
  const create = client.prepareIntent({ operation: 'prepare_create', name: 'notes', create_operation: '11',
    expected_name_revision: null, options: { quota: { mode: 'default' } } });
  const prepared: PreparedCreate = await client.submit(create);
  const saved: string = client.saveIntent(create);
  const restored: CatalogueIntent = client.restoreIntent(saved);
  const observed: CatalogueResult = await client.submit(restored);
  const progress: CreationProgress = await client.submit(client.prepareIntent({ operation: 'resume_create', creation }));
  const inspected: CreationProgress = await client.inspectCreateOperation('11');
  const named: Named = await client.resolveName('notes');
  const aborted: AbortProgress = await client.abortCreate({ creation, control_operation: '12', expected_name_revision: '1', nonce: '12' });
  const deleted: DeletionProgress = await client.deleteName({ creation, control_operation: '13',
    expected_name_revision: '2', expected_head_revision: '3', nonce: '13' });
  const namedStorage: DatabaseStatus = await client.storageStatus(creation);
  const retiredNamed: DatabaseStatus = await client.retireStorage({ creation, expected_head_serial: namedStorage.head_serial });
  const retiredIntent: DatabaseStatus = await client.submit(client.prepareIntent({
    operation: 'retire_named_storage', creation, expected_head_serial: '4' }));
  const inspectedStorage: DatabaseStatus = await client.submit(client.prepareIntent({ operation: 'named_storage_status', creation }));
  // @ts-expect-error Named retirement requires the original physical HEAD serial.
  client.retireStorage({ creation });
  // @ts-expect-error Physical retirement does not accept object keys or delete capabilities.
  client.retireStorage({ creation, expected_head_serial: '4', keys: ['unsafe'] });
  const input = { operation: 'delete_name' as const, creation: { ...creation, scope: { ...scope } },
    control_operation: '14', expected_name_revision: '2', expected_head_revision: '3', nonce: '14' };
  const tracked = client.prepareIntent(input);
  const alsoDeleted: DeletionProgress = await client.submit(tracked);
  // @ts-expect-error Persisted nested inputs are deeply readonly, even for mutable source objects.
  tracked.action.creation.scope.database = '5';
  // @ts-expect-error A catalogue intent cannot be manually constructed without tracking.
  const forged: CatalogueIntent = { version: 1, deployment: '1', tenant: '2', principal: '7', action: input };
  // @ts-expect-error Expected name revision is required even for a never-bound name.
  client.prepareCreate({ name: 'notes', create_operation: '11', options: { quota: { mode: 'default' } } });
  // @ts-expect-error u64 identities are decimal strings, never JavaScript numbers.
  client.inspectCreateOperation(11);
  // @ts-expect-error Unlimited quota cannot contain a byte limit.
  client.prepareCreate({ name: 'notes', create_operation: '11', expected_name_revision: null, options: { quota: { mode: 'unlimited', max_bytes: '4096' } } });
  // @ts-expect-error Normal deletion preserves its explicit original HEAD revision.
  client.deleteName({ creation, control_operation: '13', expected_name_revision: '2', nonce: '13' });
  const db = new Client({ endpoint: 'https://example.invalid/v1', token: 'synthetic-typecheck-only-credential', scope, principal: '7' });
  const guarded: DatabaseStatus = await db.guardedStatus('10', { timeoutMs: 1000 });
  const snapshotInput: SavedSnapshotInput = db.prepareSnapshotInput({ creator: '7', operation: '61',
    expected_revision: guarded.revision, expected_head_serial: guarded.head_serial, label: 'before migration' });
  const snapshotSaved: SavedSnapshotInput = db.restoreSnapshotInput(db.saveSnapshotInput(snapshotInput));
  const snapshotPrepared: PreparedSnapshot = await db.snapshotPrepare(snapshotSaved);
  const restoreIntent = client.prepareIntent({ operation: 'prepare_restore', name: 'restored-notes',
    restore_operation: '72', expected_name_revision: null, options: { quota: { mode: 'default' } },
    source_scope: scope, snapshot: snapshotPrepared.reference });
  const restoredDatabase: PreparedRestore = await client.submit(restoreIntent);
  const copyProgress: RestoreProgress = await client.resumeRestore(restoredDatabase.reference);
  const restoreInspection: RestoreProgress = await client.inspectRestore('72');
  const abortRestore: AbortProgress = await client.abortRestore({ reference: restoredDatabase.reference,
    control_operation: '73', expected_name_revision: '1', nonce: '73' });
  // @ts-expect-error Restore references are descriptor-bound and cannot be replaced with raw Creation.
  client.resumeRestore(creation);
  // @ts-expect-error Source provenance remains deeply readonly after preparation.
  restoreIntent.action.snapshot.capture_serial = '99';
  // @ts-expect-error Restore never accepts a caller-supplied completion proof.
  client.resumeRestore({ ...restoredDatabase.reference, completion: {} });
  void copyProgress; void restoreInspection; void abortRestore;
  const snapshotObserved: SnapshotObservation<PreparedSnapshot> = await db.snapshotInspect(snapshotSaved);
  const snapshotHistory: SnapshotObservation = await db.snapshotObserve({ creator: '7', operation: '61' });
  const snapshotListing: SnapshotListing = await db.snapshotList();
  await db.snapshotCapture(snapshotPrepared);
  await db.snapshotRelease(snapshotObserved.prepared);
  await db.setSnapshotLimits({ expectedRevision: guarded.revision, nonce: '62',
    limits: { max_points: 64, max_logical_bytes: '34359738368' } });
  // @ts-expect-error Identity-only history cannot authorize a snapshot mutation.
  db.snapshotCapture(snapshotHistory.prepared);
  // @ts-expect-error Snapshot preparation requires the saved complete input.
  db.snapshotPrepare(snapshotPrepared.input);
  // @ts-expect-error Historical page counts and immutable point identities are readonly.
  snapshotListing.snapshots[0].point.page_count = 1;
  // @ts-expect-error Original revisions cannot round through JavaScript Number.
  db.prepareSnapshotInput({ creator: '7', operation: '63', expected_revision: 1,
    expected_head_serial: '1', label: 'invalid' });
  const directStorage: DatabaseStatus = await db.storageStatus();
  const retiredDirect: DatabaseStatus = await db.retireStorage({ expectedHeadSerial: directStorage.head_serial });
  const terminalSerial: string | undefined = retiredDirect.storage.terminal?.serial;
  // @ts-expect-error Physical retirement serials are lossless decimal strings.
  db.retireStorage({ expectedHeadSerial: 1 });
  // @ts-expect-error Observed terminal barriers are immutable.
  retiredDirect.storage.terminal!.serial = '1';
  const plan: DatabaseStatus = await db.compactBegin({ expectedHeadSerial: guarded.head_serial });
  await db.compactCopy({ planSerial: plan.storage.plan!.serial });
  await db.compactPromote({ planSerial: plan.storage.plan!.serial });
  await db.compactAbort({ planSerial: '11' });
  const batch: SweepReport = await db.gcPrepare({ expectedHeadSerial: '13', generation: '1', after: null });
  await db.gcResume({ batchSerial: batch.status.storage.sweep!.serial });
  // @ts-expect-error Physical collector identities are decimal strings.
  db.gcResume({ batchSerial: 1 });
  // @ts-expect-error No public operation accepts arbitrary object keys.
  db.gcPrepare({ expectedHeadSerial: '1', generation: '2', after: null, keys: ['unsafe'] });
  // @ts-expect-error An explicit hash frontier or null is required.
  db.gcPrepare({ expectedHeadSerial: '1', generation: '2' });
  // @ts-expect-error Observed checkpoint metadata is immutable.
  batch.status.storage.sweep!.pending = 0;
  await db.takeover({ expectedRevision: '1', nonce: '2', expectedWorkerInstance: '10' });
  const routing = { bootstrapEndpoint: 'https://example.invalid/v1',
    routes: [{ workerInstance: '10', endpoint: 'https://example.invalid/v1' }],
    token: 'synthetic-typecheck-only-credential', scope, principal: '7' };
  const routed = new RoutedClient(routing), owner = new OwnerClient(routing);
  const durable = new OwnerPlanClient(routing);
  const savedPlan: SavedOwnerInput = durable.prepareInput({ creator: '7', operation: '91', expected_revision: '10',
    expected_head_serial: '15', mode: 'takeover', target_worker: '10',
    nonces: { claim: '92', cancel: '93', activate: '94', abort: '95' } });
  const originalPlan: SavedOwnerInput = durable.restoreInput(durable.saveInput(savedPlan));
  const ownerPrepared: OwnerPreparation = await durable.prepare(originalPlan);
  const verifiedPlan: OwnerObservation<PreparedOwner> = await durable.inspect(originalPlan);
  const unverifiedHistory: OwnerObservation = await durable.observe({ creator: '7', operation: '91' });
  const marker: OwnerPlan | null = verifiedPlan.status.owner_plan;
  if (ownerPrepared.state === 'prepared') {
    await durable.claim(ownerPrepared.prepared);
    await durable.resume(ownerPrepared.prepared, { timeoutMs: 1000 });
    await durable.abort(ownerPrepared.prepared);
  }
  await db.ownerPrepare(savedPlan.input);
  await db.ownerInspect(savedPlan.input);
  await db.ownerObserve({ creator: '7', operation: '91' });
  await db.ownerClaim(verifiedPlan.prepared);
  await db.ownerResume(verifiedPlan.prepared);
  await db.ownerAbort(verifiedPlan.prepared);
  // @ts-expect-error Identity-only history does not mint the SDK mutation brand.
  durable.claim(unverifiedHistory.prepared);
  // @ts-expect-error A reference alone cannot replace the saved complete input.
  durable.inspect(verifiedPlan.prepared.reference);
  // @ts-expect-error Caller-supplied worker redirects cannot replace the fixed target.
  durable.resume(verifiedPlan.prepared, { expectedWorkerInstance: '11' });
  // @ts-expect-error Saved original inputs are deeply readonly.
  savedPlan.input.nonces.claim = '99';
  // @ts-expect-error Owner markers are immutable history.
  marker!.phase.owner_instance = '11';
  // @ts-expect-error Decimal identities cannot be rounded through Number.
  durable.observe({ creator: '7', operation: 91 });
  const probed: DatabaseStatus = await owner.probe('10');
  // @ts-expect-error Worker identities are canonical decimal strings, never JavaScript numbers.
  db.guardedStatus(10);
  // @ts-expect-error Probes require an explicit trusted worker identity.
  owner.probe();
  // @ts-expect-error Probe options retain the ordinary CallOptions shape.
  owner.probe('10', { retry: true });
  const original = routed.prepare([{ sql: 'SELECT 1', parameters: [] }], { epoch: '1', id: '3' });
  await routed.execute(routed.restore(routed.save(original)));
  await routed.lookup(original); await routed.cancel(original); await routed.query([]); await routed.status();
  const ownerIntent = owner.prepareActivation(await owner.observe(), { activateNonce: '4' });
  const savedOwner: string = owner.saveIntent(ownerIntent);
  const restoredOwner: OwnerIntent = owner.restoreIntent(savedOwner);
  const inspection: OwnerInspection = await owner.inspect(restoredOwner);
  const activeOwner: ActiveOwner = await owner.reconcile(ownerIntent);
  owner.prepareTakeover(activeOwner.status, { targetWorker: '11', takeoverNonce: '5', activateNonce: '6' });
  // @ts-expect-error Owner intent identity is immutable.
  ownerIntent.targetWorker = '11';
  // @ts-expect-error Existing owner controls accept canonical decimal strings only.
  db.activate({ expectedRevision: '1', nonce: '2', expectedWorkerInstance: 10 });
  // @ts-expect-error Routed business clients do not expose owner mutation methods.
  routed.takeover({ expectedRevision: '1', nonce: '2' });
  try { await owner.reconcile(ownerIntent); } catch (error) {
    if (error instanceof OwnerReconcileError) owner.saveIntent(error.intent);
    if (error instanceof RouteError) { const notSent: 'not_sent' = error.outcome; void notSent; }
  }
  const discovery = new DiscoveryClient({ endpoint: 'https://example.invalid/v1/discovery', token: 'synthetic-typecheck-only-credential', deployment: '1', tenant: '2', principal: '7' });
  const names: NamePage = await discovery.listNames();
  const inventory: InventoryPage = await discovery.deploymentInventory(names.cursor);
  const incomplete: false = inventory.completion.recovery_complete;
  // @ts-expect-error Cursors are opaque strings, never client-authored frontiers.
  discovery.listNames({ after: 'key' });
  // @ts-expect-error Metadata inventory cannot claim completed data recovery.
  const recovered: true = inventory.completion.recovery_complete;
  // @ts-expect-error Provisioning is a catalogue phase, never a public lifecycle input.
  db.setLifecycle({ expectedRevision: '1', nonce: '1', lifecycle: 'provisioning' });
  try { await client.submit(create); } catch (error) {
    if (error instanceof UnknownError && 'intent' in error.reference) client.saveIntent(error.reference.intent);
  }
  return { prepared, observed, progress, inspected, named, aborted, deleted, alsoDeleted, forged, incomplete, recovered,
    inspection, activeOwner, guarded, probed };
}
void contract;
