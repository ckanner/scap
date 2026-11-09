/** Compile-only public API contract; it never supplies runtime coverage. */
import { CatalogueClient, DiscoveryClient, Client, RoutedClient, OwnerClient, RouteError, OwnerReconcileError, UnknownError,
  type DatabaseStatus, type OwnerIntent, type ActiveOwner, type OwnerInspection, type NamePage, type InventoryPage, type Creation, type PreparedCreate,
  type CreationProgress, type AbortProgress, type DeletionProgress, type Named,
  type CatalogueIntent, type CatalogueResult } from '../src/client.js';

const scope = { deployment: '1', tenant: '2', database: '3', incarnation: '1', generation: '1' };
const creation: Creation = { creator: '7', operation: '11', name: 'notes', scope, expected_name_revision: null };

async function contract() {
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
  await db.takeover({ expectedRevision: '1', nonce: '2', expectedWorkerInstance: '10' });
  const routing = { bootstrapEndpoint: 'https://example.invalid/v1',
    routes: [{ workerInstance: '10', endpoint: 'https://example.invalid/v1' }],
    token: 'synthetic-typecheck-only-credential', scope, principal: '7' };
  const routed = new RoutedClient(routing), owner = new OwnerClient(routing);
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
