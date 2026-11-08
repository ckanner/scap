/** Compile-only public API contract; it never supplies runtime coverage. */
import { CatalogueClient, DiscoveryClient, Client, UnknownError, type NamePage, type InventoryPage, type Creation, type PreparedCreate,
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
  return { prepared, observed, progress, inspected, named, aborted, deleted, alsoDeleted, forged, incomplete, recovered };
}
void contract;
