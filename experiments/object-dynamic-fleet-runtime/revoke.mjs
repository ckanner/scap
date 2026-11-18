/** One explicit current-admin ACL change using the real SDK and original ledger. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Client } from '../../sdk/node/src/client.js';
import { createLedger } from '../object-service/client_ledger.mjs';

const [configuration, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configuration, 'utf8'));
const ledger = createLedger(evidence, 'revoke');
const client = new Client({ endpoint: config.endpoint + '/v1', token: config.token,
  scope: config.scope, principal: '11', fetch: ledger.transport('business'), timeoutMs: 15000 });
try {
  const current = await client.status();
  const changed = await client.setPolicy({ expectedRevision: current.revision, nonce: '86015',
    permissions: [{ principal: '11', read: true, write: true, admin: true }] });
  assert.equal(BigInt(changed.auth_epoch), BigInt(current.auth_epoch) + 1n);
  ledger.append('business.jsonl', { event: 'controller_authority_revoked', call: ledger.last('business'),
    previous_revision: current.revision, revision: changed.revision });
} finally { ledger.close(); }
