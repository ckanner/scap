/** Real SDK calls only. The harness controls processes and transport faults. */
import assert from 'node:assert/strict';
import { readFileSync, openSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { Client } from '../../sdk/node/src/client.js';
import { createLedger } from '../object-service/client_ledger.mjs';

const [phase, configuration, evidence] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configuration, 'utf8'));
const ledger = createLedger(evidence, phase);
const db = new Client({ endpoint: config.endpoint + '/v1', token: config.token,
  principal: '11', scope: config.scope, timeoutMs: 15000, recoveryTimeoutMs: 60000,
  fetch: ledger.transport('business'), allowInsecureHttp: true });
const sql = (text) => ({ sql: text, parameters: [] });
function persist(name, value) {
  const fd = openSync(evidence + '/' + name, 'wx', 0o600);
  try { writeSync(fd, JSON.stringify(value) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
}
const input = () => JSON.parse(readFileSync(evidence + '/intents.json', 'utf8'));
const summary = (value) => ({ state: value.state, receipt: value.receipt,
  result: value.rawResult.toString('base64') });

try {
  if (phase === 'initialize') {
    const created = await db.create({ nonce: '86011' });
    await db.activate({ expectedRevision: created.revision, nonce: '86012' });
    await db.open();
    const head = await db.status();
    await db.setPolicy({ expectedRevision: head.revision, nonce: '86013', permissions: [
      { principal: '11', read: true, write: true, admin: true },
      { principal: '12', read: true, write: false, admin: true },
    ] });
    const statements = [[sql('CREATE TABLE witness(id INTEGER PRIMARY KEY,counter INTEGER NOT NULL,payload BLOB NOT NULL,nonce INTEGER NOT NULL)'),
      sql('INSERT INTO witness VALUES(1,1,randomblob(64),random()) RETURNING counter,payload,nonce')],
    [sql('UPDATE witness SET counter=counter+1,payload=randomblob(64),nonce=random() WHERE id=1 RETURNING counter,payload,nonce')],
    [sql('UPDATE witness SET counter=counter+1,payload=randomblob(64),nonce=random() WHERE id=1 RETURNING counter,payload,nonce')]];
    const requests = statements.map((rows, index) => db.prepare(rows, { epoch: '1', id: String(index + 1) }));
    persist('intents.json', requests.map((request) => db.save(request)));
    for (let index = 0; index < 2; index++) {
      const value = await db.execute(requests[index]);
      assert.equal(value.state, 'committed');
      ledger.append('business.jsonl', { event: 'original_ack', id: index + 1,
        call: ledger.last('business'), value: summary(value) });
    }
    const current = await db.status();
    const saved = db.prepareSnapshotInput({ creator: '11', operation: '86014',
      expected_revision: current.revision, expected_head_serial: current.head_serial, label: 'before-controller-takeover' });
    persist('snapshot-intent.json', db.saveSnapshotInput(saved));
    const prepared = await db.snapshotPrepare(saved);
    const captured = await db.snapshotCapture(prepared);
    assert.equal(captured.state, 'retained');
    persist('snapshot-original.json', captured);
    ledger.append('business.jsonl', { event: 'snapshot_captured', call: ledger.last('business') });
  } else if (phase === 'unknown') {
    const request = db.restore(input()[2]);
    let outcome;
    try { await db.execute(request); outcome = 'ACK'; }
    catch (error) { outcome = error.code; }
    ledger.append('business.jsonl', { event: 'original_unknown', id: 3, outcome,
      attempts: ledger.attempts(), call: ledger.last('business') });
    assert.equal(outcome, 'UNKNOWN'); assert.equal(ledger.attempts(), 1);
  } else if (phase === 'verify') {
    for (let index = 0; index < 3; index++) {
      const value = await db.lookup(db.restore(input()[index]));
      assert.equal(value.state, 'committed');
      ledger.append('business.jsonl', { event: 'recovered_lookup', id: index + 1,
        call: ledger.last('business'), value: summary(value) });
    }
    const query = await db.query([sql('SELECT counter,payload,nonce FROM witness WHERE id=1')]);
    assert.equal(query.statements[0].rows[0][0], 3n);
    ledger.append('business.jsonl', { event: 'recovered_query', call: ledger.last('business') });
    const observed = await db.snapshotInspect(db.restoreSnapshotInput(
      JSON.parse(readFileSync(evidence + '/snapshot-intent.json', 'utf8'))));
    const original = JSON.parse(readFileSync(evidence + '/snapshot-original.json', 'utf8'));
    assert.equal(observed.state, 'retained');
    assert.deepEqual(observed.prepared.reference, original.prepared.reference);
    assert.deepEqual(observed.prepared.point, original.prepared.point);
    ledger.append('business.jsonl', { event: 'snapshot_retained', call: ledger.last('business') });
    let outcome;
    try { await db.guardedStatus('9601'); outcome = 'ACK'; }
    catch (error) { outcome = error.code; }
    ledger.append('business.jsonl', { event: 'stale_guard', outcome, call: ledger.last('business') });
    assert.equal(outcome, 'TARGET_MISMATCH');
  } else {
    throw new Error('Unknown fixture phase');
  }
} finally { ledger.close(); }
