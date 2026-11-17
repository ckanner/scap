/** Directed mutations of actual witnesses. Successful summaries are never the oracle. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { audit, readRecords, byteRecord, strictJson, AuditError, CASES } from './audit.mjs';

const hash = (raw) => createHash('sha256').update(raw).digest('hex');
const packed = (raw) => ({ base64: raw.toString('base64'), length: raw.length, sha256: hash(raw) });
const encoded = (value) => packed(Buffer.from(JSON.stringify(value)));
const renumber = (rows) => rows.forEach((row, index) => { row.seq = index + 1; });
const request = (rows, predicate) => rows.find((row) => row.kind === 'sdk_request' && predicate(strictJson(byteRecord(row.body)), row));
const response = (rows, sent) => rows.find((row) => row.kind === 'sdk_response' && row.id === sent.id);
const rewrite = (row, change) => { const value = strictJson(byteRecord(row.body)); change(value); row.body = encoded(value); };
const marker = (rows, name) => rows.find((row) => row.kind === 'checkpoint' && row.name === name);
const original = (rows) => rows.find((row) => row.kind === 'expectation');
const headPath = (rows, operation) => {
  const sent = request(rows, (body) => body.operation === 'prepare_restore' && body.restore_operation === operation);
  const scope = strictJson(byteRecord(response(rows, sent).body)).value.reference.creation.scope;
  return `/scap-test/scap-object/v1/${scope.deployment}/${scope.tenant}/${scope.database}/head`;
};
const sourcePrefix = '/scap-test/scap-object/v1/1/2/3/inc/4/gen/5/storage/';

export function negativeControls(records) {
  const baseline = audit(records);
  const mutations = [
    ['missing_completion_marker', false, (rows) => { rows.pop(); }],
    ['ordinal_hole', false, (rows) => { rows.splice(10, 1); }],
    ['missing_http_response', false, (rows) => { rows.splice(rows.findIndex((row) => row.kind === 'sdk_response'), 1); renumber(rows); }],
    ['tampered_body_checksum', false, (rows) => { rows.find((row) => row.kind === 'sdk_response').body.sha256 = '0'.repeat(64); }],
    ['request_sql_changed_with_frame_rehashed', true, (rows) => {
      rewrite(request(rows, (body) => body.operation === 'execute' && body.request.id === '1'), (body) => { body.statements[1].sql = 'INSERT INTO saved VALUES(1,0,zeroblob(180000))'; });
    }],
    ['receipt_hash_changed_with_frame_rehashed', true, (rows) => {
      const sent = request(rows, (body) => body.operation === 'execute' && body.request.id === '1');
      rewrite(response(rows, sent), (body) => { body.value.receipt.result_hash = 'f'.repeat(64); });
      original(rows).receipt.result_hash = 'f'.repeat(64);
    }],
    ['typed_integer_rounded_above_javascript_safe_range', true, (rows) => { original(rows).rows.statements[0].rows[1][1].value = '9007199254740992'; }],
    ['changed_original_restore_descriptor_with_frame_rehashed', true, (rows) => {
      rewrite(request(rows, (body) => body.operation === 'resume_restore' && body.reference.creation.operation === '1001'), (body) => { body.reference.descriptor_hash = '0'.repeat(64); });
    }],
    ['cancel_inspection_no_longer_aborted', true, (rows) => {
      const sent = request(rows, (body, row) => body.operation === 'inspect_restore' && body.restore_operation === '1002' &&
        strictJson(byteRecord(response(rows, row).body)).value.phase === 'aborted');
      rewrite(response(rows, sent), (body) => { body.value.phase = 'copying'; });
    }],
    ['revocation_policy_still_allows_source_caller', true, (rows) => {
      rewrite(request(rows, (body) => body.operation === 'policy' && body.nonce === '1203'), (body) => {
        body.permissions.push({ principal: '3', read: true, write: true, admin: true });
      });
    }],
    ['lost_reply_claims_different_original_intent', true, (rows) => {
      rows.find((row) => row.kind === 'unknown_observed').reference.intent.action.reference.descriptor_hash = 'f'.repeat(64);
    }],
    ['completed_resume_reads_source_payload', true, (rows) => {
      const begin = marker(rows, 'completed_resume_begin').seq, end = marker(rows, 'completed_resume_end').seq;
      const read = rows.find((row) => row.kind === 's3_request' && row.method === 'GET' && row.seq > begin && row.seq < end);
      assert.ok(read); read.path = `${sourcePrefix}1/objects/${'f'.repeat(64)}`;
    }],
    ['restored_status_sequence_nonzero', true, (rows) => {
      const sent = request(rows, (body) => body.operation === 'status' && body.scope.database !== '3');
      rewrite(response(rows, sent), (body) => { body.value.sequence = '1'; });
    }],
    ['restored_head_retains_request_entries', true, (rows) => {
      const path = headPath(rows, '1001'), after = marker(rows, 'completed_resume_end').seq;
      const read = rows.find((row) => row.kind === 's3_request' && row.method === 'GET' && row.path === path && row.seq > after);
      const reply = rows.find((row) => row.kind === 's3_response' && row.id === read.id);
      const text = byteRecord(reply.body).toString('utf8'); assert.match(text, /"count":0/);
      const raw = Buffer.from(text.replace('"count":0', '"count":1'));
      reply.body = packed(raw); reply.length = raw.length; reply.sha256 = hash(raw);
    }],
    ['target_original_lookup_is_not_unknown', true, (rows) => {
      const sent = request(rows, (body) => body.operation === 'lookup' && body.scope.database !== '3');
      rewrite(response(rows, sent), (body) => { body.value.state = 'closed'; });
    }],
    ['original_lookup_receipt_changed', true, (rows) => {
      const sent = request(rows, (body) => body.operation === 'lookup' && body.scope.database === '3');
      rewrite(response(rows, sent), (body) => { body.value.receipt.transition.nonce = '2'; });
    }],
    ['source_payload_get_after_delete_is_200', true, (rows) => {
      const get = rows.find((row) => row.kind === 'admin_request' && row.method === 'GET' && row.path.startsWith(sourcePrefix));
      rows.find((row) => row.kind === 'admin_response' && row.id === get.id).status = 200;
    }],
    ['source_inventory_omits_observed_payload', true, (rows) => { marker(rows, 'source_payloads_deleted').keys.pop(); }],
    ['source_payload_pair_removed_with_ids_repaired', true, (rows) => {
      const key = marker(rows, 'source_payloads_deleted').keys[0];
      const removed = new Set(rows.filter((row) => row.kind === 'admin_request' && row.path === key).map((row) => row.id));
      for (let index = rows.length - 1; index >= 0; index--) if (['admin_request', 'admin_response'].includes(rows[index].kind) && removed.has(rows[index].id)) rows.splice(index, 1);
      const ids = new Map(rows.filter((row) => row.kind === 'admin_request').map((row, index) => [row.id, index + 1]));
      for (const row of rows) if (['admin_request', 'admin_response'].includes(row.kind)) row.id = ids.get(row.id);
      // Gate IDs are event ordinals; repair them as well when ordinals shift.
      const oldToNew = new Map(rows.map((row, index) => [row.seq, index + 1]));
      for (const row of rows) if (['gate_held', 'gate_released'].includes(row.kind)) row.gate = oldToNew.get(row.gate);
      renumber(rows);
    }],
    ['second_process_not_sigkill_reaped', true, (rows) => { rows.find((row) => row.kind === 'service_reaped' && row.process === 2).signal = 'SIGTERM'; }],
    ['cache_deletion_not_observed', true, (rows) => { rows.find((row) => row.kind === 'cache_deleted' && row.process === 2).absent = false; }],
    ['cold_process_cache_not_empty', true, (rows) => { rows.find((row) => row.kind === 'service_spawned' && row.process === 3).cache_empty = false; }],
    ['cold_query_uses_dead_previous_process', true, (rows) => { request(rows, (body, row) => body.operation === 'query' && row.stage === CASES[6]).process = 2; }],
    ['cold_query_blob_changed_with_frame_rehashed', true, (rows) => {
      const sent = request(rows, (body, row) => body.operation === 'query' && row.stage === CASES[6]);
      rewrite(response(rows, sent), (body) => { const raw = Buffer.from(body.value.result, 'base64'); raw[raw.length - 20] ^= 1; body.value.result = raw.toString('base64'); });
    }],
    ['missing_target_head_get_is_200', true, (rows) => {
      const path = headPath(rows, '1004');
      const get = rows.find((row) => row.kind === 'admin_request' && row.method === 'GET' && row.path === path);
      rows.find((row) => row.kind === 'admin_response' && row.id === get.id).status = 200;
    }],
    ['missing_target_head_inspection_not_corrupt', true, (rows) => {
      const sent = request(rows, (body) => body.operation === 'inspect_restore' && body.restore_operation === '1004');
      const reply = response(rows, sent); reply.status = 404;
      rewrite(reply, (body) => { body.error.code = 'NOT_FOUND'; });
    }],
    ['missing_target_head_recreated', true, (rows) => {
      const path = headPath(rows, '1004'), after = marker(rows, 'authority_loss_missing_verified').seq;
      const read = rows.find((row) => row.kind === 's3_request' && row.method === 'GET' && row.path === path && row.seq > after);
      assert.ok(read); read.method = 'PUT'; read.if_none_match = '*'; read.if_match = null;
    }],
    ['completion_object_witness_names_other_operation', true, (rows) => {
      const write = rows.find((row) => row.kind === 's3_request' && row.method === 'PUT' && row.path.endsWith('/restore-completion/3/1004'));
      assert.ok(write); write.path = write.path.replace('/1004', '/9999');
    }],
    ['snapshot_release_reference_changed', true, (rows) => {
      rewrite(request(rows, (body) => body.operation === 'snapshot_release'), (body) => { body.reference.operation = '999'; });
    }],
    ['source_lifecycle_request_not_deleted', true, (rows) => {
      rewrite(request(rows, (body) => body.operation === 'lifecycle'), (body) => { body.lifecycle = 'live'; });
    }],
  ];
  // Exercise the complete fixed HTTP ledger, not only the five review examples.
  for (const sent of records.filter((row) => row.kind === 'sdk_request')) {
    const body = strictJson(byteRecord(sent.body));
    mutations.push([`http_${sent.id}_${body.operation}_wrong_caller`, true, (rows) => {
      rows.find((row) => row.kind === 'sdk_request' && row.id === sent.id).principal = sent.principal === '3' ? '9' : '3';
    }]);
    if (body.scope) mutations.push([`http_${sent.id}_${body.operation}_wrong_scope`, true, (rows) => {
      rewrite(rows.find((row) => row.kind === 'sdk_request' && row.id === sent.id), (changed) => { changed.scope.database = '999'; });
    }]);
    if (body.operation === 'query') mutations.push([`http_${sent.id}_query_sql_changed_with_frame_rehashed`, true, (rows) => {
      rewrite(rows.find((row) => row.kind === 'sdk_request' && row.id === sent.id), (changed) => { changed.statements = [{ sql: 'SELECT 1', params: [] }]; });
    }]);
  }
  for (const [container, field, value] of [
    ['reference', 'deployment', '9'], ['reference', 'tenant', '9'], ['reference', 'principal', '9'],
    ['reference', 'operation', 'inspect_restore'], ['intent', 'version', 2], ['intent', 'deployment', '9'],
    ['intent', 'tenant', '9'], ['intent', 'principal', '9'],
  ]) mutations.push([`unknown_${container}_${field}_changed`, true, (rows) => {
    const reference = rows.find((row) => row.kind === 'unknown_observed').reference;
    (container === 'reference' ? reference : reference.intent)[field] = value;
  }]);
  mutations.push(['completion_digest_differs_from_copied_head', true, (rows) => {
    const sent = rows.find((row) => row.kind === 's3_request' && row.method === 'PUT' && row.path.endsWith('/restore-completion/3/1004'));
    rows.find((row) => row.kind === 's3_request_end' && row.id === sent.id).sha256 = 'f'.repeat(64);
  }]);
  const controls = [];
  for (const [name, semantic, mutate] of mutations) {
    const candidate = structuredClone(records); mutate(candidate);
    let failure;
    try { audit(candidate); } catch (error) { failure = error; }
    assert.ok(failure instanceof AuditError, `${name}: auditor must reject with a checkable witness failure`);
    if (semantic) assert.ok(!['BODY_HASH', 'S3_BODY_BINDING', 'SEQUENCE_HOLE', 'REQUEST_ID_HOLE', 'REQUEST_PAIR_COUNT', 'JSON_SYNTAX'].includes(failure.message),
      `${name}: semantic mutation failed only on bookkeeping: ${failure.message}`);
    controls.push({ name, semantic_witness: semantic, status: 'REJECTED_AS_EXPECTED', reason: failure.message });
  }
  return { schema_version: 1, status: 'PASS', baseline_records: baseline.records, controls,
    note: 'All semantic edits preserve exact frame/body hashes and ordinals where applicable; missing/partial controls are separate.' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const directory = resolve(process.argv[2] ?? '.');
  try {
    const result = negativeControls(readRecords(join(directory, 'audit.jsonl')));
    writeFileSync(join(directory, 'negative-controls.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } catch (error) {
    const result = { schema_version: 1, status: 'FAILED', reason: error instanceof AuditError ? error.message : 'NEGATIVE_CONTROL_FAILURE' };
    writeFileSync(join(directory, 'negative-controls.json'), JSON.stringify(result, null, 2) + '\n');
    console.error(JSON.stringify(result)); process.exitCode = 1;
  }
}
