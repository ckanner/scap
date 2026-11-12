/** Independent public wire records; no production encoder or decoder builds them. */
import { SCOPE, head, clone } from './owner_fixture.js';
export { SCOPE, clone } from './owner_fixture.js';

export const INPUT = { creator: '7', operation: '9007199254740993', expected_revision: '10',
  expected_head_serial: '15', mode: 'takeover', target_worker: '200',
  nonces: { claim: '101', cancel: '102', activate: '103', abort: '104' } };

export function prepared(input = INPUT, hash = 'a'.repeat(64)) {
  return { scope: clone(SCOPE), input: clone(input), reference: {
    creator: input.creator, operation: input.operation, descriptor_hash: hash } };
}

export function marker(phase, input = INPUT, admission = phase === 'cancelling' ? 'cancel' : 'claim', hash = 'a'.repeat(64)) {
  const pending = phase === 'claimed' || phase === 'cancelling', claim = admission === 'claim';
  const r = BigInt(input.expected_revision), s = BigInt(input.expected_head_serial);
  return { reference: prepared(input, hash).reference,
    admission: { kind: admission, revision: String(r + 1n), head_serial: String(s + 1n) },
    phase: { kind: phase, revision: String(r + (pending ? 1n : 2n)), head_serial: String(s + (pending ? 1n : 2n)),
      nonce: input.nonces[{ claimed: 'claim', cancelling: 'cancel', active: 'activate', aborted: 'abort' }[phase]],
      owner_epoch: claim && input.mode === 'takeover' ? '3' : '2',
      owner_instance: claim || input.mode === 'activate' ? input.target_worker : '100' } };
}

export function observed(state, input = INPUT, admission, hash = 'a'.repeat(64)) {
  const accepted = ['prepared', 'fenced'].includes(state) ? null : marker(state, input, admission, hash);
  const revision = accepted?.phase.revision ?? input.expected_revision;
  const headSerial = accepted?.phase.head_serial ?? input.expected_head_serial;
  const value = head({ revision, head_serial: headSerial, owner_plan: clone(accepted),
    active: accepted === null ? input.mode === 'takeover' : state === 'active',
    owner_instance: accepted?.phase.owner_instance ?? (input.mode === 'activate' ? input.target_worker : '100'),
    owner_epoch: accepted?.phase.owner_epoch ?? '2',
    transition: { revision, nonce: accepted?.phase.nonce ?? '9' } });
  return { state, status: value, prepared: prepared(input, hash), accepted };
}
