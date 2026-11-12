import { SCOPE, head, clone } from './owner_fixture.js';
export { SCOPE, clone };
export const INPUT = { creator: '7', operation: '81', expected_revision: '10', expected_head_serial: '15', label: 'before migration' };
export const LIMITS = { max_points: 64, max_logical_bytes: '34359738368' };
export function prepared() {
  return { scope: clone(SCOPE), input: clone(INPUT),
    reference: { creator: '7', operation: '81', capture_serial: '16', descriptor_hash: 'a'.repeat(64) },
    point: { data_root: 'b'.repeat(64), page_count: 3, sequence: '2', source_revision: '10' } };
}
export function entry() {
  const value = prepared();
  return { reference: value.reference, label: value.input.label, point: value.point };
}
export function observed(state = 'retained') {
  return { state, status: head({ head_serial: state === 'prepared' ? '15' : state === 'released_observed' ? '17' : '16', sequence: '2' }),
    prepared: prepared(), accepted: ['retained', 'released_observed'].includes(state) ? entry() : null };
}
export function listed(points = [entry()], policy = LIMITS) {
  return { status: head({ head_serial: '20', sequence: '2' }), snapshots: clone(points), limits: clone(policy) };
}
