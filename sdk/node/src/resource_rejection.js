/** Optional bounded resource diagnostics; never an outcome or retry decision. */
const MAX_HEADER_BYTES = 256;
const MAX_U64 = (1n << 64n) - 1n;
const COUNTED = new Map();
for (const lane of ['data', 'control', 'recovery', 'catalogue']) {
  for (const dimension of ['requests_global', 'requests_tenant', 'body_global', 'body_tenant']) {
    COUNTED.set(`intake_${lane}_${dimension}`, 'BACKPRESSURE');
  }
}
for (const scope of ['global', 'tenant', 'database']) {
  for (const kind of ['total', 'data']) COUNTED.set(`queue_${scope}_${kind}`, 'BACKPRESSURE');
}
for (const scope of ['global', 'tenant']) {
  COUNTED.set(`actors_${scope}`, 'BACKPRESSURE');
  for (const pool of ['shared', 'control']) COUNTED.set(`output_base_${pool}_${scope}`, 'BACKPRESSURE');
  COUNTED.set(`output_growth_${scope}`, 'LIMIT');
  COUNTED.set(`restore_staging_${scope}`, 'RECOVERY_BUSY');
}
for (const lane of ['catalogue', 'restore']) {
  for (const scope of ['global', 'tenant', 'name']) COUNTED.set(`${lane}_queue_${scope}`, 'BACKPRESSURE');
}
for (const scope of ['global', 'tenant', 'threads']) COUNTED.set(`discovery_${scope}`, 'BACKPRESSURE');
const SOURCE_ONLY = new Map([
  ['actor_draining', 'BACKPRESSURE'], ['output_base_allocation', 'BACKPRESSURE'],
  ['output_growth_allocation', 'LIMIT'], ['native_recovery_busy', 'RECOVERY_BUSY'],
  ['native_recovery_closed', 'RECOVERY_BUSY'],
]);

export function parseResourceRejection(value, code) {
  if (typeof value !== 'string' || typeof code !== 'string' || value.length > MAX_HEADER_BYTES) return undefined;
  const source = /^v=1;reason=([a-z_]+)$/.exec(value);
  if (source !== null) {
    if (source[0] !== value || SOURCE_ONLY.get(source[1]) !== code) return undefined;
    return Object.freeze({ version: 1, reason: source[1] });
  }
  const counted = /^v=1;reason=([a-z_]+);used=(0|[1-9][0-9]*);limit=([1-9][0-9]*);requested=([1-9][0-9]*)$/.exec(value);
  if (counted === null || counted[0] !== value || COUNTED.get(counted[1]) !== code) return undefined;
  const [, reason, used, limit, requested] = counted;
  const occupancy = BigInt(used), capacity = BigInt(limit), demand = BigInt(requested);
  if (occupancy > MAX_U64 || capacity > MAX_U64 || demand > MAX_U64 ||
      occupancy > capacity || occupancy + demand <= capacity) return undefined;
  return Object.freeze({ version: 1, reason, used, limit, requested });
}

export function resourceRejection(headers, code) {
  // Fetch and ControllerHttp combine duplicate fields using a comma. The
  // canonical grammar rejects that value. Bad optional metadata is discarded,
  // including a custom fetch implementation whose optional-header access fails.
  try {
    return parseResourceRejection(headers.get('x-scap-rejection'), code);
  } catch {
    return undefined;
  }
}
