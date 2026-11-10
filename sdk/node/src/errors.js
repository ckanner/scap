/** Errors carry outcome information; none authorizes an automatic SQL retry. */
export class ClientError extends Error {
  constructor(code, message, cause) {
    super(message, { cause });
    this.name = 'ClientError';
    this.code = code;
  }
}

export class RemoteError extends ClientError {
  constructor(code, message, reference) {
    super(code, message);
    this.name = 'RemoteError';
    this.outcome = 'unresolved';
    this.reference = reference;
  }
}

export class UnknownError extends ClientError {
  constructor(reference, cause) {
    super('UNKNOWN', 'The operation outcome is unknown; retain its identity and resolve it explicitly', cause);
    this.name = 'UnknownError';
    this.outcome = 'unknown';
    this.reference = reference;
  }
}

export class CommittedResultError extends ClientError {
  constructor(code, receipt, rawResult, cause) {
    super(code, 'The request is committed; its result is not available as a decoded value', cause);
    this.name = 'CommittedResultError';
    this.outcome = 'committed';
    this.receipt = receipt;
    this.rawResult = rawResult;
  }
}

function boundedCode(error) {
  return error instanceof ClientError && /^[A-Z_]{1,40}$/.test(error.code) ? error.code : 'CLIENT';
}

export class RouteError extends ClientError {
  constructor(error) {
    const code = boundedCode(error);
    super(code, 'Owner discovery or local admission failed; this SQL was not dispatched',
      new ClientError(code, 'The routed call ended before its business request'));
    this.name = 'RouteError';
    this.outcome = 'not_sent';
  }
}

export class OwnerReconcileError extends ClientError {
  constructor(intent, phase, lastConfirmed, dispatched, uncertain, error) {
    const code = uncertain ? 'UNKNOWN' : boundedCode(error);
    super(code, 'Owner coordination stopped; inspect the saved intent before any new administrative action',
      new ClientError(boundedCode(error), 'The owner phase did not complete within its contract'));
    this.name = 'OwnerReconcileError';
    this.intent = intent;
    this.phase = phase;
    this.lastConfirmed = lastConfirmed;
    this.outcome = uncertain ? 'unknown' : lastConfirmed !== null ?
      (lastConfirmed.active ? 'active' : 'partial') : dispatched ? 'unresolved' : 'not_sent';
  }
}
