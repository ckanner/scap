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
