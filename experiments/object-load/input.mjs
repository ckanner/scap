/** Materialize only fixed input values; all identity and SQL encoding belongs to the SDK. */
export function statements(call, read) {
  return call.statements.map((statement) => ({ sql: statement.sql,
    parameters: statement.params.map((value) => Object.hasOwn(value, 'integer') ? BigInt(value.integer) : read(value.blob)) }));
}
