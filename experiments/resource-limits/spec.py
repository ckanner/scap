"""Frozen resource-contract inputs and operation denominator, not product logic."""
SCOPES = {
    'a': {'deployment': '1', 'tenant': '7', 'database': '101', 'incarnation': '1', 'generation': '1'},
    'b': {'deployment': '1', 'tenant': '8', 'database': '202', 'incarnation': '1', 'generation': '1'},
}
SMALL_SQL = 'SELECT 7 AS witness'
LARGE_SQL = 'SELECT ' + ','.join('zeroblob(1048576) AS value' + str(i) for i in range(8))
UNKNOWN_SQL = 'CREATE TABLE withheld_resource_effect(n INTEGER)'
CHECK_SQL = "SELECT count(*) AS effects FROM sqlite_schema WHERE name='withheld_resource_effect'"
PROFILE = {'version': 1, 'requests_per_tenant': 1, 'body_bytes': 131072, 'body_bytes_per_tenant': 65536}
CALLS = (
    'a_create', 'a_activate', 'a_warm', 'b_create', 'b_activate', 'b_warm',
    'body_held', 'body_same_tenant', 'body_other_tenant', 'body_control', 'body_after',
    'timeout_execute', 'timeout_same_tenant', 'timeout_other_tenant', 'timeout_control',
    'after_worker', 'original_lookup', 'original_cancel', 'cancelled_lookup', 'effect_check',
    'response_held', 'response_same_tenant', 'response_other_tenant', 'response_control', 'response_after',
)
BACKPRESSURE = {'body_same_tenant', 'timeout_same_tenant', 'response_same_tenant'}
PLAN = {
    'schema': 1, 'profile': 'resource-intake-real-transport-v1', 'calls': list(CALLS),
    'http_calls': len(CALLS), 'original_execute_attempts': 1, 'scopes': SCOPES,
    'intake_profile': PROFILE, 'data_intake': 2, 'control_intake': 2, 'recovery_intake': 2,
    'body_bytes': 65536, 'timeout_ms': 5000, 'recovery_timeout_ms': 30000,
    'worker_instance': '7101', 'large_result_values': 8, 'large_result_value_bytes': 1048576,
    'pause_key': 'scap-object/v1/1/7/101/head', 'max_pause_seconds': 20,
    'client_deadline_seconds': 30, 'socket_receive_buffer': 65536,
    'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
    'final_bytes_clone_proof': 'separate production unit test; TCP exercise is supplemental',
}
