"""Frozen experiment coverage obligations, not a recovery input inventory."""

DESCRIPTOR_TENANTS = tuple(range(100, 135))
DATA_CASES = ("native", "maintenance", "retired", "acl", "reuse_old", "reuse_new")
INTERMEDIATE_CASES = ("reserved", "provisioning", "bound", "control_admitted", "aborting", "aborted")
RECOVERY_PROFILES = ("interrupted", "missing_reader", "admin_without_read", "missing_retained_result", "complete")
QUERY = "SELECT id,value,token FROM data ORDER BY id"
HEAD_FORMAT = 4
IMMUTABLE_FORMAT = 2
JOB_MS = 900_000
STEP_MS = 30_000
MAX_STEPS = 2048
