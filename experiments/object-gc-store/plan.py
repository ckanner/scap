"""Frozen expectations for the transport contract, separate from observations."""
PREFIX = "scap-object/v1/1/2/3/inc/4/gen/5/storage/6/objects/"
BUCKET = "scap-test"


def cases():
    result = [
        dict(name="unversioned_probe", kind="probe", requests=2),
        dict(name="wrong_original_etag", kind="wrong", requests=3, outcomes=["Conflict"]),
        dict(name="matching_original_etag", kind="exact", requests=3, outcomes=["Applied"]),
        dict(name="already_deleted", kind="repeat", requests=3),
        dict(name="batch_32_and_33", kind="budget", requests=34, outcomes=["Applied"] * 32 + ["Limit"]),
        dict(name="cross_deployment", kind="prefix", requests=0, error="Invalid", prefix=PREFIX.replace("/1/2/", "/9/2/")),
        dict(name="head_path", kind="prefix", requests=0, error="Invalid", prefix=PREFIX.replace("storage/6/objects/", "HEAD")),
        dict(name="catalogue_path", kind="prefix", requests=0, error="Invalid", prefix="scap-object/v1/1/catalogue/"),
        dict(name="noncanonical_prefix", kind="prefix", requests=0, error="Invalid", prefix=PREFIX.replace("/storage/6/", "/storage/06/")),
        dict(name="invalid_hash_then_valid", kind="bad_hash", requests=3, outcomes=["Invalid", "Applied"]),
        dict(name="invalid_etag_then_valid", kind="bad_etag", requests=3, outcomes=["Invalid", "Applied"]),
        dict(name="already_expired", kind="expired", requests=0, error="Unknown"),
        dict(name="actual_enabled", kind="enabled", requests=1, error="Unsupported", bucket="scap-gc-versioned"),
        dict(name="actual_suspended", kind="suspended", requests=1, error="Unsupported", bucket="scap-gc-versioned"),
        dict(name="actual_missing_bucket", kind="missing_bucket", requests=1, error="Unknown", bucket="scap-gc-absent"),
    ]
    for stage, mode, expected in (
        ("versioning", "malformed", "Corrupt"),
        ("versioning", "unknown_versioning", "Unsupported"),
        ("versioning", "oversize", "Unknown"),
        ("versioning", "short", "Unknown"),
        ("versioning", "redirect", "Unknown"),
        ("versioning", "status_401", "Unknown"),
        ("versioning", "status_403", "Denied"),
        ("versioning", "status_500", "Unknown"),
        ("object-lock", "object_lock", "Unsupported"),
        ("object-lock", "no_such_bucket", "Unsupported"),
        ("object-lock", "bad_404", "Corrupt"),
        ("object-lock", "status_403", "Denied"),
    ):
        result.append(dict(name=stage.replace("-", "_") + "_" + mode, kind="preflight_fault",
                           stage=stage, mode=mode, requests=1 if stage == "versioning" else 2, error=expected))
    for mode, expected in (
        ("version_header", "Unknown"), ("status_200", "Unknown"),
        ("status_401", "Unknown"), ("status_403", "Denied"),
        ("status_409", "Unknown"), ("status_500", "Unknown"),
        ("no_such_bucket", "Unknown"), ("bad_404", "Unknown"),
        ("oversize", "Unknown"), ("short", "Unknown"), ("redirect", "Unknown"),
        ("drop_before", "Unknown"), ("drop_after", "Unknown"), ("late_before", "Unknown"),
    ):
        result.append(dict(name="delete_" + mode, kind="delete_fault", stage="delete", mode=mode,
                           requests=3, outcomes=[expected, "Limit"]))
    result.append(dict(name="configuration_changes_after_preflight", kind="race", stage="object-lock",
                       mode="config_race", bucket="scap-gc-race", requests=3, outcomes=["Unknown", "Limit"]))
    return result
