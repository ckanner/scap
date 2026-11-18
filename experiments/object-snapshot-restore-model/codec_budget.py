"""Enumerate HEAD9 proposal JSON fields under actual HEAD8 hard bounds.

This is a size calculation, not the Rust validator. Each mutually compatible
layout is reported; a larger deliberately incompatible optional-field envelope
also upper-bounds all layouts without depending on subtle reachability claims.
"""
from copy import deepcopy
import json

U64 = (1 << 64) - 1
MAX_PAGES = (1 << 32) - 2
HEAD_CAP = 256 * 1024


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def build():
    h = "f" * 64
    scope = {name: U64 for name in ("deployment", "tenant", "database", "incarnation", "generation")}
    quota = {"max_bytes": MAX_PAGES * 4096}
    retention = {"max_entries": 65536, "max_result_bytes": U64}
    windows = [{"epoch": U64 - offset, "root": h, "count": 65536,
                "result_bytes": 65536 * 64 * 1024 * 1024} for offset in range(3)]
    points = []
    for offset in range(64):
        # Sixty-four distinct valid labels, each 128 UTF-8 bytes. Every byte
        # requires two JSON bytes, matching serde_json's worst escaping here.
        label = "".join('"' if offset & (1 << bit) else "\\" for bit in range(6)) + "\\" * 122
        points.append({"reference": {"creator": U64, "operation": U64 - offset,
                       "capture_serial": U64 - 400 + offset, "descriptor_hash": h},
                       "label": label, "point": {"data_root": h, "page_count": MAX_PAGES,
                       "sequence": U64 - 600 + offset, "source_revision": U64 - 500 + offset}})
    limits = {"max_points": 64, "max_logical_bytes": 64 * MAX_PAGES * 4096}
    origin = {"descriptor_hash": h, "phase": {"kind": "copied", "completion_hash": h,
                                              "data_root": h, "page_count": MAX_PAGES}}
    owner = {"reference": {"creator": U64, "operation": U64, "descriptor_hash": h},
             "admission": {"kind": "cancel", "revision": U64 - 222, "head_serial": U64 - 122},
             "phase": {"kind": "aborted", "revision": U64 - 221, "head_serial": U64 - 121,
                       "nonce": U64, "owner_epoch": U64 - 2, "owner_instance": U64}}
    head = {"format": 9, "scope": scope, "head_serial": U64 - 100,
            "storage": {"active_generation": U64 - 1000, "allocated_through": U64 - 999,
                        "plan": None, "sweep": None},
            "revision": U64 - 200, "transition": {"revision": U64 - 200, "nonce": U64},
            "sequence": U64 - 201, "owner_epoch": U64 - 1, "owner_instance": U64,
            "owner_plan": owner, "active": False, "auth_epoch": U64,
            "policy": [{"principal": U64 - offset, "read": False, "write": False,
                        "admin": offset == 0} for offset in range(1024)],
            "lifecycle": "ready", "creation": {"creator": U64, "operation": U64,
                                                "name_hash": h, "descriptor_hash": h},
            "deletion": None, "data_root": h, "quota": quota, "retention": retention,
            "request_epoch": U64, "windows": windows, "snapshots": points,
            "snapshot_limits": limits, "restore_origin": origin}
    basis = {name: deepcopy(head[name]) for name in
             ("data_root", "windows", "sequence", "revision", "quota", "retention", "request_epoch",
              "snapshots", "snapshot_limits")}
    plan = {"serial": U64 - 101, "source": U64 - 1000, "target": U64 - 999,
            "phase": "copying", "basis": basis}
    generation = U64 - 1001
    sweep_entries = []
    for offset in range(32):
        item_hash = f"{offset:064x}"
        object_key = (f"scap-object/v1/{U64}/{U64}/{U64}/inc/{U64}/gen/{U64}"
                      f"/storage/{generation}/objects/{item_hash}")
        sweep_entries.append({"key": object_key, "hash": item_hash, "etag": '"' + "\\" * 1022 + '"',
                              "disposition": "condition_mismatch"})
    sweep = {"serial": U64 - 100, "generation": generation, "next_after": h,
             "exhausted": False, "entries": sweep_entries}
    deletion = {"kind": "delete", "principal": U64, "operation": U64, "expected_name_revision": U64 - 2,
                "expected_head_revision": U64 - 201, "nonce": U64, "descriptor_hash": h}
    copy_head = deepcopy(head); copy_head["storage"]["plan"] = plan
    sweep_head = deepcopy(head); sweep_head["storage"]["sweep"] = sweep
    terminal = deepcopy(sweep_head)
    terminal["snapshots"] = []
    terminal["lifecycle"] = "deleted"
    terminal["deletion"] = deletion
    terminal["storage"]["terminal"] = {"serial": U64 - 102}
    envelope = deepcopy(copy_head)
    envelope["lifecycle"] = "provisioning"  # longest lifecycle spelling
    envelope["deletion"] = deletion
    envelope["storage"]["sweep"] = sweep
    envelope["storage"]["terminal"] = {"serial": U64 - 102}
    envelope["owner_plan"]["phase"]["kind"] = "cancelling"  # longest owner spelling
    return {"live_copy": copy_head, "live_sweep": sweep_head, "terminal_sweep": terminal,
            "all_optional_upper_bound_not_valid_head": envelope}


def report():
    shapes = build()
    sizes = {name: len(encoded(head)) for name, head in shapes.items()}
    assert all(size < HEAD_CAP for size in sizes.values()), sizes
    assert all(len(point["label"].encode()) == 128 for point in shapes["live_copy"]["snapshots"])
    assert len({point["label"] for point in shapes["live_copy"]["snapshots"]}) == 64
    return {"head_cap": HEAD_CAP, "bytes": sizes,
            "minimum_margin": HEAD_CAP - max(sizes.values()),
            "source_bounds": {"policy": 1024, "snapshots": 64, "label_utf8_bytes": 128,
                              "windows": 3, "sweep_entries": 32, "etag_bytes": 1024,
                              "hash_ascii_bytes": 64, "u64_decimal_bytes": 20},
            "warning": "Proposal field-size bound; exact Rust codec/schema gates remain NOT_RUN."}


if __name__ == "__main__":
    print(json.dumps(report(), sort_keys=True, indent=2))
