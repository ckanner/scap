"""Independent HEAD6 reader for the fixed ordinary-operation network profiles.

This reader has no controller, production, or transition implementation import.
These profiles perform no compaction or GC: they must retain generation one
with no plan/checkpoint. The separate reclamation oracle audits technical state
and transitions. The historical filename is not a format-5 compatibility path.
"""
from __future__ import annotations

HEAD_FIELDS = {"format", "scope", "head_serial", "storage", "revision", "transition",
               "sequence", "owner_epoch", "owner_instance", "active", "auth_epoch",
               "policy", "lifecycle", "creation", "deletion", "data_root", "quota",
               "retention", "request_epoch", "windows"}
SCOPE_FIELDS = {"deployment", "tenant", "database", "incarnation", "generation"}
MAX_RESULT = 64 * 1024 * 1024
MAX_HEAD = 256 * 1024
MAX_PRINCIPALS = 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, expected, message):
    require(type(value) is dict and set(value) == set(expected), message)


def uint(value, *, minimum=1, maximum=2**64 - 1):
    require(type(value) is int and minimum <= value <= maximum, "invalid HEAD unsigned integer")
    return value


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value), "invalid HEAD SHA-256")


def storage_generation(value):
    fields(value, {"active_generation", "allocated_through", "plan", "sweep"}, "incomplete HEAD6 storage")
    for field in ("active_generation", "allocated_through"):
        require(uint(value[field]) == 1, "unsupported HEAD6 storage generation")
    require(value["plan"] is None and value["sweep"] is None,
            "ordinary-operation profile cannot contain compaction or GC")
    return value["active_generation"]


def object_prefix(scope, generation):
    fields(scope, SCOPE_FIELDS, "incomplete object Scope")
    for value in scope.values():
        uint(value)
    uint(generation)
    return ("/scap-test/scap-object/v1/{deployment}/{tenant}/{database}"
            "/inc/{incarnation}/gen/{generation}/storage/".format(**scope)
            + str(generation) + "/objects/")


def validate(value):
    fields(value, HEAD_FIELDS, "incomplete HEAD6 fields")
    require(type(value["format"]) is int and value["format"] == 6, "HEAD is not format 6")
    fields(value["scope"], SCOPE_FIELDS, "incomplete HEAD Scope")
    for item in value["scope"].values():
        uint(item)
    for key in ("head_serial", "revision", "owner_epoch", "owner_instance", "auth_epoch", "request_epoch"):
        uint(value[key])
    require(value["head_serial"] >= value["revision"], "HEAD serial precedes logical revision")
    storage_generation(value["storage"])
    uint(value["sequence"], minimum=0)
    fields(value["transition"], {"revision", "nonce"}, "incomplete HEAD transition")
    uint(value["transition"]["revision"]); uint(value["transition"]["nonce"])
    require(value["transition"]["revision"] == value["revision"], "HEAD revision/transition mismatch")
    require(type(value["active"]) is bool and type(value["lifecycle"]) is str and
            value["lifecycle"] in {"provisioning", "ready", "maintenance", "deleted"},
            "invalid HEAD lifecycle/activity")
    digest(value["data_root"])
    fields(value["quota"], {"max_bytes"}, "incomplete HEAD quota")
    if value["quota"]["max_bytes"] is not None:
        maximum = uint(value["quota"]["max_bytes"])
        require(maximum % 4096 == 0 and maximum <= (2**32 - 2) * 4096,
                "HEAD quota page alignment/bound")
    fields(value["retention"], {"max_entries", "max_result_bytes"}, "incomplete HEAD retention")
    uint(value["retention"]["max_entries"], maximum=65536)
    uint(value["retention"]["max_result_bytes"], minimum=MAX_RESULT)
    require(type(value["policy"]) is list and 1 <= len(value["policy"]) <= MAX_PRINCIPALS,
            "HEAD policy exceeds the 1024-principal bound or is empty")
    principals = set()
    for permission in value["policy"]:
        fields(permission, {"principal", "read", "write", "admin"}, "incomplete HEAD permission")
        principal = uint(permission["principal"])
        require(principal not in principals and all(type(permission[field]) is bool
                for field in ("read", "write", "admin")), "invalid or duplicate HEAD permission")
        principals.add(principal)
    require(any(permission["admin"] for permission in value["policy"]), "HEAD has no ADMIN")
    require(type(value["windows"]) is list and len(value["windows"]) == min(value["request_epoch"], 3),
            "HEAD request window denominator changed")
    for offset, window in enumerate(value["windows"]):
        fields(window, {"epoch", "root", "count", "result_bytes"}, "incomplete HEAD window")
        require(uint(window["epoch"]) == value["request_epoch"] - offset, "HEAD window epoch changed")
        digest(window["root"])
        count = uint(window["count"], minimum=0, maximum=value["retention"]["max_entries"])
        size = uint(window["result_bytes"], minimum=0,
                    maximum=min(value["retention"]["max_result_bytes"], count * MAX_RESULT))
        if offset:
            require(count == value["retention"]["max_entries"] or
                    size > value["retention"]["max_result_bytes"] - MAX_RESULT,
                    "historical request window was not closed")
    creation, deletion = value["creation"], value["deletion"]
    if creation is not None:
        fields(creation, {"creator", "operation", "name_hash", "descriptor_hash"}, "incomplete HEAD named origin")
        uint(creation["creator"]); uint(creation["operation"])
        digest(creation["name_hash"]); digest(creation["descriptor_hash"])
    if value["lifecycle"] == "provisioning":
        require(creation is not None and not value["active"] and value["sequence"] == 0 and
                value["request_epoch"] == 1 and value["windows"][0]["count"] == 0 and
                value["windows"][0]["result_bytes"] == 0, "Provisioning exposed mutable database state")
    if deletion is None:
        require(creation is None or value["lifecycle"] != "deleted", "named Deleted HEAD lacks deletion mark")
    else:
        fields(deletion, {"kind", "principal", "operation", "expected_name_revision",
                          "expected_head_revision", "nonce", "descriptor_hash"}, "incomplete HEAD deletion origin")
        require(creation is not None and value["lifecycle"] == "deleted" and not value["active"],
                "deletion mark outside inactive named Deleted")
        for key in ("principal", "operation", "expected_name_revision", "nonce"):
            uint(deletion[key])
        digest(deletion["descriptor_hash"])
        require(value["transition"]["nonce"] == deletion["nonce"] and
                any(permission["principal"] == deletion["principal"] and permission["admin"]
                    for permission in value["policy"]), "deletion mark lacks matching nonce/ADMIN")
        if deletion["kind"] == "abort":
            require(deletion["expected_head_revision"] is None and deletion["principal"] == creation["creator"]
                    and value["revision"] <= 2 and value["sequence"] == 0 and value["request_epoch"] == 1
                    and value["windows"][0]["count"] == 0 and value["windows"][0]["result_bytes"] == 0,
                    "invalid named Abort deletion")
        else:
            require(deletion["kind"] == "delete" and
                    uint(deletion["expected_head_revision"]) + 1 == value["revision"], "invalid named Delete revision")
    return value


def advance(previous, current):
    """This initial profile has exactly one serial step per accepted HEAD PUT."""
    if previous is None:
        require(current["head_serial"] == current["revision"] == 1,
                "first HEAD did not begin at serial/revision one")
    else:
        require(current["scope"] == previous["scope"], "HEAD changed the permanent slot's complete Scope")
        require(current["head_serial"] == previous["head_serial"] + 1,
                "accepted HEAD serial chain skipped or reused a publication")
        require(current["revision"] == previous["revision"] + 1,
                "accepted HEAD revision chain skipped or reused a version")
        require(current["storage"] == previous["storage"], "HEAD changed the frozen storage generation")
