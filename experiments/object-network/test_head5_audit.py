"""Handwritten wire/schema controls, never native SQLite or S3 acceptance."""
import copy
import json
import unittest

import catalogue_oracle
import head5_audit as audit
import lifecycle_oracle


def head(revision=3, serial=7):
    return {"format": 6, "scope": {"deployment": 1, "tenant": 2, "database": 3, "incarnation": 4, "generation": 5},
            "head_serial": serial, "storage": {"active_generation": 1, "allocated_through": 1, "plan": None, "sweep": None},
            "revision": revision, "transition": {"revision": revision, "nonce": 6}, "sequence": 2,
            "owner_epoch": 1, "owner_instance": 7, "active": True, "auth_epoch": 1,
            "policy": [{"principal": 17, "read": True, "write": True, "admin": True}],
            "lifecycle": "ready", "creation": None, "deletion": None, "data_root": "a" * 64,
            "quota": {"max_bytes": 4096}, "retention": {"max_entries": 4, "max_result_bytes": 134217728},
            "request_epoch": 1, "windows": [{"epoch": 1, "root": "b" * 64, "count": 1, "result_bytes": 12}]}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class HeadFiveSchema(unittest.TestCase):
    def test_complete_head_can_have_serial_above_logical_revision(self):
        value = head()
        self.assertEqual(audit.validate(value), value)
        self.assertGreater(value["head_serial"], value["revision"])
        for read in (lambda raw: catalogue_oracle.head_record(raw, catalogue_oracle.head_path(value["scope"])),
                     lambda raw: lifecycle_oracle.head(list(raw))):
            self.assertEqual(read(encoded(value)), value)

    def test_every_top_level_field_is_required_and_unknown_fields_are_rejected(self):
        original = head()
        for field in original:
            missing = copy.deepcopy(original); del missing[field]
            with self.subTest(field=field), self.assertRaises(ValueError): audit.validate(missing)
        with self.assertRaises(ValueError): audit.validate(dict(original, future=True))
        for field in original.keys() - {"creation", "deletion"}:
            with self.subTest(null_field=field), self.assertRaises(ValueError):
                audit.validate(dict(original, **{field: None}))

    def test_exact_version_and_serial_unsigned_bounds(self):
        for value in (None, True, False, 5, 7, 6.0, "6"):
            with self.subTest(format=value), self.assertRaises(ValueError): audit.validate(dict(head(), format=value))
        for serial in (None, True, 0, -1, 2, 2**64, 7.0, "7"):
            with self.subTest(serial=serial), self.assertRaises(ValueError): audit.validate(dict(head(), head_serial=serial))
        self.assertEqual(audit.validate(head(serial=2**64 - 1))["head_serial"], 2**64 - 1)

    def test_storage_profile_is_required_exact_and_initial_only(self):
        malformed = [None, {}, [], {"active_generation": 1}, {"allocated_through": 1},
                     {"active_generation": 1, "allocated_through": 1, "future": None}]
        for field in ("active_generation", "allocated_through"):
            for value in (None, True, False, 0, 2, -1, 2**64, "1", 1.0):
                malformed.append(dict(active_generation=1, allocated_through=1, plan=None, sweep=None) | {field: value})
        for field in ("plan", "sweep"):
            malformed.append(dict(active_generation=1, allocated_through=1, plan=None, sweep=None) | {field: {}})
        for storage in malformed:
            with self.subTest(storage=storage), self.assertRaises(ValueError): audit.validate(dict(head(), storage=storage))

    def test_acl_exact_1024_boundary_and_typed_grants(self):
        value = head()
        value["policy"] = [{"principal": n, "read": False, "write": False, "admin": n == 1}
                           for n in range(1, 1025)]
        self.assertEqual(len(audit.validate(value)["policy"]), 1024)
        value["policy"].append({"principal": 1025, "read": True, "write": False, "admin": False})
        with self.assertRaisesRegex(ValueError, "1024"): audit.validate(value)
        for change in ({"principal": True}, {"read": 1}, {"extra": False}):
            value = head(); value["policy"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): audit.validate(value)

    def test_nested_fields_cannot_be_missing_unknown_or_nonobjects(self):
        value = head()
        for path in (("scope",), ("storage",), ("transition",), ("quota",), ("retention",),
                     ("windows", 0), ("policy", 0)):
            original = value
            for part in path: original = original[part]
            mutations = [{**original, "future": 1}, None]
            mutations.extend({key: item for key, item in original.items() if key != field} for field in original)
            for replacement in mutations:
                changed = copy.deepcopy(value); target = changed
                for part in path[:-1]: target = target[part]
                target[path[-1]] = replacement
                with self.subTest(path=path, replacement=replacement), self.assertRaises(ValueError): audit.validate(changed)

    def test_raw_readers_reject_duplicate_fields_before_dict_validation(self):
        value = head(); raw = encoded(value)
        duplicates = [raw[:-1] + b',"head_serial":7}',
                      raw.replace(b'"active_generation":1', b'"active_generation":1,"active_generation":1'),
                      raw.replace(b'"read":true', b'"read":true,"read":true')]
        for body in duplicates:
            for read in (lambda body: catalogue_oracle.head_record(body, catalogue_oracle.head_path(value["scope"])),
                         lambda body: lifecycle_oracle.head(list(body))):
                with self.subTest(body=body), self.assertRaisesRegex(ValueError, "duplicate JSON key"): read(body)

    def test_serial_order_uses_original_predecessor_not_revision_substitution(self):
        first = head(revision=1, serial=1); audit.advance(None, first)
        previous, current = head(), head(revision=4, serial=8)
        audit.advance(previous, current)
        for changed in (head(revision=1, serial=2), head(revision=2, serial=2)):
            with self.assertRaisesRegex(ValueError, "first HEAD"): audit.advance(None, changed)
        for changed in (head(revision=4, serial=7), head(revision=4, serial=9), head(revision=3, serial=8)):
            with self.subTest(changed=changed), self.assertRaises(ValueError): audit.advance(previous, changed)
        changed = copy.deepcopy(current); changed["storage"]["active_generation"] = 2
        with self.assertRaisesRegex(ValueError, "storage generation"): audit.advance(previous, changed)

    def test_prefix_binds_full_scope_and_explicit_captured_storage(self):
        value = head()
        prefix = audit.object_prefix(value["scope"], audit.storage_generation(value["storage"]))
        self.assertEqual(prefix, "/scap-test/scap-object/v1/1/2/3/inc/4/gen/5/storage/1/objects/")
        self.assertNotEqual(prefix, audit.object_prefix(value["scope"], 2))
        for generation in (True, None, 0, -1, "1", 2**64):
            with self.assertRaises(ValueError): audit.object_prefix(value["scope"], generation)

    def test_same_permanent_slot_cannot_change_incarnation_or_logical_generation(self):
        previous, current = head(), head(revision=4, serial=8)
        original_path = catalogue_oracle.head_path(previous["scope"])
        audit.advance(audit.validate(previous), audit.validate(current))
        for field in ("incarnation", "generation"):
            changed = copy.deepcopy(current)
            changed["scope"][field] += 1
            self.assertEqual(catalogue_oracle.head_path(changed["scope"]), original_path)
            # The changed body remains independently well-formed and maps to
            # the same permanent HEAD slot. Only predecessor binding rejects it.
            audit.validate(changed)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "complete Scope"):
                audit.advance(previous, changed)


if __name__ == "__main__":
    unittest.main()
