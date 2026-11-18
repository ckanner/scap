"""Synthetic logical-budget witnesses; no daemon or store is executed."""
import copy
import hashlib
import unittest

import discovery_oracle as audit
from test_discovery_progress import Evidence, binding_body, call, creations, encoded, inventory_fixture


def reservation_fixture(kind="name", count=2, *, dormant=False, minimum=0):
    evidence, creation = Evidence(), copy.deepcopy(creations()[0])
    if dormant:
        creation["name"] = "discovery-descriptor-only"
    tenant = "scap-object/v1/1/7/"
    keys = {"N": tenant + "catalogue/v1/name/" + audit.sha(creation["name"].encode()),
            "D": tenant + f"catalogue/v1/create/{creation['creator']}/{creation['operation']}",
            "P": tenant + f"catalogue/v1/abort-proof/{creation['creator']}/{creation['operation']}",
            "H": tenant + creation["scope"]["database"] + "/head",
            "C": tenant + "catalogue/v1/control/11/900"}
    roles = ({"create": "DNPHN", "control": "CDNPHN"} if dormant else
             {"name": "NDNDPHDN", "create": "DNDPHDN", "control": "CDNDPHDN", "head": "HDNDPHDN"})[kind]
    first_role = {"name": "N", "create": "D", "control": "C", "head": "H"}[kind]
    authority = keys[first_role]
    physical = authority[:-4] if kind == "head" else authority
    prefix, delimiter = (tenant, "/") if kind == "head" else (tenant + "catalogue/v1/" + kind + "/", None)
    evidence.listing(prefix, [physical], delimiter=delimiter)
    descriptor = encoded({"creation": creation})
    origin = {"creator": creation["creator"], "operation": creation["operation"],
              "name_hash": audit.sha(creation["name"].encode()), "descriptor_hash": audit.sha(descriptor)}
    bodies = {"N": binding_body(creation), "D": descriptor,
              "C": encoded({"creation": creation, "origin": origin, "kind": "abort"}),
              "H": encoded({"scope": creation["scope"], "creation": origin, "lifecycle": "ready"})}
    evidence.now = 3_900_000_000
    for role in roles[:count]:
        missing = role == "P" or dormant and role in "NH"
        evidence.get(keys[role], b"missing" if missing else bodies[role], 404 if missing else 200)
    first = call(1_000, 4_100_000_000, None, {"records": [], "cursor": "reservation-token",
                 "completion": {"traversal_exhausted": False}, "stopped": "UNKNOWN", "usage": {}},
                 inventory=True, label="reservation")
    evidence.now = 5_010_000_000
    resumed = evidence.listing(prefix, [physical], delimiter=delimiter)
    following = call(5_000_000_000, 5_100_000_000, "reservation-token", {"records": [], "cursor": None,
                     "completion": {"traversal_exhausted": True}, "stopped": None, "usage": {}}, inventory=True)
    pending = {"prefix": prefix, "delimiter": delimiter, "physical": physical,
               "entry": {"key": authority, "kind": kind, "creation": creation}}
    return evidence, first, following, pending, roles, keys, resumed, minimum


def budget_of(fixture, *, through=0):
    evidence, first, following, pending, _, _, _, minimum = fixture
    logical = audit.logical_successor(evidence.objects, first, following, through, pending, minimum)
    return audit.page_budget(evidence.objects, first, through, logical=logical)


def reported(row):
    return {"usage": dict(zip(("list_pages", "candidates", "exact_gets", "list_bytes", "metadata_bytes"), row))}


def prior_port_charges(fixture, charges):
    """Accounting-only completed port inputs; not a complete catalogue scan."""
    evidence = fixture[0]
    prior = Evidence()
    for index, (key, body, status) in enumerate(charges):
        prior.now = 1_000_000 + index * 1000
        prior.get(key, body, status)
    values = [*prior.objects.values(), *evidence.objects.values()]
    values.sort(key=lambda obj: audit.stamp(obj["request"]))
    evidence.objects = {}
    for index, obj in enumerate(values, 1):
        obj["request"]["request_serial"] = index
        evidence.objects[index] = obj
    return max(audit.stamp(obj["delivery"]) for obj in prior.objects.values())


class LogicalReservationControls(unittest.TestCase):
    def test_each_ready_and_dormant_prefix_has_one_exact_typed_successor(self):
        for dormant, kinds in ((False, ("name", "create", "control", "head")), (True, ("create", "control"))):
            for kind in kinds:
                roles = reservation_fixture(kind, dormant=dormant)[4]
                for count, next_role in enumerate(roles):
                    with self.subTest(kind=kind, dormant=dormant, observed=count):
                        fixture = reservation_fixture(kind, count, dormant=dormant, minimum=19)
                        budget = budget_of(fixture)
                        successor = budget["unobserved_final_reservation"]
                        self.assertEqual(successor["key"], fixture[5][next_role])
                        self.assertEqual(successor["reserved_bytes"], 262144 if next_role == "H" else 65536)
                        self.assertEqual(successor["usage"][1:3], (20, count + 1))
                        self.assertEqual(successor["dispatch_time"], "NOT_OBSERVED")
                        self.assertIs(audit.verify_usage(reported(successor["usage"]), budget), successor)

    def test_no_extra_reservation_is_also_a_valid_deadline_branch(self):
        budget = budget_of(reservation_fixture())
        observed = [row for row in budget["usage_options"] if row[2] == 2]
        self.assertTrue(observed)
        for row in observed:
            self.assertIsNone(audit.verify_usage(reported(row), budget))

    def test_started_candidate_is_not_counted_a_second_time(self):
        budget = budget_of(reservation_fixture(minimum=19))
        row = list(budget["unobserved_final_reservation"]["usage"])
        row[1] = 21
        with self.assertRaisesRegex(ValueError, "candidate budget"):
            audit.verify_usage(reported(row), budget)

    def test_first_unobserved_get_requires_the_one_candidate_reservation(self):
        budget = budget_of(reservation_fixture(count=0, minimum=19))
        row = list(budget["unobserved_final_reservation"]["usage"])
        row[1] = 19
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            audit.verify_usage(reported(row), budget)

    def test_complete_get_chain_without_cursor_progress_has_no_next_candidate(self):
        fixture = reservation_fixture(count=8)
        budget = budget_of(fixture)
        self.assertIsNone(budget["unobserved_final_reservation"])
        row = list(next(iter(budget["usage_options"])))
        row[2] += 1; row[4] += 65536
        with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
            audit.verify_usage(reported(row), budget)

    def test_no_phantom_reservation_on_non_unknown_or_early_return(self):
        for changed in ("LIMIT", None, "early"):
            fixture = reservation_fixture()
            first = fixture[1]
            if changed == "early":
                first["response"]["monotonic_ns"] = 3_400_000_000
            else:
                first["value"]["value"]["stopped"] = changed
            logical = audit.logical_successor(fixture[0].objects, first, fixture[2], 0, fixture[3], 0)
            self.assertIsNone(logical["successor"])

    def test_two_unobserved_attempts_and_wrong_typed_cap_are_rejected(self):
        budget = budget_of(reservation_fixture())
        original = budget["unobserved_final_reservation"]["usage"]
        for field, delta, reason in ((2, 1, "reported HTTP budget"), (4, 196608, "metadata budget"), (4, 1, "metadata budget")):
            row = list(original); row[field] += delta
            with self.subTest(field=field, delta=delta), self.assertRaisesRegex(ValueError, reason):
                audit.verify_usage(reported(row), budget)

    def test_joint_tuple_rejects_refund_and_count_from_different_branches(self):
        budget = budget_of(reservation_fixture())
        row = list(budget["unobserved_final_reservation"]["usage"])
        row[4] -= 65536
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            audit.verify_usage(reported(row), budget)

    def test_observed_unconsumed_tail_cannot_also_have_unobserved_successor(self):
        fixture = reservation_fixture()
        final = audit.page_requests(fixture[0].objects, fixture[1])[-1]
        final["terminal"]["event"] = "delivery_disconnected"
        budget = budget_of(fixture)
        self.assertIsNone(budget["unobserved_final_reservation"])
        row = list(next(iter(budget["usage_options"]))); row[2] += 1; row[4] += 65536
        with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
            audit.verify_usage(reported(row), budget)

    def test_new_attempt_cannot_retain_prior_successful_body_reservation(self):
        fixture = reservation_fixture()
        budget = budget_of(fixture)
        final = audit.page_requests(fixture[0].objects, fixture[1])[-1]
        row = list(budget["unobserved_final_reservation"]["usage"])
        row[4] += 65536 - len(final["outgoing"])
        with self.assertRaisesRegex(ValueError, "metadata budget"):
            audit.verify_usage(reported(row), budget)

    def test_wrong_original_dependency_key_state_or_descriptor_is_rejected(self):
        for change, reason in (("key", "typed dependency"), ("creation", "Creation"), ("origin", "descriptor")):
            fixture = reservation_fixture()
            reads = [obj for obj in audit.page_requests(fixture[0].objects, fixture[1]) if not obj["request"]["query"]]
            if change == "key":
                reads[-1]["request"]["key"] = fixture[5]["H"]
            else:
                body = audit.parse(reads[0]["outgoing"])
                if change == "creation": body["creation"]["name"] = "wrong"
                else: body["origin"]["descriptor_hash"] = "0" * 64
                reads[0]["outgoing"] = reads[0]["upstream"] = encoded(body)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, reason):
                budget_of(fixture)

    def test_binding_head_and_control_origins_bind_every_identity_field(self):
        for kind in ("name", "head", "control"):
            for field, replacement in (("creator", "99"), ("operation", "999"), ("name_hash", "0" * 64), ("extra", 1)):
                fixture = reservation_fixture(kind, count=1)
                obj = audit.page_requests(fixture[0].objects, fixture[1])[-1]
                body = audit.parse(obj["outgoing"])
                origin = body["creation"] if kind == "head" else body["origin"]
                origin[field] = replacement
                obj["outgoing"] = obj["upstream"] = encoded(body)
                with self.subTest(kind=kind, field=field), self.assertRaisesRegex(ValueError, "complete Origin identity"):
                    budget_of(fixture)

    def test_original_cursor_and_scope_are_not_replaced(self):
        fixture = reservation_fixture()
        fixture[2]["body"]["cursor"] = "replacement"
        with self.assertRaisesRegex(ValueError, "authenticated frontier"):
            budget_of(fixture)

    def test_unobserved_get_cannot_skip_the_original_pending_key(self):
        fixture = reservation_fixture()
        fixture[6]["request"]["query"]["start-after"] = fixture[3]["physical"]
        with self.assertRaisesRegex(ValueError, "unclassified physical frontier"):
            budget_of(fixture)

    def test_late_preceding_delivery_cannot_enable_a_phantom_attempt(self):
        fixture = reservation_fixture()
        final = audit.page_requests(fixture[0].objects, fixture[1])[-1]
        final["delivery"]["monotonic_ns"] = 4_020_000_000
        logical = audit.logical_successor(fixture[0].objects, fixture[1], fixture[2], 0, fixture[3], 0)
        self.assertIsNone(logical["successor"])
        budget = audit.page_budget(fixture[0].objects, fixture[1], logical=logical)
        row = list(next(iter(budget["usage_options"]))); row[2] += 1; row[4] += 65536
        with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
            audit.verify_usage(reported(row), budget)

    def test_unowned_post_return_work_rejects_the_logical_branch(self):
        fixture = reservation_fixture()
        fixture[0].now = 4_500_000_000
        fixture[0].get(fixture[5]["N"], binding_body(fixture[3]["entry"]["creation"]))
        with self.assertRaisesRegex(ValueError, "after its original HTTP response"):
            budget_of(fixture)

    def test_same_candidate_later_invocation_does_not_borrow_its_reads(self):
        fixture = reservation_fixture(count=1)
        fixture[0].now = 5_020_000_000
        fixture[0].get(fixture[5]["D"], encoded({"creation": fixture[3]["entry"]["creation"]}))
        successor = budget_of(fixture)["unobserved_final_reservation"]
        self.assertEqual(successor["key"], fixture[5]["D"])
        self.assertEqual(len(successor["observed_dependency_serials"]), 1)

    def test_full_candidate_cap_prevents_a_new_candidate_reservation(self):
        fixture = reservation_fixture(count=0, minimum=128)
        fixture[1]["value"]["value"]["stopped"] = "LIMIT"
        budget = budget_of(fixture)
        self.assertIsNone(budget["unobserved_final_reservation"])
        self.assertEqual({row[1] for row in budget["usage_options"]}, {128})

    def test_unobserved_head_reserves_only_exact_remaining_metadata_capacity(self):
        fixture = reservation_fixture("head", count=0, minimum=64)
        charges = [(f"scap-object/v1/1/7/{1000 + index}/head", b"missing", 404) for index in range(63)]
        charges.append(("scap-object/v1/1/7/catalogue/v1/create/11/1", b"x" * 65536, 200))
        through = prior_port_charges(fixture, charges)
        budget = budget_of(fixture, through=through)
        successor = budget["unobserved_final_reservation"]
        self.assertEqual(successor["reserved_bytes"], 196608)
        self.assertEqual(successor["usage"][4], 16777216)
        row = list(successor["usage"]); row[4] += 1
        with self.assertRaisesRegex(ValueError, "metadata budget"):
            audit.verify_usage(reported(row), budget)

    def test_exact_get_and_metadata_hard_caps_block_an_unobserved_attempt(self):
        fixture = reservation_fixture(count=1, minimum=64)
        through = prior_port_charges(fixture, [("scap-object/v1/1/7/catalogue/v1/create/11/1", b"x", 200)] * 511)
        budget = budget_of(fixture, through=through)
        self.assertIsNone(budget["unobserved_final_reservation"])
        self.assertEqual({row[2] for row in budget["usage_options"]}, {512})
        fixture = reservation_fixture(count=0, minimum=64)
        through = prior_port_charges(fixture, [(f"scap-object/v1/1/7/{1000 + index}/head", b"missing", 404) for index in range(64)])
        budget = budget_of(fixture, through=through)
        self.assertIsNone(budget["unobserved_final_reservation"])
        self.assertEqual({row[4] for row in budget["usage_options"]}, {16777216})

    def test_inventory_name_to_create_transition_retains_exact_candidate_count(self):
        evidence, published, scan = inventory_fixture()
        first = scan[0]
        first["label"] = "before-create"
        originals = audit.page_requests(evidence.objects, first)
        create_list = next(obj for obj in originals if obj["request"]["query"].get("prefix", "").endswith("/create/"))
        for serial, obj in list(evidence.objects.items()):
            if audit.stamp(create_list["request"]) <= audit.stamp(obj["request"]) < audit.stamp(first["response"]):
                del evidence.objects[serial]
        first["value"]["value"]["usage"] = {"candidates": 2}
        budgets = {}
        audit.inventory_progress(scan, evidence.objects, published, budgets)
        successor = budgets[first["label"]]["unobserved_final_reservation"]
        self.assertEqual(successor["operation"], "LIST")
        self.assertEqual(successor["query"]["prefix"], "scap-object/v1/1/7/catalogue/v1/create/")
        self.assertEqual(successor["usage"][1], 2)
        self.assertEqual(successor["reserved_bytes"], 1048576)

    def test_inventory_partial_descriptor_uses_next_name_not_next_candidate(self):
        evidence, published, scan = inventory_fixture()
        scan[0]["label"] = "partial"
        budgets = {}
        audit.inventory_progress(scan, evidence.objects, published, budgets)
        successor = budgets["partial"]["unobserved_final_reservation"]
        self.assertEqual(successor["operation"], "GET")
        self.assertIn("/name/", successor["key"])
        self.assertEqual(successor["usage"][1], 3)

    def test_slots_deadline_before_ignored_entry_keeps_zero_port_branch(self):
        for candidates in (2, 3):
            evidence, published, scan = inventory_fixture()
            initial, middle, final = scan
            initial["label"], middle["label"] = "initial", "before-ignored"
            middle["response"]["monotonic_ns"] = 9_100_000_000
            middle["value"]["value"].update(stopped="UNKNOWN", cursor="before-ignored", usage={"candidates": candidates})
            original_end = audit.page_requests(evidence.objects, final)[0]
            for index, event in enumerate(("request", "backend", "delivery", "terminal")):
                original_end[event]["monotonic_ns"] = 10_050_000_000 + index * 100
                if event == "request":
                    original_end[event]["request_received_monotonic_ns"] = original_end[event]["monotonic_ns"]
            tenant = "scap-object/v1/1/7/"
            head_prefix = middle["value"]["value"]["records"][-1]["key"][:-4]
            evidence.now = 10_010_000_000
            evidence.listing(tenant, [tenant + "catalogue/"], after=head_prefix, delimiter="/")
            following = call(10_000_000_000, 10_100_000_000, "before-ignored", {"records": [], "cursor": None,
                             "completion": {"traversal_exhausted": True}, "stopped": None, "usage": {"candidates": 1}},
                             inventory=True, label="after-ignored")
            budgets = {}
            audit.inventory_progress([initial, middle, following], evidence.objects, published, budgets)
            budget = budgets["before-ignored"]
            self.assertIsNone(budget["unobserved_final_reservation"])
            self.assertEqual({row[1] for row in budget["usage_options"]}, {2, 3})
            valid = next(row for row in budget["usage_options"] if row[1] == candidates)
            self.assertIsNone(audit.verify_usage(reported(valid), budget))
            forged = list(valid); forged[0] += 1; forged[3] += 1048576
            with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
                audit.verify_usage(reported(forged), budget)


class LogicalListReservationControls(unittest.TestCase):
    def fixture(self, prefix="scap-object/v1/1/7/catalogue/v1/control/", *, entries=(), delimiter=None, minimum=0):
        evidence = Evidence()
        original = evidence.listing(prefix, entries, delimiter=delimiter)
        first = call(1000, 4_100_000_000, None, {"stopped": "UNKNOWN", "cursor": "list-token", "usage": {}}, inventory=True)
        expected = {"scap-object/v1/1/": ("scap-object/v1/1/7/catalogue/v1/name/", None, ""),
                    "scap-object/v1/1/7/catalogue/v1/control/": ("scap-object/v1/1/7/catalogue/v1/abort-proof/", None, ""),
                    "scap-object/v1/1/7/": ("scap-object/v1/1/", "/", "scap-object/v1/1/7/")}[prefix]
        evidence.now = 5_010_000_000
        resumed = evidence.listing(expected[0], [], delimiter=expected[1], after=expected[2])
        following = call(5_000_000_000, 5_100_000_000, "list-token", {"stopped": None, "cursor": None}, inventory=True)
        through = audit.stamp(original["delivery"])
        return evidence, first, following, original, resumed, through, minimum

    def budget(self, fixture):
        evidence, first, following, _, _, through, minimum = fixture
        logical = audit.logical_successor(evidence.objects, first, following, through, None, minimum)
        return audit.page_budget(evidence.objects, first, through, logical=logical)

    def test_unobserved_lists_bind_phase_tenant_and_original_query(self):
        for prefix, entries, delimiter, minimum in (("scap-object/v1/1/", ("scap-object/v1/1/7/",), "/", 1),
                 ("scap-object/v1/1/7/catalogue/v1/control/", (), None, 0), ("scap-object/v1/1/7/", (), "/", 0)):
            fixture = self.fixture(prefix, entries=entries, delimiter=delimiter, minimum=minimum)
            successor = self.budget(fixture)["unobserved_final_reservation"]
            self.assertEqual(successor["query"], fixture[4]["request"]["query"])
            self.assertEqual(successor["usage"][0:3], (2, minimum, 0))
            self.assertEqual(successor["usage"][3], len(fixture[3]["outgoing"]) + 1048576)

    def test_list_cannot_increment_candidates_or_refund_unobserved_bytes(self):
        budget = self.budget(self.fixture())
        row = list(budget["unobserved_final_reservation"]["usage"])
        for index, value, reason in ((1, 1, "candidate budget"), (3, row[3] - 1, "LIST budget"),
                                     (2, 1, "reported HTTP budget")):
            changed = row.copy(); changed[index] = value
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, reason):
                audit.verify_usage(reported(changed), budget)

    def test_completed_list_scan_rejects_phantom_within_all_hard_caps(self):
        fixture = self.fixture()
        fixture[1]["value"]["value"].update(stopped=None, cursor=None)
        budget = self.budget(fixture)
        row = list(next(iter(budget["usage_options"]))); row[0] += 1; row[3] += 1048576
        self.assertLessEqual(row[0], 4)
        self.assertLessEqual(row[3], 4194304)
        with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
            audit.verify_usage(reported(row), budget)

    def test_list_wrong_scope_phase_delimiter_or_frontier_is_rejected(self):
        for field, value in (("prefix", "scap-object/v1/2/7/catalogue/v1/abort-proof/"),
                             ("prefix", "scap-object/v1/1/7/catalogue/v1/create/"),
                             ("delimiter", "/"), ("start-after", "skipped")):
            fixture = self.fixture(); fixture[4]["request"]["query"][field] = value
            with self.subTest(field=field, value=value):
                if "/2/" in value:
                    with self.assertRaisesRegex(ValueError, "frontier"):
                        self.budget(fixture)
                else:
                    budget = self.budget(fixture)
                    self.assertIsNone(budget["unobserved_final_reservation"])
                    row = list(next(iter(budget["usage_options"]))); row[0] += 1; row[3] += 1048576
                    with self.assertRaisesRegex(ValueError, "reported HTTP budget"):
                        audit.verify_usage(reported(row), budget)

    def test_list_with_unclassified_prior_work_cannot_create_a_second_tail(self):
        fixture = self.fixture()
        fixture[3]["terminal"]["event"] = "delivery_disconnected"
        self.assertIsNone(self.budget(fixture)["unobserved_final_reservation"])

    def test_four_original_list_attempts_block_an_unobserved_fifth(self):
        fixture = self.fixture()
        evidence, first, following, original, resumed, through, minimum = fixture
        prior = Evidence()
        for index in range(3):
            prior.now = 1_000_000 + index * 1000
            prior.listing("scap-object/v1/1/7/catalogue/v1/name/", [])
        values = [*prior.objects.values(), *evidence.objects.values()]
        evidence.objects = {}
        for index, obj in enumerate(sorted(values, key=lambda obj: audit.stamp(obj["request"])), 1):
            obj["request"]["request_serial"] = index; evidence.objects[index] = obj
        budget = self.budget(fixture)
        self.assertIsNone(budget["unobserved_final_reservation"])
        self.assertEqual({row[0] for row in budget["usage_options"]}, {4})


def fixed_prepare_call(role="admin", name="discovery-025", operation=10025):
    deployment, tenant, principal = {"admin": (1, 7, 11), "other": (1, 8, 22), "foreign": (2, 7, 44)}[role]
    raw = b"SCAP-NAMED-ID-v1\0" + b"".join(value.to_bytes(8, "big") for value in (deployment, tenant, principal, operation))
    digest = hashlib.sha256(raw).digest()
    scope = {"deployment": str(deployment), "tenant": str(tenant), "database": str(int.from_bytes(digest[:8], "big")),
             "incarnation": str(int.from_bytes(digest[8:16], "big")), "generation": "1"}
    creation = {"creator": str(principal), "operation": str(operation), "name": name, "scope": scope,
                "expected_name_revision": None}
    return {"role": role, "identity": {"deployment": str(deployment), "tenant": str(tenant), "principal": str(principal)},
            "body": {"version": 1, "operation": "prepare_create", "name": name, "create_operation": str(operation),
                     "expected_name_revision": None, "options": {"quota": {"mode": "default"}}},
            "value": {"ok": True, "value": {"creation": creation, "initial_quota": {"max_bytes": "10737418240"},
                                             "retention": {"max_entries": 4096, "max_result_bytes": "268435456"}}}}


def fixed_records():
    prepared = fixed_prepare_call()
    source = audit.prepared_profile(prepared, role="admin", name="discovery-025", operation=10025)
    creation = source["creation"]
    origin = {"creator": 11, "operation": 10025, "name_hash": audit.sha(b"discovery-025"),
              "descriptor_hash": audit.sha(encoded(source["descriptor"]))}
    control_call = {"role": "admin", "identity": {"deployment": "1", "tenant": "7", "principal": "11"},
                    "body": {"version": 1, "operation": "abort_create", "creation": prepared["value"]["value"]["creation"],
                             "control_operation": "30002", "expected_name_revision": "1", "nonce": "30003"},
                    "value": {"ok": True, "value": {"creation": prepared["value"]["value"]["creation"],
                              "operation": "30002", "nonce": "30003", "phase": "not_reserved", "binding_revision": None,
                              "head_revision": None}}}
    key, control = audit.control_profile(control_call, source, origin)
    profiles = {source["descriptor_key"]: source["descriptor"], key: control}
    bindings = {source["name_key"]: {state: {"format": 1, "creation": creation, "origin": origin,
                "revision": revision, "state": state, "control": None, "proof": None}
                for state, revision in (("reserved", 1), ("bound", 2))}}
    return prepared, source, control_call, profiles, bindings, key


class FixedMetadataProfileControls(unittest.TestCase):
    def test_scope_is_derived_from_authenticated_input_not_response(self):
        prepared = fixed_prepare_call()
        source = audit.prepared_profile(prepared, role="admin", name="discovery-025", operation=10025)
        self.assertEqual(source["creation"]["scope"], {"deployment": 1, "tenant": 7, "database": 2728452441337175653,
                         "incarnation": 4412984043149713831, "generation": 1})
        self.assertEqual(source["descriptor"]["initial_quota"], {"max_bytes": 10737418240})
        prepared["value"]["value"]["creation"]["scope"]["database"] = "123"
        with self.assertRaisesRegex(ValueError, "derived Scope"):
            audit.prepared_profile(prepared, role="admin", name="discovery-025", operation=10025)

    def test_original_input_caller_and_defaults_cannot_be_rebased(self):
        for choice, reason in (("caller", "authenticated creator"), ("request", "prepare input"), ("quota", "configured source"),
                               ("retention", "configured source"), ("source_extra", "configured source")):
            prepared = fixed_prepare_call()
            if choice == "caller": prepared["identity"]["principal"] = "22"
            elif choice == "request": prepared["body"]["options"]["quota"]["mode"] = "unlimited"
            elif choice == "quota": prepared["value"]["value"]["initial_quota"]["max_bytes"] = None
            elif choice == "retention": prepared["value"]["value"]["retention"]["max_entries"] = 4097
            else: prepared["value"]["value"]["creation"]["scope"]["extra"] = 1
            with self.subTest(choice=choice), self.assertRaisesRegex(ValueError, reason):
                audit.prepared_profile(prepared, role="admin", name="discovery-025", operation=10025)

    def test_only_the_fixed_descriptor_name_and_control_records_are_accepted(self):
        _, source, _, profiles, bindings, control_key = fixed_records()
        for key, body in [(source["descriptor_key"], source["descriptor"]), (control_key, profiles[control_key]),
                          *((source["name_key"], body) for body in bindings[source["name_key"]].values())]:
            with self.subTest(key=key, state=body.get("state")):
                self.assertEqual(audit.catalogue_profile_record(key, encoded(body), profiles, bindings), body)

    def test_complete_version_changes_still_reject_format_unknown_and_missing_fields(self):
        _, source, _, profiles, bindings, control_key = fixed_records()
        cases = ((source["descriptor_key"], source["descriptor"]), (control_key, profiles[control_key]),
                 (source["name_key"], bindings[source["name_key"]]["bound"]))
        for key, original in cases:
            for change in ("version", "bool", "missing", "extra"):
                body = copy.deepcopy(original)
                if change == "version": body["format"] = 2
                elif change == "bool": body["format"] = True
                elif change == "missing": body.pop("format")
                else: body["unknown"] = None
                with self.subTest(key=key, change=change), self.assertRaisesRegex(ValueError, "fixed metadata profile record differs"):
                    audit.catalogue_profile_record(key, encoded(body), profiles, bindings)

    def test_control_nonce_origin_and_exact_key_come_from_original_input(self):
        _, _, _, profiles, bindings, key = fixed_records()
        for field in ("nonce", "principal", "operation", "expected_name_revision", "expected_head_revision", "origin"):
            body = copy.deepcopy(profiles[key])
            if field == "origin": body[field]["descriptor_hash"] = "0" * 64
            else: body[field] = 1 if body[field] is None else body[field] + 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "fixed metadata profile record differs"):
                audit.catalogue_profile_record(key, encoded(body), profiles, bindings)
        with self.assertRaisesRegex(ValueError, "another exact key"):
            audit.catalogue_profile_record(key.replace("/11/abort/", "/12/abort/"), encoded(profiles[key]), profiles, bindings)

    def test_control_result_cannot_supply_a_different_expected_intent(self):
        _, source, control_call, profiles, _, key = fixed_records()
        control_call["value"]["value"]["nonce"] = "30004"
        with self.assertRaisesRegex(ValueError, "original unreserved control result"):
            audit.control_profile(control_call, source, profiles[key]["origin"])
        control_call["body"]["nonce"] = "30004"
        with self.assertRaisesRegex(ValueError, "original control input"):
            audit.control_profile(control_call, source, profiles[key]["origin"])

    def test_control_scope_and_principal_remain_from_the_original_authentication(self):
        for field in ("deployment", "tenant", "principal"):
            _, source, control_call, profiles, _, key = fixed_records()
            control_call["identity"][field] = "99"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "authenticated control caller"):
                audit.control_profile(control_call, source, profiles[key]["origin"])

    def test_name_revision_stage_and_proof_cannot_change_a_decoder_branch(self):
        _, source, _, profiles, bindings, _ = fixed_records()
        key = source["name_key"]
        for field, value in (("revision", 3), ("state", "tombstone"), ("control", {}), ("proof", "0" * 64)):
            body = copy.deepcopy(bindings[key]["bound"]); body[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "fixed metadata profile"):
                audit.catalogue_profile_record(key, encoded(body), profiles, bindings)

    def test_descriptor_options_and_effective_policy_remain_fixed(self):
        _, source, _, profiles, bindings, _ = fixed_records()
        for field in ("options", "initial_quota", "retention", "creation"):
            body = copy.deepcopy(source["descriptor"])
            if field == "options": body[field]["quota"]["kind"] = "unlimited"
            elif field == "initial_quota": body[field]["max_bytes"] = None
            elif field == "retention": body[field]["max_result_bytes"] += 1
            else: body[field]["scope"]["generation"] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "fixed metadata profile record differs"):
                audit.catalogue_profile_record(source["descriptor_key"], encoded(body), profiles, bindings)

    def test_record_byte_bound_duplicate_fields_and_unoffered_proof_are_rejected(self):
        _, source, _, profiles, bindings, key = fixed_records()
        body = encoded(profiles[key])
        for raw, reason in ((body + b" " * 65536, "byte cap"), (body.replace(b'"format":1', b'"format":1,"format":1'), "duplicate JSON key")):
            with self.assertRaisesRegex(ValueError, reason):
                audit.catalogue_profile_record(key, raw, profiles, bindings)
        with self.assertRaisesRegex(ValueError, "successful Proof"):
            audit.catalogue_profile_record(source["descriptor_key"].replace("/create/", "/abort-proof/"), body, profiles, bindings)

    def test_equal_json_with_whitespace_or_changed_field_order_is_not_a_valid_record(self):
        _, source, _, profiles, bindings, key = fixed_records()
        records = [(source["descriptor_key"], source["descriptor"]), (key, profiles[key]),
                   (source["name_key"], bindings[source["name_key"]]["bound"])]
        for key, body in records:
            for changed in (encoded(body) + b"\n", encoded(dict(reversed(list(body.items()))))):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "canonical byte encoding"):
                    audit.catalogue_profile_record(key, changed, profiles, bindings)

    def test_raw_negative_changes_every_copy_without_changing_bytes_or_etag(self):
        _, _, _, profiles, bindings, key = fixed_records()
        original = encoded(profiles[key]); before = audit.sha(original)
        def raw(body): return {"bytes": len(body), "sha256": audit.sha(body), "base64": audit.base64.b64encode(body).decode()}
        data = {"discovery-s3.jsonl": [
            {"event": "request", "request_serial": 1, "method": "PUT", "key": key, "request": raw(original),
             "monotonic_ns": 10, "request_received_monotonic_ns": 10},
            {"event": "request", "request_serial": 2, "method": "GET", "key": key, "request": raw(b""),
             "monotonic_ns": 20, "request_received_monotonic_ns": 20},
            {"event": "backend_response", "request_serial": 2, "body": raw(original), "etag": '"opaque"'},
            {"event": "delivery_started", "request_serial": 2, "body": raw(original), "etag": '"opaque"'}],
            "http-client-ledger.jsonl": [], "saved_projection": {"descriptor_hash": before}}
        report = audit.coherent_control_version_change(data, key)
        self.assertEqual(report["raw_body_instances"], 3)
        changed = audit.raw(data["discovery-s3.jsonl"][0]["request"])
        self.assertEqual(len(changed), len(original)); self.assertNotEqual(changed, original)
        for event in data["discovery-s3.jsonl"][2:]:
            self.assertEqual(audit.raw(event["body"]), changed); self.assertEqual(event["etag"], '"opaque"')
        self.assertEqual(data["saved_projection"]["descriptor_hash"], audit.sha(changed))
        with self.assertRaisesRegex(ValueError, "fixed metadata profile record differs"):
            audit.catalogue_profile_record(key, changed, profiles, bindings)


if __name__ == "__main__":
    unittest.main()
