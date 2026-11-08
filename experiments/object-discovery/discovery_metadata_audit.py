"""Independent catalogue byte classification and stable-view read witnesses."""
from __future__ import annotations

from discovery_audit_sources import catalogue, wire
from discovery_tree_audit import head as head_record

equal, require = wire.equal, wire.require
Wire = catalogue.Wire
creation, descriptor_path, head_path = catalogue.creation, catalogue.descriptor_path, catalogue.head_path
name_path, origin, proof_path = catalogue.name_path, catalogue.origin, catalogue.proof_path
control_path, mark, digest = catalogue.control_path, catalogue.mark, catalogue.digest


class Metadata(Wire):
    # Only the independent record/source/proof parser is reused. No controller,
    # product transition implementation or mutable protocol runner is called.
    def __init__(self, objects, deployment):
        self.records, self.heads, self.objects = {}, {}, objects
        self.root = f"/scap-test/scap-object/v1/{deployment}/"
        for path, raw in objects.items():
            if path.startswith(self.root) and path.endswith("/head"):
                self.heads[path] = head_record(raw, path)
        catalogue = {path: raw for path, raw in objects.items() if path.startswith(self.root) and "/catalogue/v1/" in path}
        for first in (True, False):
            for path, raw in sorted(catalogue.items()):
                if ("/create/" in path) != first: continue
                self.records[path] = {"raw": raw, "value": self.record(path, raw)}
        for path, authority in self.heads.items():
            if authority["creation"] is not None:
                item = self.records.get(descriptor_path({"scope": authority["scope"], **authority["creation"]}))
                require(item is not None, "named physical HEAD lost its immutable source")
                source = item["value"]["creation"]
                require(self.own(source, authority), "physical HEAD Scope/origin differs from actual descriptor")
                if authority["deletion"] is not None: self.deleted(source, authority)
        for path, item in self.records.items():
            if "/abort-proof/" in path:
                self.barrier(item["value"], self.head_item(item["value"]["control"]["creation"]))

    def head_item(self, source):
        value = self.heads.get(head_path(source["scope"]))
        return None if value is None else {"value": value}

    def deleted(self, source, authority):
        require(self.own(source, authority) and authority["lifecycle"] == "deleted", "missing own Deleted barrier")
        observed = authority["deletion"]
        require(observed is not None, "named Deleted has no complete control intent")
        path = self.root + f"{source['scope']['tenant']}/catalogue/v1/control/{observed['principal']}/{observed['kind']}/{observed['operation']}"
        item = self.records.get(path)
        require(item is not None, "Deleted lost immutable control")
        equal(item["value"]["creation"], source, "Deleted control redirected source")
        equal(observed, mark(item["value"], item["raw"]), "Deleted barrier changed original control conditions")

    def view(self, source):
        binding = self.records.get(name_path(source))
        proof = self.records.get(proof_path(source))
        authority = self.heads.get(head_path(source["scope"]))
        return (None if binding is None else binding["value"],
                None if proof is None else proof["value"], authority)

    def state(self, source):
        binding, proof, authority = self.view(source)
        own = authority if self.own(source, authority) else None
        if binding is None:
            require(own is None and proof is None, "unreserved metadata exposes own HEAD/proof")
            return "NameConflict" if source["expected_name_revision"] is not None else "DescriptorOnly"
        if binding["creation"] != source:
            if proof is not None:
                require(binding["revision"] > (source["expected_name_revision"] or 0) + 3, "old proof lacks name reuse barrier")
                self.barrier(proof, self.head_item(source)); return "Aborted"
            if own is not None:
                require(binding["revision"] > (source["expected_name_revision"] or 0) + 3, "old HEAD redirected to unadvanced name")
                self.deleted(source, own); return "Deleted"
            if binding["state"] == "tombstone" and source["expected_name_revision"] == binding["revision"]:
                return "IdentityConflict" if source["scope"]["database"] == binding["creation"]["scope"]["database"] else "DescriptorOnly"
            return "NameConflict"
        state = binding["state"]
        if state == "reserved":
            require(proof is None, "Reserved unexpectedly has AbortProof")
            if authority is None: return "Reserved"
            if own is None: return "IdentityConflict"
            require(own["lifecycle"] == "provisioning", "Reserved own HEAD is not Provisioning")
            return "Provisioning"
        if state == "bound":
            require(own is not None and proof is None, "Bound lost own HEAD or gained abort proof")
            if own["lifecycle"] == "deleted": self.deleted(source, own)
            return {"provisioning": "Bound", "ready": "Ready", "maintenance": "Maintenance", "deleted": "Deleting"}[own["lifecycle"]]
        self.known_control(binding["control"])
        if state == "aborting":
            require(binding["control"]["kind"] == "abort" and (own is None or own["lifecycle"] in ("provisioning", "deleted")), "Aborting exposes wrong barrier")
            return "Aborting"
        require(state == "tombstone", "unknown binding state")
        if binding["control"]["kind"] == "abort":
            require(proof is not None, "Aborted lost permanent proof")
            equal(proof["control"], binding["control"], "binding/proof control differs")
            require(binding["proof"] == digest(self.records[proof_path(source)]["raw"]), "binding proof bytes differ")
            self.barrier(proof, self.head_item(source)); return "Aborted"
        self.deleted(source, own); return "Deleted"

    def expected(self):
        values = {}
        for path, item in self.records.items():
            raw = item["value"]
            if "/abort-proof/" in path: source, kind = raw["control"]["creation"], "AbortProof"
            else:
                source = raw["creation"]
                kind = "Create" if "/create/" in path else "Control" if "/control/" in path else "Name"
            state = self.state(source)
            control = None
            if kind == "Control":
                control = {key: raw[key] for key in ("kind", "principal", "operation", "expected_name_revision", "expected_head_revision", "nonce")}
                binding, proof, authority = self.view(source)
                accepted = (proof is not None and proof["control"] == raw or
                            binding is not None and binding["state"] == "aborting" and binding["control"] == raw) if raw["kind"] == "abort" else (
                            self.own(source, authority) and authority["deletion"] == mark(raw, item["raw"]))
                if not accepted: state = "ControlAdmitted"
            values[path] = self.projection(path, kind, state, source, control)
        slots = set()
        for path in self.objects:
            if not path.startswith(self.root): continue
            parts = path[len(self.root):].split("/")
            if len(parts) >= 3 and parts[1].isascii() and parts[1].isdigit():
                slots.add(self.root + "/".join(parts[:2]) + "/")
        for slot in slots:
            path = slot + "head"; authority = self.heads.get(path)
            if authority is None:
                values[slot] = {"key": slot.removeprefix("/scap-test/"), "kind": "OrphanPrefix", "state": "Orphan",
                                "creation": None, "scope": None, "binding_revision": None, "head_revision": None, "control": None}
            elif authority["creation"] is None:
                values[path] = {"key": path.removeprefix("/scap-test/"), "kind": "Head", "state": authority["lifecycle"].title(),
                                "creation": None, "scope": authority["scope"], "binding_revision": None,
                                "head_revision": authority["revision"], "control": None}
            else:
                source = self.records[descriptor_path({"scope": authority["scope"], **authority["creation"]})]["value"]["creation"]
                values[path] = self.projection(path, "Head", authority["lifecycle"].title(), source, None)
        return values

    def projection(self, path, kind, state, source, control):
        binding, _, authority = self.view(source)
        return {"key": path.removeprefix("/scap-test/"), "kind": kind, "state": state,
                "creation": source, "scope": source["scope"],
                "binding_revision": binding["revision"] if binding is not None and binding["creation"] == source else None,
                "head_revision": authority["revision"] if self.own(source, authority) else None, "control": control}

    def witnessed(self, observation, reads):
        """Every output is backed by same-call exact raw GETs, including absence."""
        key = "/scap-test/" + observation["key"]
        source = observation["creation"]
        def matching(path): return [item for item in reads if item[0]["path"] == path]
        if observation["kind"] == "OrphanPrefix":
            require(any(response["status"] == 404 for _, response in matching(key + "head")), "orphan not checked by exact HEAD")
            return
        if observation["kind"] == "Head":
            require(any(response["status"] == 200 for _, response in matching(key)), "physical slot not read")
        elif observation["kind"] in ("Name", "Create", "Control", "AbortProof"):
            require(any(response["status"] == 200 for _, response in matching(key)), "listed record not exact-read")
        if source is None: return
        require(any(response["status"] == 200 for _, response in matching(descriptor_path(source))), "reported source lacks actual descriptor GET")
        names, proofs, heads = matching(name_path(source)), matching(proof_path(source)), matching(head_path(source["scope"]))
        require(names and proofs and heads, "incomplete stable name/proof/head view")
        stable = False
        for first, first_response in names:
            for proof, proof_response in proofs:
                for actual, actual_response in heads:
                    for last, last_response in names:
                        if (first_response["monotonic_ns"] < proof["monotonic_ns"] and
                            proof_response["monotonic_ns"] < actual["monotonic_ns"] and
                            actual_response["monotonic_ns"] < last["monotonic_ns"] and
                            [first_response[k] for k in ("status", "etag", "response_sha256")] ==
                            [last_response[k] for k in ("status", "etag", "response_sha256")]): stable = True
        require(stable, "missing stable Binding -> Proof -> HEAD -> Binding witness")
