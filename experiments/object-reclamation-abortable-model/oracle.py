#!/usr/bin/env python3
"""Independent graph closure/protocol/witness audit; no producer imports."""

import argparse
import gzip
import hashlib
import json
import sys
import time
import traceback
import zlib
from pathlib import Path

from oracle_protocol import Rules, encoded, require
from oracle_witnesses import edge_facts, edge_markers, state_facts, state_markers


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def barrier(rules, state, value):
    if "all" in value:
        return all(barrier(rules, state, part) for part in value["all"])
    if "mark" in value:
        name, marker = value["mark"].split("/", 1)
        return bool(state["actors"][name]["marks"].get(marker))
    if "actor" in value:
        actual = state["actors"][value["actor"]]
        return all(actual.get(key) == expected for key, expected in value["fields"].items())
    if "outcome" in value:
        actual = state["actors"][value["outcome"]["actor"]]["outcome"]
        return actual is not None and actual["kind"] == value["outcome"]["kind"]
    if "head" in value:
        return state["head"] is not None and all(state["head"].get(key) == expected for key, expected in value["head"].items())
    if "plan" in value:
        actual = None if state["head"] is None else state["head"]["plan"]
        return actual is not None and all(actual["identity"].get(key) == expected for key, expected in value["plan"].items())
    if "token" in value:
        owner, label = value["token"].split("/", 1)
        token = state["tokens"].get(state["actors"][owner]["labels"].get(label))
        return token is not None and all(token.get(key) == expected for key, expected in value["fields"].items())
    if "object" in value:
        item = value["object"]
        return (rules.key(item["generation"], rules.names[item["name"]]) in state["objects"]) == item["present"]
    raise ValueError("oracle lacks frozen barrier semantics")


def enabled(rules, state):
    """Reconstruct choices from explicit programs and immutable transport stages."""
    choices = []
    for name, local in state["actors"].items():
        program = rules.profile["actors"][name]["program"]
        if local["stopped"] is not None or local["pc"] == len(program):
            continue
        require(0 <= local["pc"] < len(program), "program counter escaped frozen program")
        step = program[local["pc"]]
        kind = step["op"]
        values = ["step"]
        if kind == "await":
            values = ["step"] if barrier(rules, state, step["condition"]) else []
        elif kind == "observe":
            token_id = local["labels"].get(step["label"]) if "label" in step else local["last"]
            token = state["tokens"].get(token_id)
            if token is not None and token["observed"] is None:
                values = []
                if token["stage"] == "applied":
                    values.append("known")
                if token["uncertain"] or token["stage"] == "discarded":
                    values.append("unknown")
        elif kind == "native_publish":
            values = ["commit", "fail"] if local["commit_known"] else ["abort"]
        elif kind in ("fault_authority", "fault_candidate") and "choices" in step:
            values = step["choices"]
        choices.extend({"actor": name, "choice": choice} for choice in values)
    for identifier, token in state["tokens"].items():
        if token["stage"] == "pending":
            choices.extend({"network": identifier, "choice": choice} for choice in ("apply", "discard"))
    return {encoded(value) for value in choices}


def rank(state):
    return sum(local["pc"] + int(local["stopped"] is not None) for local in state["actors"].values()) + sum(token["stage"] != "pending" for token in state["tokens"].values())


def check_edge(rules, before, after, action):
    require(rank(after) == rank(before) + 1, "edge skipped a finite program/transport step")
    if "network" in action:
        rules.network_edge(before, after, action["network"], action["choice"])
        rules.state(after)
    else:
        rules.client_edge(before, after, action["actor"], action["choice"])


def audit_profile(inputs, profile, source, destination):
    rules = Rules(inputs, profile)
    report = json.loads((source / "result.json").read_text())
    require(report["status"] == "ENUMERATED", "producer profile is capped/failed/incomplete")
    require(report["state_file_sha256"] == sha(source / "states.jsonl.gz") and report["edge_file_sha256"] == sha(source / "edges.jsonl.gz"), "raw graph hash mismatch")
    compressed, digests = [], set()
    with gzip.open(source / "states.jsonl.gz", "rt") as handle:
        for line in handle:
            row = json.loads(line)
            raw = encoded(row["state"])
            actual = hashlib.sha256(raw).hexdigest()
            require(row["id"] == len(compressed) and row["sha256"] == actual and actual not in digests, "state identity/hash/uniqueness mismatch")
            compressed.append(zlib.compress(raw, 1)); digests.add(actual)
            rules.state(row["state"])
    require(len(compressed) == report["states"] <= inputs["bounds"]["states_per_profile"], "state denominator differs")

    def state(index):
        return json.loads(zlib.decompress(compressed[index]))

    require(state(0) == profile["initial"], "graph initial state differs from frozen fixture")
    with gzip.open(source / "edges.jsonl.gz", "rt") as handle:
        edges = [json.loads(line) for line in handle]
    require(len(edges) == report["edges"] <= inputs["bounds"]["edges_per_profile"], "edge denominator differs")
    adjacency = [[] for _ in compressed]
    for index, edge in enumerate(edges):
        start, end = edge["source"], edge["target"]
        require(type(start) is int and type(end) is int and 0 <= start < end < len(compressed), "edge target is not ordered reachable BFS state")
        adjacency[start].append(index)
    parents = [None] * len(compressed)
    histories = [{} for _ in compressed]
    found = {}
    temporal = {"unknown_write_late_applied_before_freeze": "write_applied_after_original_unknown",
                "late_original_intent_cas_after_absent_observation": "pending_intent_absent_observed"}
    terminals = 0
    for index in range(len(compressed)):
        require(index == 0 or parents[index] is not None, "enumerated state has no actual reachable path")
        before = state(index)
        original_choices = enabled(rules, before)
        actual_choices = [encoded(edges[item]["action"]) for item in adjacency[index]]
        require(len(actual_choices) == len(set(actual_choices)) and set(actual_choices) == original_choices,
                "graph omitted/duplicated enabled actor or pending network delivery")
        terminals += int(not original_choices)
        for marker in state_markers(rules, before):
            histories[index].setdefault(marker, (index, None, None))
        for fact in state_facts(rules, before, histories[index]):
            if fact in profile["required_witnesses"]:
                found.setdefault(fact, (index, temporal.get(fact), None))
        for edge_index in adjacency[index]:
            edge = edges[edge_index]
            target, action = edge["target"], edge["action"]
            after = state(target)
            check_edge(rules, before, after, action)
            if parents[target] is None:
                parents[target] = (index, edge_index)
            for marker in histories[index]:
                histories[target].setdefault(marker, (index, marker, edge_index))
            for marker in edge_markers(rules, before, after, action):
                histories[target].setdefault(marker, (index, None, edge_index))
            for fact in edge_facts(rules, before, after, action):
                if fact in profile["required_witnesses"]:
                    found.setdefault(fact, (index, None, edge_index))
    require(terminals == report["terminal_states"] and report["expanded_states"] == len(compressed), "terminal/expanded graph denominator differs")
    missing = set(profile["required_witnesses"]) - set(found)
    if missing:
        raise ValueError("mandatory witnesses unreachable: " + ", ".join(sorted(missing)))
    destination.mkdir()
    witnesses = {}
    for fact, (at, marker, extra) in sorted(found.items()):
        reverse, cursor, current = [], at, marker
        while cursor != 0 or current is not None:
            if current is None:
                parent, link = parents[cursor]
                reverse.append(link); cursor = parent
            else:
                parent, next_marker, link = histories[cursor][current]
                if link is not None:
                    reverse.append(link)
                cursor, current = parent, next_marker
        path = list(reversed(reverse))
        if extra is not None:
            path.append(extra)
        reached, tags = 0, set()
        witnessed_edges = []
        for edge_index in path:
            edge = edges[edge_index]
            require(edge["source"] == reached, "witness history is not one connected path")
            before, after = state(reached), state(edge["target"])
            tags.update(state_markers(rules, before)); tags.update(edge_markers(rules, before, after, edge["action"]))
            witnessed_edges.append(edge)
            reached = edge["target"]
        final = state(reached)
        tags.update(state_markers(rules, final))
        demonstrated = state_facts(rules, final, tags)
        if path:
            last = edges[path[-1]]
            demonstrated.update(edge_facts(rules, state(last["source"]), final, last["action"]))
        require(fact in demonstrated, "witness was inferred from incompatible histories")
        trace = {"profile": profile["id"], "witness": fact, "inputs_sha256": hashlib.sha256(encoded(inputs)).hexdigest(),
                 "start": 0, "end": reached, "steps": witnessed_edges, "temporal_markers": sorted(tags),
                 "final_state_sha256": hashlib.sha256(encoded(final)).hexdigest()}
        path_file = destination / (fact + ".json")
        save(path_file, trace)
        witnesses[fact] = {"file": path_file.name, "sha256": sha(path_file), "steps": len(path)}
    result = {"status": "PASS_WITHIN_FROZEN_PROGRAMS", "profile": profile["id"], "states": len(compressed),
              "edges": len(edges), "terminal_states": terminals, "witnesses": witnesses,
              "enabled_choices_exhausted": True, "explicit_fixture_barriers": sum(step["op"] == "await" for actor in profile["actors"].values() for step in actor["program"]),
              "unrestricted_program_scheduling_claimed": False}
    save(destination / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, default=Path(__file__).with_name("inputs.json"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    started, results, error = time.monotonic(), [], None
    source = Path(__file__).resolve().parent
    files = {path.name: sha(path) for path in source.glob("oracle*.py")}
    identity = {"oracle_files": files, "python": sys.version, "executable": str(Path(sys.executable).resolve()),
                "executable_sha256": sha(Path(sys.executable).resolve()), "inputs": str(args.inputs), "inputs_sha256": sha(args.inputs)}
    save(args.out / "source.json", identity)
    try:
        producer = json.loads((args.graph / "result.json").read_text())
        manifest = json.loads((args.graph / "source.json").read_text())
        require(producer["status"] == "ENUMERATED" and producer["source_unchanged"], "producer run is incomplete/source changed")
        require(sha(args.graph / "source.json") == producer["source_inventory_sha256"], "producer source inventory changed")
        for name, value in manifest["files"].items():
            require(sha(args.graph / "source" / name) == value["sha256"], "frozen producer source changed")
        require(sha(args.inputs) == producer["inputs_sha256"] == manifest["files"]["inputs.json"]["sha256"], "audit inputs differ from enumerated frozen inputs")
        inputs = json.loads(args.inputs.read_text())
        profiles = {profile["id"]: profile for profile in inputs["profiles"]}
        selection = manifest["profile_selection"]
        require(selection == [report["profile"] for report in producer["profiles"]] and len(set(selection)) == len(selection), "producer selected profile denominator differs")
        for name in selection:
            result = audit_profile(inputs, profiles[name], args.graph / name, args.out / name)
            results.append(result)
            print(json.dumps({key: result[key] for key in ("profile", "status", "states", "edges")}), flush=True)
        require({name: sha(source / name) for name in files} == files, "oracle source changed during audit")
    except Exception as failure:
        error = {"type": type(failure).__name__, "message": str(failure), "traceback": traceback.format_exc()}
    report = {"status": "PASS_WITHIN_FROZEN_PROGRAMS" if error is None else "INCOMPLETE" if "mandatory witnesses" in error["message"] else "FAILED",
              "profiles": results, "states": sum(result["states"] for result in results), "edges": sum(result["edges"] for result in results),
              "seconds": time.monotonic() - started, "error": error, "source": identity,
              "all_frozen_profiles": error is None and producer["all_frozen_profiles_selected"],
              "production_gc_enabled_or_proven": False}
    save(args.out / "result.json", report)
    print(json.dumps({key: report[key] for key in ("status", "states", "edges", "error")}), flush=True)
    raise SystemExit(0 if error is None else 1)


if __name__ == "__main__":
    main()
