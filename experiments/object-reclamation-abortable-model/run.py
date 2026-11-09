"""Enumerate the frozen programs. ENUMERATED is not protocol acceptance."""

import argparse
import gzip
import hashlib
import json
import platform
import resource
import sys
import time
import traceback
import zlib
from pathlib import Path

from model import Model, wire


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def enumerate_profile(spec, profile, out):
    started = time.monotonic()
    model = Model(spec, profile)
    out.mkdir()
    initial = wire(profile["initial"])
    memory = [zlib.compress(initial, 1)]
    seen = {hashlib.sha256(initial).hexdigest(): 0}
    position, edge_count, terminal, status, error = 0, 0, 0, "INCOMPLETE", None
    with gzip.open(out / "states.jsonl.gz", "wt", encoding="utf-8") as states, gzip.open(out / "edges.jsonl.gz", "wt", encoding="utf-8") as edges:
        states.write(json.dumps({"id": 0, "sha256": hashlib.sha256(initial).hexdigest(), "state": profile["initial"]}, separators=(",", ":")) + "\n")
        try:
            while position < len(memory):
                if time.monotonic() - started > spec["bounds"]["seconds_per_profile"]:
                    raise RuntimeError("TIME_CAP")
                previous = json.loads(zlib.decompress(memory[position]))
                actions = model.actions(previous)
                terminal += int(not actions)
                for action in actions:
                    if edge_count == spec["bounds"]["edges_per_profile"]:
                        raise RuntimeError("EDGE_CAP")
                    successor = model.successor(previous, action)
                    raw = wire(successor)
                    digest = hashlib.sha256(raw).hexdigest()
                    target = seen.get(digest)
                    if target is None:
                        if len(memory) == spec["bounds"]["states_per_profile"]:
                            raise RuntimeError("STATE_CAP")
                        target = len(memory)
                        seen[digest] = target
                        memory.append(zlib.compress(raw, 1))
                        states.write(json.dumps({"id": target, "sha256": digest, "state": successor}, separators=(",", ":")) + "\n")
                    elif zlib.decompress(memory[target]) != raw:
                        raise RuntimeError("STATE_DIGEST_COLLISION")
                    edges.write(json.dumps({"source": position, "target": target, "action": action}, separators=(",", ":")) + "\n")
                    edge_count += 1
                position += 1
            if time.monotonic() - started > spec["bounds"]["seconds_per_profile"]:
                raise RuntimeError("TIME_CAP_AFTER_FINAL_EXPANSION")
            status = "ENUMERATED"
        except Exception as failure:
            error = {"class": type(failure).__name__, "message": str(failure), "traceback": traceback.format_exc()}
            status = "INCOMPLETE" if str(failure).endswith("CAP") or "CAP_" in str(failure) else "FAILED"
    result = {"profile": profile["id"], "status": status, "states": len(memory), "edges": edge_count,
              "expanded_states": position, "terminal_states": terminal, "seconds": time.monotonic() - started,
              "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, "error": error,
              "state_file_sha256": sha(out / "states.jsonl.gz"), "edge_file_sha256": sha(out / "edges.jsonl.gz"),
              "safety_acceptance": "NOT_EVALUATED_BY_PRODUCER"}
    write(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", action="append", default=[])
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    spec = json.loads((source / "inputs.json").read_text())
    profiles = [profile for profile in spec["profiles"] if not args.profile or profile["id"] in args.profile]
    if args.profile and {profile["id"] for profile in profiles} != set(args.profile):
        parser.error("unknown profile")
    args.out.mkdir(parents=True, exist_ok=False)
    freeze = args.out / "source"
    freeze.mkdir()
    inventory = {}
    for path in sorted(source.iterdir()):
        if path.is_file():
            (freeze / path.name).write_bytes(path.read_bytes())
            inventory[path.name] = {"sha256": sha(path), "bytes": path.stat().st_size}
    write(args.out / "source.json", {"files": inventory, "python": sys.version,
                                     "executable": str(Path(sys.executable).resolve()), "executable_sha256": sha(Path(sys.executable).resolve()),
                                     "platform": platform.platform(), "profile_selection": [profile["id"] for profile in profiles]})
    write(args.out / "result.json", {"status": "RUNNING", "safety_acceptance": "NOT_EVALUATED_BY_PRODUCER"})
    reports = []
    for profile in profiles:
        result = enumerate_profile(spec, profile, args.out / profile["id"])
        reports.append(result)
        print(json.dumps({key: result[key] for key in ("profile", "status", "states", "edges", "seconds", "error")}), flush=True)
    unchanged = all(sha(source / name) == value["sha256"] for name, value in inventory.items())
    complete = all(report["status"] == "ENUMERATED" for report in reports) and unchanged
    final = {"status": "ENUMERATED" if complete else "INCOMPLETE", "profiles": reports,
             "all_frozen_profiles_selected": len(profiles) == len(spec["profiles"]), "source_unchanged": unchanged,
             "states": sum(report["states"] for report in reports), "edges": sum(report["edges"] for report in reports),
             "inputs_sha256": inventory["inputs.json"]["sha256"], "source_inventory_sha256": sha(args.out / "source.json"),
             "safety_acceptance": "NOT_EVALUATED_BY_PRODUCER"}
    write(args.out / "result.json", final)
    raise SystemExit(0 if complete else 1)


if __name__ == "__main__":
    main()
