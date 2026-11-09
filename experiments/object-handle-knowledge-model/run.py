"""Bounded BFS producer. ENUMERATED is not independent oracle acceptance."""

import argparse
from collections import deque
import gzip
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
import zlib

import model


def saved(path):
    value = path.read_bytes()
    return {'path': str(path), 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def source_inventory(directory):
    return [saved(path) for path in sorted(directory.iterdir()) if path.suffix in ('.py', '.json', '.md')]


def enumerate_profile(spec, profile, directory):
    directory.mkdir(exist_ok=False)
    start = time.monotonic_ns()
    caps = spec['bounds']
    initial = model.canonical(profile['initial'])
    initial_hash = hashlib.sha256(initial).hexdigest()
    seen = {initial_hash: 0}
    pending = deque([(0, zlib.compress(initial))])
    nodes = 1
    edges = 0
    expanded = 0
    status, failure = 'ENUMERATED', None
    node_id, event = None, None
    with gzip.open(directory / 'states.jsonl.gz', 'wb') as states, gzip.open(directory / 'edges.jsonl.gz', 'wb') as graph:
        states.write(model.canonical({'id': 0, 'sha256': initial_hash, 'state': profile['initial'],
                                      'parent': None, 'event': None}) + b'\n')
        try:
            while pending:
                if (time.monotonic_ns() - start) / 1e9 >= caps['seconds_per_profile']:
                    raise TimeoutError('seconds_per_profile')
                node_id, encoded = pending.popleft()
                state = json.loads(zlib.decompress(encoded))
                for event in model.choices(state, profile):
                    if edges == caps['edges_per_profile']:
                        raise TimeoutError('edges_per_profile')
                    next_state = model.transition(state, spec, profile, event)
                    raw = model.canonical(next_state)
                    fingerprint = hashlib.sha256(raw).hexdigest()
                    target = seen.get(fingerprint)
                    if target is None:
                        if nodes == caps['states_per_profile']:
                            raise TimeoutError('states_per_profile')
                        target = nodes
                        nodes += 1
                        seen[fingerprint] = target
                        pending.append((target, zlib.compress(raw)))
                        states.write(model.canonical({'id': target, 'sha256': fingerprint, 'state': next_state,
                                                      'parent': node_id, 'event': event}) + b'\n')
                    graph.write(model.canonical({'id': edges, 'from': node_id, 'to': target, 'event': event}) + b'\n')
                    edges += 1
                    if (time.monotonic_ns() - start) / 1e9 >= caps['seconds_per_profile']:
                        raise TimeoutError('seconds_per_profile')
                expanded += 1
            if (time.monotonic_ns() - start) / 1e9 >= caps['seconds_per_profile']:
                raise TimeoutError('seconds_per_profile_after_final_expansion')
        except TimeoutError as error:
            status = 'INCOMPLETE'
            failure = {'kind': 'cap', 'reason': str(error), 'source': node_id, 'event': event}
        except Exception as error:  # Preserve development bugs as failed evidence.
            status = 'FAILED'
            failure = {'kind': type(error).__name__, 'reason': str(error), 'source': node_id, 'event': event}
    finished = time.monotonic_ns()
    if status == 'ENUMERATED' and (finished - start) / 1e9 > caps['seconds_per_profile']:
        status = 'INCOMPLETE'
        failure = {'kind': 'cap', 'reason': 'seconds_per_profile_after_graph_close', 'source': node_id, 'event': event}
    report = {'schema': 1, 'profile': profile['id'], 'profile_sha256': model.digest(profile),
              'status': status, 'states': nodes, 'edges': edges, 'expanded': expanded,
              'pending_states': len(pending), 'started_monotonic_ns': start,
              'finished_monotonic_ns': finished, 'caps': caps,
              'states_file': saved(directory / 'states.jsonl.gz'),
              'edges_file': saved(directory / 'edges.jsonl.gz'), 'failure': failure}
    dump(directory / 'report.json', report)
    return report


def select_profiles(spec, requested):
    if len(requested) != len(set(requested)):
        raise ValueError('duplicate requested profile')
    selected = [profile for profile in spec['profiles'] if not requested or profile['id'] in requested]
    if requested and set(requested) != {profile['id'] for profile in selected}:
        raise ValueError('unknown requested profile')
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', type=Path, default=Path(__file__).with_name('inputs.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', action='append', default=[])
    args = parser.parse_args()
    spec = json.loads(args.inputs.read_text())
    try:
        selected = select_profiles(spec, args.profile)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    args.output.mkdir(exist_ok=False)
    source = source_inventory(Path(__file__).resolve().parent)
    dump(args.output / 'source-before.json', source)
    dump(args.output / 'inputs.json', spec)
    reports = []
    try:
        for profile in selected:
            print('START', profile['id'], flush=True)
            report = enumerate_profile(spec, profile, args.output / profile['id'])
            reports.append(report)
            print(report['status'], profile['id'], report['states'], report['edges'], flush=True)
            if report['status'] != 'ENUMERATED':
                break  # Preserve this failed/capped attempt; do not spend another cap blindly.
    finally:
        after = source_inventory(Path(__file__).resolve().parent)
        dump(args.output / 'source-after.json', after)
        status = ('ENUMERATED' if len(reports) == len(selected)
                  and all(report['status'] == 'ENUMERATED' for report in reports) and after == source else 'INCOMPLETE')
        if any(report['status'] == 'FAILED' for report in reports) or after != source:
            status = 'FAILED'
        manifest = {'schema': 1, 'status': status, 'independent_oracle': 'NOT_RUN',
                    'requested_profiles': [profile['id'] for profile in selected],
                    'whole_inventory': not args.profile, 'inputs': saved(args.inputs),
                    'source_before': saved(args.output / 'source-before.json'),
                    'source_after': saved(args.output / 'source-after.json'), 'source_unchanged': after == source,
                    'python': sys.version, 'platform': platform.platform(),
                    'profiles': [saved(args.output / report['profile'] / 'report.json') for report in reports],
                    'states': sum(report['states'] for report in reports),
                    'edges': sum(report['edges'] for report in reports)}
        dump(args.output / 'manifest.json', manifest)
    raise SystemExit(0 if manifest['status'] == 'ENUMERATED' else 1)


if __name__ == '__main__':
    main()
