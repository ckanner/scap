"""Independent complete-graph audit. Does not import model.py or run.py."""

import argparse
from collections import OrderedDict
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time
import zlib

from oracle_protocol import choice_closure, edge_checks, expected_labels, fingerprint, must, state_checks, wire
from oracle_witnesses import hits


def bound_file(item):
    path = Path(item['path'])
    raw = path.read_bytes()
    must(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'], 'artifact identity: ' + str(path))
    return raw


def identity(path):
    value = path.read_bytes()
    return {'path': str(path), 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def records(path):
    with gzip.open(path, 'rb') as file:
        for line in file:
            yield json.loads(line)


class States:
    """Compressed finite index plus a small decode cache, not an unbounded prefix cache."""

    def __init__(self):
        self.encoded = []
        self.parents = []
        self.hashes = []
        self.cache = OrderedDict()

    def append(self, record):
        must(record['id'] == len(self.encoded), 'nonsequential state index')
        raw = wire(record['state'])
        must(hashlib.sha256(raw).hexdigest() == record['sha256'], 'state canonical digest')
        self.encoded.append(zlib.compress(raw))
        self.parents.append((record['parent'], record['event']))
        self.hashes.append(record['sha256'])

    def __getitem__(self, index):
        must(type(index) is int and 0 <= index < len(self.encoded), 'edge refers to absent state')
        if index in self.cache:
            self.cache.move_to_end(index)
            return self.cache[index]
        result = json.loads(zlib.decompress(self.encoded[index]))
        self.cache[index] = result
        if len(self.cache) > 128:
            self.cache.popitem(last=False)
        return result


def witness_path(states, final_edge):
    suffix = []
    current = final_edge['from']
    while current:
        parent, event = states.parents[current]
        must(type(parent) is int and parent < current, 'discovery parent chain cycle')
        suffix.append({'from': parent, 'to': current, 'event': event})
        current = parent
    suffix.reverse()
    suffix.append({key: final_edge[key] for key in ('from', 'to', 'event')})
    return [{'from': edge['from'], 'to': edge['to'], 'from_sha256': states.hashes[edge['from']],
             'to_sha256': states.hashes[edge['to']], 'event': edge['event']} for edge in suffix]


def audit_profile(spec, profile, report, output):
    must(report['status'] == 'ENUMERATED', 'producer graph is incomplete/failed')
    must(report['profile'] == profile['id'] and report['profile_sha256'] == fingerprint(profile), 'profile not frozen input')
    must(report['caps'] == spec['bounds'], 'producer changed declared caps')
    must(report['states'] <= spec['bounds']['states_per_profile'] and report['edges'] <= spec['bounds']['edges_per_profile'],
         'producer exceeded declared graph caps')
    must((report['finished_monotonic_ns'] - report['started_monotonic_ns']) / 1e9 <= spec['bounds']['seconds_per_profile'],
         'producer exceeded time cap')
    must(report['pending_states'] == 0 and report['expanded'] == report['states'], 'producer omitted pending expansion')
    bound_file(report['states_file']); bound_file(report['edges_file'])
    states = States()
    unique = set()
    expected = []
    for record in records(report['states_file']['path']):
        states.append(record)
        must(record['sha256'] not in unique, 'duplicate state under different IDs')
        unique.add(record['sha256'])
        state_checks(record['state'], spec, profile)
        expected.append({wire(label) for label in expected_labels(record['state'], profile)})
    must(len(states.encoded) == report['states'], 'state count differs from raw graph')
    must(states[0] == profile['initial'] and states.parents[0] == (None, None), 'not exact frozen initial state')
    actual = [set() for _ in states.encoded]
    parents_seen = {0}
    witnesses = {}
    edge_count = 0
    for edge in records(report['edges_file']['path']):
        must(edge['id'] == edge_count, 'nonsequential raw edge index')
        edge_count += 1
        source, target = states[edge['from']], states[edge['to']]
        label = wire(edge['event'])
        must(label not in actual[edge['from']], 'same enabled choice recorded twice')
        actual[edge['from']].add(label)
        edge_checks(source, target, spec, profile, edge['event'])
        if states.parents[edge['to']] == (edge['from'], edge['event']):
            parents_seen.add(edge['to'])
        for name in hits(source, target, edge['event'], spec, profile):
            witnesses.setdefault(name, edge)
    must(edge_count == report['edges'], 'edge count differs from raw graph')
    must(parents_seen == set(range(len(states.encoded))), 'unreachable injected state/parent edge')
    for node, (wanted, present) in enumerate(zip(expected, actual)):
        must(wanted == present, 'enabled choice closure differs at state ' + str(node))
        choice_closure(states[node], profile, present)
    missing = set(profile['required_witnesses']) - set(witnesses)
    must(not missing, 'mandatory witnesses unreachable: ' + ', '.join(sorted(missing)))
    output.mkdir(exist_ok=False)
    written = []
    for name in profile['required_witnesses']:
        edge = witnesses[name]
        artifact = {'schema': 1, 'profile': profile['id'], 'witness': name,
                    'profile_sha256': fingerprint(profile), 'states_file': report['states_file'],
                    'edges_file': report['edges_file'], 'qualifying_edge': edge,
                    'path': witness_path(states, edge)}
        path = output / (name + '.json')
        write_json(path, artifact)
        written.append(identity(path))
    return {'profile': profile['id'], 'status': 'PASS_WITHIN_DECLARED_MODEL_SCOPE',
            'states': report['states'], 'edges': report['edges'], 'witnesses': written}


def audit(graph, output, inputs, selected=None):
    manifest = json.loads((graph / 'manifest.json').read_text())
    must(manifest['status'] == 'ENUMERATED' and manifest['source_unchanged'], 'producer did not finish frozen graph')
    must(bound_file(manifest['inputs']) == inputs.read_bytes(), 'audit inputs differ from producer')
    spec = json.loads(inputs.read_text())
    before = json.loads(bound_file(manifest['source_before']))
    after = json.loads(bound_file(manifest['source_after']))
    must(before == after, 'source changed during enumeration')
    for item in before:
        bound_file(item)
    root = inputs.resolve().parents[2]
    source_inputs = json.loads(inputs.with_name('source-inputs.json').read_text())
    for item in source_inputs['accepted_model_sources']:
        bound_file({**item, 'path': str(root / item['path'])})
    by_id = {profile['id']: profile for profile in spec['profiles']}
    reports = [json.loads(bound_file(item)) for item in manifest['profiles']]
    must([report['profile'] for report in reports] == manifest['requested_profiles'], 'producer scope/report mismatch')
    if manifest['whole_inventory']:
        must(manifest['requested_profiles'] == list(by_id), 'whole inventory omitted a frozen profile')
    chosen = [report for report in reports if selected is None or report['profile'] in selected]
    must(selected is None or {report['profile'] for report in chosen} == set(selected), 'unknown selected audit scope')
    output.mkdir(exist_ok=False)
    results = []
    started = time.monotonic_ns()
    for report in chosen:
        print('AUDIT', report['profile'], flush=True)
        result = audit_profile(spec, by_id[report['profile']], report, output / report['profile'])
        results.append(result)
    for item in before:
        bound_file(item)
    receipt = {'schema': 1, 'status': 'PASS_WITHIN_DECLARED_MODEL_SCOPE',
               'graph_manifest': identity(graph / 'manifest.json'), 'inputs': identity(inputs),
               'profiles': results, 'whole_inventory': manifest['whole_inventory'] and selected is None,
               'states': sum(item['states'] for item in results), 'edges': sum(item['edges'] for item in results),
               'witnesses': sum(len(item['witnesses']) for item in results),
               'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
               'source_unchanged': True, 'python': sys.version,
               'limitations': spec['claims'], 'oracle_imports_producer': False}
    write_json(output / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, default=Path(__file__).with_name('inputs.json'))
    parser.add_argument('--profile', action='append')
    args = parser.parse_args()
    try:
        receipt = audit(args.graph, args.output, args.inputs, args.profile)
        print(json.dumps({key: receipt[key] for key in ('status', 'states', 'edges', 'witnesses')}), flush=True)
    except Exception as error:
        args.output.mkdir(exist_ok=True)
        write_json(args.output / 'failure.json', {'schema': 1, 'status': 'FAILED',
                                                 'error_type': type(error).__name__, 'error': str(error)})
        raise


if __name__ == '__main__':
    main()
