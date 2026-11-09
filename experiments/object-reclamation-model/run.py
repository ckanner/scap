"""Emit exhaustive finite-program graphs; never claim safety by itself."""

import argparse
import gzip
import hashlib
import io
import json
import platform
from pathlib import Path
import shutil
import sys
import tarfile
import time

from model import Model, digest, encoded


def write_json(path, value):
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True).encode() + b'\n')


def source_receipt(directory, destination):
    files = sorted(path for path in directory.iterdir() if path.is_file() and path.suffix in ('.py', '.json', '.md'))
    receipt = {path.name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size} for path in files}
    with tarfile.open(destination, 'w') as archive:
        for path in files:
            raw = path.read_bytes(); entry = tarfile.TarInfo(path.name)
            entry.size = len(raw); entry.mode = 0o644; entry.mtime = 0
            archive.addfile(entry, io.BytesIO(raw))
    return receipt


def explore(spec, profile, destination):
    destination.mkdir()
    model = Model(spec, profile)
    states = [profile['initial']]
    identifiers = {digest(states[0]): 0}
    edge_count, cursor, started = 0, 0, time.monotonic()
    reason, terminals = None, 0
    limits = spec['execution_limits']
    with (destination / 'states.jsonl.gz').open('wb') as sf, (destination / 'edges.jsonl.gz').open('wb') as ef:
        with gzip.GzipFile(fileobj=sf, mode='wb', mtime=0) as state_file, gzip.GzipFile(fileobj=ef, mode='wb', mtime=0) as edge_file:
            state_file.write(encoded({'id': 0, 'sha256': digest(states[0]), 'value': states[0]}) + b'\n')
            while cursor < len(states):
                if time.monotonic() - started >= limits['seconds_per_profile']:
                    reason = 'ELAPSED_RESOURCE_LIMIT'; break
                old = states[cursor]
                actions = model.actions(old)
                if not actions:
                    terminals += 1
                for action in actions:
                    if edge_count == limits['edges_per_profile']:
                        reason = 'EDGE_RESOURCE_LIMIT'; break
                    new = model.successor(old, action); key = digest(new)
                    target = identifiers.get(key)
                    if target is None:
                        if len(states) == limits['states_per_profile']:
                            reason = 'STATE_RESOURCE_LIMIT'; break
                        target = len(states); identifiers[key] = target; states.append(new)
                        state_file.write(encoded({'id': target, 'sha256': key, 'value': new}) + b'\n')
                    edge_file.write(encoded({'source': cursor, 'action': action, 'target': target}) + b'\n')
                    edge_count += 1
                if reason is not None:
                    break
                cursor += 1
    elapsed = time.monotonic() - started
    if reason is None and elapsed >= limits['seconds_per_profile']:
        reason = 'ELAPSED_RESOURCE_LIMIT'
    result = {'profile': profile['name'], 'complete': reason is None and cursor == len(states),
              'status': 'ENUMERATED' if reason is None else 'INCOMPLETE', 'reason': reason,
              'states': len(states), 'edges': edge_count, 'expanded_states': cursor, 'terminals': terminals,
              'elapsed_seconds': elapsed,
              'files': {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                        for name in ('states.jsonl.gz', 'edges.jsonl.gz')}}
    write_json(destination / 'enumeration.json', result)
    return result


def main(args):
    source = Path(__file__).resolve().parent
    spec = json.loads(args.inputs.read_bytes())
    selected = [profile for profile in spec['profiles'] if not args.profile or profile['name'] in args.profile]
    if not selected or args.profile and set(args.profile) != {profile['name'] for profile in selected}:
        raise ValueError('unknown or empty finite profile selection')
    args.output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.inputs, args.output / 'inputs.json')
    before = source_receipt(source, args.output / 'source.tar')
    report = {'schema': 1, 'profile': spec['profile'], 'producer_safety_authority': False,
              'status': 'INCOMPLETE', 'input_sha256': hashlib.sha256(args.inputs.read_bytes()).hexdigest(),
              'source': before, 'python': {'version': platform.python_version(), 'executable': sys.executable,
                                         'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
              'selected_profiles': [profile['name'] for profile in selected], 'all_frozen_profiles_selected': len(selected) == len(spec['profiles']),
              'profiles': []}
    failure = None
    try:
        for profile in selected:
            result = explore(spec, profile, args.output / profile['name'])
            report['profiles'].append(result)
            print(json.dumps(result, sort_keys=True), flush=True)
            if not result['complete']:
                failure = RuntimeError('finite exploration incomplete: ' + profile['name']); break
        after = {path.name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
                 for path in sorted(source.iterdir()) if path.is_file() and path.suffix in ('.py', '.json', '.md')}
        if after != before:
            failure = RuntimeError('source changed during enumeration')
        report['source_unchanged'] = after == before
        if failure is None:
            report['status'] = 'ENUMERATED'
    except BaseException as error:
        failure = error
    finally:
        report['error'] = repr(failure) if failure else None
        write_json(args.output / 'run.json', report)
    if failure:
        raise failure


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', type=Path, default=Path(__file__).with_name('inputs.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', action='append')
    main(parser.parse_args())
