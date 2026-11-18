"""Small original-byte utilities; no product logic or runner pass/fail imports."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tarfile

import spec

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def require(condition, rule):
    if not condition:
        raise Rejected(rule)


def same(left, right):
    """JSON equality keeps booleans distinct from integer resource counts."""
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate-json-key')
            value[key] = item
        return value

    def invalid(_):
        raise Rejected('nonfinite-json-number')

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def persist(path, value):
    with Path(path).open('w', encoding='utf-8') as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def load_module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(module)
    return module


def safe_absolute(value, rule='absolute-safe-path'):
    require(isinstance(value, str) and re.fullmatch(r'/[a-zA-Z0-9_./+-]+', value)
            and '..' not in Path(value).parts and str(Path(value)) == value, rule)
    return Path(value)


def fixture_inputs(source=ROOT):
    source = Path(source)
    directory = source / 'experiments/kernel-envelope'
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    require(actual == set(spec.SOURCE_NAMES), 'fixture-input-inventory')
    names = [f'experiments/kernel-envelope/{name}' for name in spec.SOURCE_NAMES]
    return {name: digest(source / name) for name in sorted([*names, *spec.EXTERNAL_INPUTS])}


def archive_fixture(root, source_commit):
    inputs = fixture_inputs()
    value = {'schema': 1, 'source_commit': source_commit, 'inputs': inputs}
    persist(root / 'fixture-source-manifest.json', value)
    with tarfile.open(root / 'fixture-source.tar', 'x:') as archive:
        for name in inputs:
            archive.add(ROOT / name, arcname=name, recursive=False)
    return {'inputs': inputs, 'manifest_sha256': digest(root / 'fixture-source-manifest.json'),
            'archive_sha256': digest(root / 'fixture-source.tar')}


def audit_fixture(root, record):
    value = record['fixture']
    require(digest(root / 'fixture-source-manifest.json') == value['manifest_sha256']
            and digest(root / 'fixture-source.tar') == value['archive_sha256'], 'fixture-archive-hash')
    expected = {'schema': 1, 'source_commit': record['source_commit'], 'inputs': value['inputs']}
    require(parse((root / 'fixture-source-manifest.json').read_bytes()) == expected, 'fixture-manifest')
    require(value['inputs'] == fixture_inputs(), 'fixture-current-inputs')
    with tarfile.open(root / 'fixture-source.tar', 'r:') as archive:
        members = archive.getmembers()
        require(len(members) == len(value['inputs']) and
                {item.name for item in members} == set(value['inputs']), 'fixture-source-inventory')
        for member in members:
            require(member.isfile() and 0 < member.size <= 1024 * 1024, 'fixture-source-member')
            stream = archive.extractfile(member)
            require(stream is not None, 'fixture-source-member')
            with stream:
                raw = stream.read()
            require(len(raw) == member.size and hashlib.sha256(raw).hexdigest() ==
                    value['inputs'][member.name], 'fixture-source-bytes')


def remember(root, item, suffix):
    name = f'{item["name"]}.{suffix}'
    item.setdefault('files', {})[suffix] = {'path': name, 'sha256': digest(root / name)}


def original(root, item, suffix, maximum=2 * 1024 * 1024):
    entry = item['files'][suffix]
    name = f'{item["name"]}.{suffix}'
    require(entry.get('path') == name, 'original-path')
    path = root / name
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= maximum,
            'original-file')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == entry.get('sha256'), 'original-bytes')
    return raw


def fields(raw):
    require(raw.endswith(b'\n') and b'\x00' not in raw, 'systemd-original-format')
    result = {}
    for line in raw.decode('utf-8').splitlines():
        require('=' in line, 'systemd-original-format')
        key, value = line.split('=', 1)
        require(key not in result, 'systemd-duplicate-field')
        result[key] = value
    return result


def decimal(raw, rule):
    require(isinstance(raw, str) and re.fullmatch(r'0|[1-9][0-9]*', raw), rule)
    return int(raw)


def counters(raw, rule):
    result = {}
    require(isinstance(raw, str) and raw.endswith('\n'), rule)
    for line in raw.splitlines():
        pair = line.split(' ')
        require(len(pair) == 2 and pair[0] not in result, rule)
        result[pair[0]] = decimal(pair[1], rule)
    return result
