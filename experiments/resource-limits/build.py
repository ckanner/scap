#!/usr/bin/env python3
"""Freeze the real transport experiment executable and its native archive."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
BINARY = 'scap-resource-limits'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    with Path(path).open('w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def inputs():
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    return {raw.decode(): digest(ROOT / raw.decode()) for raw in files if raw}


def artifacts(events, target):
    completed = [row for row in events if row.get('reason') == 'build-finished']
    assert len(completed) == 1 and events[-1] == completed[0] and completed[0]['success'] is True
    binaries = [row for row in events if row.get('reason') == 'compiler-artifact' and row.get('executable')]
    assert len(binaries) == 1 and binaries[0]['target']['name'] == BINARY
    assert binaries[0]['target']['kind'] == ['bin'] and not binaries[0]['profile']['test']
    path = Path(binaries[0]['executable']).resolve()
    assert path == target / 'release' / BINARY
    native = [row for row in events if row.get('reason') == 'build-script-executed'
              and row.get('package_id', '').rsplit('#', 1)[-1].split('@', 1)[0] == 'libsql-ffi']
    assert len(native) == 1
    directory = Path(native[0]['out_dir']).resolve()
    assert directory.parent.parent == target / 'release' / 'build'
    archives = {str(p.resolve()): digest(p) for p in directory.rglob('*.a')}
    assert archives
    return {'path': str(path), 'sha256': digest(path)}, archives


def verify(path, binary):
    path = Path(path)
    value = json.loads(path.read_text())
    assert value['status'] == 'passed' and value['exit_code'] == 0
    assert value['profile'] == 'release' and value['source_dirty'] is False
    assert value['inputs'] == inputs(), 'source changed after build'
    assert value['binary'] == {'path': str(Path(binary).resolve()), 'sha256': digest(binary)}
    for name, expected in value['logs'].items():
        assert digest(path.parent / name) == expected
    raw = (path.parent / 'cargo.stdout.jsonl').read_bytes()
    assert raw.endswith(b'\n')
    events = [json.loads(line) for line in raw.splitlines()]
    observed, native = artifacts(events, Path(value['target']))
    assert observed == value['binary'] and native == value['native_archives']
    for tool in value['tools'].values():
        assert digest(tool['path']) == tool['sha256']
    return value


def capture(path, binary, evidence):
    value = verify(path, binary)
    for name in value['logs']:
        raw = (Path(path).parent / name).read_bytes()
        (evidence / ('build-' + name)).write_bytes(raw)
    with (evidence / 'source.tar').open('xb') as stream:
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, expected in value['inputs'].items():
                raw = (ROOT / name).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == expected
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(raw), 0o644, 0
                archive.addfile(info, io.BytesIO(raw))
        stream.flush()
        os.fsync(stream.fileno())
    value['source_archive_sha256'] = digest(evidence / 'source.tar')
    save(evidence / 'build.json', value)
    return value


def main(args):
    evidence, target = args.evidence.resolve(), args.target.resolve()
    assert not evidence.is_relative_to(ROOT) and not target.is_relative_to(ROOT)
    assert not evidence.exists() and not target.exists()
    evidence.mkdir(parents=True)
    record = {'schema': 1, 'status': 'failed', 'profile': 'release', 'target': str(target)}
    try:
        record['source_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
        assert record['source_dirty'] is False, 'freeze candidate first'
        record['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        record['inputs'] = inputs()
        assert 'experiments/resource-limits/src/main.rs' in record['inputs']
        record['tools'] = {}
        for name in ('cargo', 'rustc'):
            path = Path(subprocess.check_output(['rustup', 'which', '--toolchain', '1.90.0', name], text=True).strip())
            record['tools'][name] = {'path': str(path), 'sha256': digest(path),
                                     'version': subprocess.check_output([name, '+1.90.0', '-Vv'], text=True)}
        command = ['cargo', '+1.90.0', 'build', '--release', '--frozen', '--manifest-path',
                   'experiments/resource-limits/Cargo.toml', '--message-format=json-render-diagnostics']
        record['command'] = command
        environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0')
        for name in ('LLVM_PROFILE_FILE', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC',
                     'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
            environment.pop(name, None)
        with (evidence / 'cargo.stdout.jsonl').open('xb') as out, (evidence / 'cargo.stderr.log').open('xb') as err:
            process = subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err, timeout=3600)
            for stream in (out, err):
                stream.flush()
                os.fsync(stream.fileno())
        record['exit_code'] = process.returncode
        record['logs'] = {name: digest(evidence / name) for name in ('cargo.stdout.jsonl', 'cargo.stderr.log')}
        assert process.returncode == 0
        assert record['inputs'] == inputs(), 'source changed during build'
        events = [json.loads(line) for line in (evidence / 'cargo.stdout.jsonl').read_bytes().splitlines()]
        record['binary'], record['native_archives'] = artifacts(events, target)
        record['status'] = 'passed'
    except BaseException as error:
        record['error'] = repr(error)
        raise
    finally:
        save(evidence / 'build.json', record)
    print(json.dumps({'status': record['status'], 'binary': record['binary']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    main(parser.parse_args())
