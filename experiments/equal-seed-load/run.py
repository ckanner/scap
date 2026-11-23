#!/usr/bin/env python3
"""Eight fresh equal-seed cells; failures are retained and never rerun here."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

import lifecycle
import observer
import shared
import spec

support, resources = shared.observers()
build = shared.module('equal_seed_build', shared.ROOT / 'experiments/object-service/build.py')
network = shared.module('equal_seed_backend_commands', shared.ROOT / 'experiments/object-network/run.py')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fixture():
    return {path.relative_to(shared.ROOT).as_posix(): sha(path) for path in shared.fixture_files()}


class EventTrace(support.Trace):
    def emit(self, event, **fields):
        with self.lock:
            row = {'event': event, 'sequence': self.sequence + 1,
                   'monotonic_ns': time.monotonic_ns(), **fields}
            raw = observer.encoded(row)
            if self.sequence >= spec.BOUNDS['events_rows'] or self.bytes + len(raw) > spec.BOUNDS['events_bytes']:
                raise ValueError('runner event budget')
            with self.path.open('ab') as stream:
                stream.write(raw)
                stream.flush()
            self.sequence += 1
            self.bytes += len(raw)
            return row


class Backend(network.Backend):
    """Same backend commands/readiness, owned proc-fd monitoring for all four."""
    def start_owned(self, cell, until):
        for name, arguments in self.commands:
            requested = time.monotonic_ns()
            process, proc, identity, proof = resources.spawn_owned(
                [str(self.binary), *arguments], dict(os.environ), self.directory,
                self.directory / f'{name}.private.log', cell.events.emit)
            self.processes.append(process)
            self.process_metadata[process.pid] = identity
            cell.monitor.add('backend', process, proc, identity, proof, self.binary, requested)
        while time.monotonic() < until:
            cell.check()
            if self.signed('HEAD', '/scap-test') or self.signed('PUT', '/scap-test'):
                if self.signed('PUT', '/scap-test/fixture-ready', 'ready'):
                    return
            time.sleep(.15)
        raise TimeoutError('backend startup deadline')

    def stop_owned(self, cell):
        for process in self.processes:
            resources.signal_owned(process, signal.SIGKILL)
        observed = []
        for (name, _), process in zip(self.commands, self.processes):
            status, usage = cell.monitor.wait(process, 8, check=False)
            observed.append({'role': name, **self.process_metadata[process.pid],
                             'wait_status': status, 'kernel_usage': usage})
        self.processes = []
        if any(row['wait_status'] != -signal.SIGKILL for row in observed):
            raise RuntimeError({'backend_premature_exit': observed})
        return observed


class Cell:
    def __init__(self, args, cell, matrix_until):
        self.args, self.cell = args, cell
        self.contract = spec.CONTRACTS[cell['rate']]
        self.until = min(matrix_until, time.monotonic() + spec.DEADLINES['cell_seconds'])
        self.directory = args.evidence / cell['name']
        self.directory.mkdir(mode=0o700)
        self.temporary = tempfile.TemporaryDirectory(prefix='scap-equal-seed-', dir=args.evidence.parent)
        self.private = Path(self.temporary.name)
        self.events, self.raw = EventTrace(self.directory / 'events.jsonl'), support.RawStore(self.directory)
        self.phase = 'startup'
        self.monitor = observer.Monitor(self.directory, args.evidence, self.private, self.events, lambda: self.phase)
        self.backend = self.proxy = self.service = self.child = None
        self.diag_count = self.diag_bytes = self.diag_ledger_bytes = 0
        self.diagnostic_status = 'NOT_RUN'
        self.finished = False
        self.events.emit('cell_started', name=cell['name'],
                         deadline_ns=int(self.until * 1_000_000_000), private_directory=str(self.private))
        self.monitor.start()

    def remaining(self, stage_until=None):
        result = min(self.until, stage_until if stage_until is not None else self.until) - time.monotonic()
        if result <= 0:
            raise TimeoutError('frozen cell/stage deadline')
        return result

    def check(self):
        self.remaining()
        self.monitor.check()
        if self.proxy is not None and self.proxy.errors:
            raise RuntimeError({'proxy_errors': list(self.proxy.errors)})

    def setup(self):
        until = min(self.until, time.monotonic() + spec.DEADLINES['startup_seconds'])
        calls = spec.calls(self.contract)
        support.save_json(self.directory / 'workload.json', {
            'plan': self.contract.plan, 'calls': calls, 'final_sql': spec.ALL_ROWS,
            'payloads': {str(item['row']): self.raw.save(spec.payload(item['row']))
                         for item in calls if 'row' in item}})
        self.backend = Backend(self.args.weed, self.private / 'backend', volume_size_mib=256, max_volumes=8)
        self.backend.start_owned(self, until)
        self.events.emit('backend_started', identities=self.backend.identities(), binary_sha256=sha(self.args.weed))
        self.proxy = support.Proxy(self.backend.port, self.directory, self.raw)
        self.port = network.free_port(set())
        self.cache = self.private / 'cache'
        temporary = self.private / 'tmp'
        self.cache.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        token, self.diagnostic_token = secrets.token_hex(32), secrets.token_hex(32)
        configuration = spec.configuration(f'127.0.0.1:{self.port}', self.cache, self.proxy.endpoint,
            hashlib.sha256(token.encode()).hexdigest(), self.cell['group_commit'], self.contract,
            hashlib.sha256(self.diagnostic_token.encode()).hexdigest())
        support.save_json(self.directory / 'service-config.json', configuration)
        config_path = self.private / 'service.json'
        support.save_json(config_path, configuration)
        self.client = self.private / 'client.json'
        support.save_json(self.client, {'endpoint': f'http://127.0.0.1:{self.port}', 'token': token,
                                       'source_root': str(shared.ROOT)})
        self.proxy.set_phase('startup')
        self.events.emit('service_start_requested', empty_cache=not list(self.cache.iterdir()),
                         group_commit=self.cell['group_commit'], configuration_sha256=sha(config_path))
        environment = dict(os.environ, TMPDIR=str(temporary), SCAP_TEST_ACCESS=self.backend.access,
                           SCAP_TEST_SECRET=self.backend.secret)
        requested = time.monotonic_ns()
        self.service, proc, self.identity, proof = resources.spawn_owned(
            [str(self.args.binary), str(config_path)], environment, shared.ROOT,
            self.private / 'service.log', self.events.emit)
        self.monitor.add('service', self.service, proc, self.identity, proof, self.args.binary, requested)
        expected = {'path': str(self.args.binary), 'sha256': sha(self.args.binary)}
        while time.monotonic() < until:
            self.check()
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=min(.5, self.remaining(until)))
            try:
                actual = resources.executable(proc)
                if actual != expected:
                    time.sleep(.01)
                    continue
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                body = response.read(4097)
                self.events.emit('readiness_probe', status=response.status, response=self.raw.save(body))
                if response.status == 200 and json.loads(body) == {'status': 'alive', 'protocol': 1}:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('service startup deadline')
        self.events.emit('service_started', identity=self.identity, proof=proof, binary=actual)
        with self.monitor.lock:
            self.monitor.service_live = True

    def diagnostic(self, boundary, until):
        self.check()
        if self.diag_count >= spec.BOUNDS['diagnostic_gets']:
            raise ValueError('diagnostic GET budget')
        self.diag_count += 1
        start = time.monotonic_ns()
        row = {'event': 'diagnostic_response', 'attempt': self.diag_count, 'boundary': boundary,
               'request_ns': start, 'request': {'method': 'GET',
                    'url': f'http://127.0.0.1:{self.port}/diagnostics/lifecycle',
                    'token_sha256': hashlib.sha256(self.diagnostic_token.encode()).hexdigest()}}
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=min(2, self.remaining(until)))
        parsed = None
        try:
            connection.request('GET', '/diagnostics/lifecycle',
                               headers={'Authorization': 'Bearer ' + self.diagnostic_token})
            response = connection.getresponse()
            body = response.read(spec.BOUNDS['diagnostic_response_bytes'] + 1)
            if len(body) > spec.BOUNDS['diagnostic_response_bytes']:
                raise ValueError('diagnostic response byte budget')
            if self.diag_bytes + len(body) > spec.BOUNDS['diagnostic_bytes']:
                raise ValueError('diagnostic aggregate byte budget')
            self.diag_bytes += len(body)
            row.update(status=response.status, response=self.raw.save(body),
                       content_type=response.getheader('Content-Type'))
            if response.status == 200:
                try:
                    parsed = lifecycle.parse(json.loads(body))
                except (ValueError, TypeError) as error:
                    row['parse_error'] = str(error)
        except (OSError, ValueError, http.client.HTTPException) as error:
            row.update(event='diagnostic_error', error=repr(error))
        finally:
            row['response_ns'] = time.monotonic_ns()
            connection.close()
            raw = observer.encoded(row)
            if self.diag_ledger_bytes + len(raw) > spec.BOUNDS['diagnostic_ledger_bytes']:
                raise ValueError('diagnostic ledger byte budget')
            with (self.directory / 'diagnostics.jsonl').open('ab') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.diag_ledger_bytes += len(raw)
        return row, parsed

    def quiesce(self, boundary, until):
        # Eight independently captured GETs per boundary; a retry is diagnostic
        # observation only. It never resubmits or changes a business operation.
        for attempt in range(8):
            row, snapshot = self.diagnostic(boundary, until)
            if snapshot is not None and lifecycle.quiescent(snapshot):
                self.events.emit('diagnostic_boundary', boundary=boundary, attempt=row['attempt'],
                                 response=row['response'], response_ns=row['response_ns'])
                return True
            if attempt != 7:
                time.sleep(min(1, self.remaining(until)))
        self.events.emit('diagnostic_incomplete', boundary=boundary)
        return False

    def phase_run(self, phase, until):
        self.phase = phase
        self.proxy.set_phase(phase)
        self.events.emit('phase_started', phase=phase)
        command = [str(self.args.node), str(shared.HERE / 'probe.mjs'), phase,
                   str(self.client), str(self.directory)]
        requested = time.monotonic_ns()
        self.child, proc, identity, proof = resources.spawn_owned(command, dict(os.environ), shared.HERE,
            self.directory / (phase + '.stdout'), self.events.emit)
        self.monitor.add('node', self.child, proc, identity, proof, self.args.node, requested)
        self.events.emit('node_started', phase=phase, identity=identity, spawn_requested_ns=requested,
                         binary_sha256=sha(self.args.node))
        status, usage = self.monitor.wait(self.child, self.remaining(until))
        self.events.emit('node_stopped', phase=phase, identity=identity, status=status, usage=usage)
        self.child = None
        if status != 0:
            raise RuntimeError('SDK phase failed: ' + phase)
        self.check()
        if phase == 'seed_rows':
            # The probe exits nonzero for every seed SDK error. Validate the
            # original completions again before any load can be launched.
            history = [json.loads(line) for line in (self.directory / 'sdk.jsonl').read_bytes().splitlines()]
            completions = [row for row in history if row['event'] == 'call_finished'
                           and row['phase'] == 'seed_rows' and '-control-' not in row['id']]
            if len(completions) != spec.SEED_ROWS or any(not row['ok'] for row in completions):
                raise ValueError('seed original ACK denominator')
            if not self.quiesce('baseline', until):
                raise ValueError('seed diagnostic baseline incomplete')
        elif phase == 'load':
            self.diagnostic_status = 'OBSERVED_NOT_AUDITED' if self.quiesce('end', until) else 'NOT_RUN'
        self.events.emit('phase_finished', phase=phase)

    def observe(self):
        seed_until = min(self.until, time.monotonic() + spec.DEADLINES['seed_seconds'])
        self.phase_run('seed', seed_until)
        self.phase_run('seed_rows', seed_until)
        self.phase_run('load', min(self.until, time.monotonic() + spec.DEADLINES['load_seconds']))
        self.phase_run('verify', min(self.until, time.monotonic() + spec.DEADLINES['settlement_seconds']))
        self.finished = self.diagnostic_status == 'OBSERVED_NOT_AUDITED'
        if not self.finished:
            raise ValueError('load diagnostic attribution NOT_RUN after original settlement')

    def close(self):
        errors = []
        if self.child is not None and self.child.returncode is None:
            resources.signal_owned(self.child, signal.SIGKILL)
            try:
                status, usage = self.monitor.wait(self.child, 10, check=False)
                self.events.emit('node_forced_stop', status=status, usage=usage)
                errors.append('unfinished SDK phase')
            except BaseException as error:
                errors.append(repr(error))
        if self.service is not None:
            resources.signal_owned(self.service, signal.SIGINT)
            try:
                status, usage = self.monitor.wait(self.service, spec.DEADLINES['shutdown_seconds'], check=False)
            except BaseException as error:
                errors.append(repr(error))
                resources.signal_owned(self.service, signal.SIGKILL)
                status, usage = self.monitor.wait(self.service, 10, check=False)
            self.events.emit('service_stopped', identity=self.identity, status=status, usage=usage,
                             cache_empty=not list(self.cache.iterdir()))
            if status != 0:
                errors.append('service did not stop normally')
        if self.proxy is not None:
            try:
                self.proxy.close()
                self.events.emit('proxy_stopped', errors=self.proxy.errors, request_count=self.proxy.serial)
                errors.extend(self.proxy.errors)
            except BaseException as error:
                errors.append(repr(error))
        if self.backend is not None:
            try:
                self.events.emit('backend_final_allocation', observed=observer.tree(self.private / 'backend'))
                self.events.emit('backend_stopped', processes=self.backend.stop_owned(self))
            except BaseException as error:
                errors.append(repr(error))
        try:
            self.monitor.close()
        except BaseException as error:
            errors.append(repr(error))
        log = self.private / 'service.log'
        if log.exists():
            if log.stat().st_size > spec.BOUNDS['child_log_bytes']:
                errors.append('service log budget')
            else:
                shutil.copyfile(log, self.directory / 'service.log')
        try:
            self.events.emit('cell_final_allocation', observed=observer.check_filesystem(self.args.evidence, self.private))
        except BaseException as error:
            errors.append(repr(error))
        self.events.close()
        if not errors and self.finished:
            self.temporary.cleanup()
        else:
            # TemporaryDirectory's finalizer must not erase failed backend or
            # private cache evidence. Credentials remain private and uncommitted.
            self.temporary._finalizer.detach()
        return errors


def preflight(args):
    if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
        raise ValueError('assertions required by unchanged observer helpers')
    if any(key in os.environ for key in ('LLVM_PROFILE_FILE', 'NODE_V8_COVERAGE')) or any(
            'instrument-coverage' in os.environ.get(key, '') for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')):
        raise ValueError('runtime evidence cannot use coverage instrumentation')
    space = os.statvfs(args.evidence.parent)
    if space.f_bavail * space.f_frsize < spec.BOUNDS['startup_free_bytes'] or space.f_favail < spec.BOUNDS['startup_free_inodes']:
        raise ValueError('frozen startup disk/inode reserve')
    if subprocess.check_output([str(args.node), '--version'], text=True).strip() != 'v22.16.0':
        raise ValueError('Node must be exactly 22.16.0')
    tracked = set(subprocess.check_output(['git', 'ls-files'], cwd=shared.ROOT, text=True).splitlines())
    if any(path.relative_to(shared.ROOT).as_posix() not in tracked for path in shared.fixture_files()):
        raise ValueError('publish frozen experiment sources before actual evidence')
    subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--', *sorted(fixture())], cwd=shared.ROOT, check=True)
    # /proc ownership and filesystem rules are exercised before any load. The
    # first original monitor sample also records actual environment limits.
    descriptor = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
    try:
        identity = resources.stat_identity(resources.read_at(descriptor, 'stat'))
        row = observer.process_sample(descriptor, identity)
        observer.accept_processes([{**row, 'role': 'observer'}])
    finally:
        os.close(descriptor)
    import sqlite3
    with sqlite3.connect(':memory:') as connection:
        connection.execute(spec.DDL)
        if connection.execute('SELECT count(*) FROM dbstat').fetchone()[0] != 2:
            raise ValueError('independent SQLite dbstat unavailable')


def run(args):
    for name in ('binary', 'node', 'weed', 'build_record', 'evidence'):
        setattr(args, name, getattr(args, name).resolve())
    preflight(args)
    args.evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    before = fixture()
    report = {'status': 'FAILED', 'profile': spec.NAME, 'aws_standard': 'NOT_RUN',
              'production_slo': 'NOT_RUN', 'cells': []}
    matrix_start_ns = time.monotonic_ns()
    until = matrix_start_ns / 1_000_000_000 + spec.DEADLINES['run_seconds']
    try:
        build.verify(args.build_record, args.binary)
        (args.evidence / 'build').mkdir()
        receipt = build.capture_receipt(args.build_record, args.binary, args.evidence / 'build')
        with tarfile.open(args.evidence / 'fixture-source.tar', 'w') as archive:
            for name in before:
                archive.add(shared.ROOT / name, arcname=name, recursive=False)
        inputs = {'fixture': before, 'fixture_archive_sha256': sha(args.evidence / 'fixture-source.tar'),
            'matrix_start_ns': matrix_start_ns,
            'fixture_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=shared.ROOT, text=True).strip(),
            'build_source_commit': receipt['source_commit'],
            'tools': {name: {'path': str(path), 'sha256': sha(path)} for name, path in (
                ('scapd', args.binary), ('node', args.node), ('weed', args.weed),
                ('python', Path(sys.executable).resolve()))}}
        support.save_json(args.evidence / 'inputs.json', inputs)
        support.save_json(args.evidence / 'plan.json', spec.matrix_plan())
        for item in spec.cells():
            observed = {**item, 'status': 'FAILED'}
            report['cells'].append(observed)
            cell = Cell(args, item, until)
            try:
                cell.setup()
                cell.observe()
                observed['status'] = 'OBSERVED_NOT_AUDITED'
                observed['diagnostic_status'] = cell.diagnostic_status
            finally:
                observed['diagnostic_status'] = cell.diagnostic_status
                observed['cleanup_errors'] = cell.close()
                if observed['cleanup_errors']:
                    raise RuntimeError(observed['cleanup_errors'])
            print(json.dumps(observed), flush=True)
        build.verify(args.build_record, args.binary)
        if fixture() != before or any(sha(value['path']) != value['sha256'] for value in inputs['tools'].values()):
            raise ValueError('frozen source/tool changed during actual run')
        support.save_json(args.evidence / 'fixture-after.json', fixture())
        observer.check_filesystem(args.evidence)
        report['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_ns'] = time.monotonic_ns()
        support.save_json(args.evidence / 'result.json', report)
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'build-record', 'weed', 'node', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
