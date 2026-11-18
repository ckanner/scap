#!/usr/bin/env python3
"""One real, frozen production CLI takeover and HEAD9 recovery history."""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import traceback

import support as io

SCOPE = {'deployment': '1', 'tenant': '7', 'database': '8601', 'incarnation': '1', 'generation': '1'}
WORKERS = {'A': 9601, 'B': 9602, 'C': 9603}


class Harness:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.trace = io.Trace(evidence)
        self.tokens = {principal: secrets.token_hex(32) for principal in ('11', '12')}
        self.backend = None
        self.children, self.proxies, self.http, self.services = [], {}, {}, {}
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.original = None

    def child(self, command, name, environment=None):
        child = io.Child(command, io.ROOT, environment or os.environ.copy(), self.trace, name, self.private)
        self.children.append(child)
        return child

    def setup(self):
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(key, '')
                       for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        self.source = io.load('controller_runtime_source', io.ROOT / 'scripts/source_manifest.py')
        self.original = self.source.capture(io.ROOT)
        io.save(self.evidence / 'source.json', io.encoded(self.original))
        source_files = {row['path']: row['sha256'] for row in self.original['files']}
        receipt = io.build.verify(self.args.build_record, self.args.server)
        assert all(source_files.get(name) == digest for name, digest in receipt['inputs'].items())
        build_dir = self.evidence / 'service-build'
        build_dir.mkdir()
        io.build.capture_receipt(self.args.build_record, self.args.server, build_dir)
        with tarfile.open(self.evidence / 'source.tar', 'w') as archive:
            for row in self.original['files']:
                archive.add(io.ROOT / row['path'], arcname=row['path'], recursive=False)
        tools = {name: {'path': str(path.resolve()), 'sha256': io.build.digest(path)}
                 for name, path in (('node', self.node), ('weed', self.args.weed), ('scapd', self.args.server))}
        node_version = subprocess.check_output([str(self.node), '--version'], text=True).strip()
        assert node_version == 'v22.16.0'
        io.save(self.evidence / 'inputs.json', io.encoded({
            'version': 1, 'scope': SCOPE, 'workers': WORKERS, 'tools': tools,
            'source_commit': self.original['commit'], 'source_sha256': self.original['source_sha256'],
            'source_archive_sha256': io.build.digest(self.evidence / 'source.tar'),
            'plan_sha256': source_files['experiments/object-controller-runtime/PLAN.md'],
            'node_version': node_version, 'whole_seconds': 180, 'stage_seconds': 75,
            'sql_requests': 3, 'client_acks': 2, 'business_unknowns': 1, 'claim_unknowns': 1,
        }))
        self.backend = io.network.Backend(self.args.weed, self.private / 'backend',
                                          volume_size_mib=128, max_volumes=4)
        self.backend.start()
        self.trace.emit('backend_started', identities=self.backend.identities(), binary=tools['weed'],
                        normal_access_sha256=io.sha(self.backend.access.encode()))
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            connection.request('GET', '/scap-test/unsigned-controller-probe')
            response = connection.getresponse()
            raw = response.read(65537)
            self.trace.emit('unsigned_probe', status=response.status, response=self.trace.raw(raw))
            assert response.status == 403 and len(raw) <= 65536
        finally:
            connection.close()
        used = set()
        for role, worker in WORKERS.items():
            port = io.network.free_port(used)
            used.add(port)
            self.proxies[role] = io.Proxy(self.backend, role, self.trace,
                                         {self.backend.access: self.backend.secret})
            self.http[role] = io.HTTPProxy(role, port, self.trace, self.tokens)
            cache = self.private / ('cache-' + role)
            cache.mkdir(mode=0o700)
            config = io.configuration(port, cache, self.proxies[role].endpoint,
                                      io.sha(self.tokens['11'].encode()), worker, False)
            config['credentials'].append({'sha256': io.sha(self.tokens['12'].encode()),
                'deployment': '1', 'tenant': '7', 'principal': '12', 'provision': False})
            config['s3']['timeout_ms'] = 5000
            config['admission']['timeout_ms'] = 30000
            config['admission']['recovery_timeout_ms'] = 60000
            path = self.private / ('service-' + role + '.json')
            io.save(path, io.encoded(config))
            io.save(self.evidence / path.name, io.encoded(config))
            environment = dict(os.environ, SCAP_RECLAIM_ACCESS=self.backend.access,
                               SCAP_RECLAIM_SECRET=self.backend.secret)
            child = self.child([str(self.args.server), str(path)], 'service-' + role, environment)
            self.services[role] = (child, cache)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
                try:
                    connection.request('GET', '/healthz')
                    response = connection.getresponse()
                    if response.status == 200 and json.loads(response.read(4097)) == {'status': 'alive', 'protocol': 1}:
                        self.trace.emit('service_ready', role=role, worker=str(worker), id=child.id)
                        break
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(.02)
            else:
                raise TimeoutError('service readiness')
        policy = {'scope': SCOPE, 'authorityId': 'controller-runtime-private-s3', 'principal': '12',
            'metadataEndpoints': [self.http['C'].endpoint + '/v1'],
            'workers': [{'workerInstance': str(WORKERS[role]), 'endpoint': self.http[role].endpoint + '/v1',
                         'rank': rank} for rank, role in enumerate(('A', 'B'))],
            'modes': {'takeover': True, 'activate': True, 'cancel': True},
            'allowInsecureHttp': True, 'recoveryTimeoutMs': 60000}
        config = {'version': 1, 'scopes': [{'policy': policy, 'tokenEnv': 'SCAP_CONTROLLER_RUNTIME_TOKEN'}]}
        self.controller_config = self.private / 'controller.json'
        io.save(self.controller_config, io.encoded(config))
        io.save(self.evidence / 'controller.json', io.encoded(config))

    def phase(self, label):
        self.trace.emit('scenario_phase', label=label)
        for proxy in (*self.proxies.values(), *self.http.values()):
            proxy.phase_to(label)

    def business(self, phase, role):
        config = self.private / ('business-' + phase + '.json')
        io.save(config, io.encoded({'endpoint': self.http[role].endpoint,
                                   'token': self.tokens['11'], 'scope': SCOPE}))
        child = self.child([str(self.node), str(io.HERE / 'client.mjs'), phase,
                            str(config), str(self.evidence)], 'business-' + phase)
        status, usage = io.network.wait_child(child.process, 45)
        self.trace.emit('child_stopped', id=child.id, identity=child.identity, status=status,
                        usage=usage, crash=False, forced=False, stderr=self.trace.raw(child.log.read_bytes()))
        assert status == 0, (phase, child.log.read_text())

    def start_controller(self, name):
        environment = dict(os.environ, SCAP_CONTROLLER_RUNTIME_TOKEN=self.tokens['12'])
        return self.child([str(self.node), str(io.ROOT / 'sdk/node/bin/owner-controller.mjs'),
                           str(self.controller_config)], name, environment)

    def wait_report(self, child, state):
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            # Read only complete output lines. No summary or model manufactures a report.
            data = child.log.read_bytes()
            assert len(data) <= 1048576, 'controller output bound'
            lines = data.splitlines(keepends=True)
            reports = [json.loads(line) for line in lines if line.endswith(b'\n')]
            for report in reports:
                if report.get('state') == state:
                    self.trace.emit('controller_report_observed', id=child.id, state=state, report=report)
                    return report
            if child.process.poll() is not None:
                raise RuntimeError('controller exited before expected report')
            time.sleep(.05)
        raise TimeoutError('fixed controller report deadline: ' + state)

    def stop_controller(self, child):
        child.close()
        self.trace.emit('controller_reports', id=child.id, raw=self.trace.raw(child.log.read_bytes()))

    def history(self):
        self.phase('initialize')
        self.business('initialize', 'A')
        self.phase('business-unknown')
        sql_loss = self.http['A'].arm('business-ack-loss', 'execute')
        self.business('unknown', 'A')
        assert sql_loss.arrived.is_set() and sql_loss.finished.wait(5) and sql_loss.used == 1
        self.phase('healthy')
        first = self.start_controller('controller-one')
        healthy = self.wait_report(first, 'healthy')
        assert healthy['mutations'] == 0
        claim_loss = self.http['B'].arm('claim-ack-loss', 'owner_claim')
        self.phase('owner-loss')
        old, cache = self.services['A']
        old.close(crash=True)
        existed = cache.is_dir()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', id=old.id, path=str(cache), existed=existed, absent=not cache.exists())
        unknown = self.wait_report(first, 'unknown')
        assert unknown['reason'] == 'UNKNOWN' and unknown['lastUncertainCall']['operation'] == 'owner_claim'
        assert claim_loss.arrived.is_set() and claim_loss.finished.wait(5) and claim_loss.used == 1
        self.stop_controller(first)
        self.phase('controller-restart')
        second = self.start_controller('controller-two')
        active = self.wait_report(second, 'active_observed')
        assert active['currentAuthority']['owner_instance'] == '9602' and active['currentAuthority']['active']
        self.stop_controller(second)
        self.phase('cold-verification')
        self.business('verify', 'B')

    def cleanup(self):
        failures = []
        for child in reversed(self.children):
            try:
                child.close()
            except BaseException as error:
                failures.append(repr(error))
        for proxy in (*self.http.values(), *self.proxies.values()):
            try:
                proxy.close()
                assert not proxy.errors
            except BaseException as error:
                failures.append(repr(error))
        if self.backend:
            try:
                self.trace.emit('backend_stopped', processes=self.backend.stop())
            except BaseException as error:
                failures.append(repr(error))
        self.trace.emit('cleanup_finished', errors=failures)
        return failures


def main(args):
    evidence = args.evidence.resolve()
    assert not evidence.is_relative_to(io.ROOT), 'evidence must be outside source'
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-controller-private-', dir=evidence.parent))
    suite = Harness(args, evidence, private)
    summary = {'status': 'FAILED', 'aws': 'NOT_RUN', 'production_slo': 'NOT_RUN',
               'whole_seconds': 180, 'oracle': 'NOT_RUN', 'controls': 'NOT_RUN'}
    started = time.monotonic()

    def expired(_signal, _frame):
        raise TimeoutError('fixed whole-fixture deadline')

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        suite.setup()
        suite.history()
        summary['status'] = 'OBSERVED_NOT_AUDITED'
    except BaseException as error:
        summary['error'] = repr(error)
        io.save(evidence / 'failure.txt', traceback.format_exc().encode())
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        summary['cleanup_errors'] = suite.cleanup()
        if summary['cleanup_errors']:
            summary['status'] = 'FAILED'
        try:
            assert suite.original is not None and suite.source.capture(io.ROOT) == suite.original
            io.build.verify(args.build_record, args.server)
            suite.trace.emit('source_verified', commit=suite.original['commit'],
                             source_sha256=suite.original['source_sha256'])
        except BaseException as error:
            summary['source_error'] = repr(error)
            summary['status'] = 'FAILED'
        shutil.rmtree(private)
        suite.trace.emit('private_removed', absent=not private.exists())
        summary['elapsed_seconds'] = time.monotonic() - started
        io.save(evidence / 'summary.json', io.encoded(summary))
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('real validation requires Python assertions')
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--build-record', required=True, type=Path)
    parser.add_argument('--weed', required=True, type=Path)
    parser.add_argument('--node', default='node')
    parser.add_argument('--evidence', required=True, type=Path)
    arguments = parser.parse_args()
    arguments.server = arguments.server.resolve()
    arguments.weed = arguments.weed.resolve()
    raise SystemExit(main(arguments))
