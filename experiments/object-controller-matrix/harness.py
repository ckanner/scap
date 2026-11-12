"""Per-case isolated real services, production CLIs and original byte capture."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import time

import support as io


class Harness:
    def __init__(self, args, evidence, private, case):
        self.args, self.evidence, self.private, self.case = args, evidence, private, case
        self.scope, self.trace = case['scope'], io.Trace(evidence)
        self.tokens = {principal: secrets.token_hex(32) for principal in ('11', '12', '13')}
        self.children, self.controllers, self.proxies, self.http, self.services = [], [], {}, {}, {}
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.backend = self.original = None

    def child(self, command, name, environment=None):
        child = io.Child(command, io.ROOT, environment or os.environ.copy(), self.trace, name, self.private)
        self.children.append(child)
        return child

    def setup(self):
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(key, '')
                       for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        self.source = io.load('controller_matrix_source', io.ROOT / 'scripts/source_manifest.py')
        self.original = self.source.capture(io.ROOT)
        io.save(self.evidence / 'source.json', io.encoded(self.original))
        files = {row['path']: row['sha256'] for row in self.original['files']}
        receipt = io.build.verify(self.args.build_record, self.args.server)
        assert all(files.get(name) == digest for name, digest in receipt['inputs'].items())
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
        io.save(self.evidence / 'scenario.json', io.encoded(self.case))
        io.save(self.evidence / 'inputs.json', io.encoded({
            **self.case, 'tools': tools, 'node_version': node_version,
            'source_commit': self.original['commit'], 'source_sha256': self.original['source_sha256'],
            'source_archive_sha256': io.build.digest(self.evidence / 'source.tar'),
            'plan_sha256': files['experiments/object-controller-matrix/PLAN.md'],
            'scenario_sha256': io.build.digest(self.evidence / 'scenario.json')}))
        self.backend = io.network.Backend(self.args.weed, self.private / 'backend',
                                          volume_size_mib=128, max_volumes=4)
        self.backend.start()
        self.trace.emit('backend_started', identities=self.backend.identities(), binary=tools['weed'])
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            connection.request('GET', '/scap-test/unsigned-controller-matrix-probe')
            response = connection.getresponse()
            raw = response.read(65537)
            self.trace.emit('unsigned_probe', status=response.status, response=self.trace.raw(raw))
            assert response.status == 403 and len(raw) <= 65536
        finally:
            connection.close()
        used = set()
        for role, configured_worker in io.WORKERS.items():
            worker = self.case['worker_b_actual'] if role == 'B' else configured_worker
            port = io.network.free_port(used)
            used.add(port)
            self.proxies[role] = io.Proxy(self.backend, role, self.trace,
                                         {self.backend.access: self.backend.secret})
            self.http[role] = io.HTTPProxy(role, port, self.trace, self.tokens)
            cache = self.private / ('cache-' + role)
            cache.mkdir(mode=0o700)
            config = io.configuration(port, cache, self.proxies[role].endpoint,
                                      io.sha(self.tokens['11'].encode()), worker, False)
            config['credentials'].extend({'sha256': io.sha(self.tokens[principal].encode()),
                'deployment': '1', 'tenant': '7', 'principal': principal, 'provision': False}
                for principal in ('12', '13'))
            config['s3']['timeout_ms'] = self.case['metadata_s3_timeout_ms'] if role == 'M' else 5000
            config['admission']['timeout_ms'] = 30000
            config['admission']['recovery_timeout_ms'] = 60000
            if role == 'B' and self.case['zero_recovery_budget']:
                config['owner_recovery'] = {'payload_gets': 0, 'payload_bytes': 0}
            if role == 'M' and self.case['control_intake_occupant']:
                config['admission']['control_intake'] = 1
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

    def phase(self, label):
        self.trace.emit('scenario_phase', label=label, case_id=self.case['case_id'])
        for proxy in (*self.proxies.values(), *self.http.values()):
            proxy.phase_to(label)

    def business_begin(self, phase, role='M'):
        config = self.private / ('business-' + phase + '.json')
        io.save(config, io.encoded({'endpoint': self.http[role].endpoint,
            'token': self.tokens['11'], 'scope': self.scope,
            'targetEndpoint': self.http['B'].endpoint, 'targetWorker': str(io.WORKERS['B']),
            'guardWorker': '9602' if role == 'A' else '9601'}))
        child = self.child([str(self.node), str(io.HERE / 'client.mjs'), phase,
                            str(config), str(self.evidence)], 'business-' + phase)
        return child

    def business_finish(self, child):
        status, usage = io.network.wait_child(child.process, io.LIMITS['business_seconds'])
        self.trace.emit('child_stopped', id=child.id, identity=child.identity, status=status,
                        usage=usage, crash=False, forced=False, stderr=self.trace.raw(child.log.read_bytes()))
        assert status == 0, (child.id, child.log.read_text())

    def business(self, phase, role='M'):
        self.business_finish(self.business_begin(phase, role))

    def seed(self):
        self.phase('initialize')
        self.business('initialize', 'A')
        self.phase('business-unknown')
        gate = self.http['A'].arm('business-ack-loss', 'execute')
        self.business('unknown', 'A')
        self.arrived(gate)
        self.finished(gate)

    def policy(self, principal='12', reversed_ranks=False):
        roles = ['A', 'B', 'C'] if self.case['three_rank_workers'] else ['A', 'B']
        if reversed_ranks:
            assert roles == ['A', 'B', 'C']
            roles = ['A', 'C', 'B']
        metadata = ['M', 'C'] if self.case['metadata_routes'] == 2 else ['M']
        return {'scope': self.scope, 'authorityId': 'controller-matrix-private-s3', 'principal': principal,
            'metadataEndpoints': [self.http[role].endpoint + '/v1' for role in metadata],
            'workers': [{'workerInstance': str(io.WORKERS[role]), 'endpoint': self.http[role].endpoint + '/v1',
                         'rank': rank} for rank, role in enumerate(roles)],
            'modes': {'takeover': True, 'activate': True, 'cancel': True},
            'allowInsecureHttp': True, 'recoveryTimeoutMs': 60000}

    def start_controller(self, name, principal='12', reversed_ranks=False):
        policy = self.policy(principal, reversed_ranks)
        config = {'version': 1, 'scopes': [{'policy': policy, 'tokenEnv': 'SCAP_CONTROLLER_MATRIX_TOKEN'}]}
        path = self.private / (name + '.json')
        io.save(path, io.encoded(config))
        io.save(self.evidence / path.name, io.encoded(config))
        self.trace.emit('controller_configuration', id=name, config=self.trace.raw(io.encoded(config)),
                        principal=principal, file=path.name)
        environment = dict(os.environ, SCAP_CONTROLLER_MATRIX_TOKEN=self.tokens[principal])
        child = self.child([str(self.node), str(io.ROOT / 'sdk/node/bin/owner-controller.mjs'),
                           str(path)], name, environment)
        child.report_cursor, child.report_saved = 0, False
        self.controllers.append(child)
        return child

    def wait_report(self, child, state, reason=None):
        deadline = time.monotonic() + io.LIMITS['stage_seconds']
        while time.monotonic() < deadline:
            data = child.log.read_bytes()
            assert len(data) <= 1048576, 'controller output bound'
            reports = [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith(b'\n')]
            for index in range(child.report_cursor, len(reports)):
                report = reports[index]
                if report.get('state') == state and (reason is None or report.get('reason') == reason):
                    child.report_cursor = index + 1
                    self.trace.emit('controller_report_observed', id=child.id, state=state,
                                    line_index=index, report=report)
                    return report
            if child.process.poll() is not None:
                raise RuntimeError('controller exited before expected report')
            time.sleep(.05)
        raise TimeoutError('fixed report deadline: ' + state + '/' + str(reason))

    def stop_controller(self, child):
        if not child.report_saved:
            child.close()
            self.trace.emit('controller_reports', id=child.id, raw=self.trace.raw(child.log.read_bytes()))
            child.report_saved = True

    def reports_after_now(self, child):
        data = child.log.read_bytes()
        assert len(data) <= 1048576, 'controller output bound'
        child.report_cursor = sum(line.endswith(b'\n') for line in data.splitlines(keepends=True))
        self.trace.emit('controller_report_cut', id=child.id, line_count=child.report_cursor)

    def stop_controllers(self):
        for child in self.controllers:
            self.stop_controller(child)

    def owner_loss(self):
        self.phase('owner-loss')
        old, cache = self.services['A']
        old.close(crash=True)
        existed = cache.is_dir()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', id=old.id, path=str(cache), existed=existed, absent=not cache.exists())

    @staticmethod
    def arrived(gate):
        deadline = time.monotonic() + io.LIMITS['stage_seconds']
        while not gate.arrived.wait(.1):
            if time.monotonic() >= deadline:
                raise TimeoutError('fixed fault arrival deadline')
        return gate.observed

    @staticmethod
    def finished(gate):
        assert gate.finished.wait(15) and gate.used == 1, 'fixed fault completion deadline'

    def release(self, proxy, gate, lost=False):
        (proxy.release_lost if lost else proxy.release)(gate)
        self.finished(gate)

    def verify(self):
        self.stop_controllers()
        self.phase('verification')
        self.business('verify')

    def cleanup(self):
        failures = []
        for child in reversed(self.children):
            try:
                if child in self.controllers:
                    self.stop_controller(child)
                else:
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
