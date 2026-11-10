"""Owned native/service/SDK assembly and explicit public operations only."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import tarfile
import time

import spec
import support as io


class Harness:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.trace = io.Trace(evidence)
        self.backend = None
        self.proxies, self.http, self.services, self.clients = {}, {}, {}, {}
        self.children, self.ports, self.workers = [], {}, {}
        self.service_incarnations, self.sdk_incarnations, self.responses = {}, {}, {}
        self.tokens = {principal: secrets.token_hex(32) for principal in ('11', '12')}
        self.gc_access, self.gc_secret = secrets.token_hex(32), secrets.token_hex(32)
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.specs, self.plans = spec.inputs(), {row['name']: row for row in spec.plans()}
        self.sql, self.saved, self.originals = {row['name']: row for row in self.specs}, {}, {}
        self.nonce = 90000000

    def next_nonce(self):
        self.nonce += 1
        return str(self.nonce)

    def child(self, command, name, interactive=False, environment=None):
        value = io.Child(command, io.ROOT, environment or os.environ.copy(), self.trace,
                         name, self.private, interactive)
        self.children.append(value)
        return value

    def setup(self):
        from http_proxy import HTTPProxy
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(key, '')
                       for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        spec.validate()
        self.source_module = io.module('owner_source_manifest', io.ROOT / 'scripts/source_manifest.py')
        self.original_source = self.source_module.capture(io.ROOT)
        io.save(self.evidence / 'source.json', io.encoded(self.original_source))
        service = io.service_build.verify(self.args.build_record, self.args.server)
        native = io.seed_build.verify(self.args.seed_build_record, self.args.worker)
        assert service['source_commit'] == native['source_commit']
        source = {row['path']: row['sha256'] for row in self.original_source['files']}
        assert all(source.get(name) == digest for receipt in (service, native)
                   for name, digest in receipt['inputs'].items())
        for name, module, receipt, binary in (
                ('service-build', io.service_build, self.args.build_record, self.args.server),
                ('seed-build', io.seed_build, self.args.seed_build_record, self.args.worker)):
            directory = self.evidence / name
            directory.mkdir()
            module.capture_receipt(receipt, binary, directory)
        with tarfile.open(self.evidence / 'source.tar', 'w') as archive:
            for row in self.original_source['files']:
                archive.add(io.ROOT / row['path'], arcname=row['path'], recursive=False)
        tools = {name: {'path': str(path.resolve()), 'sha256': io.service_build.digest(path)}
                 for name, path in (('node', self.node), ('weed', self.args.weed),
                                    ('scapd', self.args.server), ('native-seed', self.args.worker))}
        for name, path, argument in (('node', self.node, '--version'), ('weed', self.args.weed, 'version')):
            child = self.child([str(path), argument], name + '-version')
            status, usage = io.network.wait_child(child.process, 10)
            self.trace.emit('child_stopped', id=child.id, identity=child.identity, status=status,
                            usage=usage, crash=False, forced=False, stderr=self.trace.raw(child.log.read_bytes()))
            assert status == 0
            assert (child.log.read_bytes().strip() == b'v22.16.0' if name == 'node'
                    else io.network.VERSION in child.log.read_text())
        io.save(self.evidence / 'inputs.json', io.encoded({
            'schema': 1, 'fixture_source_root': str(io.ROOT), 'commit': self.original_source['commit'],
            'runtime_source_commit': service['source_commit'], 'runtime_source_root': service['source_root'],
            'seed_source_root': native['source_root'], 'source_sha256': self.original_source['source_sha256'],
            'source_archive_sha256': io.sha((self.evidence / 'source.tar').read_bytes()),
            'plan_sha256': source['experiments/object-owner-plan-runtime/PLAN.md'],
            'tools': tools, 'scopes': spec.SCOPES, 'named': {name: spec.creation(name) for name in spec.NAMED},
            'specs': self.specs, 'plans': list(self.plans.values()), 'exceptional_plans': spec.exceptional_plans(),
            'expected': spec.EXPECTED, 'owner_rpc': spec.OWNER_RPC, 'faults': spec.FAULTS,
            'workers': spec.WORKERS, 'native_worker': spec.NATIVE_WORKER, 'limits': spec.LIMITS,
            'timeouts': spec.TIMEOUTS, 'max_sweep_pages': spec.MAX_SWEEP_PAGES,
        }))
        self.backend = io.network.Backend(self.args.weed, self.private / 'backend',
                                          volume_size_mib=128, max_volumes=4)
        identity = json.loads(self.backend.identity.read_text())
        identity['identities'].append({'name': 'explicit-owner-history-gc-capability',
            'credentials': [{'accessKey': self.gc_access, 'secretKey': self.gc_secret}],
            'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging']})
        self.backend.identity.write_text(json.dumps(identity))
        self.backend.start()
        self.trace.emit('backend_started', identities=self.backend.identities(), binary=tools['weed'],
                        capacity=self.backend.capacity, normal_access_sha256=io.sha(self.backend.access.encode()),
                        gc_access_sha256=io.sha(self.gc_access.encode()))
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            connection.request('GET', '/scap-test/fixture-ready')
            response = connection.getresponse()
            raw = response.read(65537)
            self.trace.emit('unsigned_probe', status=response.status, response=self.trace.raw(raw))
            assert response.status == 403 and len(raw) <= 65536
        finally:
            connection.close()
        credentials = {self.backend.access: self.backend.secret, self.gc_access: self.gc_secret}
        for role in ('seed', *spec.ROLES):
            self.proxies[role] = io.Proxy(self.backend, role, self.trace, credentials)
        for role in spec.ROLES:
            self.ports[role] = io.network.free_port(set(self.ports.values()))
            for worker in spec.WORKERS[role]:
                self.http[str(worker)] = HTTPProxy(f'{role}-{worker}', self.ports[role], self.trace, self.tokens)
        for role in spec.ROLES:
            self.start_service(role, spec.WORKERS[role][0])
        for role in spec.ROLES:
            self.start_sdk(role)
        self.call('C', 'prepare-original-sql', 'prepare_sql', specs=self.specs)

    def start_service(self, role, worker):
        assert role not in self.services and worker in spec.WORKERS[role]
        self.service_incarnations[role] = self.service_incarnations.get(role, 0) + 1
        incarnation = self.service_incarnations[role]
        cache = self.private / f'cache-{role}-{incarnation}'
        cache.mkdir(mode=0o700)
        configuration = spec.configuration(self.ports[role], cache, self.proxies[role].endpoint,
            {principal: io.sha(token.encode()) for principal, token in self.tokens.items()}, worker, role)
        path = self.private / f'service-{role}-{incarnation}.json'
        io.save(path, io.encoded(configuration))
        io.save(self.evidence / path.name, io.encoded(configuration))
        environment = dict(os.environ, SCAP_OWNER_ACCESS=self.backend.access,
            SCAP_OWNER_SECRET=self.backend.secret, SCAP_OWNER_GC_ACCESS=self.gc_access,
            SCAP_OWNER_GC_SECRET=self.gc_secret)
        child = self.child([str(self.args.server), str(path)], f'service-{role}-{incarnation}',
                           environment=environment)
        self.services[role], self.workers[role] = (child, cache), str(worker)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', self.ports[role], timeout=.5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read(4097)) == {'status': 'alive', 'protocol': 1}:
                    self.trace.emit('service_ready', role=role, incarnation=incarnation, worker=str(worker), id=child.id)
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('original service readiness deadline')

    def start_sdk(self, role):
        assert role not in self.clients
        self.sdk_incarnations[role] = self.sdk_incarnations.get(role, 0) + 1
        incarnation = self.sdk_incarnations[role]
        name = f'{role}-{incarnation}'
        config = self.private / f'client-{name}.private.json'
        endpoints = {worker: proxy.endpoint for worker, proxy in self.http.items()}
        io.save(config, io.encoded({'endpoint': endpoints[self.workers[role]], 'tokens': self.tokens,
            'scopes': spec.SCOPES, 'source_root': str(io.ROOT), 'timeouts': spec.TIMEOUTS,
            'workerEndpoints': endpoints, 'routes': [
                {'workerInstance': worker, 'endpoint': endpoint + '/v1'} for worker, endpoint in endpoints.items()]}))
        client = self.child([str(self.node), str(io.HERE / 'client.mjs'), str(config),
                             str(self.evidence), name], 'sdk-' + name, interactive=True)
        assert client.read() == {'ready': True}
        self.clients[role], self.responses[role] = client, {}

    def stop_sdk(self, role):
        assert not self.responses[role]
        self.clients.pop(role).close()

    def restart_sdk(self, role, label):
        self.trace.emit('controller_restart_started', role=role, label=label)
        self.stop_sdk(role)
        self.start_sdk(role)
        self.trace.emit('controller_restart_finished', role=role, label=label)

    def stop_service(self, role, crash=False):
        child, cache = self.services.pop(role)
        child.close(crash)
        existed = cache.exists()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', role=role, service=child.id, path=str(cache),
                        existed=existed, absent=not cache.exists())

    def begin(self, role, identifier, operation, scope_name='bulk', **fields):
        self.trace.emit('sdk_dispatch', role=role, sdk=self.clients[role].id,
                        id=identifier, operation=operation, scope_name=scope_name)
        self.clients[role].send({'id': identifier, 'operation': operation,
                                'scope_name': scope_name, **fields})

    def finish(self, role, identifier, expect='ok', seconds=310):
        deadline = time.monotonic() + seconds
        while identifier not in self.responses[role]:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'original SDK response deadline'
            result = self.clients[role].read(remaining)
            assert result['id'] not in self.responses[role], 'duplicate original response'
            self.responses[role][result['id']] = result
        result = self.responses[role].pop(identifier)
        if expect == 'ok':
            assert result['ok'], (identifier, result)
            return result['value']
        assert not result['ok'], (identifier, result)
        assert result['error']['code'] == expect, (identifier, result)
        return result['error']

    def call(self, role, identifier, operation, scope_name='bulk', expect='ok', **fields):
        self.begin(role, identifier, operation, scope_name, **fields)
        return self.finish(role, identifier, expect)

    def phase(self, name):
        self.trace.emit('scenario_phase', label=name)
        for proxy in (*self.proxies.values(), *self.http.values()):
            proxy.phase_to(name)

    def status(self, name, label, role='C', principal='11'):
        return self.call(role, label, 'status', name, principal=principal)

    def owner(self, method, name, label=None, expect='ok', **fields):
        scope_name = name.rsplit('-p', 1)[0] if name in self.plans else self.saved[name]['scope_name']
        return self.call('C', label or name + '-' + method, 'owner_' + method, scope_name,
                         expect=expect, intent=name, **fields)

    def owner_begin(self, method, name, label, **fields):
        self.begin('C', label, 'owner_' + method, self.saved[name]['scope_name'], intent=name, **fields)

    def save_plan(self, record, head, label=None):
        name = record['name']
        assert name not in self.saved
        original = {key: record[key] for key in ('creator', 'operation', 'mode', 'target_worker', 'nonces')}
        original = {'creator': original['creator'], 'operation': original['operation'],
            'expected_revision': str(head['revision']), 'expected_head_serial': str(head['head_serial']),
            'mode': original['mode'], 'target_worker': original['target_worker'], 'nonces': original['nonces']}
        saved = self.call('C', label or name + '-save', 'owner_save', record['scope_name'],
                          intent=name, input=original, principal=record['creator'])
        self.saved[name] = {'scope_name': record['scope_name'], 'input': original, 'saved': saved}
        return name

    def new_plan(self, scope_name, ordinal, head=None):
        record = self.plans[f'{scope_name}-p{ordinal}']
        if head is None:
            head = self.status(scope_name, record['name'] + '-base')
        return self.save_plan(record, head)

    def save_variant(self, original, variant, head):
        old = self.saved[original]
        record = {'name': variant, 'scope_name': old['scope_name'], **old['input']}
        return self.save_plan(record, head)

    def prepare_claim_resume(self, name, principal='11'):
        prepared = self.owner('prepare', name, principal=principal)
        assert prepared['state'] == 'prepared'
        claimed = self.owner('claim', name, principal=principal)
        assert claimed['state'] == 'claimed'
        active = self.owner('resume', name, principal=principal)
        assert active['state'] == 'active'
        return active

    def policy(self, name, label, admin11=True, read11=True, write11=True, principal='11', head=None):
        if head is None:
            head = self.status(name, label + '-status', principal=principal)
        return self.call('C', label, 'policy', name, principal=principal,
            input={'expectedRevision': head['revision'], 'nonce': self.next_nonce(), 'permissions': [
                {'principal': '11', 'read': read11, 'write': write11, 'admin': admin11},
                {'principal': '12', 'read': True, 'write': True, 'admin': True}]})

    def legacy_activate(self, name, role, label):
        head = self.status(name, label + '-status', role)
        if head['owner_instance'] != self.workers[role]:
            head = self.call(role, label + '-takeover', 'takeover', name, input={
                'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
                'expectedWorkerInstance': self.workers[role]})
        return self.call(role, label + '-activate', 'activate', name, input={
            'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
            'expectedWorkerInstance': self.workers[role]})

    def named(self, label, name, action, role='C', expect='ok', **fields):
        return self.call(role, label, 'named', name, intent=label, input=action, expect=expect, **fields)

    def create_named(self, name, role='A'):
        original = spec.creation(name)
        prepared = self.named(name + '-prepare-create', name, {'operation': 'prepare_create',
            'name': original['name'], 'create_operation': original['operation'],
            'expected_name_revision': original['expected_name_revision'],
            'options': {'quota': {'mode': 'limited', 'max_bytes': '67108864'}}}, role)
        assert prepared['creation'] == original
        resumed = self.named(name + '-resume-create', name, {'operation': 'resume_create', 'creation': original}, role)
        assert resumed['phase'] == 'ready'

    def record_original(self, name, value):
        assert name not in self.originals and value['state'] == 'committed'
        self.originals[name] = {'receipt': value['receipt'], 'result': value['result']}
        self.trace.emit('original_ack', name=name, receipt=value['receipt'], result=value['result'])

    def seed_small(self, name, role='A'):
        if name in spec.NAMED:
            self.create_named(name, role)
        else:
            self.call(role, name + '-create', 'create', name, input={'nonce': self.next_nonce()})
        self.legacy_activate(name, role, name + '-initial')
        for counter in (1, 2):
            original = f'{name}-{counter:03d}'
            value = self.call(role, 'execute-' + original, 'execute', name, intent=original)
            self.record_original(original, value)
        self.policy(name, name + '-initial-acl')

    def seed_bulk(self):
        self.phase('native-three-retained-windows')
        cache = self.private / 'native-seed-cache'
        cache.mkdir(mode=0o700)
        configuration = {'endpoint': self.proxies['seed'].endpoint, 'region': 'us-east-1',
            'bucket': 'scap-test', 'access_key': self.backend.access, 'secret_key': self.backend.secret,
            'scope': {key: int(value) for key, value in spec.SCOPES['bulk'].items()},
            'worker': spec.NATIVE_WORKER, 'principal': 11, 'provision': True,
            'cache_root': str(cache), 'fixture_limits': spec.LIMITS, 'resource_log': None}
        path = self.private / 'native-seed.private.json'
        io.save(path, io.encoded(configuration))
        io.save(self.evidence / 'native-seed-config.json', io.encoded({
            key: value for key, value in configuration.items() if key not in ('access_key', 'secret_key')}))
        worker = self.child([str(self.args.worker), str(path)], 'native-seed', interactive=True)
        assert worker.read()['ready'] is True

        def command(value):
            worker.send(value)
            result = worker.read()
            assert result['ok'] is True, (value, result)
            return result['value']

        head = command({'op': 'create', 'nonce': int(self.next_nonce())})
        command({'op': 'activate_session', 'revision': head['revision'],
                 'nonce': int(self.next_nonce()), 'directory': 'native'})
        for original in self.specs:
            if original['scope_name'] != 'bulk' or original['purpose'] != 'seed':
                continue
            answer = command({'op': 'session_execute', 'epoch': int(original['epoch']),
                'id': int(original['request_id']), 'budget_ms': 8000,
                'statements': [{'sql': row['sql'], 'parameters': []} for row in original['statements']]})
            raw = bytes(answer['result']['encoded'])
            self.originals[original['name']] = {'receipt': answer['receipt'], 'result': self.trace.raw(raw)}
            self.trace.emit('native_original_ack', name=original['name'], receipt=answer['receipt'], result=self.trace.raw(raw))
            if original['counter'] in (129, 258):
                head = command({'op': 'status'})
                closed = command({'op': 'close_full', 'revision': head['revision'], 'nonce': int(self.next_nonce())})
                self.trace.emit('window_closed', counter=original['counter'], head=closed)
                command({'op': 'session_close'})
                command({'op': 'session_open', 'directory': 'native'})
        cancelled = self.sql['bulk-cancel']
        observed = command({'op': 'cancel', 'epoch': 3, 'id': 3,
            'statements': [{'sql': row['sql'], 'parameters': []} for row in cancelled['statements']]})
        self.trace.emit('original_cancel', value=observed)
        self.trace.emit('seed_completed', scope_name='bulk', head=command({'op': 'status'}))
        command({'op': 'session_close'})
        worker.close()
        shutil.rmtree(cache)
        self.trace.emit('native_cache_removed', path=str(cache), absent=not cache.exists())
        self.legacy_activate('bulk', 'A', 'bulk-initial')
        self.policy('bulk', 'bulk-initial-acl')

    def extra_sql(self, name):
        original = name + '-003'
        value = self.call('B', 'execute-' + original, 'execute', name, intent=original)
        self.record_original(original, value)

    def sweep_named_old(self):
        name, after = 'named_old', None
        self.trace.emit('sweep_round_started', scope_name=name, generation=1, label='named-terminal', after=None)
        for page in range(spec.MAX_SWEEP_PAGES):
            label = f'named-terminal-{page}'
            head = self.named(label + '-storage', name, {'operation': 'named_storage_status', 'creation': spec.creation(name)})
            prepared = self.call('C', label + '-prepare', 'gc_prepare', name, input={
                'expectedHeadSerial': head['head_serial'], 'generation': '1', 'after': after})
            batch = prepared['status']['storage']['sweep']
            if batch is not None:
                self.call('C', label + '-resume', 'gc_resume', name, input={'batchSerial': batch['serial']})
            self.trace.emit('sweep_page_finished', label='named-terminal', page=page, report=prepared)
            if prepared['exhausted']:
                self.trace.emit('sweep_round_finished', label='named-terminal', pages=page + 1)
                return
            assert prepared['next_after'] is not None and (after is None or after < prepared['next_after'])
            after = prepared['next_after']
        raise AssertionError('fixed sweep page budget')

    def cleanup(self, successful):
        failures = []
        if not successful:
            for proxy in (*self.proxies.values(), *self.http.values()):
                for gate in proxy.gates:
                    if not gate.finished.is_set():
                        gate.aborted = True
                        gate.released.set()
        for child in reversed(self.children):
            try:
                child.close(crash=not successful)
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
                for name in ('master', 'volume', 'filer', 's3'):
                    self.trace.emit('backend_log', role=name,
                        raw=self.trace.raw((self.backend.directory / (name + '.private.log')).read_bytes()))
            except BaseException as error:
                failures.append(repr(error))
        self.trace.emit('cleanup_finished', errors=failures)
        return failures

    def verify_source(self):
        current = self.source_module.capture(io.ROOT)
        assert current == self.original_source, 'frozen fixture changed during actual'
        io.service_build.verify(self.args.build_record, self.args.server)
        io.seed_build.verify(self.args.seed_build_record, self.args.worker)
        self.trace.emit('source_verified', commit=current['commit'], source_sha256=current['source_sha256'])
