"""Owned formal service/SDK/backend assembly and explicit public calls only."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import tarfile
import time
from types import SimpleNamespace

import spec
import support as io


class Harness:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.trace = io.Trace(evidence)
        self.backend = None
        self.proxies, self.services, self.clients, self.children = {}, {}, {}, []
        self.ports, self.workers, self.incarnations = {}, {}, {}
        self.tokens = {principal: secrets.token_hex(32) for principal in ('11', '12')}
        self.gc_access, self.gc_secret = secrets.token_hex(32), secrets.token_hex(32)
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.specs, self.originals, self.nonce = spec.inputs(), {}, 80000

    def next_nonce(self):
        self.nonce += 1
        return str(self.nonce)

    def child(self, command, name, interactive=False, environment=None):
        value = io.Child(command, io.ROOT, environment or os.environ.copy(), self.trace,
                         name, self.private, interactive)
        self.children.append(value)
        return value

    def setup(self):
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(key, '')
                       for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        self.source_module = io.module('terminal_source_manifest', io.ROOT / 'scripts/source_manifest.py')
        self.original_source = self.source_module.capture(io.ROOT)
        io.save(self.evidence / 'source.json', io.encoded(self.original_source))
        receipt = io.service_build.verify(self.args.build_record, self.args.server)
        source = {row['path']: row['sha256'] for row in self.original_source['files']}
        assert all(source.get(name) == digest for name, digest in receipt['inputs'].items())
        build = self.evidence / 'service-build'
        build.mkdir()
        io.service_build.capture_receipt(self.args.build_record, self.args.server, build)
        with tarfile.open(self.evidence / 'source.tar', 'w') as archive:
            for row in self.original_source['files']:
                archive.add(io.ROOT / row['path'], arcname=row['path'], recursive=False)
        tools = {name: {'path': str(path.resolve()), 'sha256': io.service_build.digest(path)}
                 for name, path in (('node', self.node), ('weed', self.args.weed), ('scapd', self.args.server))}
        for name, path, option in (('node', self.node, '--version'), ('weed', self.args.weed, 'version')):
            child = self.child([str(path), option], name + '-version')
            status, usage = io.network.wait_child(child.process, 10)
            self.trace.emit('child_stopped', id=child.id, identity=child.identity, status=status,
                            usage=usage, crash=False, forced=False, stderr=self.trace.raw(child.log.read_bytes()))
            assert status == 0
            assert (child.log.read_bytes().strip() == b'v22.16.0' if name == 'node'
                    else io.network.VERSION in child.log.read_text())
        io.save(self.evidence / 'inputs.json', io.encoded({
            'schema': 1, 'fixture_source_root': str(io.ROOT), 'commit': self.original_source['commit'],
            'runtime_source_commit': receipt['source_commit'], 'runtime_source_root': receipt['source_root'],
            'source_sha256': self.original_source['source_sha256'],
            'source_archive_sha256': io.sha((self.evidence / 'source.tar').read_bytes()),
            'plan_sha256': source['experiments/object-terminal-retirement-runtime/PLAN.md'],
            'tools': tools, 'scopes': spec.SCOPES, 'named': {name: spec.creation(name) for name in spec.NAMED},
            'specs': self.specs, 'timeouts': spec.TIMEOUTS, 'max_sweep_pages': spec.MAX_SWEEP_PAGES,
            'seed_sql_count': 20, 'committed_delayed_sql_count': 1, 'unknown_sql_count': 2,
            'lookup_core_deadline': 'unchanged service deadline; no Options clamp',
            'operator_scope_names': ['stale', 'bad_sweep'],
        }))
        self.backend = io.network.Backend(self.args.weed, self.private / 'backend',
                                          volume_size_mib=128, max_volumes=4)
        identities = json.loads(self.backend.identity.read_text())
        identities['identities'].append({'name': 'explicit-terminal-gc-capability',
            'credentials': [{'accessKey': self.gc_access, 'secretKey': self.gc_secret}],
            'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging']})
        self.backend.identity.write_text(json.dumps(identities))
        self.backend.start()
        self.trace.emit('backend_started', identities=self.backend.identities(), binary=tools['weed'],
                        capacity=self.backend.capacity, normal_access_sha256=io.sha(self.backend.access.encode()),
                        gc_access_sha256=io.sha(self.gc_access.encode()))
        connection = http.client.HTTPConnection('127.0.0.1', self.backend.port, timeout=5)
        try:
            connection.request('GET', '/scap-test/fixture-ready')
            response = connection.getresponse()
            body = response.read(65537)
            self.trace.emit('unsigned_probe', status=response.status, response=self.trace.raw(body))
            assert response.status == 403 and len(body) <= 65536
        finally:
            connection.close()
        credentials = {self.backend.access: self.backend.secret, self.gc_access: self.gc_secret}
        for role in (*spec.ROLES, 'O'):
            self.proxies[role] = io.Proxy(self.backend, role, self.trace, credentials)
        for index, role in enumerate(spec.ROLES):
            self.ports[role] = io.network.free_port(set(self.ports.values()))
            self.start_service(role, 8101 + index)
        self.call('A', 'prepare-original-sql', 'prepare', specs=self.specs)

    def start_service(self, role, worker):
        assert role not in self.services
        self.incarnations[role] = self.incarnations.get(role, 0) + 1
        incarnation = self.incarnations[role]
        cache = self.private / f'cache-{role}-{incarnation}'
        cache.mkdir(mode=0o700)
        configuration = spec.configuration(self.ports[role], cache, self.proxies[role].endpoint,
            {key: io.sha(value.encode()) for key, value in self.tokens.items()}, worker, role)
        path = self.private / f'service-{role}-{incarnation}.json'
        io.save(path, io.encoded(configuration))
        io.save(self.evidence / path.name, io.encoded(configuration))
        environment = dict(os.environ, SCAP_TERMINAL_ACCESS=self.backend.access,
            SCAP_TERMINAL_SECRET=self.backend.secret, SCAP_TERMINAL_GC_ACCESS=self.gc_access,
            SCAP_TERMINAL_GC_SECRET=self.gc_secret)
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
        if role not in self.clients:
            config = self.private / f'client-{role}.private.json'
            io.save(config, io.encoded({'endpoint': f'http://127.0.0.1:{self.ports[role]}',
                'tokens': self.tokens, 'scopes': spec.SCOPES, 'source_root': str(io.ROOT)}))
            client = self.child([str(self.node), str(io.HERE / 'client.mjs'), str(config),
                str(self.evidence), role], 'sdk-' + role, interactive=True)
            assert client.read() == {'ready': True}
            self.clients[role] = client

    def stop_service(self, role, crash=False):
        child, cache = self.services.pop(role)
        child.close(crash)
        existed = cache.exists()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', role=role, service=child.id, path=str(cache),
                        existed=existed, absent=not cache.exists())

    def restart_b(self, label):
        self.trace.emit('maintenance_restart_started', label=label)
        self.stop_service('B', crash=True)
        self.start_service('B', int(self.workers['B']) + 100)
        self.trace.emit('maintenance_restart_finished', label=label)

    def begin(self, role, identifier, operation, scope_name='late', **fields):
        self.trace.emit('sdk_dispatch', role=role, id=identifier, operation=operation, scope_name=scope_name)
        self.clients[role].send({'id': identifier, 'operation': operation, 'scope_name': scope_name, **fields})

    def finish(self, role, identifier, expect='ok', seconds=310):
        result = self.clients[role].read(seconds)
        assert result['id'] == identifier, ('original-command', result)
        if expect == 'ok':
            assert result['ok'], (identifier, result)
            return result['value']
        assert not result['ok'], (identifier, result)
        if expect != 'error':
            assert result['error']['code'] == expect, (identifier, result)
        return result['error']

    def call(self, role, identifier, operation, scope_name='late', expect='ok', **fields):
        self.begin(role, identifier, operation, scope_name, **fields)
        return self.finish(role, identifier, expect)

    def named(self, role, identifier, name, action, expect='ok', **fields):
        return self.call(role, identifier, 'named', name, expect=expect, intent=identifier, input=action, **fields)

    def named_begin(self, role, identifier, name, action, **fields):
        self.begin(role, identifier, 'named', name, intent=identifier, input=action, **fields)

    def phase(self, name):
        self.trace.emit('scenario_phase', label=name)
        for proxy in self.proxies.values():
            proxy.phase_to(name)

    def status(self, name, label, role='B', deleted=False):
        if deleted and name in spec.NAMED:
            return self.named(role, label, name, {'operation': 'named_storage_status', 'creation': spec.creation(name)})
        return self.call(role, label, 'storage_status' if deleted else 'status', name)

    def seal(self, name, label, role='C'):
        head = self.status(name, label + '-status', 'B', deleted=True)
        if name in spec.NAMED:
            return self.named(role, label, name, {'operation': 'retire_named_storage',
                'creation': spec.creation(name), 'expected_head_serial': head['head_serial']})
        return self.call(role, label, 'retire_storage', name, input={'expectedHeadSerial': head['head_serial']})

    def activate(self, name, label, role):
        head = self.status(name, label + '-status', role)
        if head['owner_instance'] != self.workers[role]:
            head = self.call(role, label + '-takeover', 'takeover', name, input={
                'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
                'expectedWorkerInstance': self.workers[role]})
        return self.call(role, label + '-activate', 'activate', name, input={
            'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
            'expectedWorkerInstance': self.workers[role]})

    def create_direct(self, name, role='A'):
        return self.call(role, name + '-create', 'create', name, input={'nonce': self.next_nonce()})

    def prepare_name(self, name, role='A'):
        original = spec.creation(name)
        result = self.named(role, name + '-prepare', name, {'operation': 'prepare_create',
            'name': original['name'], 'create_operation': original['operation'],
            'expected_name_revision': original['expected_name_revision'],
            'options': {'quota': {'mode': 'limited', 'max_bytes': '67108864'}}})
        assert result['creation'] == original
        return result

    def create_name(self, name, role='A'):
        self.prepare_name(name, role)
        result = self.named(role, name + '-resume', name,
            {'operation': 'resume_create', 'creation': spec.creation(name)})
        assert result['phase'] == 'ready'
        return result

    def seed(self, name, role='A'):
        self.activate(name, name + '-seed', role)
        for counter in (1, 2):
            original = name + '-' + str(counter)
            value = self.call(role, 'execute-' + original, 'execute', name, intent=original)
            self.record_original(original, value)

    def record_original(self, name, value):
        assert name not in self.originals and value['state'] == 'committed'
        self.originals[name] = {'receipt': value['receipt'], 'result': value['result']}
        self.trace.emit('original_ack', name=name, receipt=value['receipt'], result=value['result'])

    def delete_direct(self, name, label):
        head = self.status(name, label + '-status')
        return self.call('B', label, 'lifecycle', name, input={'expectedRevision': head['revision'],
            'nonce': self.next_nonce(), 'lifecycle': 'deleted'})

    def abort_copy(self, name, label):
        head = self.status(name, label + '-status')
        begun = self.call('B', label + '-begin', 'compact_begin', name,
                         input={'expectedHeadSerial': head['head_serial']})
        serial = begun['storage']['plan']['serial']
        self.call('B', label + '-copy', 'compact_copy', name, input={'planSerial': serial})
        self.call('B', label + '-abort', 'compact_abort', name, input={'planSerial': serial})
        self.activate(name, label + '-reactivate', 'A')

    def prepare_gc(self, name, generation, label, after=None):
        head = self.status(name, label + '-status', deleted=True)
        return self.call('B', label + '-prepare', 'gc_prepare', name, input={
            'expectedHeadSerial': head['head_serial'], 'generation': str(generation), 'after': after})

    def resume_gc(self, name, prepared, label):
        batch = prepared['status']['storage']['sweep']
        assert batch is not None
        return self.call('B', label, 'gc_resume', name, input={'batchSerial': batch['serial']})

    def sweep(self, name, generation, label):
        self.trace.emit('sweep_round_started', scope_name=name, generation=generation, label=label, after=None)
        after = None
        for page in range(spec.MAX_SWEEP_PAGES):
            prepared = self.prepare_gc(name, generation, f'{label}-{page}', after)
            if prepared['status']['storage']['sweep'] is not None:
                self.resume_gc(name, prepared, f'{label}-{page}-resume')
            self.trace.emit('sweep_page_finished', label=label, page=page, report=prepared)
            if prepared['exhausted']:
                self.trace.emit('sweep_round_finished', label=label, pages=page + 1)
                return
            assert prepared['next_after'] is not None and (after is None or after < prepared['next_after'])
            after = prepared['next_after']
        raise AssertionError('fixed sweep page budget')

    def corrupt_only(self, name, label, mutation):
        assert name in ('stale', 'bad_sweep')
        proxy = self.proxies['O']
        backend = SimpleNamespace(port=proxy.server.server_port, access=self.backend.access, secret=self.backend.secret)
        before = io.signing.signed_request(backend, 'GET', spec.head_path(name))
        assert before['status'] == 200
        raw = io.signing.body_value(before['body'])
        value = json.loads(raw)
        if name == 'stale':
            assert set(mutation) == {'terminal_serial'}
            assert value['storage']['sweep'] is None
            assert value['revision'] < mutation['terminal_serial'] < value['head_serial']
            value['storage']['terminal']['serial'] = mutation['terminal_serial']
        else:
            assert mutation == {'sweep_serial': 'terminal_serial'}
            assert value['storage']['sweep'] is not None
            value['storage']['sweep']['serial'] = value['storage']['terminal']['serial']
        changed = json.dumps(value, separators=(',', ':')).encode()
        self.trace.emit('explicit_bad_authority', scope_name=name, label=label, mutation=mutation,
                        before=self.trace.raw(raw), after=self.trace.raw(changed))
        result = io.signing.signed_request(backend, 'PUT', spec.head_path(name), changed,
            {'if-match': io.signing.header(before, 'etag'), 'content-type': 'application/json'})
        assert result['status'] == 200
        actual = io.signing.signed_request(backend, 'GET', spec.head_path(name))
        assert actual['status'] == 200 and io.signing.body_value(actual['body']) == changed

    def verify_source(self):
        current = self.source_module.capture(io.ROOT)
        assert current == self.original_source
        io.service_build.verify(self.args.build_record, self.args.server)
        self.trace.emit('source_verified', commit=current['commit'], source_sha256=current['source_sha256'])

    def cleanup(self, successful):
        failures = []
        if not successful:
            for proxy in self.proxies.values():
                for gate in proxy.gates:
                    if not gate.finished.is_set():
                        gate.aborted = True
                        gate.released.set()
        for child in reversed(self.children):
            try:
                child.close(crash=not successful)
            except BaseException as error:
                failures.append(repr(error))
        for proxy in self.proxies.values():
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
