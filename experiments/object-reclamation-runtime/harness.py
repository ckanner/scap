"""Real process assembly and explicit operations for the fixed GC experiment."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import tarfile
import time
from urllib.parse import quote
import xml.etree.ElementTree as ET

import spec
import support as io


class Harness:
    def __init__(self, args, evidence, private):
        self.args, self.evidence, self.private = args, evidence, private
        self.trace = io.Trace(evidence)
        self.backend = None
        self.proxies, self.children, self.services, self.clients = {}, [], {}, {}
        self.ports, self.workers, self.incarnations = {}, {}, {}
        self.nonce, self.ordinal = 70000, 0
        self.token, self.gc_access, self.gc_secret = (secrets.token_hex(32) for _ in range(3))
        self.node = Path(shutil.which(args.node) or args.node).resolve()
        self.specs = spec.inputs()
        self.by_name = {row['name']: row for row in self.specs}
        self.originals = {}

    def next_nonce(self):
        self.nonce += 1
        return str(self.nonce)

    def start_child(self, command, name, interactive=False, environment=None):
        child = io.Child(command, io.ROOT, environment or os.environ.copy(),
                         self.trace, name, self.private, interactive)
        self.children.append(child)
        return child

    def setup(self):
        assert 'LLVM_PROFILE_FILE' not in os.environ and 'NODE_V8_COVERAGE' not in os.environ
        assert not any('instrument-coverage' in os.environ.get(k, '')
                       for k in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'))
        source = io.module('reclamation_source_manifest', io.ROOT / 'scripts/source_manifest.py')
        self.source_module = source
        self.original_source = source.capture(io.ROOT)
        io.save(self.evidence / 'source.json', io.encoded(self.original_source))
        service = io.service_build.verify(self.args.build_record, self.args.server)
        seed = io.seed_build.verify(self.args.seed_build_record, self.args.worker)
        assert service['source_commit'] == seed['source_commit']
        committed = {row['path']: row['sha256'] for row in self.original_source['files']}
        assert all(committed.get(name) == digest for record in (service, seed)
                   for name, digest in record['inputs'].items())
        for name, module, record, binary in (
                ('service-build', io.service_build, self.args.build_record, self.args.server),
                ('seed-build', io.seed_build, self.args.seed_build_record, self.args.worker)):
            directory = self.evidence / name
            directory.mkdir()
            module.capture_receipt(record, binary, directory)
        with tarfile.open(self.evidence / 'source.tar', 'w') as archive:
            for row in self.original_source['files']:
                archive.add(io.ROOT / row['path'], arcname=row['path'], recursive=False)
        tools = {name: {'path': str(path.resolve()), 'sha256': io.service_build.digest(path)}
                 for name, path in (('node', self.node), ('weed', self.args.weed),
                                    ('scapd', self.args.server), ('native-seed', self.args.worker))}
        for name, path, argument in (('node', self.node, '--version'), ('weed', self.args.weed, 'version')):
            child = self.start_child([str(path), argument], name + '-version')
            status, usage = io.network.wait_child(child.process, 10)
            self.trace.emit('child_stopped', id=child.id, identity=child.identity,
                            status=status, usage=usage, crash=False, forced=False,
                            stderr=self.trace.raw(child.log.read_bytes()))
            assert status == 0
            if name == 'node':
                assert child.log.read_bytes().strip() == b'v22.16.0'
            else:
                assert io.network.VERSION in child.log.read_text()
        io.save(self.evidence / 'inputs.json', io.encoded({
            'schema': 1, 'fixture_source_root': str(io.ROOT), 'commit': self.original_source['commit'],
            'runtime_source_commit': service['source_commit'],
            'runtime_source_root': service['source_root'],
            'seed_source_root': seed['source_root'],
            'source_sha256': self.original_source['source_sha256'],
            'source_archive_sha256': io.sha((self.evidence / 'source.tar').read_bytes()),
            'plan_sha256': io.sha((io.HERE / 'PLAN.md').read_bytes()),
            'tools': tools, 'scopes': spec.SCOPES, 'limits': spec.LIMITS,
            'specs': self.specs, 'max_sweep_pages': spec.MAX_SWEEP_PAGES,
            'http_timeout_ms': 120000, 'sdk_timeout_ms': 90000,
            's3_timeout_ms': 120000, 'reader_observation_bound_ms': 30000,
            'lookup_core_deadline': 'unchanged deadline supplied by service; no Options clamp',
            'whole_fixture_timeout_seconds': 1200,
        }))
        self.backend = io.network.Backend(self.args.weed, self.private / 'backend',
                                           volume_size_mib=128, max_volumes=4)
        identity = json.loads(self.backend.identity.read_text())
        identity['identities'].append({'name': 'explicit-reclamation-capability',
            'credentials': [{'accessKey': self.gc_access, 'secretKey': self.gc_secret}],
            'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging']})
        self.backend.identity.write_text(json.dumps(identity))
        self.backend.start()
        self.trace.emit('backend_started', identities=self.backend.identities(),
                        binary=tools['weed'], capacity=self.backend.capacity,
                        normal_access_sha256=io.sha(self.backend.access.encode()),
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
        for role in ('seed', 'A', 'B', 'R'):
            self.proxies[role] = io.Proxy(self.backend, role, self.trace, credentials)
        for role, worker in (('A', 5101), ('B', 5102), ('R', 5103)):
            self.ports[role] = io.network.free_port(set(self.ports.values()))
            self.start_service(role, worker)
        self.call('A', 'prepare-inputs', 'prepare', specs=self.specs)

    def start_service(self, role, worker):
        assert role not in self.services
        self.incarnations[role] = self.incarnations.get(role, 0) + 1
        generation = self.incarnations[role]
        cache = self.private / f'cache-{role}-{generation}'
        cache.mkdir(mode=0o700)
        config = spec.configuration(self.ports[role], cache, self.proxies[role].endpoint,
                                    io.sha(self.token.encode()), worker, role == 'B')
        path = self.private / f'service-{role}-{generation}.json'
        io.save(path, io.encoded(config))
        io.save(self.evidence / path.name, io.encoded(config))
        env = dict(os.environ, SCAP_RECLAIM_ACCESS=self.backend.access,
                   SCAP_RECLAIM_SECRET=self.backend.secret,
                   SCAP_RECLAIM_GC_ACCESS=self.gc_access, SCAP_RECLAIM_GC_SECRET=self.gc_secret)
        child = self.start_child([str(self.args.server), str(path)], f'service-{role}-{generation}',
                                 environment=env)
        self.services[role] = (child, cache)
        self.workers[role] = str(worker)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', self.ports[role], timeout=.5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read(4097)) == {'status': 'alive', 'protocol': 1}:
                    self.trace.emit('service_ready', role=role, incarnation=generation,
                                    worker=str(worker), id=child.id)
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        else:
            raise TimeoutError('service readiness original deadline')
        if role not in self.clients:
            client_config = self.private / ('client-' + role + '.private.json')
            io.save(client_config, io.encoded({'endpoint': f'http://127.0.0.1:{self.ports[role]}',
                'token': self.token, 'scopes': spec.SCOPES, 'source_root': str(io.ROOT)}))
            client = self.start_child([str(self.node), str(io.HERE / 'client.mjs'),
                str(client_config), str(self.evidence), role], 'sdk-' + role, interactive=True)
            assert client.read() == {'ready': True}
            self.clients[role] = client

    def stop_service(self, role, crash=False):
        child, cache = self.services.pop(role)
        child.close(crash=crash)
        existed = cache.exists()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', role=role, service=child.id, path=str(cache),
                        existed=existed, absent=not cache.exists())

    def restart_b(self, label):
        self.trace.emit('maintenance_restart_started', label=label)
        old = int(self.workers['B'])
        self.stop_service('B', crash=True)
        self.start_service('B', old + 100)
        self.trace.emit('maintenance_restart_finished', label=label)

    def begin_call(self, role, identifier, operation, scope_name='main', **fields):
        assert role in self.clients
        self.trace.emit('sdk_dispatch', role=role, id=identifier, operation=operation, scope_name=scope_name)
        self.clients[role].send({'id': identifier, 'operation': operation,
                                'scope_name': scope_name, **fields})

    def finish_call(self, role, identifier, expect='ok', seconds=310):
        value = self.clients[role].read(seconds)
        assert value['id'] == identifier, 'wrong original SDK response'
        if expect == 'ok':
            assert value['ok'], (identifier, value)
            return value['value']
        assert not value['ok'], (identifier, value)
        if expect != 'error':
            assert value['error']['code'] == expect, (identifier, value)
        return value['error']

    def call(self, role, identifier, operation, scope_name='main', expect='ok', **fields):
        self.begin_call(role, identifier, operation, scope_name, **fields)
        return self.finish_call(role, identifier, expect)

    def phase(self, label):
        self.trace.emit('scenario_phase', label=label)
        for proxy in self.proxies.values():
            proxy.phase_to(label)

    def status(self, scope_name, label, role='B'):
        return self.call(role, label, 'status', scope_name)

    def activate(self, scope_name, label, role):
        head = self.status(scope_name, label + '-status', role)
        if head['owner_instance'] != self.workers[role]:
            head = self.call(role, label + '-takeover', 'takeover', scope_name,
                input={'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
                       'expectedWorkerInstance': self.workers[role]})
        return self.call(role, label + '-activate', 'activate', scope_name,
            input={'expectedRevision': head['revision'], 'nonce': self.next_nonce(),
                   'expectedWorkerInstance': self.workers[role]})

    def seed(self):
        self.phase('seed-native-originals')
        for offset, name in enumerate(spec.SCOPES):
            directory = self.private / ('seed-' + name)
            directory.mkdir(mode=0o700)
            config = {'endpoint': self.proxies['seed'].endpoint, 'region': 'us-east-1',
                'bucket': 'scap-test', 'access_key': self.backend.access, 'secret_key': self.backend.secret,
                'scope': {k: int(v) for k, v in spec.SCOPES[name].items()},
                'worker': 4001 + offset, 'principal': 11, 'provision': True,
                'cache_root': str(directory), 'fixture_limits': spec.LIMITS, 'resource_log': None}
            path = self.private / ('seed-' + name + '.private.json')
            io.save(path, io.encoded(config))
            public = {k: v for k, v in config.items() if k not in ('access_key', 'secret_key')}
            io.save(self.evidence / ('seed-' + name + '-config.json'), io.encoded(public))
            worker = self.start_child([str(self.args.worker), str(path)], 'seed-' + name, interactive=True)
            assert worker.read()['ready'] is True

            def command(value):
                worker.send(value)
                answer = worker.read()
                assert answer['ok'] is True, (value, answer)
                return answer['value']

            head = command({'op': 'create', 'nonce': int(self.next_nonce())})
            command({'op': 'activate_session', 'revision': head['revision'],
                     'nonce': int(self.next_nonce()), 'directory': 'native'})
            for original in self.specs:
                if original['scope_name'] != name or original['purpose'] != 'seed':
                    continue
                request = {'op': 'session_execute', 'epoch': int(original['epoch']),
                    'id': int(original['request_id']), 'budget_ms': 8000,
                    'statements': [{'sql': row['sql'], 'parameters': []}
                                   for row in original['statements']]}
                answer = command(request)
                raw = bytes(answer['result']['encoded'])
                self.originals[original['name']] = {'receipt': answer['receipt'], 'result': self.trace.raw(raw)}
                self.trace.emit('seed_ack', name=original['name'], scope_name=name,
                                receipt=answer['receipt'], result=self.trace.raw(raw))
                if name == 'main' and original['counter'] in (129, 258):
                    head = command({'op': 'status'})
                    closed = command({'op': 'close_full', 'revision': head['revision'],
                                      'nonce': int(self.next_nonce())})
                    self.trace.emit('window_closed', counter=original['counter'], head=closed)
                    command({'op': 'session_close'})
                    command({'op': 'session_open', 'directory': 'native'})
            if name == 'main':
                cancel = self.by_name['main-cancel']
                observed = command({'op': 'cancel', 'epoch': 3, 'id': 3,
                    'statements': [{'sql': row['sql'], 'parameters': []} for row in cancel['statements']]})
                self.trace.emit('original_cancel', value=observed)
            head = command({'op': 'status'})
            self.trace.emit('seed_completed', scope_name=name, head=head)
            command({'op': 'session_close'})
            worker.close()
            shutil.rmtree(directory)
            self.trace.emit('seed_cache_removed', scope_name=name, path=str(directory), absent=not directory.exists())
            self.activate(name, 'initial-' + name, 'A')
        io.save(self.evidence / 'original-results.json', io.encoded(self.originals))

    def prepare(self, scope_name, generation, label, after=None):
        head = self.status(scope_name, label + '-status')
        return self.call('B', label + '-prepare', 'gc_prepare', scope_name,
            input={'expectedHeadSerial': head['head_serial'], 'generation': str(generation), 'after': after})

    def resume(self, scope_name, prepared, label):
        sweep = prepared['status']['storage']['sweep']
        assert sweep is not None
        return self.call('B', label + '-resume', 'gc_resume', scope_name,
                         input={'batchSerial': sweep['serial']})

    def sweep(self, scope_name, generation, label):
        self.trace.emit('sweep_round_started', scope_name=scope_name, generation=generation, label=label, after=None)
        after = None
        for page in range(spec.MAX_SWEEP_PAGES):
            prepared = self.prepare(scope_name, generation, f'{label}-{page}', after)
            if prepared['status']['storage']['sweep'] is not None:
                self.resume(scope_name, prepared, f'{label}-{page}')
            self.trace.emit('sweep_page_finished', label=label, page=page, report=prepared)
            if prepared['exhausted']:
                self.trace.emit('sweep_round_finished', label=label, pages=page + 1)
                return
            assert prepared['next_after'] is not None and (after is None or after < prepared['next_after'])
            after = prepared['next_after']
        raise AssertionError('fixed sweep page budget exhausted')

    def compact(self, scope_name, label, policy=False, promote=True):
        head = self.status(scope_name, label + '-status')
        begun = self.call('B', label + '-begin', 'compact_begin', scope_name,
                         input={'expectedHeadSerial': head['head_serial']})
        serial = begun['storage']['plan']['serial']
        if policy:
            self.call('B', label + '-policy', 'policy', scope_name,
                input={'expectedRevision': begun['revision'], 'nonce': self.next_nonce(),
                       'permissions': [{'principal': '11', 'read': True, 'write': True, 'admin': True},
                                       {'principal': '12', 'read': True, 'write': False, 'admin': False}]})
        sealed = self.call('B', label + '-copy', 'compact_copy', scope_name, input={'planSerial': serial})
        if not promote:
            return sealed
        return self.call('B', label + '-promote', 'compact_promote', scope_name, input={'planSerial': serial})

    def operator(self, label, method, path, payload=b'', extra=None):
        # Only same-byte multipart recreation and exact independent observations.
        # This interface cannot mutate HEAD and never performs fixture DELETE.
        assert '/objects/' in path and not path.endswith('/HEAD')
        assert method in ('GET', 'POST', 'PUT')
        self.trace.emit('operator_request', id=label, method=method, path=path,
                        request=self.trace.raw(payload), headers=extra or {})
        result = io.signing.signed_request(self.backend, method, path, payload, extra)
        self.trace.emit('operator_response', id=label, status=result['status'],
                        headers={k.lower(): v for k, v in result['headers'].items()},
                        response=self.trace.raw(io.signing.body_value(result)))
        return result

    def multipart_recreate(self, key, original):
        assert len(original) < 1024 * 1024
        started = self.operator('multipart-create', 'POST', key + '?uploads')
        assert started['status'] == 200
        document = ET.fromstring(io.signing.body_value(started))
        upload = next(child.text for child in document.iter() if child.tag.rsplit('}', 1)[-1] == 'UploadId')
        suffix = 'uploadId=' + quote(upload, safe='')
        part = self.operator('multipart-part', 'PUT', key + '?partNumber=1&' + suffix, original)
        assert part['status'] == 200
        etag = io.signing.header(part, 'etag')
        xml = ('<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>' +
               etag + '</ETag></Part></CompleteMultipartUpload>').encode()
        completed = self.operator('multipart-complete', 'POST', key + '?' + suffix,
                                  xml, {'content-type': 'application/xml'})
        assert completed['status'] == 200
        actual = self.operator('multipart-readback', 'GET', key)
        assert actual['status'] == 200 and io.signing.body_value(actual) == original
        return io.signing.header(actual, 'etag')

    def cleanup(self, successful):
        failures = []
        # Release blocked transports first on failures so child draining is bounded.
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
                stopped = self.backend.stop()
                self.trace.emit('backend_stopped', processes=stopped)
                for name in ('master', 'volume', 'filer', 's3'):
                    path = self.backend.directory / (name + '.private.log')
                    self.trace.emit('backend_log', role=name, raw=self.trace.raw(path.read_bytes()))
            except BaseException as error:
                failures.append(repr(error))
        self.trace.emit('cleanup_finished', errors=failures)
        return failures

    def verify_source(self):
        current = self.source_module.capture(io.ROOT)
        assert current == self.original_source, 'frozen source changed during actual contract'
        io.service_build.verify(self.args.build_record, self.args.server)
        io.seed_build.verify(self.args.seed_build_record, self.args.worker)
        self.trace.emit('source_verified', commit=current['commit'], source_sha256=current['source_sha256'])
