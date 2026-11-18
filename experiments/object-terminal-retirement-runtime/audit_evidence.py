"""Independent source, owned-child, public HTTP, and closed S3 ledgers."""
from __future__ import annotations

from collections import defaultdict
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import tarfile
from urllib.parse import urlsplit

from audit_model import (Graph, Rejected, advance, catalogue, digest, envelope, head,
                         head_path, need, object_path, prefix, scope_key, sha, wire)


def rows(path):
    need(path.is_file(), 'ledger-present')
    value = path.read_bytes()
    need(value and value.endswith(b'\n'), 'ledger-complete-lines')
    return [wire.parse(line) for line in value.splitlines()]


def raw(directory, description):
    need(isinstance(description, dict) and set(description) == {'file', 'bytes', 'sha256'}, 'raw-description')
    name = digest(description['sha256'])
    need(description['file'] == 'raw/' + name and type(description['bytes']) is int
         and 0 <= description['bytes'] <= 67108864, 'raw-safe-path')
    path = directory / description['file']
    need(path.is_file() and not path.is_symlink(), 'raw-original-file')
    value = path.read_bytes()
    need(len(value) == description['bytes'] and sha(value) == name, 'raw-original-hash')
    return value


def moment(value):
    number = value['monotonic_ns']
    need(type(number) is int or isinstance(number, str) and number.isdecimal(), 'observation-clock')
    return int(number)


def select(values, event, **fields):
    return [row for row in values if row['event'] == event and all(row.get(key) == value for key, value in fields.items())]


def one(values, event, **fields):
    found = select(values, event, **fields)
    need(len(found) == 1, 'one-' + event)
    return found[0]


def archive(path, expected):
    with tarfile.open(path) as file:
        members = file.getmembers()
        need(len(members) == len(expected) and len({m.name for m in members}) == len(members), 'source-archive-denominator')
        for member in members:
            need(member.isfile() and member.name in expected, 'source-archive-member')
            need(sha(file.extractfile(member).read()) == expected[member.name], 'source-archive-bytes')


def identity(directory, inputs, events):
    source = wire.parse((directory / 'source.json').read_bytes())
    files = source['files']
    need(source['commit'] == inputs['commit'] and source['source_sha256'] == inputs['source_sha256']
         and sha(json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()) == source['source_sha256'], 'source-manifest')
    expected = {row['path']: row['sha256'] for row in files}
    need(len(expected) == len(files) and inputs['plan_sha256'] == expected['experiments/object-terminal-retirement-runtime/PLAN.md'], 'frozen-input-plan')
    need(sha((directory / 'source.tar').read_bytes()) == inputs['source_archive_sha256'], 'fixture-source-archive')
    archive(directory / 'source.tar', expected)
    with tarfile.open(directory / 'source.tar') as file:
        for row in files:
            value = file.extractfile(row['path']).read()
            need(len(value) == row['bytes'] and hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest() == row['git_blob'], 'committed-fixture-bytes')
    root = directory / 'service-build'
    receipt = wire.parse((root / 'build-receipt.json').read_bytes())
    need(receipt['status'] == 'passed' and receipt['exit_code'] == 0 and receipt['profile'] == 'release'
         and receipt['source_commit'] == inputs['runtime_source_commit'], 'original-release-build')
    need(receipt['binary'] == inputs['tools']['scapd'] and all(expected.get(key) == value for key, value in receipt['inputs'].items()),
         'release-input-equivalence')
    need(Path(receipt['binary']['path']).is_file() and sha(Path(receipt['binary']['path']).read_bytes()) == receipt['binary']['sha256'], 'actual-release-binary')
    need(receipt['native_archives'], 'native-sqlite-build-required')
    for name, digest_value in receipt['native_archives'].items():
        need(Path(name).is_file() and sha(Path(name).read_bytes()) == digest_value, 'actual-native-archive')
    evidence = receipt['archived_evidence']
    for name in ('source_archive', 'source_manifest'):
        need(sha((root / evidence[name]).read_bytes()) == evidence[name + '_sha256'], 'build-source-evidence')
    archive(root / evidence['source_archive'], receipt['inputs'])
    need(sha((root / 'build-cargo.stdout.jsonl').read_bytes()) == receipt['cargo.stdout.jsonl_sha256']
         and sha((root / 'build-cargo.stderr.log').read_bytes()) == receipt['cargo.stderr.log_sha256'], 'original-build-logs')
    cargo = rows(root / 'build-cargo.stdout.jsonl')
    need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'cargo-success-terminal')
    artifact = [row for row in cargo if row.get('reason') == 'compiler-artifact' and row.get('executable') == receipt['binary']['path']]
    need(len(artifact) == 1 and artifact[0]['profile']['opt_level'] == '3', 'release-artifact')
    after = one(events, 'source_verified')
    need(after['commit'] == source['commit'] and after['source_sha256'] == source['source_sha256'], 'source-after-unchanged')


def processes(directory, inputs, events):
    starts = {r['id']: r for r in select(events, 'child_started')}
    stops = {r['id']: r for r in select(events, 'child_stopped')}
    need(len(starts) == len(select(events, 'child_started')) and len(stops) == len(select(events, 'child_stopped'))
         and set(starts) == set(stops), 'owned-child-denominator')
    identities = set()
    for name, first in starts.items():
        last, identity_value = stops[name], first['identity']
        need(identity_value == last['identity'] and identity_value['pid_source'] == 'owned_Popen_child'
             and moment(first) < moment(last), 'owned-original-child')
        key = (identity_value['pid'], identity_value['spawn_monotonic_ns'])
        need(key not in identities, 'owned-child-incarnation')
        identities.add(key)
        need(last['forced'] is False and last['status'] == (-9 if last['crash'] else 0)
             and last['usage'].get('available') is True and last['usage'].get('source') == 'kernel_wait4_owned_child', 'owned-wait4')
        raw(directory, last['stderr'])
        tool = 'scapd' if name.startswith('service-') else 'weed' if name == 'weed-version' else 'node'
        need(first['executable_sha256'] == inputs['tools'][tool]['sha256'] and first['command'][0] == inputs['tools'][tool]['path'], 'owned-executable')
    ready = select(events, 'service_ready')
    services = [name for name in starts if name.startswith('service-')]
    need(len(services) == len(ready) == 11 and len({row['worker'] for row in ready}) == 11
         and len([name for name in starts if name.startswith('sdk-')]) == 4, 'fixed-process-denominator')
    configurations = {}
    for row in ready:
        value = wire.parse((directory / (row['id'] + '.json')).read_bytes())
        configurations[row['role']] = value
        need(value['worker_instance'] == row['worker'] and value['s3']['timeout_ms'] == 120000
             and value['admission']['timeout_ms'] == 120000 and value['catalogue']['timeout_ms'] == 120000
             and value['transport']['response_timeout_ms'] == 120000, 'original-server-budgets')
        need((value['gc'] is not None) == (row['role'] == 'B'), 'explicit-gc-capability')
        if value['gc'] is not None:
            need(value['gc']['access_key_env'] != value['s3']['access_key_env']
                 and value['gc']['secret_key_env'] != value['s3']['secret_key_env'], 'independent-gc-credentials')
        need([credential['principal'] for credential in value['credentials']] == ['11', '12'], 'fixed-principals')
        need(value['credentials'][0]['provision'] == (row['role'] in ('A', 'B'))
             and value['credentials'][1]['provision'] is False, 'seal-no-provision-credential')
    backend, stopped = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend['identities']) == len(stopped['processes']) == 4, 'backend-process-denominator')
    for first, last in zip(backend['identities'], stopped['processes']):
        need(all(last.get(key) == value for key, value in first.items()) and last['wait_status'] == -9
             and last['kernel_usage'].get('source') == 'kernel_wait4_owned_child', 'backend-owned-wait4')
    need(backend['normal_access_sha256'] != backend['gc_access_sha256'] and one(events, 'unsigned_probe')['status'] == 403, 'signed-backend-required')
    proxies = select(events, 's3_proxy_stopped')
    need(len(proxies) == 5 and {row['role'] for row in proxies} == {'A', 'B', 'C', 'R', 'O'}
         and all(row['joined'] is True and row['errors'] == [] for row in proxies), 'closed-proxy-denominator')
    need(one(events, 'cleanup_finished')['errors'] == [], 'owned-cleanup-complete')
    cold = one(events, 'scenario_phase', label='all-compute-cache-loss')
    removals = select(events, 'cache_removed')
    need(len(removals) == 10 and all(row['existed'] and row['absent'] for row in removals), 'cache-loss-denominator')
    final = [row for row in ready if moment(row) > moment(cold)]
    need(len(final) == 1 and final[0]['role'] == 'B', 'cold-new-service')
    for role in ('A', 'B', 'C', 'R'):
        values = [row for row in removals if row['role'] == role and moment(row) > moment(cold)]
        need(len(values) == 1 and moment(values[0]) < moment(final[0]), 'all-owned-compute-loss')
    return backend, configurations, {'services': len(services), 'sdk': 4, 'backend': 4,
                                     'owned_wait4': len(stops) + 4, 'cache_losses': len(removals)}


def original_inputs(directory, inputs):
    specifications = {row['name']: row for row in inputs['specs']}
    seeded = {'late', 'race', 'receipt', 'before', 'before_successor', 'after', 'after_successor', 'foreign', 'stale', 'bad_sweep'}
    required = {f'{name}-{counter}' for name in seeded for counter in (1, 2)} | {'late-3', 'race-3', 'receipt-3'}
    need(set(specifications) == required and len(inputs['specs']) == 23, 'frozen-sql-denominator')
    originals = wire.parse((directory / 'intents.json').read_bytes())
    need(set(originals) == required, 'saved-sql-denominator')
    for name, entry in originals.items():
        value = wire.parse(entry['serialized'])
        original = specifications[name]
        need(set(entry) == {'scope_name', 'serialized'}
             and set(value) == {'scope', 'request', 'statements'}
             and entry['scope_name'] == original['scope_name']
             and value['scope'] == inputs['scopes'][original['scope_name']]
             and value['statements'] == original['statements']
             and value['request'] == {'epoch': original['epoch'], 'id': original['request_id'], 'principal': '11',
                                      'fingerprint': wire.fingerprint(original['statements'])}, 'original-sql-fingerprint')
        entry['decoded'] = value
    named = {}
    for row in rows(directory / 'named-intents.jsonl'):
        need(row['name'] not in named, 'original-catalogue-intent-unique')
        value = wire.parse(row['serialized'])
        need(set(value) == {'version', 'deployment', 'tenant', 'principal', 'action'}
             and value['version'] == 1 and value['deployment'] == '1' and value['tenant'] == '7'
             and value['principal'] == row['principal'], 'saved-catalogue-context')
        action = value['action']
        if 'creation' in action:
            need(action['creation'] in inputs['named'].values(), 'fixed-original-named-creation')
        if action['operation'] == 'prepare_create':
            candidates = [creation for creation in inputs['named'].values()
                          if creation['operation'] == action['create_operation']]
            need(len(candidates) == 1 and candidates[0]['name'] == action['name']
                 and candidates[0]['expected_name_revision'] == action['expected_name_revision']
                 and action['options'] == {'quota': {'mode': 'limited', 'max_bytes': '67108864'}},
                 'fixed-original-create-choice')
        named[row['name']] = {**row, 'decoded': value}
    return specifications, originals, named


def sdk(directory, inputs, events, configurations, originals, named):
    calls = {}
    for role in ('A', 'B', 'C', 'R'):
        ledger = rows(directory / ('sdk-' + role + '.jsonl'))
        need([row['sequence'] for row in ledger] == list(range(1, len(ledger) + 1))
             and all(row['role'] == role for row in ledger), 'sdk-closed-sequence')
        one(ledger, 'sdk_started'); one(ledger, 'sdk_finished')
        commands = select(ledger, 'command_started')
        endings = select(ledger, 'command_finished')
        posts = select(ledger, 'http_request')
        need(len(commands) == len(endings), 'sdk-command-denominator')
        child_inputs = select(events, 'child_input', id='sdk-' + role)
        child_outputs = select(events, 'child_output', id='sdk-' + role)
        need(len(child_inputs) == len(commands) and len(child_outputs) == len(commands) + 1
             and wire.parse(raw(directory, child_outputs[0]['raw'])) == {'ready': True}, 'owned-sdk-command-denominator')
        for started, received, produced in zip(commands, child_inputs, child_outputs[1:]):
            name = started['command']
            need(name not in calls, 'http-original-command-unique')
            command = wire.parse(raw(directory, started['input']))
            need(command == wire.parse(raw(directory, received['raw'])) and command['id'] == name, 'sdk-original-input')
            dispatch = one(events, 'sdk_dispatch', role=role, id=name)
            need(dispatch['operation'] == command['operation'] and dispatch['scope_name'] == command['scope_name'], 'dispatch-original-operation')
            done = one(ledger, 'command_finished', command=name)
            need(done['result'] == wire.parse(raw(directory, produced['raw']))
                 and moment(started) < moment(done), 'sdk-original-output')
            requests = select(ledger, 'http_request', command=name)
            if command['operation'] == 'prepare':
                need(not requests and done['attempts'] == 0 and done['result']['value'] == {'prepared': 23}, 'local-sql-prepare')
                continue
            need(len(requests) == done['attempts'] == 1, 'one-original-http-post')
            request = requests[0]
            need(request['method'] == 'POST' and request['ordinal'] == 1, 'post-method-denominator')
            body = wire.parse(raw(directory, request['request']))
            principal = command.get('principal', '11')
            credential = next(item for item in configurations[role]['credentials'] if item['principal'] == principal)
            need(request['token_sha256'] == credential['sha256'] and request['principal'] == principal, 'actual-http-principal')
            operation = command['operation']
            if operation in ('named', 'named_submit'):
                saved = named[command['intent']]['decoded']
                need(body == {'version': 1, **saved['action']} and saved['principal'] == principal, 'original-catalogue-action')
                if operation == 'named':
                    need(command['input'] == saved['action'], 'saved-catalogue-input')
                need(urlsplit(request['url']).path == '/v1/catalogue' and request['headers'].get('x-scap-admission') == 'catalogue', 'catalogue-lane')
            else:
                need(body['version'] == 1 and body['operation'] == operation
                     and body['scope'] == inputs['scopes'][command['scope_name']]
                     and urlsplit(request['url']).path == '/v1', 'original-database-action')
                if operation in ('execute', 'lookup'):
                    original = originals[command['intent']]['decoded']
                    need(body['request'] == original['request'], 'original-sql-request')
                    if operation == 'execute':
                        need(body['statements'] == original['statements'], 'original-sql-bytes')
                mapping = {'expectedHeadSerial': 'expected_head_serial', 'planSerial': 'plan_serial',
                           'batchSerial': 'batch_serial', 'expectedRevision': 'expected_revision',
                           'expectedWorkerInstance': 'expected_worker_instance'}
                if command.get('input') is not None:
                    need(all(body.get(mapping.get(key, key)) == value for key, value in command['input'].items()), 'original-control-candidate')
                if operation in ('gc_prepare', 'gc_resume', 'compact_copy'):
                    need(request['headers'].get('x-scap-admission') == 'recovery', 'gc-recovery-lane')
                if operation in ('storage_status', 'retire_storage'):
                    need(request['headers'].get('x-scap-admission') == 'control', 'terminal-control-lane')
            responses, errors = select(ledger, 'http_response', command=name), select(ledger, 'http_error', command=name)
            need(len(responses) + len(errors) == 1, 'http-terminal-denominator')
            entry = {'role': role, 'command': command, 'start': started, 'done': done, 'request': request,
                     'body': body, 'result': done['result'], 'response': None}
            if responses:
                response = responses[0]
                need(response['complete'] is True and moment(request) < moment(response) <= moment(done), 'complete-http-response')
                value = wire.parse(raw(directory, response['response']))
                need(value['ok'] == done['result']['ok'], 'original-http-knowledge')
                if value['ok']:
                    need(response['status'] == 200, 'http-ack-status')
                    if operation not in ('execute', 'lookup', 'query'):
                        need(done['result']['value'] == value['value'], 'sdk-public-result-exact')
                    if operation in ('named', 'named_submit') and 'creation' in value['value']:
                        expected_creation = (body.get('creation') or next(original for original in inputs['named'].values()
                            if original['operation'] == body['create_operation']))
                        need(value['value']['creation'] == expected_creation, 'public-original-creation')
                else:
                    need(value['error']['code'] == done['result']['error']['code'], 'sdk-original-error')
                entry.update(response=response, response_body=value)
            else:
                need(done['result']['ok'] is False and done['result']['error']['code'] == 'UNKNOWN', 'original-unknown-not-overwritten')
            if not done['result']['ok'] and done['result']['error']['code'] == 'UNKNOWN':
                if operation in ('named', 'named_submit'):
                    expected = {'deployment': '1', 'tenant': '7', 'principal': principal,
                        'operation': body['operation'], 'intent': named[command['intent']]['decoded']}
                else:
                    expected = {'scope': body['scope'], 'operation': body['operation']}
                    for field, public in (('request', 'request'), ('expected_head_serial', 'expectedHeadSerial'),
                                          ('batch_serial', 'batchSerial')):
                        if field in body:
                            expected[public] = body[field]
                need(done['result']['error']['reference'] == expected, 'original-unknown-reference')
            calls[name] = entry
        need(len(posts) == sum(call['role'] == role for call in calls.values()), 'all-http-posts-accounted')
    executions = [call['command']['intent'] for call in calls.values() if call['body']['operation'] == 'execute']
    need(len(executions) == 23 and set(executions) == set(originals), 'original-sql-once-no-replay')
    return calls


def exchange_integrity(groups, final_counts):
    actual = defaultdict(set)
    for (role, serial), group in groups.items():
        need(type(serial) is int and serial > 0, 's3-closed-denominator')
        actual[role].add(serial)
        need('s3_request' in group, 's3-request-stage')
        request = group['s3_request']
        need(all(row.get('method') == request['method'] and row.get('path') == request['path'] for row in group.values()), 's3-original-method-path')
    need(set(actual) <= set(final_counts), 's3-closed-denominator')
    for role, count in final_counts.items():
        need(type(count) is int and count >= 0 and sorted(actual.get(role, ())) == list(range(1, count + 1)), 's3-closed-denominator')


class ObservationIndex(list):
    """Exact raw observations, indexed once; no cached acceptance decisions."""
    def __init__(self, values):
        super().__init__(values)
        self.paths, self.roles, self.methods = defaultdict(list), defaultdict(list), defaultdict(list)
        self.identities = {}
        for value in values:
            request = value['request']
            self.paths[request['path']].append(value)
            self.roles[request['role']].append(value)
            self.methods[request['method']].append(value)
            self.identities[(request['role'], request['serial'])] = value
        self.role_times = {role: [moment(value['request']) for value in records]
                           for role, records in self.roles.items()}

    def at_path(self, path):
        return self.paths.get(path, ())

    def method(self, method):
        return self.methods.get(method, ())

    def for_call(self, call, before=None):
        role = call['role']
        records, times = self.roles.get(role, ()), self.role_times.get(role, ())
        start = bisect_right(times, moment(call['request']))
        end = len(records) if before is None else bisect_right(times, before)
        return [record for record in records[start:end] if before is None or
                record['backend'] is not None and moment(record['backend']) < before]


def exchanges(directory, events, backend):
    groups = defaultdict(dict)
    stages = ('s3_request', 's3_forward_started', 's3_backend_response', 's3_delivery_started',
              's3_delivery_finished', 's3_handler_started', 's3_handler_finished')
    for row in events:
        if row['event'] in stages:
            group = groups[(row['role'], row['serial'])]
            need(row['event'] not in group, 's3-stage-unique')
            group[row['event']] = row
    exchange_integrity(groups, {row['role']: row['request_count'] for row in select(events, 's3_proxy_stopped')})
    values = []
    for group in groups.values():
        need(all(name in group for name in ('s3_request', 's3_handler_started', 's3_handler_finished')), 's3-handler-lifetime')
        request = group['s3_request']
        payload = raw(directory, request['request'])
        need(request['signature_valid'] is True and request['access_sha256'] in
             (backend['normal_access_sha256'], backend['gc_access_sha256']), 'actual-s3-signature')
        need(int(request['headers'].get('content-length', '0')) == len(payload)
             and request['headers'].get('x-amz-content-sha256') in ('UNSIGNED-PAYLOAD', sha(payload)), 'signed-public-payload')
        need(moment(group['s3_handler_started']) <= moment(request) < moment(group['s3_handler_finished']), 's3-handler-order')
        value = {'request': request, 'payload': payload, 'group': group,
                 'backend': group.get('s3_backend_response'), 'delivered': False}
        if value['backend'] is not None:
            need('s3_forward_started' in group and moment(request) <= moment(group['s3_forward_started'])
                 < moment(value['backend']) < moment(group['s3_handler_finished']), 'actual-backend-order')
            value['bytes'] = raw(directory, value['backend']['response'])
        else:
            need('s3_forward_started' not in group and group['s3_delivery_started']['origin'] == 'fixture_no_such_bucket', 'original-backend-accounting')
        if 's3_delivery_started' in group:
            delivered = group['s3_delivery_started']
            raw(directory, delivered['response'])
            need('s3_delivery_finished' in group and moment(delivered) <= moment(group['s3_delivery_finished']), 's3-delivery-lifetime')
            if delivered['origin'] == 'backend':
                need(value['backend'] is not None and delivered['status'] == value['backend']['status']
                     and delivered['response'] == value['backend']['response'] and moment(value['backend']) < moment(delivered), 'unaltered-backend-response')
                value['delivered'] = group['s3_delivery_finished']['complete'] is True
        values.append(value)
    need(not select(events, 's3_fixture_error'), 'fixture-transport-error')
    claims = wire.raw_worker_claims(events, values, backend['normal_access_sha256'], check=need)
    return ObservationIndex(sorted((value for value in values
        if (value['request']['role'], value['request']['serial']) not in claims),
        key=lambda value: moment(value['request'])))


def within(call, exchange, before=None):
    return (exchange['request']['role'] == call['role'] and moment(call['request']) < moment(exchange['request'])
            and (before is None or exchange['backend'] is not None and moment(exchange['backend']) < before))


def same_scope(call, logical):
    value = call['body'].get('scope', call['body'].get('creation', {}).get('scope'))
    return value is not None and {key: int(number) for key, number in value.items()} == logical


def original_call(exchange, calls, operations=None):
    request = exchange['request']
    path = urlsplit(request['path']).path
    database = head_path(path)
    if database is None and '/objects/' in path:
        database = object_path(path)[0]['database']
    matches = []
    for call in calls.values():
        if call['role'] != request['role'] or moment(call['request']) >= moment(request):
            continue
        if operations is not None and call['body']['operation'] not in operations:
            continue
        logical = call['body'].get('scope', call['body'].get('creation', {}).get('scope'))
        if database is None or logical is not None and int(logical['database']) == database:
            matches.append(call)
    need(matches, 's3-original-public-call')
    return max(matches, key=lambda call: moment(call['request']))


def candidate_basis(exchange, call, values):
    request = exchange['request']
    matching = [observed for observed in values.at_path(request['path'])
                if observed['request']['role'] == request['role'] and observed['request']['method'] == 'GET'
                and observed.get('read_head') is not None and observed['delivered']
                and observed['backend']['headers'].get('etag') == request['headers'].get('if-match')
                and moment(call['request']) < moment(observed['request'])
                < moment(observed['group']['s3_delivery_finished']) < moment(request)]
    need(matching, 'fresh-original-head-candidate')
    return matching[-1]['read_head']


def histories(directory, inputs, events, calls, values):
    scopes = {scope_key({key: int(number) for key, number in logical.items()}) for logical in inputs['scopes'].values()}
    heads, objects, metadata = defaultdict(list), {}, defaultdict(list)
    bad = {row['scope_name']: row for row in select(events, 'explicit_bad_authority')}
    need(set(bad) == {'stale', 'bad_sweep'}, 'explicit-damaged-scope-denominator')
    accepted = [x for x in values if x['request']['method'] == 'PUT' and x['backend'] is not None and x['backend']['status'] == 200]
    for exchange in sorted(accepted, key=lambda x: moment(x['backend'])):
        request, payload = exchange['request'], exchange['payload']
        path, database = request['path'], head_path(request['path'])
        etag = exchange['backend']['headers'].get('etag')
        need(isinstance(etag, str), 'accepted-backend-etag')
        if database is not None:
            previous = heads[database][-1] if heads[database] else None
            operator = request['role'] == 'O'
            if operator:
                name = next((name for name in bad if int(inputs['scopes'][name]['database']) == database), None)
                need(name is not None and previous is not None, 'operator-fixed-damaged-scope')
                mark = bad[name]
                need(raw(directory, mark['before']) == previous['exchange']['payload']
                     and raw(directory, mark['after']) == payload, 'operator-original-bytes')
                value = wire.parse(payload)
                old = previous['head']
                if name == 'stale':
                    expected = json.loads(json.dumps(old))
                    expected['storage']['terminal']['serial'] = mark['mutation']['terminal_serial']
                    need(value == expected, 'operator-only-terminal-serial')
                    head(payload, scopes)
                else:
                    expected = json.loads(json.dumps(old))
                    expected['storage']['sweep']['serial'] = old['storage']['terminal']['serial']
                    need(value == expected, 'operator-only-sweep-serial')
                    try:
                        head(payload, scopes)
                    except Rejected as error:
                        need(error.rule == 'checkpoint-after-terminal', 'bad-checkpoint-exact-rejection')
                    else:
                        need(False, 'bad-checkpoint-accepted')
                kind = 'explicit_fault'
            else:
                value = head(payload, scopes)
                kind = 'create' if previous is None else advance(previous['head'], value)
            need(value['scope']['database'] == database, 'physical-head-slot')
            if previous is None:
                need(value['head_serial'] == value['revision'] == 1 and request['headers'].get('if-none-match') == '*'
                     and request['headers'].get('if-match') is None, 'initial-absent-head')
            else:
                need(moment(previous['exchange']['backend']) < moment(exchange['group']['s3_forward_started'])
                     and request['headers'].get('if-match') == previous['exchange']['backend']['headers']['etag']
                     and request['headers'].get('if-none-match') is None, 'original-head-etag')
                reads = [x for x in values.at_path(path) if x['request']['role'] == request['role'] and x['request']['method'] == 'GET'
                         and x['request']['path'] == path and x['backend'] is not None and x['backend']['status'] == 200
                         and x.get('bytes') == previous['exchange']['payload'] and x['backend']['headers'].get('etag') == request['headers']['if-match']
                         and x['delivered'] and moment(x['group']['s3_delivery_finished']) < moment(request)]
                need(reads, 'same-exact-get-body-etag')
            record = {'head': value, 'kind': kind, 'previous': previous, 'exchange': exchange}
            heads[database].append(record)
            exchange['head_record'] = record
        elif '/catalogue/v1/' in path:
            kind, value = catalogue(payload, path)
            previous = metadata[path][-1] if metadata[path] else None
            if kind == 'name' and previous is not None:
                need(request['headers'].get('if-match') == previous['exchange']['backend']['headers']['etag']
                     and request['headers'].get('if-none-match') is None, 'original-name-etag')
            else:
                need(request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None,
                     'immutable-metadata-absent')
                if previous:
                    need(payload == previous['exchange']['payload'], 'permanent-record-identity')
            record = {'kind': kind, 'value': value, 'previous': previous, 'exchange': exchange}
            metadata[path].append(record)
            exchange['metadata_record'] = record
        else:
            envelope(payload, path)
            need(request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None, 'immutable-payload-absent')
            if path in objects:
                need(objects[path] == payload, 'immutable-content-identity')
            objects[path] = payload
    expected_slots = {int(value['database']) for name, value in inputs['scopes'].items() if name != 'foreign_loser'}
    need(set(heads) == expected_slots, 'all-real-head-slots')
    for exchange in values:
        request, response = exchange['request'], exchange['backend']
        if request['method'] != 'GET' or response is None or response['status'] != 200:
            continue
        database = head_path(request['path'])
        versions = heads.get(database) if database is not None else metadata.get(request['path'])
        if versions is not None:
            matches = [record for record in versions if record['exchange']['payload'] == exchange['bytes']
                       and record['exchange']['backend']['headers'].get('etag') == response['headers'].get('etag')
                       and moment(record['exchange']['backend']) < moment(response)]
            need(len(matches) == 1, 'actual-read-version')
            exchange['read_head' if database is not None else 'read_metadata'] = matches[0]
        elif '/objects/' in request['path']:
            envelope(exchange['bytes'], request['path'])
            need(request['path'] in objects and objects[request['path']] == exchange['bytes'], 'actual-immutable-version')
    for exchange in values:
        if exchange['request']['role'] != 'O':
            call = original_call(exchange, calls)
            exchange['call'] = call
            request = exchange['request']
            if request['method'] == 'PUT' and head_path(request['path']) is not None:
                candidate = head(exchange['payload'], scopes)
                if request['headers'].get('if-match') is not None:
                    basis = candidate_basis(exchange, call, values)
                    advance(basis['head'], candidate)
                    if call['body']['operation'] == 'execute':
                        need(candidate['sequence'] == basis['head']['sequence'] + 1
                             and candidate['transition']['nonce'] == int(call['body']['request']['id']),
                             'original-sql-head-candidate')
                else:
                    need(request['headers'].get('if-none-match') == '*'
                         and candidate['head_serial'] == candidate['revision'] == 1, 'original-absent-head-candidate')
    return heads, objects, metadata
