"""Independent source, owned processes, original SDK and closed network ledgers."""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import tarfile
from urllib.parse import urlsplit

import audit_model as model
from audit_model import Rejected, need, digest, sha, wire

def rows(path):
    need(path.is_file(), 'ledger-missing')
    raw = path.read_bytes()
    need(raw and raw.endswith(b'\n'), 'ledger-framing')
    return [wire.parse(line) for line in raw.splitlines()]


def raw(directory, description):
    need(set(description) == {'file', 'bytes', 'sha256'}, 'raw-description')
    name = digest(description['sha256'])
    need(description['file'] == 'raw/' + name, 'raw-path')
    path = directory / 'raw' / name
    need(path.is_file() and not path.is_symlink() and type(description['bytes']) is int
         and 0 <= description['bytes'] <= 67108864, 'raw-file')
    value = path.read_bytes()
    need(len(value) == description['bytes'] and sha(value) == name, 'raw-integrity')
    return value


def moment(row):
    value = row['monotonic_ns']
    need(type(value) is int or isinstance(value, str) and value.isdecimal(), 'observation-time')
    return int(value)


def selection(rows_value, event, **fields):
    return [row for row in rows_value if row['event'] == event and
            all(row.get(name) == value for name, value in fields.items())]


def one(rows_value, event, **fields):
    result = selection(rows_value, event, **fields)
    need(len(result) == 1, 'one-' + event)
    return result[0]


def archive(path, expected):
    with tarfile.open(path) as file:
        members = file.getmembers()
        need(len(members) == len(expected) and len({m.name for m in members}) == len(members), 'archive-denominator')
        for member in members:
            need(member.isfile() and member.name in expected, 'archive-member')
            data = file.extractfile(member).read()
            need(sha(data) == expected[member.name], 'archive-source-bytes')


def identity(directory, inputs, events, plan_path='experiments/object-owner-plan-runtime/PLAN.md'):
    source = wire.parse((directory / 'source.json').read_bytes())
    files = source['files']
    need(source['commit'] == inputs['commit'] and source['source_sha256'] == inputs['source_sha256']
         and sha(json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()) == source['source_sha256'], 'source-identity')
    need(sha((directory / 'source.tar').read_bytes()) == inputs['source_archive_sha256'], 'source-archive')
    expected = {row['path']: row['sha256'] for row in files}
    need(len(expected) == len(files), 'source-duplicate')
    archive(directory / 'source.tar', expected)
    with tarfile.open(directory / 'source.tar') as file:
        for row in files:
            data = file.extractfile(row['path']).read()
            need(len(data) == row['bytes'] and hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob'], 'committed-source-bytes')
    need(inputs['plan_sha256'] == expected[plan_path], 'frozen-plan')
    receipts = {}
    for name, tool, stdout_key, stderr_key in (
            ('service-build', 'scapd', 'cargo.stdout.jsonl_sha256', 'cargo.stderr.log_sha256'),
            ('seed-build', 'native-seed', 'build_stdout_sha256', 'build_stderr_sha256')):
        root = directory / name
        receipt = wire.parse((root / 'build-receipt.json').read_bytes())
        need(receipt['status'] == 'passed' and receipt['exit_code'] == 0 and receipt['profile'] == 'release'
             and receipt['source_commit'] == inputs['runtime_source_commit'], 'original-release-build')
        need(receipt['binary'] == inputs['tools'][tool] and all(expected.get(k) == v for k, v in receipt['inputs'].items()), 'release-source-binding')
        need(Path(receipt['binary']['path']).is_file() and sha(Path(receipt['binary']['path']).read_bytes()) == receipt['binary']['sha256'], 'actual-native-binary')
        need(receipt['native_archives'], 'native-archive-required')
        for path, digest_value in receipt['native_archives'].items():
            need(Path(path).is_file() and sha(Path(path).read_bytes()) == digest_value, 'actual-native-archive')
        archived = receipt['archived_evidence']
        for key, hash_key in (('source_archive', 'source_archive_sha256'), ('source_manifest', 'source_manifest_sha256')):
            need(sha((root / archived[key]).read_bytes()) == archived[hash_key], 'release-archive')
        archive(root / archived['source_archive'], receipt['inputs'])
        need(sha((root / 'build-cargo.stdout.jsonl').read_bytes()) == receipt[stdout_key]
             and sha((root / 'build-cargo.stderr.log').read_bytes()) == receipt[stderr_key], 'original-cargo-log')
        cargo = rows(root / 'build-cargo.stdout.jsonl')
        need(cargo[-1].get('reason') == 'build-finished' and cargo[-1].get('success') is True, 'cargo-finished')
        artifacts = [row for row in cargo if row.get('reason') == 'compiler-artifact'
                     and row.get('executable') == receipt['binary']['path']]
        need(artifacts and artifacts[-1]['profile']['opt_level'] == '3', 'original-release-artifact')
        receipts[name] = receipt
    verified = one(events, 'source_verified')
    need(verified['commit'] == source['commit'] and verified['source_sha256'] == source['source_sha256'], 'source-after')
    return receipts


NAMES = ('bulk', 'late_prepare', 'claim_cancel', 'claim_wins', 'resume_cancel', 'resume_wins',
         'acl', 'target_death', 'resume_death', 'legacy', 'proof_claim', 'proof_cancel',
         'named_old', 'named_successor', 'missing_descriptor', 'budget_gets', 'budget_bytes')
WARM_COUNTS = (2, 1, 2, 2, 2, 1, 1, 2, 2, 2, 2, 3, 2, 0, 2, 2, 2)
OWNER_COUNTS = ((5, 4, 3, 0, 5), (2, 2, 2, 0, 2), (4, 3, 3, 2, 2),
    (4, 3, 2, 2, 1), (3, 3, 3, 1, 1), (2, 2, 3, 2, 1), (3, 2, 5, 0, 2),
    (3, 4, 3, 1, 2), (3, 3, 4, 1, 2), (3, 3, 2, 1, 1), (3, 5, 3, 0, 5),
    (4, 3, 2, 4, 2), (2, 2, 2, 0, 5), (1, 1, 1, 0, 0), (5, 3, 3, 0, 2),
    (3, 3, 3, 1, 1), (3, 3, 3, 1, 1))
WORKERS = {'A': (9101,), 'B': (9102, 9202), 'C': (9103, 9203),
           'R': (9104, 9204, 9304), 'G': (9105,), 'Z': (9106,)}


def native(value):
    if isinstance(value, dict):
        return {key: native(item) for key, item in value.items()}
    if isinstance(value, list):
        return [native(item) for item in value]
    if isinstance(value, str) and value.isdecimal() and len(value) <= 20:
        return wire.decimal(value, zero=True)
    return value


def fixed_inputs(inputs):
    need(tuple(inputs['scopes']) == tuple(sorted(NAMES)) or set(inputs['scopes']) == set(NAMES), 'fixed-scope-denominator')
    logical = {name: native(value) for name, value in inputs['scopes'].items()}
    direct = dict(zip(NAMES[:12], range(7201, 7213))) | {'missing_descriptor': 7214, 'budget_gets': 7215, 'budget_bytes': 7216}
    for name, database in direct.items():
        need(logical[name] == dict(zip(model.SCOPE, (1, 7, database, 1, 1))), 'fixed-direct-scope')
    need(set(inputs['named']) == {'named_old', 'named_successor'}, 'fixed-named-denominator')
    for name, operation, revision in (('named_old', 7601, None), ('named_successor', 7602, 3)):
        creation = native(inputs['named'][name])
        model.native_creation(creation)
        need(creation == {'creator': 11, 'operation': operation, 'name': 'owner-head8-history',
                          'scope': logical[name], 'expected_name_revision': revision}, 'fixed-named-creation')
    need(len({model.scope_key(value) for value in logical.values()}) == 17, 'full-scope-distinct')
    need(inputs['workers'] == {role: list(values) for role, values in WORKERS.items()}
         and inputs['native_worker'] == 9000, 'fixed-worker-incarnations')
    need(inputs['timeouts'] == {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
        's3_ms': 120000, 'original_unknown_ms': 1500, 'hold_seconds': 180, 'whole_seconds': 1200}, 'fixed-original-deadlines')
    need(inputs['limits'] == {'quota_bytes': 67108864, 'retention_entries': 129,
        'retention_result_bytes': 268435456}, 'fixed-native-retention')
    need(inputs['owner_rpc'] == {name: list(count) for name, count in zip(NAMES, OWNER_COUNTS)}, 'fixed-owner-post-denominator')
    return logical


def processes(directory, inputs, events):
    starts, stops = {}, {}
    for event, target in (('child_started', starts), ('child_stopped', stops)):
        for row in selection(events, event):
            need(row['id'] not in target, 'owned-child-denominator')
            target[row['id']] = row
    need(set(starts) == set(stops), 'owned-child-denominator')
    identities = set()
    for name, first in starts.items():
        last, identifier = stops[name], first['identity']
        need(identifier == last['identity'] and identifier['pid_source'] == 'owned_Popen_child'
             and moment(first) < moment(last), 'owned-original-child')
        key = (identifier['pid'], identifier['spawn_monotonic_ns'])
        need(key not in identities, 'owned-child-incarnation')
        identities.add(key)
        need(last['forced'] is False and last['status'] == (-9 if last['crash'] else 0)
             and last['usage'].get('available') is True
             and last['usage'].get('source') == 'kernel_wait4_owned_child', 'owned-wait4')
        raw(directory, last['stderr'])
        tool = ('scapd' if name.startswith('service-') else 'native-seed' if name == 'native-seed'
                else 'weed' if name == 'weed-version' else 'node')
        need(first['command'][0] == inputs['tools'][tool]['path']
             and first['executable_sha256'] == inputs['tools'][tool]['sha256'], 'owned-executable')
    services = [name for name in starts if name.startswith('service-')]
    sdks = [name for name in starts if name.startswith('sdk-')]
    need(len(services) == 10 and len(sdks) == 10 and len(starts) == 23 and 'native-seed' in starts,
         'fixed-process-denominator')
    ready = selection(events, 'service_ready')
    need(len(ready) == 10 and {row['id'] for row in ready} == set(services)
         and len({row['worker'] for row in ready}) == 10, 'worker-instance-never-reused')
    configurations = {}
    for role, expected in WORKERS.items():
        observed = sorted((row for row in ready if row['role'] == role), key=moment)
        need([int(row['worker']) for row in observed] == list(expected), 'fixed-worker-incarnation-order')
        for row in observed:
            value = wire.parse((directory / (row['id'] + '.json')).read_bytes())
            configurations[row['id']] = value
            need(value['worker_instance'] == row['worker'] and value['s3']['timeout_ms'] == 120000
                 and value['admission']['timeout_ms'] == 120000 and value['admission']['recovery_timeout_ms'] == 300000
                 and value['admission']['actor_idle_timeout_ms'] == 120000
                 and value['transport']['response_timeout_ms'] == 120000, 'original-server-budgets')
            need(value['owner_recovery'] == {'payload_gets': 0 if role == 'G' else 1048576,
                 'payload_bytes': 1 if role == 'Z' else 68719476736}, 'fixed-owner-recovery-budget')
            need((value['gc'] is not None) == (role == 'C'), 'explicit-gc-capability')
            if value['gc'] is not None:
                need(value['gc']['access_key_env'] != value['s3']['access_key_env']
                     and value['gc']['secret_key_env'] != value['s3']['secret_key_env'], 'independent-gc-credentials')
            need([credential['principal'] for credential in value['credentials']] == ['11', '12'], 'fixed-principal-order')
            need(value['credentials'][0]['provision'] == (role in ('A', 'C'))
                 and value['credentials'][1]['provision'] is False, 'explicit-provision-capability')
    backend, ended = one(events, 'backend_started'), one(events, 'backend_stopped')
    need(len(backend['identities']) == len(ended['processes']) == 4, 'backend-process-denominator')
    for first, last in zip(backend['identities'], ended['processes']):
        need(all(last.get(key) == value for key, value in first.items()) and last['wait_status'] == -9
             and last['kernel_usage'].get('source') == 'kernel_wait4_owned_child', 'backend-owned-wait4')
    need(backend['normal_access_sha256'] != backend['gc_access_sha256']
         and one(events, 'unsigned_probe')['status'] == 403, 'actual-signed-backend')
    proxies = selection(events, 's3_proxy_stopped')
    need(len(proxies) == 7 and {row['role'] for row in proxies} == {'seed', *WORKERS}
         and all(row['joined'] is True and row['errors'] == [] for row in proxies), 'owned-s3-proxy-cleanup')
    fronts = selection(events, 'http_proxy_closed')
    need(len(fronts) == 10 and {row['role'] for row in fronts} ==
         {f'{role}-{worker}' for role, workers in WORKERS.items() for worker in workers}
         and all(row['joined'] is True and row['errors'] == [] for row in fronts), 'owned-http-proxy-cleanup')
    need(one(events, 'cleanup_finished')['errors'] == [], 'owned-cleanup-complete')
    cold = one(events, 'scenario_phase', label='all-compute-cache-loss')
    removed = selection(events, 'cache_removed')
    need(len(removed) == 9 and all(row['existed'] and row['absent'] for row in removed), 'all-warm-cache-loss-denominator')
    final = [row for row in ready if moment(row) > moment(cold)]
    need(len(final) == 1 and final[0]['role'] == 'C' and final[0]['worker'] == '9203', 'cold-distinct-worker')
    need({row['service'] for row in removed} == set(services) - {final[0]['id']}
         and all(moment(row) < moment(final[0]) for row in removed), 'all-warm-compute-loss-before-cold')
    need(one(events, 'native_cache_removed')['absent'] is True, 'native-seed-cache-loss')
    for service in ('service-A-1', 'service-R-1', 'service-B-1', 'service-R-2'):
        need(stops[service]['crash'] is True, 'fixed-original-process-exits')
    return backend, configurations, starts, stops


def original_inputs(directory, inputs, events):
    specs = {row['name']: row for row in inputs['specs']}
    expected = {f'{name}-{counter:03d}' for name in NAMES for counter in range(1, (260 if name == 'bulk' else 2) + 1)}
    expected |= {'resume_wins-003', 'proof_claim-003', 'named_old-003', 'bulk-cancel', 'bulk-blocked'}
    need(len(inputs['specs']) == len(specs) == len(expected) == 297 and set(specs) == expected, 'frozen-sql-denominator')
    for name, item in specs.items():
        scope_name = name.rsplit('-', 1)[0]
        suffix = name.rsplit('-', 1)[1]
        special = suffix in ('cancel', 'blocked')
        counter = {'cancel': 777777, 'blocked': 888888}[suffix] if special else int(suffix)
        epoch = 3 if special else (counter - 1) // 129 + 1 if scope_name == 'bulk' else 1
        request_id = {'cancel': 3, 'blocked': 4}[suffix] if special else (counter - 1) % 129 + 1
        statements = ([{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
                        'params': []}] if counter == 1 else [])
        statement = (f'INSERT INTO witness VALUES(1,{counter},randomblob(64))' if counter == 1 else
                     f'UPDATE witness SET counter={counter},payload=randomblob(64) WHERE id=1')
        statements.append({'sql': statement + ' RETURNING counter,payload,random() AS nonce', 'params': []})
        purpose = suffix if special else 'after_owner' if scope_name in ('resume_wins', 'proof_claim', 'named_old') and counter == 3 else 'seed'
        fixed = {'name': name, 'scope_name': scope_name, 'epoch': str(epoch), 'request_id': str(request_id),
                 'statements': statements, 'purpose': purpose}
        if not special:
            fixed['counter'] = counter
        need(item == fixed, 'fixed-original-sql-workload')
    originals = wire.parse((directory / 'intents.json').read_bytes())
    need(set(originals) == expected, 'saved-sql-denominator')
    for name, row in originals.items():
        value, original = wire.parse(row['serialized']), specs[name]
        need(set(row) == {'scope_name', 'serialized'} and set(value) == {'scope', 'request', 'statements'}
             and row['scope_name'] == original['scope_name'] and value['scope'] == inputs['scopes'][row['scope_name']]
             and value['statements'] == original['statements'] and value['request'] == {
                'epoch': original['epoch'], 'id': original['request_id'], 'principal': '11',
                'fingerprint': wire.fingerprint(original['statements'])}, 'original-sql-fingerprint')
        row['decoded'] = value
    owners = {}
    real = {f'{name}-p{ordinal}' for name, count in zip(NAMES, WARM_COUNTS)
            for ordinal in range(1, count + 1 + (name != 'named_old'))}
    extras = {'claim_cancel-p90', 'claim_wins-p91', 'bulk-p1-changed-base', 'missing_descriptor-p1-changed-base'}
    need(len(real) == 46, 'original-owner-profile')
    for row in rows(directory / 'owner-inputs.jsonl'):
        need(set(row) == {'name', 'scope_name', 'role', 'principal', 'serialized'} and row['name'] not in owners,
             'owner-original-input-unique')
        value = wire.parse(row['serialized'])
        need(set(value) == {'version', 'scope', 'input'} and type(value['version']) is int and value['version'] == 1
             and value['scope'] == inputs['scopes'][row['scope_name']], 'owner-saved-input-scope')
        original = model.owner_input(native(value['input']))
        need(value['input']['creator'] == row['principal'], 'owner-original-creator-before-dispatch')
        need(all(isinstance(value['input'][key], str) for key in model.OWNER_INPUT[:4] + ('target_worker',))
             and all(isinstance(item, str) for item in value['input']['nonces'].values()), 'owner-original-decimal-wire')
        owners[row['name']] = {**row, 'decoded': value, 'native': original}
    need(set(owners) == real | extras and len(owners) == 50, 'owner-saved-input-denominator')
    for index, (name, warm) in enumerate(zip(NAMES, WARM_COUNTS), 1):
        for ordinal in range(1, warm + 1 + (name != 'named_old')):
            record = owners[f'{name}-p{ordinal}']
            original = record['native']
            operation = 800000 + index * 100 + ordinal
            cold = ordinal > warm
            worker = 9203 if cold else 9102
            if not cold:
                worker = {('target_death', 2): 9204, ('resume_death', 1): 9204,
                          ('resume_death', 2): 9103, ('budget_gets', 1): 9105,
                          ('budget_bytes', 1): 9106}.get((name, ordinal), worker)
            activation = not cold and ((name in ('claim_wins', 'resume_cancel', 'legacy') and ordinal == 2)
                                      or name == 'proof_cancel' and ordinal in (2, 3))
            need(record['scope_name'] == name and original['operation'] == operation
                 and original['creator'] == (12 if cold else 11) and original['target_worker'] == worker
                 and original['mode'] == ('activate' if activation else 'takeover')
                 and original['nonces'] == {key: operation * 10 + offset for offset, key in enumerate(model.NONCES, 1)},
                 'fixed-original-owner-input')
    for name in ('bulk', 'missing_descriptor'):
        before, after = owners[name + '-p1']['native'], owners[name + '-p1-changed-base']['native']
        need(all(before[key] == after[key] for key in set(before) - {'expected_revision', 'expected_head_serial'})
             and after['expected_revision'] > before['expected_revision']
             and after['expected_head_serial'] > before['expected_head_serial'], 'same-owner-id-only-original-base-variant')
    for name, ordinal, creator, mode, target in (('claim_cancel', 90, 12, 'takeover', 9102),
                                                ('claim_wins', 91, 11, 'activate', 9101)):
        original = owners[f'{name}-p{ordinal}']['native']
        operation = 800000 + (NAMES.index(name) + 1) * 100 + ordinal
        need(original['creator'] == creator and original['operation'] == operation
             and original['mode'] == mode and original['target_worker'] == target
             and original['nonces'] == {key: operation * 10 + offset for offset, key in enumerate(model.NONCES, 1)},
             'fixed-unaccepted-owner-input')
    named = {}
    for row in rows(directory / 'named-intents.jsonl'):
        need(row['name'] not in named, 'original-catalogue-identity-unique')
        value = wire.parse(row['serialized'])
        need(set(value) == {'version', 'deployment', 'tenant', 'principal', 'action'} and value['version'] == 1
             and value['deployment'] == '1' and value['tenant'] == '7' and value['principal'] == row['principal'],
             'original-catalogue-context')
        action = value['action']
        if 'creation' in action:
            need(action['creation'] == inputs['named'][row['scope_name']], 'original-catalogue-creation')
        named[row['name']] = {**row, 'decoded': value}
    return specs, originals, owners, named


def query_result(raw_value):
    """Independent projection of SCAPRES1 into the driver's public SDK JSON.

    Query returns TransactionResult directly; only execute/lookup include
    rawResult. Bigints are decimal strings and Buffer.toJSON keeps its bytes.
    """
    def scalar(value):
        if type(value) is int:
            return str(value)
        if isinstance(value, bytes):
            return {'type': 'Buffer', 'data': list(value)}
        return value
    return {'statements': [{'columns': statement['columns'],
        'rows': [[scalar(value) for value in row] for row in statement['rows']],
        'affectedRows': str(statement['affected_rows']),
        'lastInsertRowid': str(statement['last_insert_rowid'])} for statement in wire.result(raw_value)]}


def sdk(directory, inputs, events, configurations, originals, owners, named,
        sql_count=297, saved_count=50, owner_counts=None):
    if owner_counts is None:
        owner_counts = dict(zip(NAMES, OWNER_COUNTS))
    calls, local = {}, {}
    sdk_starts = selection(events, 'child_started')
    sdk_starts = [row for row in sdk_starts if row['id'].startswith('sdk-')]
    for child in sdk_starts:
        identifier = child['id']
        role = identifier.removeprefix('sdk-')
        ledger = rows(directory / ('sdk-' + role + '.jsonl'))
        need([row['sequence'] for row in ledger] == list(range(1, len(ledger) + 1))
             and all(row['role'] == role for row in ledger)
             and all(moment(a) <= moment(b) for a, b in zip(ledger, ledger[1:])), 'sdk-closed-sequence')
        one(ledger, 'sdk_started'); one(ledger, 'sdk_finished')
        commands, endings = selection(ledger, 'command_started'), selection(ledger, 'command_finished')
        need(len(commands) == len(endings), 'sdk-command-denominator')
        sent, received = {}, {}
        for event, destination in (('child_input', sent), ('child_output', received)):
            for row in selection(events, event, id=identifier):
                value = wire.parse(raw(directory, row['raw']))
                if value == {'ready': True}:
                    need(event == 'child_output' and None not in received, 'one-sdk-ready')
                    destination[None] = row
                    continue
                need(value.get('id') not in destination, 'owned-sdk-command-unique')
                destination[value['id']] = row
        need(len(sent) == len(commands) and len(received) == len(commands) + 1 and None in received,
             'owned-sdk-command-denominator')
        for started in commands:
            name = started['command']
            need(name not in calls and name not in local, 'original-command-unique')
            command = wire.parse(raw(directory, started['input']))
            done = one(ledger, 'command_finished', command=name)
            need(command['id'] == name and wire.parse(raw(directory, sent[name]['raw'])) == command
                 and wire.parse(raw(directory, received[name]['raw'])) == done['result'], 'owned-sdk-original-bytes')
            need(moment(sent[name]) <= moment(started) < moment(done) <= moment(received[name]), 'original-sdk-command-order')
            dispatch = one(events, 'sdk_dispatch', id=name)
            need(dispatch['sdk'] == identifier and dispatch['operation'] == command['operation']
                 and dispatch['scope_name'] == command['scope_name'], 'original-dispatch-context')
            requests = selection(ledger, 'http_request', command=name)
            entry = {'name': name, 'sdk': role, 'controller': role.split('-')[0], 'command': command,
                     'start': started, 'done': done, 'result': done['result'], 'response': None}
            operation = command['operation']
            if operation in ('prepare_sql', 'owner_save', 'owner_claim_pending'):
                need(not requests and done['attempts'] == 0, 'local-sdk-no-product-dispatch')
                if operation == 'prepare_sql':
                    need(command['specs'] == inputs['specs'] and done['result'] ==
                         {'id': name, 'ok': True, 'value': {'prepared': sql_count}}, 'all-original-sql-prepared')
                    saved = one(ledger, 'intents_prepared')
                    need(raw(directory, saved['original']) == (directory / 'intents.json').read_bytes(), 'saved-sql-original-ledger')
                elif operation == 'owner_save':
                    owner = owners[command['intent']]
                    need(owner['decoded']['input'] == command['input'] and owner['scope_name'] == command['scope_name']
                         and done['result'] == {'id': name, 'ok': True, 'value': owner['decoded']}, 'owner-input-saved-before-dispatch')
                    saved = one(ledger, 'owner_input_saved', name=command['intent'])
                    need(wire.parse(raw(directory, saved['original'])) == {key: value for key, value in owner.items()
                         if key not in ('decoded', 'native')} and moment(saved) < moment(done), 'owner-input-fsync-original')
                    owner['saved_at'] = saved
                else:
                    need(not done['result']['ok'] and done['result']['error']['code'] == 'INVALID', 'pending-not-a-prepared-capability')
                local[name] = entry
                continue
            need(len(requests) == done['attempts'] == 1, 'one-original-http-post')
            request = requests[0]
            need(request['method'] == 'POST' and request['ordinal'] == 1
                 and moment(started) <= moment(request) < moment(done), 'original-post-order')
            body = wire.parse(raw(directory, request['request']))
            principal = command.get('principal', '11')
            credential = next(item for item in configurations['service-C-1']['credentials'] if item['principal'] == principal)
            need(request['principal'] == principal and request['token_sha256'] == credential['sha256'], 'actual-http-principal')
            if operation in ('named', 'named_submit'):
                saved = named[command['intent']]['decoded']
                need(body == {'version': 1, **saved['action']} and saved['principal'] == principal,
                     'original-catalogue-action')
                if operation == 'named':
                    need(command['input'] == saved['action'], 'saved-catalogue-input')
                need(urlsplit(request['url']).path == '/v1/catalogue'
                     and request['headers'].get('x-scap-admission') == 'catalogue', 'catalogue-admission-lane')
            else:
                expected_operation = 'owner_inspect' if operation == 'owner_observe' else operation
                need(body['version'] == 1 and body['operation'] == expected_operation
                     and body['scope'] == inputs['scopes'][command['scope_name']]
                     and urlsplit(request['url']).path == '/v1', 'original-database-action')
                if operation in ('execute', 'lookup', 'cancel'):
                    original = originals[command['intent']]['decoded']
                    need(body['request'] == original['request'], 'original-sql-request-identity')
                    if operation == 'execute':
                        need(body['statements'] == original['statements'], 'original-sql-bytes')
                elif operation.startswith('owner_'):
                    saved = owners[command['intent']]
                    if operation == 'owner_prepare':
                        need(set(body) == {'version', 'scope', 'operation', 'input'}
                             and body['input'] == saved['decoded']['input'], 'original-owner-prepare-input')
                    elif operation in ('owner_inspect', 'owner_observe'):
                        need(set(body) == {'version', 'scope', 'operation', 'identity'}
                             and body['identity'] == {key: saved['decoded']['input'][key]
                                                     for key in ('creator', 'operation')}, 'original-owner-inspect-identity')
                    else:
                        required = {'version', 'scope', 'operation', 'plan'}
                        if operation in ('owner_claim', 'owner_resume'):
                            required.add('expected_worker_instance')
                            need(body['expected_worker_instance'] == saved['decoded']['input']['target_worker'], 'original-fixed-owner-target')
                        need(set(body) == required, 'owner-mutation-wire-shape')
                        model.owner_reference(native(body['plan']))
                        need(all(body['plan'][key] == saved['decoded']['input'][key] for key in ('creator', 'operation')),
                             'original-owner-plan-reference')
                    need(request['headers'].get('x-scap-admission') ==
                         ('recovery' if operation == 'owner_resume' else 'control'), 'owner-admission-lane')
                else:
                    mapping = {'expectedHeadSerial': 'expected_head_serial', 'planSerial': 'plan_serial',
                        'batchSerial': 'batch_serial', 'expectedRevision': 'expected_revision',
                        'expectedWorkerInstance': 'expected_worker_instance'}
                    if command.get('input') is not None:
                        need(all(body.get(mapping.get(key, key)) == value for key, value in command['input'].items()), 'original-control-candidate')
            response, errors = selection(ledger, 'http_response', command=name), selection(ledger, 'http_error', command=name)
            need(len(response) + len(errors) == 1, 'original-http-terminal-denominator')
            if response:
                terminal = response[0]
                need(terminal['complete'] is True and moment(request) < moment(terminal) <= moment(done), 'original-complete-http-response')
                value = wire.parse(raw(directory, terminal['response']))
                need(type(value['ok']) is bool and value['ok'] == done['result']['ok'], 'original-client-knowledge')
                if value['ok']:
                    need(set(value) == {'ok', 'value'} and terminal['status'] == 200, 'original-ack-envelope')
                    public = value['value']
                    if isinstance(public, dict) and 'result' in public and operation in ('execute', 'lookup', 'query'):
                        payload = wire.b64(public['result'])
                        if operation == 'query':
                            need(done['result']['value'] == query_result(payload), 'sdk-original-query-values')
                        else:
                            need(raw(directory, done['result']['value']['result']) == payload, 'sdk-original-full-result')
                        wire.result(payload)
                        if 'receipt' in public:
                            need(done['result']['value']['receipt'] == public['receipt'], 'sdk-original-receipt')
                    else:
                        need(done['result']['value'] == public, 'sdk-public-result-exact')
                else:
                    need(set(value) == {'ok', 'error'} and value['error']['code'] == done['result']['error']['code'],
                         'sdk-original-error')
                entry.update(response=terminal, response_body=value)
            else:
                terminal = errors[0]
                need(not done['result']['ok'] and done['result']['error']['code'] == 'UNKNOWN', 'original-unknown-not-overwritten')
            if not done['result']['ok'] and done['result']['error']['code'] == 'UNKNOWN':
                reference = {'scope': body['scope'], 'operation': body['operation']}
                for key, public in (('request', 'request'), ('nonce', 'nonce'), ('expected_worker_instance', 'expectedWorkerInstance'),
                    ('expected_revision', 'expectedRevision'), ('expected_head_serial', 'expectedHeadSerial'),
                    ('plan_serial', 'planSerial'), ('batch_serial', 'batchSerial'), ('generation', 'storageGeneration'),
                    ('after', 'after'), ('input', 'ownerInput'), ('identity', 'ownerIdentity'), ('plan', 'ownerPlan')):
                    if key in body:
                        reference[public] = body[key]
                need(done['result']['error']['reference'] == reference, 'original-unknown-reference')
            entry.update(request=request, body=body, terminal=terminal, principal=principal)
            calls[name] = entry
        need(len(selection(ledger, 'http_request')) == sum(call['sdk'] == role for call in calls.values()), 'all-sdk-posts-accounted')
    need(len([entry for entry in local.values() if entry['command']['operation'] == 'owner_save']) == saved_count,
         'all-owner-originals-saved')
    for call in calls.values():
        if call['body']['operation'].startswith('owner_'):
            saved = owners[call['command']['intent']]
            need('saved_at' in saved and moment(saved['saved_at']) < moment(call['request']), 'owner-save-before-every-dispatch')
    method_names = ('owner_prepare', 'owner_claim', 'owner_resume', 'owner_abort', 'owner_inspect')
    for name, counts in owner_counts.items():
        observed = tuple(sum(call['command']['scope_name'] == name and call['body']['operation'] == method
                             for call in calls.values()) for method in method_names)
        need(observed == counts, 'fixed-owner-post-denominator')
    need(sum(call['body']['operation'].startswith('owner_') for call in calls.values()) == sum(map(sum, owner_counts.values())),
         'all-owner-posts-accounted')
    return calls, local


def http_exchanges(directory, events, calls, expected_count=10):
    starts = {row['role']: row for row in selection(events, 'http_proxy_started')}
    ends = {row['role']: row for row in selection(events, 'http_proxy_closed')}
    need(set(starts) == set(ends) and len(starts) == expected_count, 'http-proxy-lifetime')
    expected_limits = {'request_bytes': 1048576, 'response_bytes': 67108864, 'header_bytes': 16384,
        'headers': 64, 'handlers': 16, 'requests': 10000, 'gates': 128, 'input_seconds': 10,
        'output_seconds': 10, 'backend_seconds': 330, 'hold_seconds': 180, 'close_seconds': 10}
    groups = defaultdict(dict)
    stages = ('handler_started', 'request', 'forward_started', 'forward_finished', 'backend_response',
              'backend_failure', 'delivery_started', 'delivery_finished', 'handler_finished')
    for row in events:
        if row['event'].startswith('http_proxy_') and row['event'].removeprefix('http_proxy_') in stages:
            stage = row['event'].removeprefix('http_proxy_')
            group = groups[(row['role'], row['serial'])]
            need(stage not in group, 'http-proxy-stage-unique')
            group[stage] = row
    for role, first in starts.items():
        last = ends[role]
        need(first['limits'] == expected_limits and last['joined'] and last['errors'] == [], 'http-proxy-original-limits')
        need(sorted(serial for r, serial in groups if r == role) == list(range(1, last['request_count'] + 1)),
             'http-proxy-closed-denominator')
        connections = selection(events, 'http_proxy_connection_started', role=role)
        finished = selection(events, 'http_proxy_connection_finished', role=role)
        need(sorted(row['connection'] for row in connections) == list(range(1, last['connection_count'] + 1))
             and len(finished) == len(connections), 'http-proxy-connection-denominator')
        for begin in connections:
            end = one(finished, 'http_proxy_connection_finished', role=role, connection=begin['connection'])
            need(moment(begin) < moment(end) < moment(last), 'http-owned-connection-lifetime')
            if end['serial'] is None:
                one(events, 'http_proxy_connection_empty', role=role, connection=begin['connection'])
            else:
                need(groups[(role, end['serial'])]['request']['connection'] == begin['connection'], 'http-request-owned-connection')
    candidates = defaultdict(list)
    for key, group in groups.items():
        need(all(stage in group for stage in ('request', 'handler_started', 'forward_started', 'handler_finished')), 'http-proxy-request-lifetime')
        request = group['request']
        need(all(all(row.get(field) == request[field] for field in ('role', 'serial', 'phase', 'method', 'path', 'operation'))
                 for row in group.values()), 'http-original-method-path')
        payload = raw(directory, request['request'])
        need(request['method'] == 'POST' and request['path'] in ('/v1', '/v1/catalogue')
             and int(request['headers']['content-length']) == len(payload) <= 1048576
             and 'authorization' not in request['headers']
             and wire.parse(payload)['operation'] == request['operation'], 'http-original-request-bytes')
        forward = group['forward_started']
        need(forward['request'] == request['request'] and forward['headers']['x-scap-admission'] == request['headers']['x-scap-admission']
             and forward['target_port'] == starts[key[0]]['target_port'], 'http-forward-original-no-retry')
        need(moment(group['handler_started']) <= moment(request) < moment(forward) < moment(group['handler_finished']), 'http-proxy-causal-order')
        need(('backend_response' in group) != ('backend_failure' in group), 'http-proxy-product-terminal')
        product = group.get('backend_response')
        if product is not None:
            need('forward_finished' in group and moment(forward) < moment(product) < moment(group['handler_finished']), 'http-product-response-order')
            raw(directory, product['response'])
        if 'delivery_started' in group:
            delivered = group['delivery_started']
            need(product is not None and delivered['response'] == product['response'] and delivered['status'] == product['status']
                 and 'delivery_finished' in group and moment(product) < moment(delivered)
                 <= moment(group['delivery_finished']) < moment(group['handler_finished']), 'http-unaltered-product-delivery')
        endpoint = starts[key[0]]['endpoint'] + request['path']
        candidates[(endpoint, request['request']['sha256'], request['principal'])].append((key, group))
    for values in candidates.values():
        values.sort(key=lambda item: moment(item[1]['request']))
    used = set()
    for call in sorted(calls.values(), key=lambda item: moment(item['request'])):
        request = call['request']
        key = (request['url'], request['request']['sha256'], request['principal'])
        matches = candidates.get(key, [])
        need(matches, 'original-sdk-real-http-request')
        identifier, group = matches.pop(0)
        need(identifier not in used and group['request']['request'] == request['request']
             and group['request']['token_sha256'] == request['token_sha256']
             and moment(request) < moment(group['request']) < moment(call['terminal']), 'sdk-http-original-binding')
        used.add(identifier)
        if call['response'] is not None:
            need('backend_response' in group and 'delivery_finished' in group
                 and group['delivery_finished']['complete'] is True
                 and call['response']['response'] == group['backend_response']['response'], 'sdk-received-original-product-response')
        call.update(proxy=group, role=identifier[0].split('-')[0], front=identifier[0],
                    product=group.get('backend_response'), product_body=None)
        if call['product'] is not None:
            call['product_body'] = wire.parse(raw(directory, call['product']['response']))
        group['call'] = call
    need(len(used) == len(groups) and all(not remaining for remaining in candidates.values()), 'all-product-posts-accounted')
    need(not selection(events, 'http_proxy_fixture_error') and not selection(events, 'http_proxy_connection_rejected'),
         'http-proxy-no-observer-errors')
    return groups, starts


class ObservationIndex(list):
    """Index immutable raw records once, without caching verdicts."""
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
        self.times = {role: [moment(value['request']) for value in records] for role, records in self.roles.items()}

    def at_path(self, path):
        return self.paths.get(path, ())

    def method(self, method):
        return self.methods.get(method, ())

    def interval(self, role, start, end):
        records, times = self.roles.get(role, ()), self.times.get(role, ())
        return records[bisect_right(times, start):bisect_left(times, end)]

    def for_call(self, call, before=None):
        terminal = call['proxy'].get('backend_response') or call['proxy'].get('backend_failure')
        until = moment(terminal) if before is None else before
        records = self.interval(call['role'], moment(call['proxy']['forward_started']), until)
        logical = call['body'].get('scope', call['body'].get('creation', {}).get('scope'))
        if logical is None:
            return list(records)
        return [value for value in records if path_database(value['request']['path']) in (None, int(logical['database']))]


def path_database(path):
    value = urlsplit(path).path
    if '/catalogue/v1/' in value or value in ('/scap-test', '/scap-test/'):
        return None
    parts = value.split('/')
    return int(parts[6]) if len(parts) >= 8 and parts[1:6] == ['scap-test', 'scap-object', 'v1', '1', '7'] else None


def s3_exchanges(directory, events, backend):
    stages = ('s3_request', 's3_forward_started', 's3_backend_response', 's3_delivery_started',
              's3_delivery_finished', 's3_handler_started', 's3_handler_finished')
    groups = defaultdict(dict)
    for row in events:
        if row['event'] in stages:
            group = groups[(row['role'], row['serial'])]
            need(row['event'] not in group, 's3-stage-unique')
            group[row['event']] = row
    closed = {row['role']: row for row in selection(events, 's3_proxy_stopped')}
    for role, end in closed.items():
        need(type(end['request_count']) is int and end['request_count'] >= 0
             and sorted(serial for r, serial in groups if r == role) == list(range(1, end['request_count'] + 1)),
             's3-closed-denominator')
    need({role for role, _ in groups} <= set(closed), 's3-closed-denominator')
    values = []
    for key, group in groups.items():
        need(all(stage in group for stage in ('s3_request', 's3_handler_started', 's3_handler_finished')), 's3-handler-lifetime')
        request = group['s3_request']
        need(all(all(row[field] == request[field] for field in ('method', 'path', 'phase'))
                 for row in group.values()), 's3-original-method-path')
        payload = raw(directory, request['request'])
        need(request['method'] in ('GET', 'PUT', 'DELETE') and request['signature_valid'] is True
             and request['access_sha256'] in (backend['normal_access_sha256'], backend['gc_access_sha256']), 'actual-s3-signature')
        need(int(request['headers'].get('content-length', '0')) == len(payload)
             and request['headers'].get('x-amz-content-sha256') == sha(payload), 'signed-original-payload-hash')
        need(moment(group['s3_handler_started']) <= moment(request) < moment(group['s3_handler_finished']), 's3-handler-order')
        value = {'request': request, 'payload': payload, 'group': group, 'backend': group.get('s3_backend_response'),
                 'delivered': False, 'delivery_complete': False, 'delivery_bytes': None}
        if value['backend'] is not None:
            need('s3_forward_started' in group and moment(request) <= moment(group['s3_forward_started'])
                 < moment(value['backend']) < moment(group['s3_handler_finished']), 'actual-s3-backend-order')
            value['bytes'] = raw(directory, value['backend']['response'])
        else:
            need('s3_forward_started' not in group and group.get('s3_delivery_started', {}).get('origin') == 'fixture_no_such_key',
                 's3-original-backend-accounting')
        if 's3_delivery_started' in group:
            delivery = group['s3_delivery_started']
            need('s3_delivery_finished' in group and moment(delivery) <= moment(group['s3_delivery_finished'])
                 < moment(group['s3_handler_finished']), 's3-delivery-lifetime')
            value['delivery_bytes'] = raw(directory, delivery['response'])
            value['delivery_complete'] = group['s3_delivery_finished']['complete'] is True
            if delivery['origin'] == 'backend':
                need(value['backend'] is not None and delivery['status'] == value['backend']['status']
                     and delivery['response'] == value['backend']['response']
                     and moment(value['backend']) < moment(delivery), 'unaltered-s3-backend-response')
                value['delivered'] = value['delivery_complete']
            elif delivery['origin'] == 'fixture_no_such_key':
                fault = one(events, 'fault_arrived', role=key[0], serial=key[1])
                need(fault['mode'] == 'no_such_key' and delivery['status'] == 404 and value['backend'] is None
                     and value['delivery_bytes'] == b'<Error><Code>NoSuchKey</Code><Message>fixture</Message></Error>',
                     'only-explicit-missing-delivery')
            else:
                need(delivery['origin'] == 'fixture_metadata_mutation' and value['backend'] is not None,
                     'only-explicit-metadata-delivery')
                replacement = one(events, 'fault_body_replaced', role=key[0], serial=key[1])
                need(replacement['original'] == value['backend']['response'] and replacement['replacement'] == delivery['response'],
                     'metadata-fault-original-and-delivery')
                native_value = wire.parse(value['bytes'])
                mutation = replacement['mutation']
                if replacement['id'] == 'same-id-different-hash':
                    need(mutation['kind'] == 'same_id_hash' and set(mutation) ==
                         {'kind', 'creator', 'operation', 'descriptor_hash'}, 'fixed-hash-fault-shape')
                    reference = native_value['owner_plan']['reference']
                    need(reference['creator'] == mutation['creator'] and reference['operation'] == mutation['operation']
                         and reference['descriptor_hash'] != mutation['descriptor_hash'], 'same-id-only-hash-fault')
                    reference['descriptor_hash'] = mutation['descriptor_hash']
                elif replacement['id'] == 'old-proof-not-before-admission':
                    need(mutation['kind'] == 'proof_at_admission' and set(mutation) == {'kind', 'revision', 'head_serial'},
                         'fixed-proof-fault-shape')
                    for field in ('revision', 'head_serial'):
                        native_value['marker']['phase'][field] = mutation[field]
                else:
                    need(False, 'unplanned-metadata-fault')
                need(value['delivery_bytes'] == model.encoded(native_value), 'exact-predeclared-metadata-fault')
        else:
            one(events, 'fault_suppressed', role=key[0], serial=key[1])
        values.append(value)
    need(not selection(events, 's3_fixture_error'), 's3-observer-errors')
    return ObservationIndex(sorted(values, key=lambda value: moment(value['request'])))


def histories(directory, inputs, values):
    known = {model.scope_key(native(logical)) for logical in inputs['scopes'].values()}
    heads, objects, metadata, owner_records = defaultdict(list), {}, defaultdict(list), {}
    accepted = [value for value in values if value['request']['method'] == 'PUT'
                and value['backend'] is not None and value['backend']['status'] == 200]
    for exchange in sorted(accepted, key=lambda value: moment(value['backend'])):
        request, payload = exchange['request'], exchange['payload']
        path, database = request['path'], model.head_path(request['path'])
        etag = exchange['backend']['headers'].get('etag')
        need(isinstance(etag, str), 'accepted-backend-etag')
        if database is not None:
            value = model.head(payload, known)
            need(value['scope']['database'] == database, 'physical-head-slot')
            previous = heads[database][-1] if heads[database] else None
            if previous is None:
                need(value['head_serial'] == value['revision'] == 1 and request['headers'].get('if-none-match') == '*'
                     and request['headers'].get('if-match') is None, 'initial-absent-head')
                kind = 'create'
            else:
                need(request['headers'].get('if-match') == previous['exchange']['backend']['headers']['etag']
                     and request['headers'].get('if-none-match') is None
                     and moment(previous['exchange']['backend']) < moment(exchange['group']['s3_forward_started']), 'original-head-etag')
                reads = [read for read in values.at_path(path) if read['request']['role'] == request['role']
                    and read['request']['method'] == 'GET' and read['delivered'] and read['backend']['status'] == 200
                    and read['bytes'] == previous['exchange']['payload']
                    and read['backend']['headers'].get('etag') == request['headers']['if-match']
                    and moment(read['group']['s3_delivery_finished']) < moment(request)]
                need(reads, 'same-exact-get-body-etag')
                kind = model.advance(previous['head'], value)
            record = {'head': value, 'kind': kind, 'previous': previous, 'exchange': exchange}
            heads[database].append(record)
            exchange['head_record'] = record
        elif '/owner/v1/' in path:
            logical, kind, _, _ = model.owner_key(path)
            need(model.scope_key(logical) in known and path not in owner_records
                 and request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None,
                 'permanent-owner-record-once-absent')
            value = model.descriptor(payload, path) if kind == 'descriptor' else model.proof(payload, path)
            record = {'kind': kind, 'value': value, 'exchange': exchange}
            owner_records[path] = record
            exchange['owner_record'] = record
        elif '/catalogue/v1/' in path:
            kind, value = model.catalogue(payload, path)
            previous = metadata[path][-1] if metadata[path] else None
            if kind == 'name' and previous is not None:
                need(request['headers'].get('if-match') == previous['exchange']['backend']['headers']['etag']
                     and request['headers'].get('if-none-match') is None, 'original-name-etag')
            else:
                need(previous is None and request['headers'].get('if-none-match') == '*'
                     and request['headers'].get('if-match') is None, 'immutable-catalogue-record')
            record = {'kind': kind, 'value': value, 'previous': previous, 'exchange': exchange}
            metadata[path].append(record)
            exchange['metadata_record'] = record
        else:
            model.envelope(payload, path)
            need(request['headers'].get('if-none-match') == '*' and request['headers'].get('if-match') is None,
                 'immutable-payload-absent')
            need(path not in objects or objects[path] == payload, 'immutable-payload-content')
            objects[path] = payload
    need(set(heads) == {int(value['database']) for value in inputs['scopes'].values()}, 'all-real-head-slots')
    for exchange in values:
        request, response = exchange['request'], exchange['backend']
        if request['method'] != 'GET' or response is None or response['status'] != 200:
            continue
        path, database = request['path'], model.head_path(request['path'])
        versions = heads.get(database) if database is not None else (
            [owner_records[path]] if path in owner_records else metadata.get(path))
        if versions is not None:
            matching = [record for record in versions if record['exchange']['payload'] == exchange['bytes']
                        and record['exchange']['backend']['headers'].get('etag') == response['headers'].get('etag')
                        and moment(record['exchange']['backend']) < moment(response)]
            need(len(matching) == 1, 'actual-exact-read-version')
            exchange['read_head' if database is not None else 'read_owner' if path in owner_records else 'read_metadata'] = matching[0]
        elif '/objects/' in path:
            model.envelope(exchange['bytes'], path)
            need(path in objects and objects[path] == exchange['bytes'], 'actual-immutable-read-version')
    return heads, objects, owner_records, metadata
