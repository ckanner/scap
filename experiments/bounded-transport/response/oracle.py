#!/usr/bin/env python3
"""Audit raw TCP, SDK, S3 and owned child histories without product code."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scap_response_raw_audit', HERE.parents[1] / 'output-pool/oracle.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
wire, need, raw, rows, time_of = common.wire, common.need, common.raw, common.rows, common.time_of
SLOW = ('stalled', 'drip', 'committed', 'shutdown')
SCOPE = {'deployment': '1', 'tenant': '7', 'database': '101', 'incarnation': '1', 'generation': '1'}


def one(records, kind, identifier=None):
    values = [r for r in records if r['event'] == kind and (identifier is None or r.get('id') == identifier)]
    need(len(values) == 1, 'event-denominator:' + kind)
    return values[0]


def deadline_case(directory, events, identifier, request, response):
    header = one(events, 'slow_headers', identifier)
    drain = one(events, 'slow_drain_started', identifier)
    received = raw(directory, response['response'])
    head = raw(directory, header['headers']).decode('latin1')
    need(head.startswith('HTTP/1.1 200 ') and head.endswith('\r\n\r\n'), 'slow-header')
    lengths = [int(line.split(':', 1)[1]) for line in head.split('\r\n')
               if line.lower().startswith('content-length:')]
    need(lengths == [header['content_length']] and 'transfer-encoding:' not in head.lower(), 'slow-framing')
    need(header['status'] == response['status'] == 200 and header['content_length'] > 21 * 1024 * 1024,
         'slow-length')
    need(header['body_bytes_read'] == drain['body_bytes_read'] == 0
         and 4096 <= header['receive_buffer'] <= 16384, 'slow-consumer')
    need(time_of(request) < time_of(header) < time_of(drain) < time_of(response), 'slow-order')
    drips = [r for r in events if r['event'] == 'slow_drip' and r['id'] == identifier]
    need([r['ordinal'] for r in drips] == ([1, 2, 3] if identifier == 'drip' else []), 'drip-count')
    prefix = b''
    for row, offset in zip(drips, (.5, 1, 1.5)):
        byte = raw(directory, row['response'])
        need(len(byte) == 1, 'drip-byte')
        need(offset - .2 <= (time_of(row) - time_of(header)) / 1e9 <= offset + .2, 'drip-time')
        prefix += byte
    need(response['expected_bytes'] == header['content_length']
         and len(prefix) + len(received) < header['content_length']
         and response['complete'] is False, 'peer-truncated')
    need(response['peer_eof'] is True or response['peer_failure'] in ('ConnectionResetError', 'BrokenPipeError'),
         'peer-closed')
    need(not any(r['event'] in ('slow_disconnect_requested', 'slow_disconnected')
                 and r.get('id') == identifier for r in events), 'no-client-disconnect')
    if identifier != 'shutdown':
        need(2.1 <= (time_of(drain) - time_of(header)) / 1e9 <= 2.7, 'absolute-drain-window')
    need(0 < (time_of(response) - time_of(drain)) / 1e9 <= 2, 'peer-close-window')
    return header, drain


def audit(directory):
    directory = Path(directory)
    inputs = wire.parse((directory / 'inputs.json').read_bytes())
    common.identity(directory, inputs)
    config = wire.parse((directory / 'service-config.json').read_bytes())
    transport = config['transport']
    need(inputs['profile'] in ('bounded', 'baseline') and transport['max_connections'] == 8
         and transport['header_timeout_ms'] == 5000, 'transport-profile')
    if inputs['profile'] == 'bounded':
        need(transport['response_timeout_ms'] == 2000 and transport['shutdown_timeout_ms'] == 500,
             'transport-deadlines')
    else:
        need('response_timeout_ms' not in transport and 'shutdown_timeout_ms' not in transport, 'baseline-profile')
    credentials = {c['sha256']: c for c in config['credentials']}
    events, sdk = rows(directory / 'events.jsonl'), rows(directory / 'sdk.jsonl')
    need([r['sequence'] for r in events] == list(range(1, len(events) + 1)), 'event-sequence')
    need(all(time_of(a) <= time_of(b) for a, b in zip(events, events[1:])), 'event-order')
    requests, responses = {}, {}
    for row in [*events, *sdk]:
        if row['event'] == 'http_request':
            need(row['id'] not in requests, 'http-duplicate')
            requests[row['id']] = {**row, 'body': wire.parse(raw(directory, row['request']))}
        elif row['event'] == 'http_response':
            need(row['id'] not in responses, 'http-duplicate')
            responses[row['id']] = row.copy()
            if row['id'] not in SLOW:
                responses[row['id']]['body'] = wire.parse(raw(directory, row['response']))
    expected = {'setup-1', 'setup-2', 'setup-3', 'after-stalled-1', 'after-drip-1', 'lookup-1', 'lookup-2', *SLOW}
    need(set(requests) == set(responses) == expected and len(requests) == 11, 'http-denominator')
    for name, request in requests.items():
        need(request['body']['version'] == 1 and request['body']['scope'] == SCOPE, 'request-scope')
        credential = credentials.get(request['token_sha256'])
        need(credential is not None and credential['tenant'] == '7' and credential['principal'] == '11',
             'request-credential')
        need(time_of(request) < time_of(responses[name]), 'response-time')
        if name not in SLOW:
            need(responses[name]['status'] == 200 and responses[name]['complete'] is True
                 and responses[name]['body']['ok'] is True, 'sdk-success')
    heads = {}
    for name in SLOW:
        heads[name], _ = deadline_case(directory, events, name, requests[name], responses[name])
        need(requests[name]['body']['operation'] == ('execute' if name == 'committed' else 'query'), 'slow-operation')
    for name in ('after-stalled', 'after-drip'):
        request, response = requests[name + '-1'], responses[name + '-1']
        need(request['body']['operation'] == 'query'
             and wire.result(wire.b64(response['body']['value']['result']))[0]['rows'] == [[17]], 'healthy-query')
        need(time_of(responses[name.removeprefix('after-')]) < time_of(request), 'healthy-after-expiry')
    intent_record = wire.parse((directory / 'intent.json').read_bytes())
    intent = wire.parse(intent_record['serialized'])
    original = requests['committed']['body']
    need(int(intent_record['prepared_monotonic_ns']) < time_of(requests['stalled']), 'intent-before-pressure')
    need(original['scope'] == intent['scope'] and original['request'] == intent['request']
         and original['statements'] == intent['statements'], 'original-intent')
    need(original['request']['id'] == '2' and original['request']['principal'] == '11'
         and original['request']['fingerprint'] == wire.fingerprint(original['statements']), 'original-fingerprint')
    executions = [r for r in requests.values() if r['body']['operation'] == 'execute'
                  and r['body']['request'] == original['request']]
    need(len(executions) == 1, 'sql-not-replayed')
    lookup = responses['lookup-1']['body']['value']
    need(requests['lookup-1']['body']['operation'] == 'lookup'
         and requests['lookup-1']['body']['request'] == original['request']
         and lookup['state'] == 'committed', 'lookup-original')
    need(time_of(responses['committed']) < time_of(requests['lookup-1']), 'lookup-after-truncation')
    receipt = lookup['receipt']
    need(receipt['scope'] == original['scope'] and receipt['request'] == original['request'], 'lookup-receipt')
    recovered, decoded = wire.committed(lookup)
    need(len(decoded) == 1 and decoded[0]['columns'] == ['b' + str(i) for i in range(8)]
         and len(decoded[0]['rows']) == 1 and len(decoded[0]['rows'][0]) == 8, 'result-shape')
    need(all(type(b) is bytes and len(b) == 2097152 and b.count(0) == len(b)
             for b in decoded[0]['rows'][0]), 'result-bytes')
    need(decoded[0]['affected_rows'] == 1 and decoded[0]['last_insert_rowid'] == 1, 'committed-row-effect')
    need(requests['lookup-2']['body']['operation'] == 'query'
         and wire.result(wire.b64(responses['lookup-2']['body']['value']['result']))[0]['rows'] == [[1]], 'single-effect')
    history = rows(directory / 'history.jsonl')
    puts = [r for r in history if r['event'] == 'object_response' and r['method'] == 'PUT' and r['status'] == 200]
    need(all(r['response_origin'] == 'backend' and r['suppressed'] is False for r in puts), 'real-s3-acceptance')
    publications = [r for r in puts if r['phase'] == 'committed' and r['path'].endswith('/head')]
    need(len(publications) == 1, 'one-business-publication')
    publication = publications[0]
    head = wire.parse(bytes(publication['head_request_bytes']))
    need(time_of(requests['committed']) < time_of(publication) < time_of(heads['committed']), 'commit-before-response')
    need(head['scope'] == {k: int(v) for k, v in receipt['scope'].items()}
         and head['sequence'] == int(receipt['sequence']) and head['data_root'] == receipt['data_root']
         and head['transition'] == {k: int(v) for k, v in receipt['transition'].items()}, 'head-receipt')
    need(isinstance(publication['if_match'], str) and publication['if_none_match'] is None, 'head-cas')
    reads = [r for r in history if r['event'] == 'object_response' and r['method'] == 'GET' and r['status'] == 200]
    need(any(r['path'] == publication['path'] and r['etag'] == publication['if_match']
             and time_of(r) < time_of(publication) for r in reads), 'original-head-etag')
    results = [r for r in puts if r['phase'] == 'committed' and r['path'].endswith('/' + receipt['result_hash'])]
    need(len(results) == 1 and results[0]['request_sha256'] == receipt['result_hash']
         and results[0]['if_none_match'] == '*' and results[0]['if_match'] is None, 'result-put')
    result = results[0]
    need(any(r['path'] == result['path'] and r['response_sha256'] == receipt['result_hash']
             and r['response_bytes'] == result['request_bytes']
             and time_of(result) < time_of(r) < time_of(publication) for r in reads), 'result-readback')
    stopping, stopped = one(events, 'service_stop_requested'), one(events, 'service_stopped')
    need(stopping['signal'] == 'SIGINT' and stopping['identity'] == stopped['identity']
         and stopped['status'] == 0 and stopped['usage'].get('source') == 'kernel_wait4_owned_child', 'owned-exit')
    need(time_of(heads['shutdown']) < time_of(stopping) < time_of(stopped)
         < time_of(one(events, 'slow_drain_started', 'shutdown')), 'shutdown-held-until-exit')
    need(.3 <= (time_of(stopped) - time_of(stopping)) / 1e9 <= 1.8, 'shutdown-window')
    need(not any(r['event'] == 'service_forced_stop' for r in events), 'not-forced-exit')
    nodes = [r for r in events if r['event'] == 'node_stopped']
    need(tuple(r['phase'] for r in nodes) == ('setup', 'after-stalled', 'after-drip', 'lookup')
         and all(r['status'] == 0 and not r['forced'] and r['usage'].get('source') == 'kernel_wait4_owned_child'
                 for r in nodes), 'sdk-processes')
    need(one(events, 'unsigned_probe')['status'] == 403, 'signed-backend')
    proxy, backend = one(events, 'proxy_stopped'), one(events, 'backend_stopped')
    need(proxy['joined'] is True and proxy['errors'] == [] and len(backend['processes']) == 4
         and all(r['wait_status'] == -9 and r['kernel_usage'].get('source') == 'kernel_wait4_owned_child'
                 for r in backend['processes']), 'owned-cleanup')
    startup = common.startup_objects(config, events, history,
        phases=('setup', 'after-stalled', 'after-drip', 'lookup', *SLOW), binary=inputs['tools']['scapd'],
        configuration_sha256=common.digest((directory / 'service-config.json').read_bytes()))
    return {'status': 'PASSED', 'profile': inputs['profile'], 'http_posts': len(requests),
        'peer_truncated_responses': len(SLOW), 'body_drips': 3, 'business_sql_executions': 1,
        'committed_result_bytes': len(recovered), 'committed_result_sha256': common.digest(recovered),
        'connection_shutdown_seconds': (time_of(stopped) - time_of(stopping)) / 1e9,
        'worker_startup': startup,
        'aws_standard': 'NOT_RUN', 'production_slo_passed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    print(json.dumps(audit(parser.parse_args().evidence), sort_keys=True))
