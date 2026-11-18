"""Independent complete S3 exchanges, original authority and ACK dependencies."""
from collections import defaultdict
from bisect import bisect_right
import re
import struct

import oracle as o
import spec


def frame(data, path, scope):
    o.need(len(data) >= 20 and data[:8] == b'SCAPOBJ2' and path.rsplit('/', 1)[1] == o.digest(data),
           'immutable-frame')
    meta, length = struct.unpack_from('<IQ', data, 8)
    o.need(meta <= 65516 and 20 + meta + length == len(data), 'immutable-frame-length')
    value = o.wire.parse(data[20:20 + meta])
    o.same(value['scope'], scope, 'immutable-scope')
    o.need(value['format'] == 2 and set(value['payload']) == {'kind', 'value'}, 'immutable-format')
    return value['payload']['kind'], value['payload']['value'], data[20 + meta:]


def closures(accepted, requests, responses, heads, prefixes):
    reads = defaultdict(list)
    for serial, response in responses.items():
        if requests[serial]['method'] == 'GET' and response['status'] == 200:
            reads[(response['path'], response['response_sha256'])].append(o.moment(response))
    for times in reads.values():
        times.sort()
    objects = {}
    for request, response, data in accepted:
        if '/objects/' not in request['path']:
            continue
        scope_name = next(name for name, prefix in prefixes.items() if request['path'].startswith(prefix))
        decoded = frame(data, request['path'], {k: int(v) for k, v in spec.SCOPES[scope_name].items()})
        times = reads[(request['path'], o.digest(data))]
        index = bisect_right(times, o.moment(response))
        objects[request['path']] = (decoded, times[index] if index < len(times) else None)
    # Memoize validated immutable dependency closures. Every dependency's first
    # complete readback must precede each HEAD that publishes that closure.
    checked, visiting = {}, set()

    def dependency(path):
        if path in checked:
            return checked[path]
        o.need(path in objects and path not in visiting and len(visiting) <= 12, 'publication-closure')
        visiting.add(path)
        (kind, value, data), ready = objects[path]
        o.need(ready is not None, 'dependency-readback')
        prefix = path.rsplit('/', 1)[0] + '/'
        children = []
        if kind == 'manifest':
            o.need(not data and type(value['page_count']) is int and value['page_count'] >= 0, 'manifest-payload')
            if value['root'] is not None:
                children = [value['root']]
        elif kind == 'node':
            o.need(not data and 0 <= value['level'] <= 4 and 0 < len(value['children']) <= 256, 'node-payload')
            children = value['children']
        elif kind == 'chunk':
            o.need(value['first_page'] >= 1 and value['bytes'] == [] and
                   0 < len(data) <= 131072 and len(data) % 4096 == 0, 'chunk-payload')
        elif kind == 'index':
            o.need(not data, 'index-payload')
            if value['kind'] == 'branch':
                children = [child['hash'] for child in value['children']]
            else:
                o.need(value['kind'] == 'leaf', 'index-payload')
                children = [entry['outcome']['result'] for entry in value['entries']
                            if entry['outcome']['state'] == 'committed']
        else:
            o.need(kind == 'result' and value['bytes'] == [], 'result-payload')
            o.wire.result(data)
        for child in children:
            o.need(type(child) is str and re.fullmatch('[0-9a-f]{64}', child), 'dependency-hash')
            ready = max(ready, dependency(prefix + child))
        visiting.remove(path)
        checked[path] = ready
        return ready

    count = 0
    for request, _, data in accepted:
        name = next((name for name, path in heads.items() if path == request['path']), None)
        if name is None:
            continue
        head = o.wire.parse(data)
        roots = [window['root'] for window in head['windows']]
        if head['data_root'] is not None:
            roots.append(head['data_root'])
        for root in roots:
            o.need(dependency(prefixes[name] + root) < o.moment(request), 'closure-before-head')
        count += 1
    return {'head_publications': count, 'distinct_dependencies': len(checked),
            'all_required_immutable_readbacks_before_publication': True}


def audit(directory, calls, committed, events):
    history = o.rows(directory / 's3.jsonl')
    o.need([r['sequence'] for r in history] == list(range(1, len(history) + 1)), 's3-trace-sequence')
    o.need(all(o.moment(b) > o.moment(a) for a, b in zip(history, history[1:])), 's3-trace-clock')
    o.need(all(r['event'] in ('request', 'forwarded', 'response', 'delivered') for r in history), 's3-proxy-error')
    groups = defaultdict(list)
    for row in history:
        groups[row['request_serial']].append(row)
    stopped = o.one([r for r in events if r['event'] == 'proxy_stopped'], 'proxy-cleanup')
    total = stopped['request_count']
    o.need(type(total) is int and 0 < total <= spec.BOUNDS['s3_requests']
           and sorted(groups) == list(range(1, total + 1)), 's3-denominator')
    heads = {name: ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/head').format(**scope)
             for name, scope in spec.SCOPES.items()}
    prefixes = {name: ('/scap-test/scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}'
                '/gen/{generation}/storage/1/objects/').format(**scope) for name, scope in spec.SCOPES.items()}
    worker = f'/scap-test/scap-worker/v1/instances/{spec.WORKER}'
    marker = b'SCAP-WORKER-INSTANCE-v1\0' + struct.pack('>Q', spec.WORKER)
    requests, responses, accepted = {}, {}, []
    for serial, group in groups.items():
        request, forwarded, response, delivered = (o.one([r for r in group if r['event'] == event], 's3-exchange')
                                                  for event in ('request', 'forwarded', 'response', 'delivered'))
        o.need(o.moment(request) < o.moment(forwarded) < o.moment(response) <= o.moment(delivered), 's3-clock')
        for row in group:
            for key in ('phase', 'method', 'path', 'request', 'if_match', 'if_none_match', 'signing'):
                o.same(row[key], request[key], 's3-original-request')
        for key in ('status', 'response', 'etag'):
            o.same(delivered[key], response[key], 's3-original-response')
        body, reply = o.raw(directory, request['request']), o.raw(directory, response['response'])
        path, method = request['path'], request['method']
        bound = [name for name in spec.SCOPES if path == heads[name] or
                 re.fullmatch(re.escape(prefixes[name]) + '[0-9a-f]{64}', path)]
        o.need((len(bound) == 1 or path == worker) and method in ('GET', 'PUT'), 's3-exact-namespace')
        o.need(response['status'] in ((200, 404) if method == 'GET' else (200, 412)), 's3-status')
        if response['status'] == 200:
            o.need(type(response['etag']) is str and bool(response['etag']), 's3-etag')
        signed = request['signing']
        o.need({'host', 'x-amz-date', 'x-amz-content-sha256'} <= set(signed['signed_headers'])
               and re.fullmatch('[0-9a-f]{64}', signed['access_key_sha256'])
               and signed['payload_sha256'] == o.digest(body), 'signed-s3')
        if path == worker:
            o.need(response['status'] == 200 and request['phase'] == 'startup', 'worker-claim-success')
            if method == 'PUT':
                o.need(request['if_none_match'] == '*' and request['if_match'] is None, 'worker-claim-create-only')
                o.need(body == marker, 'worker-claim-body')
            else:
                o.need(reply == marker, 'worker-claim-body')
        q = {'monotonic_ns': o.moment(request), 'phase': request['phase'], 'method': method, 'path': path,
             'request_bytes': len(body), 'request_sha256': o.digest(body),
             'if_match': request['if_match'], 'if_none_match': request['if_none_match']}
        r = {**q, 'monotonic_ns': o.moment(response), 'status': response['status'],
             'response_bytes': len(reply), 'response_sha256': o.digest(reply), 'etag': response['etag']}
        if path.endswith('/head'):
            q['head_request_bytes'], r['head_request_bytes'], r['head_response_bytes'] = list(body), list(body), list(reply)
        if method == 'GET':
            o.need(not body and request['if_match'] is None and request['if_none_match'] is None, 's3-get-conditions')
            if '/objects/' in path and response['status'] == 200:
                frame(reply, path, {k: int(v) for k, v in spec.SCOPES[bound[0]].items()})
        else:
            o.need((request['if_match'] is None and request['if_none_match'] == '*') or
                   (type(request['if_match']) is str and request['if_none_match'] is None), 's3-put-conditions')
            if response['status'] == 200:
                accepted.append((request, response, body))
                if '/objects/' in path:
                    o.need(request['if_none_match'] == '*' and request['if_match'] is None, 'immutable-create-only')
                    frame(body, path, {k: int(v) for k, v in spec.SCOPES[bound[0]].items()})
        requests[serial], responses[serial] = q, r
    claims = [serial for serial, request in requests.items() if request['path'] == worker]
    o.need(len(claims) == 2 and [requests[i]['method'] for i in claims] == ['PUT', 'GET'], 'worker-claim-denominator')
    put, get = claims
    launch = o.one([r for r in events if r['event'] == 'service_start_requested'], 'service-launch')
    ready = o.one([r for r in events if r['event'] == 'readiness_probe' and r['status'] == 200], 'service-readiness')
    o.need(o.wire.parse(o.raw(directory, ready['response'])) == {'status': 'alive', 'protocol': 1}, 'readiness-body')
    o.need(o.moment(launch) < o.moment(requests[put]) < o.moment(responses[put])
           < o.moment(requests[get]) < o.moment(responses[get]) < o.moment(ready), 'worker-startup-window')
    o.need(responses[put]['etag'] == responses[get]['etag'], 'worker-claim-readback')
    try:
        authority = o.wire.object_versions(requests, responses)
    except (ValueError, KeyError):
        raise o.Rejected('original-s3-authority') from None
    publication_closures = closures(accepted, requests, responses, heads, prefixes)
    publications, immutable_puts = defaultdict(list), defaultdict(list)
    for request, response, data in accepted:
        if request['path'].endswith('/head'):
            head = o.wire.parse(data)
            publications[(request['path'], head['sequence'],
                          json_transition(head['transition']))].append((request, response, head))
        elif '/objects/' in request['path']:
            immutable_puts[request['path']].append((request, response, data))
    for original, saved in committed.items():
        call, receipt = calls[original], saved['receipt']
        candidates = publications[(heads[call['item']['scope']], int(receipt['sequence']),
                                   json_transition({k: int(v) for k, v in receipt['transition'].items()}))]
        request, response, head = o.one(candidates, 'one-original-publication')
        o.need(head['data_root'] == receipt['data_root'], 'publication-data-root')
        key = prefixes[call['item']['scope']] + receipt['result_hash']
        result_put, result_response, result = o.one(immutable_puts[key], 'durable-result-put')
        kind, _, data = frame(result, key, head['scope'])
        o.need(kind == 'result' and data == saved['raw'] and o.moment(result_response) < o.moment(request),
               'durable-original-result')
        for identifier, observed in calls.items():
            if observed['item'].get('original', identifier) != original:
                continue
            envelope = observed['value']
            if envelope is not None and envelope['ok'] and envelope['value'].get('state') == 'committed':
                o.need(o.moment(response) < o.moment(observed['terminal']), 'head-before-every-committed-ack')
    return {'requests': requests, 'responses': responses, 'authority': authority,
            'worker_claims': {'worker_instance': str(spec.WORKER), 'object_requests': 2,
                              'included_in_s3_denominator': True},
            'publication_closures': publication_closures}


def json_transition(value):
    return tuple(sorted(value.items()))
