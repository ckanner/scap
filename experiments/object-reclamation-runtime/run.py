#!/usr/bin/env python3
"""Explicit compaction/GC through the production daemon, native SQLite and SDK."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import signal
import tempfile
import time
import traceback

from harness import Harness
import spec
import support as io

if not __debug__:
    raise RuntimeError('actual contract requires assertions')


def wait(gate):
    assert gate.arrived.wait(10), 'original request did not reach its fixed transport gate'


def release(proxy, gate):
    proxy.release(gate)
    assert gate.finished.wait(15), 'released original transport did not finish'


def observed(events, event, **match):
    return [row for row in events if row['event'] == event and
            all(row.get(key) == value for key, value in match.items())]


def trace_rows(suite):
    return [json.loads(line) for line in (suite.evidence / 'events.jsonl').read_bytes().splitlines()]


def main_scenario(suite):
    suite.phase('main-old-put')
    old_put = suite.proxies['A'].arm('late-source-put', 'PUT', spec.prefix('main', 1), 'hold')
    suite.begin_call('A', 'main-late-put-execute', 'execute', intent='main-late-put', options={'timeoutMs': 1500})
    wait(old_put)
    suite.finish_call('A', 'main-late-put-execute', 'UNKNOWN', seconds=5)

    suite.phase('main-full-retained-copy')
    sealed = suite.compact('main', 'main-compaction', policy=True, promote=False)
    serial = sealed['storage']['plan']['serial']
    assert sealed['storage']['plan']['source'] == '1' and sealed['storage']['plan']['target'] == '2'

    # Old lookup obtains source authority only after the expensive complete COPY.
    # The fixture imposes a 30s observed interval, without changing the service's
    # original 120s lookup deadline or the SDK's original 90s deadline.
    suite.phase('main-old-reader-before-promotion')
    old_get = suite.proxies['R'].arm('old-source-get', 'GET', spec.prefix('main', 1), 'hold')
    reader_started = time.monotonic()
    suite.begin_call('R', 'main-old-reader', 'lookup', intent='main-001')
    wait(old_get)
    held_hash = old_get.observed['path'].rsplit('/', 1)[-1]
    assert len(held_hash) == 64 and int(held_hash, 16) > 0
    after = f'{int(held_hash, 16) - 1:064x}'
    suite.trace.emit('reader_target_frontier', hash=held_hash, after=after)
    promoted = suite.call('B', 'main-compaction-promote', 'compact_promote', input={'planSerial': serial})
    assert promoted['storage']['active_generation'] == '2' and promoted['active'] is False
    first = suite.prepare('main', 1, 'main-reader-first', after)
    assert first['status']['storage']['sweep'] is not None
    batch = first['status']['storage']['sweep']['serial']
    suite.restart_b('main-persisted-reader-batch')
    resumed = suite.call('B', 'main-reader-first-resume', 'gc_resume', input={'batchSerial': batch})
    assert resumed['status']['storage']['sweep'] is None
    release(suite.proxies['R'], old_get)
    suite.finish_call('R', 'main-old-reader', 'SNAPSHOT_EXPIRED', seconds=10)
    elapsed = time.monotonic() - reader_started
    suite.trace.emit('old_reader_completed', observed_seconds=elapsed, fixture_bound_seconds=30)
    assert elapsed < 30, 'old reader exceeded the fixed observation interval'

    suite.phase('main-first-complete-source-sweep')
    suite.sweep('main', 1, 'main-full-first-round')
    suite.phase('main-late-original-put-release')
    release(suite.proxies['A'], old_put)
    events = trace_rows(suite)
    put_reply = observed(events, 's3_backend_response', role='A', serial=old_put.observed['serial'])
    assert len(put_reply) == 1 and put_reply[0]['status'] == 200
    suite.trace.emit('late_original_put_observed', path=old_put.observed['path'],
                    serial=old_put.observed['serial'], response=put_reply[0]['response'])
    suite.phase('main-late-orphan-new-round')
    suite.sweep('main', 1, 'main-late-round-from-start')
    # A's original job may finish after the original HTTP caller ended, but it
    # cannot be turned into a successful replay or a refreshed candidate.
    suite.status('main', 'main-after-late-put')


def fence_scenario(suite):
    suite.phase('fence-old-cas')
    old_cas = suite.proxies['A'].arm('old-head-cas', 'PUT', spec.head_path('fence'), 'hold')
    suite.begin_call('A', 'fence-old-execute', 'execute', 'fence', intent='fence-old-cas', options={'timeoutMs': 1500})
    wait(old_cas)
    suite.finish_call('A', 'fence-old-execute', 'UNKNOWN', seconds=5)
    suite.compact('fence', 'fence-first-compaction')
    release(suite.proxies['A'], old_cas)
    replies = observed(trace_rows(suite), 's3_backend_response', role='A', serial=old_cas.observed['serial'])
    assert len(replies) == 1 and replies[0]['status'] == 412
    suite.phase('fence-late-delete')
    prepared = suite.prepare('fence', 1, 'fence-late-delete')
    batch = prepared['status']['storage']['sweep']['serial']
    old_delete = suite.proxies['B'].arm('late-original-delete', 'DELETE', spec.prefix('fence', 1), 'hold')
    suite.begin_call('B', 'fence-delete-original', 'gc_resume', 'fence',
                     input={'batchSerial': batch}, options={'timeoutMs': 1500})
    wait(old_delete)
    suite.finish_call('B', 'fence-delete-original', 'UNKNOWN', seconds=5)
    suite.restart_b('fence-pending-delete')
    suite.call('B', 'fence-delete-restart-resume', 'gc_resume', 'fence', input={'batchSerial': batch})
    promoted = suite.compact('fence', 'fence-second-compaction')
    assert promoted['storage']['active_generation'] == '3'
    release(suite.proxies['B'], old_delete)
    suite.sweep('fence', 1, 'fence-old-generation-rest')
    suite.sweep('fence', 2, 'fence-middle-generation')


def aborted_scenario(suite):
    suite.phase('aborted-target')
    sealed = suite.compact('aborted', 'aborted-compaction', promote=False)
    serial = sealed['storage']['plan']['serial']
    aborted = suite.call('B', 'aborted-target-abort', 'compact_abort', 'aborted', input={'planSerial': serial})
    assert aborted['storage']['active_generation'] == '1' and aborted['storage']['allocated_through'] == '2'
    prepared = suite.prepare('aborted', 2, 'aborted-original-checkpoint')
    batch = prepared['status']['storage']['sweep']['serial']
    suite.restart_b('aborted-persisted-checkpoint')

    suite.phase('aborted-accepted-delete-lost-response')
    lost = suite.proxies['B'].arm('accepted-delete-response-loss', 'DELETE',
        spec.prefix('aborted', 2), 'drop', stage='after_response')
    suite.call('B', 'aborted-delete-unknown', 'gc_resume', 'aborted', expect='UNKNOWN', input={'batchSerial': batch})
    wait(lost)
    assert lost.finished.wait(5)
    key = lost.observed['path']
    events = trace_rows(suite)
    request = observed(events, 's3_request', role='B', serial=lost.observed['serial'])[0]
    old_etag = request['headers']['if-match']
    replies = observed(events, 's3_backend_response', role='B', serial=lost.observed['serial'])
    assert len(replies) == 1 and replies[0]['status'] in (200, 204)
    reads = [row for row in events if row['event'] == 's3_backend_response' and
             row['method'] == 'GET' and row['path'] == key and row['status'] == 200]
    assert reads
    original = (suite.evidence / reads[-1]['response']['file']).read_bytes()
    pending = suite.status('aborted', 'aborted-after-unknown')
    assert pending['storage']['sweep']['serial'] == batch and pending['storage']['sweep']['pending'] > 0
    absent = suite.operator('accepted-delete-observed-absent', 'GET', key)
    assert absent['status'] == 404 and b'<Code>NoSuchKey</Code>' in io.signing.body_value(absent['body'])
    new_etag = suite.multipart_recreate(key, original)
    assert new_etag and new_etag != old_etag
    suite.trace.emit('same_bytes_new_backend_etag', key=key, original=suite.trace.raw(original),
                    old_etag=old_etag, new_etag=new_etag)

    suite.phase('aborted-original-etag-conflict')
    suite.call('B', 'aborted-old-batch-resume', 'gc_resume', 'aborted', input={'batchSerial': batch})
    current = suite.operator('conflict-preserved-new-object', 'GET', key)
    assert current['status'] == 200 and io.signing.body_value(current['body']) == original
    assert io.signing.header(current, 'etag') == new_etag
    fresh = suite.prepare('aborted', 2, 'aborted-fresh-new-etag')
    new_batch = fresh['status']['storage']['sweep']['serial']
    assert new_batch != batch

    suite.phase('aborted-no-such-bucket-not-missing')
    injected = suite.proxies['B'].arm('inspect-no-such-bucket', 'GET', key, 'no_such_bucket')
    suite.call('B', 'aborted-bucket-unknown', 'gc_resume', 'aborted', expect='UNKNOWN',
               input={'batchSerial': new_batch})
    wait(injected)
    assert injected.finished.wait(5)
    after = suite.status('aborted', 'aborted-after-bucket-unknown')
    assert after['storage']['sweep']['serial'] == new_batch and after['storage']['sweep']['pending'] > 0
    suite.phase('aborted-resume-after-bucket-error')
    suite.call('B', 'aborted-new-batch-resume', 'gc_resume', 'aborted', input={'batchSerial': new_batch})
    suite.call('B', 'aborted-old-batch-conflict', 'gc_resume', 'aborted', expect='CONFLICT',
               input={'batchSerial': batch})
    suite.sweep('aborted', 2, 'aborted-final-round')


def cold_recovery(suite):
    suite.phase('all-compute-cache-loss')
    for role in ('A', 'R', 'B'):
        suite.stop_service(role)
    suite.start_service('B', int(suite.workers['B']) + 100)
    for name in spec.SCOPES:
        suite.activate(name, 'cold-' + name, 'B')
        for original in suite.specs:
            if original['scope_name'] != name or original['purpose'] != 'seed':
                continue
            answer = suite.call('B', 'cold-lookup-' + original['name'], 'lookup', name, intent=original['name'])
            assert answer['state'] == 'committed' and answer['result'] == suite.originals[original['name']]['result']
            suite.trace.emit('cold_original_recovered', name=original['name'], result=answer['result'], receipt=answer['receipt'])
        suite.call('B', 'cold-query-' + name, 'query', name,
                   statements=[{'sql': 'SELECT id,counter,payload FROM witness ORDER BY id', 'params': []}])
    cancelled = suite.call('B', 'cold-main-cancel-lookup', 'lookup', intent='main-cancel')
    assert cancelled['state'] == 'cancelled'
    late = suite.call('B', 'cold-main-late-lookup', 'lookup', intent='main-late-put')
    fenced = suite.call('B', 'cold-fence-old-lookup', 'lookup', 'fence', intent='fence-old-cas')
    assert late['state'] == fenced['state'] == 'unknown'


def run(args):
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-reclamation-private-', dir=evidence.parent))
    private.chmod(0o700)
    suite = Harness(args, evidence, private)
    summary = {'schema': 1, 'status': 'FAILED', 'private': str(private), 'private_removed': False,
               'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN', 'error': None}
    started = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError('fixed whole-fixture deadline')

    original_alarm = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(1200)
    successful = False
    try:
        suite.setup()
        suite.seed()
        main_scenario(suite)
        fence_scenario(suite)
        aborted_scenario(suite)
        cold_recovery(suite)
        suite.verify_source()
        successful = True
    except BaseException as error:
        summary['error'] = repr(error)
        io.save(evidence / 'failure.txt', traceback.format_exc().encode())
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_alarm)
        cleanup = suite.cleanup(successful)
        summary['cleanup_errors'] = cleanup
        if successful and not cleanup:
            shutil.rmtree(private)
            summary.update(status='OBSERVED_NOT_AUDITED', private_removed=not private.exists())
        summary['elapsed_seconds'] = time.monotonic() - started
        io.save(evidence / 'summary.json', io.encoded(summary))
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary['status'] == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--seed-build-record', type=Path, required=True)
    parser.add_argument('--weed', type=Path, required=True)
    parser.add_argument('--node', default='node')
    parser.add_argument('--evidence', type=Path, required=True)
    arguments = parser.parse_args()
    for name in ('server', 'build_record', 'worker', 'seed_build_record', 'weed'):
        setattr(arguments, name, getattr(arguments, name).resolve())
    raise SystemExit(run(arguments))
