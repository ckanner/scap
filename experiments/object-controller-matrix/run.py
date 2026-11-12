#!/usr/bin/env python3
"""Frozen real CLI policy histories; raw observations require a separate oracle."""
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
import support as io


def held(suite, role, identifier, operation, stage='before_forward'):
    return suite.http[role].arm(identifier, operation, mode='hold', stage=stage)


def c1(s):
    s.owner_loss()
    s.phase('first-candidate-cut')
    s.http['B'].cut_status('first-b-candidate', 1)
    first, second = s.http['M'].hold_pair('first-prepare-held', 'second-prepare-held', 'owner_prepare')
    one = s.start_controller('controller-one')
    s.wait_report(one, 'waiting', 'CANDIDATE_UNAVAILABLE')
    two = s.start_controller('controller-two')
    s.arrived(first)
    s.phase('two-prepares-held')
    s.arrived(second)
    s.phase('first-winner-ack-lost')
    s.release(s.http['M'], first, lost=True)
    s.release(s.http['M'], second)
    s.wait_report(one, 'unknown', 'UNKNOWN')
    s.wait_report(two, 'blocked', 'CONFLICT')
    s.stop_controllers()
    s.phase('issuers-joined')
    s.phase('descriptor-adoption')
    three = s.start_controller('controller-three')
    s.wait_report(three, 'active_observed')


def c2_policy(s):
    s.owner_loss()
    s.phase('policy-race')
    first, second = s.http['M'].hold_pair('policy-first-prepare', 'policy-second-prepare', 'owner_prepare')
    one = s.start_controller('controller-one')
    two = s.start_controller('controller-two', reversed_ranks=True)
    s.arrived(first)
    s.arrived(second)
    s.release(s.http['M'], first)
    s.release(s.http['M'], second)
    # Requests and four nonces, not arrival order, identify the actual winner.
    request = json.loads((s.evidence / first.observed['request']['file']).read_bytes())
    winner, loser = (one, two) if request['input']['target_worker'] == '9602' else (two, one)
    s.wait_report(winner, 'active_observed')
    s.phase('foreign-policy-blocked')
    s.reports_after_now(loser)
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(loser, 'blocked', 'POLICY')


def c2_creators(s):
    s.owner_loss()
    s.phase('creator-race')
    first, second = s.http['B'].hold_pair('creator-first-claim', 'creator-second-claim', 'owner_claim')
    one = s.start_controller('controller-one')
    two = s.start_controller('controller-two', principal='13')
    s.arrived(first)
    s.arrived(second)
    s.release(s.http['B'], first)
    s.release(s.http['B'], second)
    request = json.loads((s.evidence / first.observed['request']['file']).read_bytes())
    winner, loser = (one, two) if request['plan']['creator'] == '12' else (two, one)
    s.wait_report(winner, 'active_observed')
    s.phase('foreign-creator-blocked')
    s.reports_after_now(loser)
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(loser, 'blocked', 'FOREIGN_CREATOR')


def c2_manual(s):
    s.phase('manual-marker-setup')
    s.business('manual-marker')
    s.phase('manual-marker-blocked')
    one = s.start_controller('controller-one')
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(one, 'blocked', 'FOREIGN_CREATOR')


def c3_claimed(s):
    s.owner_loss()
    original = held(s, 'B', 'original-resume-held', 'owner_resume')
    one = s.start_controller('controller-one')
    s.arrived(original)
    s.phase('claimed-target-unavailable')
    s.http['B'].cut_status('claimed-target-unavailable')
    two = s.start_controller('controller-two')
    s.wait_report(two, 'aborted')
    s.stop_controller(two)
    s.phase('late-original-resume')
    s.release(s.http['B'], original)
    s.wait_report(one, 'aborted')


def c3_cancelling(s):
    s.owner_loss()
    original = held(s, 'B', 'original-claim-held', 'owner_claim')
    one = s.start_controller('controller-one')
    s.arrived(original)
    s.phase('unaccepted-target-unavailable')
    s.http['B'].cut_status('unaccepted-target-unavailable')
    lost = s.http['M'].arm('cancelling-ack-loss', 'owner_abort')
    two = s.start_controller('controller-two')
    s.wait_report(two, 'unknown', 'UNKNOWN')
    s.arrived(lost)
    s.finished(lost)
    s.stop_controllers()
    s.phase('cancelling-restart')
    three = s.start_controller('controller-three')
    s.wait_report(three, 'aborted')
    s.stop_controller(three)
    s.phase('late-original-claim')
    s.release(s.http['B'], original)


def c3_healthy(s):
    s.phase('original-owner-probe-cut')
    s.http['A'].cut_status('original-owner-unreachable')
    prepared = held(s, 'M', 'unaccepted-prepare-held', 'owner_prepare', 'after_response')
    one = s.start_controller('controller-one')
    s.arrived(prepared)
    s.phase('original-owner-restored')
    s.http['A'].restore_status()
    s.release(s.http['M'], prepared)
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(one, 'healthy', 'CURRENT_OWNER_RESPONDED')


def c4_revoked(s):
    s.phase('authorized-healthy')
    one = s.start_controller('controller-one')
    s.wait_report(one, 'healthy')
    s.phase('authority-revoked')
    s.business('revoke', 'A')
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(one, 'blocked', 'DENIED')


def c4_mismatch(s):
    s.owner_loss()
    s.phase('worker-mismatch')
    one = s.start_controller('controller-one')
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(one, 'blocked', 'TARGET_MISMATCH')


def c4_resource(s):
    s.phase('real-control-intake-occupied')
    head = f'/scap-test/scap-object/v1/1/7/{s.scope["database"]}/head'
    occupied = s.proxies['M'].arm('control-intake-status-held', 'GET', head, 'hold')
    business = s.business_begin('occupy-control')
    s.arrived(occupied)
    one = s.start_controller('controller-one')
    s.wait_report(one, 'waiting', 'BACKPRESSURE')
    s.release(s.proxies['M'], occupied)
    s.business_finish(business)
    s.phase('control-intake-fresh-recovery')
    s.wait_report(one, 'healthy')
    s.owner_loss()
    s.phase('real-recovery-budget-refusal')
    for _ in range(io.LIMITS['post_fault_reports']):
        s.wait_report(one, 'waiting', 'LIMIT')


def c4_store(s):
    preferred, alternate = sorted(('M', 'C'), key=lambda role: s.http[role].endpoint + '/v1')
    s.phase('metadata-healthy')
    one = s.start_controller('controller-one')
    s.wait_report(one, 'healthy')
    s.phase('metadata-s3-unavailable')
    head = f'/scap-test/scap-object/v1/1/7/{s.scope["database"]}/head'
    gate = s.proxies[preferred].arm('metadata-s3-disconnect', 'GET', head, 'drop')
    s.trace.emit('metadata_routes_observed', preferred=preferred, alternate=alternate)
    s.arrived(gate)
    s.finished(gate)
    s.wait_report(one, 'unknown', 'UNKNOWN')
    s.business('observe-alternate', alternate)
    s.phase('metadata-fresh-recovery')
    s.wait_report(one, 'healthy')


def c5(s):
    s.phase('healthy-before-stall')
    one = s.start_controller('controller-one')
    s.wait_report(one, 'healthy')
    s.phase('original-probe-deadline')
    probe = held(s, 'A', 'original-probe-held', 'status')
    s.arrived(probe)
    s.wait_report(one, 'waiting', 'OWNER_SUSPICION_INCOMPLETE')
    s.release(s.http['A'], probe)
    s.owner_loss()
    s.wait_report(one, 'claimed')
    s.phase('recovery-cas-held')
    head = f'/scap-test/scap-object/v1/1/7/{s.scope["database"]}/head'
    original = s.proxies['B'].arm('original-active-cas-held', 'PUT', head, 'hold')
    s.arrived(original)
    s.phase('sigint-with-owned-io')
    s.stop_controller(one)
    s.phase('fresh-controller-recovery')
    two = s.start_controller('controller-two')
    s.wait_report(two, 'active_observed')
    s.stop_controller(two)
    s.phase('late-original-cas')
    s.release(s.proxies['B'], original)


HISTORIES = dict(zip(io.CASE_IDS, (c1, c2_policy, c2_creators, c2_manual, c3_claimed,
    c3_cancelling, c3_healthy, c4_revoked, c4_mismatch, c4_resource, c4_store, c5), strict=True))


def run_case(args, identifier, evidence):
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix='scap-controller-matrix-private-', dir=evidence.parent))
    case = io.scenario(identifier)
    suite = Harness(args, evidence, private, case)
    summary = {'status': 'FAILED', 'case_id': identifier, 'aws': 'NOT_RUN', 'production_slo': 'NOT_RUN',
               'whole_seconds': case['whole_seconds'], 'oracle': 'NOT_RUN', 'controls': 'NOT_RUN'}
    started = time.monotonic()

    def expired(_signal, _frame):
        raise TimeoutError('fixed whole-case deadline')

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(case['whole_seconds'])
    try:
        suite.setup()
        suite.seed()
        HISTORIES[identifier](suite)
        suite.verify()
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
    return summary


def main(args):
    evidence = args.evidence.resolve()
    assert not evidence.is_relative_to(io.ROOT), 'evidence must be outside source'
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    # --case creates explicitly partial diagnostic evidence, never a complete suite verdict.
    selected = [args.case] if args.case else list(io.CASE_IDS)
    io.save(evidence / 'cases.json', io.encoded({'version': 1, 'expected': list(io.CASE_IDS),
                                               'selected': selected, 'complete': not args.case}))
    results = [run_case(args, identifier, evidence / identifier) for identifier in selected]
    status = 'OBSERVED_NOT_AUDITED' if all(row['status'] == 'OBSERVED_NOT_AUDITED' for row in results) else 'FAILED'
    summary = {'status': status, 'complete': not args.case, 'expected_cases': len(io.CASE_IDS),
               'observed_cases': len(results), 'cases': results, 'oracle': 'NOT_RUN', 'controls': 'NOT_RUN'}
    io.save(evidence / 'summary.json', io.encoded(summary))
    print(json.dumps(summary, sort_keys=True))
    return 0 if status == 'OBSERVED_NOT_AUDITED' else 1


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('real validation requires Python assertions')
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--build-record', required=True, type=Path)
    parser.add_argument('--weed', required=True, type=Path)
    parser.add_argument('--node', default='node')
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--case', choices=io.CASE_IDS)
    arguments = parser.parse_args()
    arguments.server = arguments.server.resolve()
    arguments.weed = arguments.weed.resolve()
    raise SystemExit(main(arguments))
