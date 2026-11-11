"""Counterexamples exercise independent guards before any product execution."""
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import tempfile
import unittest

import audit_model as m
import audit_evidence as e
import oracle
import spec
import controls
from harness import Harness


def head():
    return {'format': 9, 'scope': dict(e.SCOPE), 'head_serial': 15,
        'storage': {'active_generation': 1, 'allocated_through': 1, 'plan': None, 'sweep': None},
        'revision': 12, 'transition': {'revision': 12, 'nonce': 42}, 'sequence': 6,
        'owner_epoch': 2, 'owner_instance': 9401, 'snapshots': [],
        'snapshot_limits': {'max_points': 2, 'max_logical_bytes': 4194304}, 'restore_origin': None,
        'active': True, 'auth_epoch': 1,
        'policy': [{'principal': 11, 'read': True, 'write': True, 'admin': True}],
        'lifecycle': 'ready', 'creation': None, 'deletion': None, 'data_root': 'a' * 64,
        'quota': {'max_bytes': 67108864}, 'retention': {'max_entries': 2, 'max_result_bytes': 268435456},
        'request_epoch': 3, 'windows': [{'epoch': epoch, 'root': str(epoch) * 64, 'count': 2, 'result_bytes': 512}
                                      for epoch in (3, 2, 1)]}


def retained():
    return {'reference': {'creator': 11, 'operation': 880001, 'capture_serial': 9, 'descriptor_hash': 'd' * 64},
            'label': 'after-original-2', 'point': {'data_root': 'c' * 64, 'page_count': 2, 'sequence': 2, 'source_revision': 7}}


def descriptor(base):
    original = {'creator': 11, 'operation': 880001, 'expected_revision': base['revision'],
                'expected_head_serial': base['head_serial'], 'label': 'after-original-2'}
    saved_base = {'head_hash': m.sha(m.canonical_head(base)), 'etag': '"original-etag"',
                  'revision': base['revision'], 'head_serial': base['head_serial']}
    position = {'data_root': base['data_root'], 'page_count': 2, 'sequence': base['sequence'], 'source_revision': base['revision']}
    value = {'version': 1, 'scope': dict(e.SCOPE), 'input': original, 'base': saved_base,
             'point': position, 'limits': base['snapshot_limits']}
    value['input_digest'] = m.sha(m.encoded([1, e.SCOPE, original, saved_base, position, base['snapshot_limits']]))
    return value


def frame(kind, value, raw=b''):
    metadata = m.encoded({'format': 2, 'scope': e.SCOPE, 'payload': {'kind': kind, 'value': value}})
    body = b'SCAPOBJ2' + struct.pack('<IQ', len(metadata), len(raw)) + metadata + raw
    return m.sha(body), body


def image(counter, payload):
    connection = sqlite3.connect(':memory:')
    connection.execute('CREATE TABLE witness(id INTEGER PRIMARY KEY,counter INTEGER NOT NULL,payload BLOB NOT NULL)')
    connection.execute('INSERT INTO witness VALUES(1,?,?)', (counter, payload))
    connection.commit()
    result = connection.serialize()
    connection.close()
    return result


def data_tree(objects, data):
    prefix = m.prefix(e.SCOPE, 2)
    children = []
    for offset in range(0, len(data), 32 * 4096):
        name, raw = frame('chunk', {'first_page': offset // 4096 + 1, 'bytes': []}, data[offset:offset + 32 * 4096])
        objects[prefix + name] = raw
        children.append(name)
    node, raw = frame('node', {'level': 0, 'first_chunk': 0, 'children': children})
    objects[prefix + node] = raw
    manifest, raw = frame('manifest', {'page_count': len(data) // 4096, 'root': node})
    objects[prefix + manifest] = raw
    return manifest


class GuardAssertions(unittest.TestCase):
    def rejected(self, guard, action):
        with self.assertRaises(m.Rejected) as error:
            action()
        self.assertEqual(error.exception.rule, guard)

    def validate(self, value):
        return m.head(m.encoded(value), {m.scope_key(e.SCOPE)})


class HeadWitnessTests(GuardAssertions):

    def test_valid_head9_and_canonical_new_fields(self):
        value = head(); value['snapshots'] = [retained()]
        self.assertEqual(self.validate(value), value)
        parsed = m.wire.parse(m.canonical_head(value))
        self.assertEqual(parsed, value)
        before = m.sha(m.canonical_head(value))
        value['snapshots'][0]['point']['data_root'] = 'f' * 64
        self.assertNotEqual(before, m.sha(m.canonical_head(value)))

    def test_null_origin_must_be_present_and_null(self):
        value = head(); del value['restore_origin']
        self.rejected('head9-exact-shape', lambda: self.validate(value))
        value['restore_origin'] = {'kind': 'copying'}
        self.rejected('s1-null-origin-only', lambda: self.validate(value))

    def test_snapshot_identity_unique_even_if_hash_and_serial_differ(self):
        value = head(); first = retained(); second = copy.deepcopy(first)
        second['label'] = 'another'; second['reference']['capture_serial'] += 1
        second['reference']['descriptor_hash'] = 'e' * 64
        value['snapshots'] = [first, second]
        self.rejected('snapshot-unique-identity-label', lambda: self.validate(value))

    def test_future_revision_is_not_inferred_from_capture_serial(self):
        value = head(); value['snapshots'] = [retained()]
        value['snapshots'][0]['reference']['capture_serial'] = 15
        value['snapshots'][0]['point']['source_revision'] = 13
        self.rejected('snapshot-current-authority-bound', lambda: self.validate(value))

    def test_shared_roots_are_charged_per_point(self):
        value = head(); first = retained(); second = copy.deepcopy(first)
        second['reference'].update(operation=880002, capture_serial=10)
        second['label'] = 'second'; value['snapshots'] = [first, second]
        value['snapshot_limits']['max_logical_bytes'] = 8192
        self.rejected('snapshot-gross-policy', lambda: self.validate(value))

    def test_terminal_cannot_drop_a_held_root_implicitly(self):
        value = head(); value['snapshots'] = [retained()]
        value['storage']['terminal'] = {'serial': 15}; value['lifecycle'] = 'deleted'; value['active'] = False
        self.rejected('terminal-no-held-roots', lambda: self.validate(value))

    def test_copy_basis_replacement_has_specific_guard(self):
        value = head(); value['snapshots'] = [retained()]; value['active'] = False
        basis = {field: copy.deepcopy(value[field]) for field in m.legacy.BASIS | {'snapshots', 'snapshot_limits'}}
        value['storage'].update(allocated_through=2, plan={'serial': 15, 'source': 1, 'target': 2, 'phase': 'copying', 'basis': basis})
        self.validate(value)
        basis['snapshots'] = []
        self.rejected('copy-frozen-held-basis', lambda: self.validate(value))

    def test_cleanup_debt_cannot_be_spent_by_a_new_point(self):
        value = head(); value['head_serial'] = 2**64 - 3
        value['snapshots'] = [retained()]
        self.rejected('snapshot-physical-cleanup-reserve', lambda: self.validate(value))

    def test_capture_changes_only_technical_serial_and_one_original_point(self):
        before = head(); after = copy.deepcopy(before); value = retained()
        value['reference']['capture_serial'] = 16
        value['point'].update(data_root=before['data_root'], source_revision=12, sequence=6)
        after['head_serial'] += 1; after['snapshots'] = [value]
        self.assertEqual(m.advance(before, after), 'snapshot_capture')
        after['revision'] += 1
        self.rejected('snapshot-business-preserved', lambda: m.advance(before, after))

    def test_release_preserves_business_on_deleted(self):
        before = head(); before['snapshots'] = [retained()]; before['lifecycle'] = 'deleted'
        after = copy.deepcopy(before); after['head_serial'] += 1; after['snapshots'] = []
        self.assertEqual(m.advance(before, after), 'snapshot_release')

    def test_descriptor_scope_and_full_reference(self):
        value = descriptor(head()); path = oracle.BASE + 'snapshot/v1/descriptor/11/880001'
        observed, item = m.descriptor(m.encoded(value), path)
        self.assertEqual(observed, value)
        self.assertEqual(item['reference']['capture_serial'], 16)
        self.assertEqual(item['reference']['descriptor_hash'], m.sha(m.encoded(value)))
        value['scope']['incarnation'] = 2
        self.rejected('snapshot-descriptor-scope', lambda: m.descriptor(m.encoded(value), path))

    def test_descriptor_input_digest_does_not_ignore_original_etag(self):
        value = descriptor(head()); value['base']['etag'] = '"different"'
        self.rejected('snapshot-input-digest', lambda: m.descriptor(m.encoded(value), oracle.BASE + 'snapshot/v1/descriptor/11/880001'))

    def test_proof_cannot_change_scope_or_original_identity(self):
        value = {'version': 1, 'scope': dict(e.SCOPE), 'entry': retained()}
        path = oracle.BASE + 'snapshot/v1/proof/11/880001'
        self.assertEqual(m.proof(m.encoded(value), path), value)
        value['entry']['reference']['operation'] = 880002
        self.rejected('snapshot-proof-identity', lambda: m.proof(m.encoded(value), path))


class ClosureWitnessTests(GuardAssertions):
    def fixture(self):
        objects = {}
        current = data_tree(objects, image(6, b'current'))
        held_root = data_tree(objects, image(2, b'original'))
        empty, raw = frame('index', {'kind': 'leaf', 'epoch': 1, 'entries': []})
        objects[m.prefix(e.SCOPE, 2) + empty] = raw
        item = retained(); item['point']['data_root'] = held_root
        value = {'data_root': current, 'sequence': 6, 'revision': 12,
                 'windows': [{'epoch': 1, 'root': empty, 'count': 0, 'result_bytes': 0}], 'snapshots': [item]}
        return objects, value

    def test_held_image_has_its_own_manifest_geometry_and_original_ack_expectation(self):
        objects, value = self.fixture()
        closure = m.Graph(objects, e.SCOPE, 2).complete(value)
        self.assertEqual(len(closure['held']), 1)
        oracle.image_witness(closure['image'], [6, b'current'])
        oracle.image_witness(closure['held'][0][1], [2, b'original'])
        self.rejected('retained-business-from-original-ack', lambda: oracle.image_witness(closure['held'][0][1], [6, b'current']))

    def test_native_wal_image_is_read_without_changing_its_original_bytes(self):
        with tempfile.TemporaryDirectory(prefix='snapshot-wal-fixture-') as directory:
            connection = sqlite3.connect(Path(directory) / 'wal.sqlite')
            self.assertEqual(connection.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
            connection.execute('CREATE TABLE witness(id INTEGER PRIMARY KEY,counter INTEGER NOT NULL,payload BLOB NOT NULL)')
            connection.execute('INSERT INTO witness VALUES(1,2,?)', (b'original',))
            connection.commit()
            original = connection.serialize()
            connection.close()
        self.assertEqual(original[18:20], b'\x02\x02')
        digest = m.sha(original)
        oracle.image_witness(original, [2, b'original'])
        self.assertEqual(m.sha(original), digest)

    def test_a_missing_held_root_is_rejected_even_with_complete_current_root(self):
        objects, value = self.fixture()
        del objects[m.prefix(e.SCOPE, 2) + value['snapshots'][0]['point']['data_root']]
        self.rejected('held-root-complete-closure', lambda: m.Graph(objects, e.SCOPE, 2).complete(value))

    def test_a_held_root_page_count_is_checked_independently(self):
        objects, value = self.fixture()
        value['snapshots'][0]['point']['page_count'] += 1
        self.rejected('held-root-page-count', lambda: m.Graph(objects, e.SCOPE, 2).complete(value))

    def test_canonical_frame_scope_must_match_key(self):
        objects, value = self.fixture()
        prefix = m.prefix(e.SCOPE, 2)
        first = next(iter(objects))
        moved = first.replace('/8201/', '/8202/')
        self.rejected('immutable-full-scope', lambda: m.envelope(objects[first], moved))


class ProfileTests(unittest.TestCase):
    def test_counterfactual_replacement_breaks_hardlink_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; original.mkdir()
            (original / 'raw.json').write_bytes(b'original-raw-bytes')
            before = controls.inventory(original)
            counterfactual = root / 'counterfactual'
            shutil.copytree(original, counterfactual, copy_function=os.link)
            controls.replace(counterfactual / 'raw.json', b'counterfactual-bytes')
            self.assertEqual(controls.inventory(original), before)
            self.assertNotEqual((counterfactual / 'raw.json').read_bytes(), (original / 'raw.json').read_bytes())

    def test_ten_controls_have_distinct_expected_guards(self):
        self.assertEqual(len(controls.CASES), 10)
        self.assertEqual(len({row[0] for row in controls.CASES}), 10)
        self.assertEqual(len({row[1] for row in controls.CASES}), 10)

    def test_fixed_denominators_include_backend_processes(self):
        self.assertEqual(spec.validate()['owned_wait4'], 13)
        self.assertEqual(len(spec.inputs()), 6)
        self.assertEqual([row['epoch'] for row in spec.inputs()], ['1', '1', '2', '2', '3', '3'])
        self.assertEqual(len(spec.POINTS), 2)

    def test_every_original_sql_changes_data_and_returns_random_blob_and_nonce(self):
        connection = sqlite3.connect(':memory:')
        try:
            for original in spec.inputs():
                for statement in original['statements']:
                    cursor = connection.execute(statement['sql'])
                row = cursor.fetchone()
                self.assertEqual(row[0], original['counter'])
                self.assertEqual(len(row[1]), 64 if original['counter'] <= 2 else 196608)
                self.assertIsInstance(row[2], int)
        finally:
            connection.close()


class CrossControllerOriginalTests(GuardAssertions):
    def fixture(self, directory):
        (directory / 'raw').mkdir()
        original = {'name': 'point-one', 'scope_name': 'bulk', 'role': 'C-1', 'principal': '11',
                    'serialized': '{"version":1}'}
        data = m.encoded(original)
        digest = m.sha(data)
        (directory / 'raw' / digest).write_bytes(data)
        saved = {'event': 'snapshot_input_saved', 'name': 'point-one', 'monotonic_ns': '20',
                 'original': {'file': 'raw/' + digest, 'sha256': digest, 'bytes': len(data)}}
        snapshots = {'point-one': {**original, 'decoded': {}, 'native': {}}}
        # A was created before C, but C's fsync happened before A's request.
        ledgers = [[{'event': 'http_request', 'monotonic_ns': '30'}], [saved]]
        return snapshots, ledgers

    def test_first_started_controller_can_use_another_controllers_saved_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshots, ledgers = self.fixture(directory)
            saved = e.saved_inputs(directory, ledgers, {}, snapshots)
            self.assertLess(e.moment(saved['snapshot']['point-one']), e.moment(ledgers[0][0]))

    def test_cross_controller_index_still_requires_exact_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshots, ledgers = self.fixture(directory)
            snapshots['point-one']['serialized'] = '{"version":2}'
            self.rejected('snapshot-input-fsync-original', lambda: e.saved_inputs(directory, ledgers, {}, snapshots))

    def test_saved_event_cannot_be_omitted_or_duplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshots, ledgers = self.fixture(directory)
            self.rejected('all-original-inputs-fsynced', lambda: e.saved_inputs(directory, ledgers[:1], {}, snapshots))
            self.rejected('snapshot-fsync-original-unique', lambda: e.saved_inputs(directory, ledgers + [ledgers[1]], {}, snapshots))


class OwnedComputeLossTests(GuardAssertions):
    def fixture(self):
        def event(kind, time, **fields):
            return {'event': kind, 'monotonic_ns': time, **fields}
        events = [event('native_cache_removed', 20, absent=True),
                  event('scenario_phase', 30, label='warm-owner-and-original-point-one'),
                  event('scenario_phase', 100, label='all-compute-cache-loss'),
                  event('cache_removed', 130, service='service-A-1', path='/cache/A-1', existed=True, absent=True),
                  event('cache_removed', 140, service='service-C-1', path='/cache/C-1', existed=True, absent=True)]
        starts = {'service-C-2': event('child_started', 150)}
        stops = {name: event('child_stopped', time) for name, time in (
            ('native-seed', 10), ('service-A-1', 120), ('service-C-1', 125), ('sdk-A-1', 110), ('sdk-C-1', 115))}
        configurations = {name: {'cache_directory': path} for name, path in (
            ('service-A-1', '/cache/A-1'), ('service-C-1', '/cache/C-1'), ('service-C-2', '/cache/C-2'))}
        return events, starts, stops, configurations

    def test_all_owned_exits_precede_cold_spawn_and_cache_loss_follows_exit(self):
        e.compute_loss(*self.fixture())

    def test_old_daemon_or_sdk_exit_after_cold_spawn_is_rejected(self):
        for name in ('service-A-1', 'service-C-1', 'sdk-A-1', 'sdk-C-1'):
            values = self.fixture()
            values[2][name]['monotonic_ns'] = 160
            self.rejected('all-warm-wait4-before-cold', lambda: e.compute_loss(*values))

    def test_cache_removal_cannot_precede_the_owned_daemon_exit(self):
        values = self.fixture()
        values[0][3]['monotonic_ns'] = 119
        self.rejected('owned-cache-loss-before-cold-spawn', lambda: e.compute_loss(*values))

    def test_native_process_must_exit_before_its_cache_is_discarded(self):
        values = self.fixture()
        values[2]['native-seed']['monotonic_ns'] = 21
        self.rejected('native-owned-exit-and-cache-loss-before-owner', lambda: e.compute_loss(*values))


class SweepPageChainTests(GuardAssertions):
    def fixture(self):
        events = [{'event': 'scenario_phase', 'label': 'all-compute-cache-loss', 'monotonic_ns': 50}]
        calls = {}
        for label, generation, count, origin in (('retired-one', '1', 2, 10), ('terminal-two', '2', 1, 60)):
            events.append({'event': 'sweep_round_started', 'label': label, 'generation': int(generation),
                           'after': None, 'monotonic_ns': origin})
            after = None
            for page in range(count):
                name, time, serial = f'{label}-{page}', origin + 1 + page * 10, 100 + page * 10
                exhausted = page == count - 1
                frontier = None if exhausted else 'a' * 64
                batch = {'serial': str(serial + 1), 'generation': generation, 'next_after': frontier, 'exhausted': exhausted}
                report = {'generation': generation, 'scanned': 2, 'exhausted': exhausted, 'next_after': frontier,
                          'status': {'head_serial': str(serial + 1), 'storage': {'sweep': batch}}}
                completed = {**report, 'status': {'head_serial': str(serial + 5), 'storage': {'sweep': None}}}
                for suffix, offset, body, value in (
                    ('-storage', 0, {}, {'head_serial': str(serial)}),
                    ('-prepare', 2, {'generation': generation, 'after': after, 'expected_head_serial': str(serial)}, report),
                    ('-resume', 4, {'batch_serial': str(serial + 1)}, completed)):
                    calls[name + suffix] = {'body': body, 'product_body': {'value': value}, 'proxy': {
                        'forward_started': {'monotonic_ns': time + offset}, 'backend_response': {'monotonic_ns': time + offset + 1}}}
                events.append({'event': 'sweep_page_finished', 'label': label, 'page': page,
                               'report': copy.deepcopy(report), 'monotonic_ns': time + 6})
                after = frontier
            events.append({'event': 'sweep_round_finished', 'label': label, 'pages': count, 'monotonic_ns': origin + count * 10})
        return events, calls

    def test_two_complete_original_page_chains(self):
        self.assertEqual(len(oracle.gc_page_chain(*self.fixture())), 3)

    def test_first_page_must_start_at_null_and_later_page_uses_exact_returned_frontier(self):
        for name, changed in (('retired-one-0-prepare', 'a' * 64), ('retired-one-1-prepare', None)):
            events, calls = self.fixture()
            calls[name]['body']['after'] = changed
            self.rejected('original-exclusive-sweep-frontier', lambda: oracle.gc_page_chain(events, calls))

    def test_generation_cannot_drift_between_round_and_original_call(self):
        events, calls = self.fixture(); calls['retired-one-0-prepare']['body']['generation'] = '2'
        self.rejected('fixed-sweep-generation', lambda: oracle.gc_page_chain(events, calls))

    def test_runner_cannot_label_an_incomplete_last_page_exhausted(self):
        events, calls = self.fixture(); calls['retired-one-1-prepare']['product_body']['value']['exhausted'] = False
        self.rejected('terminal-sweep-exhausted', lambda: oracle.gc_page_chain(events, calls))

    def test_progress_marker_must_equal_the_original_product_report(self):
        events, calls = self.fixture()
        next(row for row in events if row['event'] == 'sweep_page_finished')['report']['scanned'] = 1
        self.rejected('sweep-marker-original-product-report', lambda: oracle.gc_page_chain(events, calls))

    def test_old_generation_must_be_exhausted_before_compute_loss(self):
        events, calls = self.fixture()
        events[0]['monotonic_ns'] = 25
        self.rejected('retired-generation-finished-before-compute-loss', lambda: oracle.gc_page_chain(events, calls))


class SweepDriverTests(unittest.TestCase):
    class Trace:
        def __init__(self):
            self.events = []

        def emit(self, event, **fields):
            self.events.append({'event': event, **fields})

    class PublicCalls:
        def __init__(self):
            self.trace = SweepDriverTests.Trace()
            self.calls = []

        def call(self, role, identifier, operation, **fields):
            self.calls.append({'role': role, 'id': identifier, 'operation': operation, **fields})
            if operation in ('status', 'storage_status'):
                return {'head_serial': '17'}
            if operation == 'gc_prepare':
                return {'status': {'storage': {'sweep': None}}, 'exhausted': True, 'next_after': None}
            raise AssertionError('unplanned public call')

    def test_ready_retired_generation_uses_ordinary_status(self):
        suite = self.PublicCalls()
        Harness.sweep(suite, 1, 'retired-one')
        self.assertEqual([call['operation'] for call in suite.calls], ['status', 'gc_prepare'])
        self.assertEqual(suite.calls[1]['input'], {'expectedHeadSerial': '17', 'generation': '1', 'after': None})

    def test_deleted_terminal_generation_uses_deleted_metadata_status(self):
        suite = self.PublicCalls()
        Harness.sweep(suite, 2, 'terminal-two')
        self.assertEqual([call['operation'] for call in suite.calls], ['storage_status', 'gc_prepare'])
        self.assertEqual(suite.calls[1]['input'], {'expectedHeadSerial': '17', 'generation': '2', 'after': None})


if __name__ == '__main__':
    unittest.main()
