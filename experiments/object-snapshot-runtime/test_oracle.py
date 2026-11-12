"""Regressions for distinguishing real GC preflights from bounded LIST pages."""
import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

import audit_model as m
import audit_evidence as e
import controls
import oracle


NS = 'http://s3.amazonaws.com/doc/2006-03-01/'
VERSIONING = f'<VersioningConfiguration xmlns="{NS}"></VersioningConfiguration>'.encode()
NO_LOCK = (b'<?xml version="1.0" encoding="UTF-8"?>\n<Error>'
           b'<Code>ObjectLockConfigurationNotFoundError</Code>'
           b'<Resource>/scap-test</Resource><BucketName>scap-test</BucketName></Error>')
BACKEND = {'gc_access_sha256': 'gc-credential', 'normal_access_sha256': 'ordinary-credential'}


def exchange(query, raw, status=200, moment=2):
    return {'request': {'method': 'GET', 'path': '/scap-test?' + query, 'role': 'C',
                        'access_sha256': 'gc-credential', 'monotonic_ns': moment},
            'backend': {'status': status, 'monotonic_ns': moment + 1, 'headers': {}},
            'delivered': True, 'bytes': raw}


def listing(live, after=None, maximum='32'):
    prefix = oracle.BASE + 'storage/1/objects/'
    query = {'list-type': '2', 'prefix': prefix.removeprefix('/scap-test/'), 'max-keys': maximum}
    if after is not None:
        query['start-after'] = after.removeprefix('/scap-test/')
    keys = sorted(key for key in live if key.startswith(prefix) and (after is None or key > after))
    body = '<ListBucketResult xmlns="' + NS + '"><IsTruncated>'
    body += 'true' if len(keys) > 32 else 'false'
    body += '</IsTruncated>'
    body += ''.join('<Contents><Key>' + key.removeprefix('/scap-test/') + '</Key></Contents>' for key in keys[:32])
    value = exchange(urlencode(query), (body + '</ListBucketResult>').encode())
    value['request']['access_sha256'] = 'ordinary-credential'
    return value


class BucketQueryWitnessTests(unittest.TestCase):
    def rejected(self, guard, action):
        with self.assertRaises(m.Rejected) as error:
            action()
        self.assertEqual(error.exception.rule, guard)

    def test_actual_preflight_shapes_are_valid_without_becoming_list_pages(self):
        for value in (exchange('versioning', VERSIONING), exchange('object-lock', NO_LOCK, 404)):
            with self.subTest(query=value['request']['path']):
                oracle.query_witness(value, {}, BACKEND)
                self.assertNotIn('listed', value)

    def test_preflights_require_the_dedicated_gc_principal_and_bucket(self):
        for field, value in (('access_sha256', 'ordinary-credential'), ('role', 'A')):
            item = exchange('versioning', VERSIONING); item['request'][field] = value
            self.rejected('dedicated-gc-capability-check', lambda: oracle.query_witness(item, {}, BACKEND))
        item = exchange('versioning', VERSIONING); item['request']['path'] = '/other-bucket?versioning'
        self.rejected('gc-bucket-query-shape', lambda: oracle.query_witness(item, {}, BACKEND))

    def test_non_success_statuses_never_certify_disabled_capabilities(self):
        for query, raw, status, guard in (
                ('versioning', VERSIONING, 404, 'gc-versioning-status'),
                ('versioning', VERSIONING, 403, 'gc-versioning-status'),
                ('object-lock', NO_LOCK, 200, 'gc-object-lock-status'),
                ('object-lock', NO_LOCK, 403, 'gc-object-lock-status')):
            with self.subTest(query=query, status=status):
                self.rejected(guard, lambda: oracle.query_witness(exchange(query, raw, status), {}, BACKEND))

    def test_enabled_suspended_or_present_empty_versioning_fields_are_unsupported(self):
        for fields in ('<Status>Enabled</Status>', '<Status>Suspended</Status>', '<Status/>', '<MFADelete>Disabled</MFADelete>'):
            raw = f'<VersioningConfiguration xmlns="{NS}">{fields}</VersioningConfiguration>'.encode()
            self.rejected('gc-bucket-unversioned', lambda: oracle.query_witness(exchange('versioning', raw), {}, BACKEND))

    def test_object_lock_404_requires_the_exact_error_code_not_missing_bucket(self):
        for code in ('NoSuchBucket', 'NoSuchKey', '', 'ObjectLockConfigurationNotFoundError '):
            raw = ('<Error><Code>' + code + '</Code></Error>').encode()
            self.rejected('gc-object-lock-disabled', lambda: oracle.query_witness(exchange('object-lock', raw, 404), {}, BACKEND))
        self.rejected('gc-object-lock-disabled', lambda: oracle.query_witness(exchange('object-lock', b'<Error/>', 404), {}, BACKEND))

    def test_duplicate_nested_unknown_or_attributed_error_fields_are_not_proofs(self):
        fields = ('<Code>ObjectLockConfigurationNotFoundError</Code><Code>NoSuchBucket</Code>',
                  '<Code><Nested>ObjectLockConfigurationNotFoundError</Nested></Code>',
                  '<Code><![CDATA[ObjectLockConfigurationNotFoundError]]></Code>',
                  '<Code extra="bad">ObjectLockConfigurationNotFoundError</Code>',
                  '<Other>ObjectLockConfigurationNotFoundError</Other>')
        for content in fields:
            with self.subTest(content=content):
                raw = ('<Error>' + content + '</Error>').encode()
                self.rejected('gc-capability-xml', lambda: oracle.query_witness(exchange('object-lock', raw, 404), {}, BACKEND))

    def test_capability_metadata_has_exact_xml_envelope_and_encoding_bounds(self):
        invalid = (
            b'<VersioningConfiguration/>',
            b'<VersioningConfiguration xmlns="wrong"/>',
            f'<VersioningConfiguration xmlns="{NS}" extra="bad"/>'.encode(),
            b'<!DOCTYPE VersioningConfiguration>' + VERSIONING,
            b'<?extra instruction?>' + VERSIONING,
            b'<!-- unobserved metadata -->' + VERSIONING,
            b'<?xml version="1.0" encoding="UTF-16"?>' + VERSIONING,
            VERSIONING.decode().encode('utf-16'),
            VERSIONING + b'<VersioningConfiguration/>',
            f'<VersioningConfiguration xmlns="{NS}">\u00a0</VersioningConfiguration>'.encode(),
            b'<VersioningConfiguration',
        )
        for raw in invalid:
            with self.subTest(raw=raw[:60]):
                self.rejected('gc-capability-xml', lambda: oracle.query_witness(exchange('versioning', raw), {}, BACKEND))
        self.rejected('bounded-gc-capability-response', lambda: oracle.query_witness(
            exchange('versioning', b' ' * 32769), {}, BACKEND))
        valid = b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\n' + VERSIONING
        oracle.query_witness(exchange('versioning', valid), {}, BACKEND)

    def test_query_aliases_and_unrelated_bucket_queries_are_not_skipped(self):
        for query in ('versioning=yes', 'versioning&object-lock', 'object-lock&list-type=2', 'policy', 'uploads'):
            with self.subTest(query=query):
                self.rejected('retired-list-prefix-bound', lambda: oracle.query_witness(exchange(query, VERSIONING), {}, BACKEND))

    def test_list_bound_frontier_and_complete_page_are_unchanged(self):
        prefix = oracle.BASE + 'storage/1/objects/'
        live = {prefix + f'{number:064x}': {} for number in range(40)}
        first = listing(live); oracle.query_witness(first, live, BACKEND)
        self.assertEqual(first['listed'], sorted(live)[:32])
        second = listing(live, first['listed'][-1]); oracle.query_witness(second, live, BACKEND)
        self.assertEqual(second['listed'], sorted(live)[32:])
        for maximum in ('31', '33', '1000'):
            self.rejected('retired-list-prefix-bound', lambda: oracle.query_witness(listing(live, maximum=maximum), live, BACKEND))
        wrong = listing(live); wrong['bytes'] = wrong['bytes'].replace(b'<IsTruncated>true', b'<IsTruncated>false')
        self.rejected('complete-list-frontier', lambda: oracle.query_witness(wrong, live, BACKEND))
        omitted = listing(live); omitted['bytes'] = omitted['bytes'].replace(
            ('<Contents><Key>' + sorted(live)[0].removeprefix('/scap-test/') + '</Key></Contents>').encode(), b'')
        self.rejected('complete-retired-list-page', lambda: oracle.query_witness(omitted, live, BACKEND))

    def test_gc_checkpoint_binds_one_real_list_among_successful_versioning_gets(self):
        prefix = oracle.BASE + 'storage/1/objects/'
        key = prefix + 'a' * 64
        page = listing({key: {}})
        versioning = exchange('versioning', VERSIONING, moment=4)
        lock = exchange('object-lock', NO_LOCK, 404, moment=6)
        for item in (page, versioning, lock):
            oracle.query_witness(item, {key: {}}, BACKEND)
        exact = exchange('', b'payload', moment=8)
        exact['request']['path'] = key; exact['backend']['headers']['etag'] = 'original-etag'
        prepare = {'role': 'C', 'proxy': {'forward_started': {'monotonic_ns': 1},
                                         'backend_response': {'monotonic_ns': 20}}, 'body': {'after': None}}
        before = {'head': {'storage': {'active_generation': 2, 'allocated_through': 2, 'plan': None}}}
        prepared = {'head': {'storage': {'sweep': {'entries': [{'key': key.removeprefix('/scap-test/'),
                                                               'etag': 'original-etag'}]}}}}
        completed = {'live': {}}
        report = {'scanned': 1, 'exhausted': True}
        with patch.object(oracle, 'gc_page_chain', return_value=[('retired-one', 0, '1', prepare, {}, report)]), \
                patch.object(oracle, 'find_public_head', side_effect=[before, prepared, completed]):
            oracle.gc_protocol([], {}, [], [page, versioning, lock, exact], BACKEND)
        duplicate = copy.deepcopy(page)
        with patch.object(oracle, 'gc_page_chain', return_value=[('retired-one', 0, '1', prepare, {}, report)]), \
                patch.object(oracle, 'find_public_head', side_effect=[before, prepared, completed]):
            self.rejected('one-original-candidate-list-page', lambda: oracle.gc_protocol(
                [], {}, [], [page, duplicate, versioning, lock, exact], BACKEND))
        wrong_list = copy.deepcopy(page)
        wrong_list['request']['access_sha256'] = 'gc-credential'
        with patch.object(oracle, 'gc_page_chain', return_value=[('retired-one', 0, '1', prepare, {}, report)]), \
                patch.object(oracle, 'find_public_head', side_effect=[before, prepared, completed]):
            self.rejected('one-original-candidate-list-page', lambda: oracle.gc_protocol(
                [], {}, [], [wrong_list, versioning, lock, exact], BACKEND))
        wrong_exact = copy.deepcopy(exact)
        wrong_exact['request']['access_sha256'] = 'ordinary-credential'
        with patch.object(oracle, 'gc_page_chain', return_value=[('retired-one', 0, '1', prepare, {}, report)]), \
                patch.object(oracle, 'find_public_head', side_effect=[before, prepared, completed]):
            self.rejected('dedicated-exact-gc-get-before-checkpoint', lambda: oracle.gc_protocol(
                [], {}, [], [page, versioning, lock, wrong_exact], BACKEND))


class SnapshotResponseMutationTests(unittest.TestCase):
    def fixture(self, directory, delivered=False):
        directory.mkdir(); (directory / 'raw').mkdir()
        body = {'ok': True, 'value': {'prepared': {'scope': {'incarnation': '1'},
                'reference': {'descriptor_hash': 'a' * 64}}, 'state': 'retained'}}
        original = controls.put_raw(directory, m.encoded(body))
        rows = [
            {'event': 'http_proxy_backend_response', 'role': 'C-9403', 'serial': 5,
             'operation': 'snapshot_capture', 'response': original,
             'headers': {'content-length': str(original['bytes'])}},
            {'event': 'http_proxy_delivery_started' if delivered else 'http_proxy_delivery_suppressed',
             'role': 'C-9403', 'serial': 5, 'operation': 'snapshot_capture'},
            {'event': 'http_proxy_backend_response', 'role': 'A-9401', 'serial': 3,
             'operation': 'snapshot_inspect', 'response': original},
            {'event': 'http_proxy_delivery_started', 'role': 'A-9401', 'serial': 3,
             'operation': 'snapshot_inspect', 'response': original},
            {'event': 'http_proxy_backend_response', 'role': 'C-9403', 'serial': 6,
             'operation': 'snapshot_capture', 'response': original},
        ]
        controls.save_rows(directory / 'events.jsonl', rows)
        controls.save_rows(directory / 'sdk-A-1.jsonl', [
            {'event': 'http_response', 'command': 'point-one-inspect', 'response': original},
            {'event': 'command_finished', 'command': 'point-one-inspect',
             'result': {'ok': True, 'value': body['value']}},
        ])
        controls.save_rows(directory / 'sdk-C-1.jsonl', [
            {'event': 'command_finished', 'command': 'capture-original-ack',
             'result': {'ok': False, 'error': {'code': 'UNKNOWN'}}},
        ])
        return original, body

    def test_lost_capture_mutations_preserve_shared_inspect_and_sdk_views(self):
        for scope in (False, True):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temporary:
                source, target = Path(temporary) / 'original', Path(temporary) / 'control'
                original, body = self.fixture(source)
                before = controls.inventory(source)
                shutil.copytree(source, target, copy_function=os.link)
                controls.changed_snapshot_response(target, scope=scope)
                self.assertEqual(controls.inventory(source), before)
                original_rows, changed = e.rows(source / 'events.jsonl'), e.rows(target / 'events.jsonl')
                self.assertEqual([index for index, pair in enumerate(zip(original_rows, changed))
                                  if pair[0] != pair[1]], [0])
                self.assertEqual(e.raw(target, original), m.encoded(body))
                expected = copy.deepcopy(body)
                if scope:
                    expected['value']['prepared']['scope']['incarnation'] = '2'
                else:
                    expected['value']['prepared']['reference']['descriptor_hash'] = '0' + 'a' * 63
                self.assertEqual(m.wire.parse(e.raw(target, changed[0]['response'])), expected)
                for name in ('sdk-A-1.jsonl', 'sdk-C-1.jsonl'):
                    self.assertEqual((target / name).read_bytes(), (source / name).read_bytes())
                ledger = e.rows(target / 'sdk-A-1.jsonl')
                self.assertEqual(m.wire.parse(e.raw(target, ledger[0]['response']))['value'], ledger[1]['result']['value'])

    def test_suppressed_response_mutation_refuses_a_delivered_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'delivered'
            self.fixture(target, delivered=True)
            before = controls.inventory(target)
            with self.assertRaises(AssertionError):
                controls.changed_snapshot_response(target)
            self.assertEqual(controls.inventory(target), before)


if __name__ == '__main__':
    unittest.main()
