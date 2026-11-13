"""Small verifier tests; these never stand in for the original 1 GiB run."""
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('capacity_audit_v2', Path(__file__).with_name('audit_capacity_gib1_v2.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ImageTests(unittest.TestCase):
    def image(self, folder):
        path = Path(folder) / 'native image #1.sqlite'
        data = [(1, b'a' * audit.BLOB), (2, b'b' * audit.BLOB)]
        with sqlite3.connect(path) as database:
            database.execute('CREATE TABLE payloads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)')
            database.executemany('INSERT INTO payloads VALUES (?,?)', data)
        expected = {rid: {'blob_bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()} for rid, value in data}
        return path, expected

    def test_reads_every_actual_blob_and_preserves_image(self):
        with tempfile.TemporaryDirectory() as folder:
            path, expected = self.image(folder)
            original = path.read_bytes()
            result = audit.check_image(path, expected)
            self.assertEqual(result['rows_rehashed'], 2)
            self.assertEqual(result['blob_bytes_rehashed'], 2 * audit.BLOB)
            self.assertEqual(result['integrity_check'], ['ok'])
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse(Path(str(path) + '-wal').exists())
            self.assertFalse(Path(str(path) + '-shm').exists())

    def test_changed_second_blob_is_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            path, expected = self.image(folder)
            original = path.read_bytes()
            expected[2]['sha256'] = '0' * 64
            with self.assertRaises(audit.Rejected) as failure:
                audit.check_image(path, expected)
            self.assertEqual(failure.exception.guard, 'every-native-blob-byte')
            self.assertEqual(path.read_bytes(), original)

    def test_missing_native_row_is_not_accepted_as_sample(self):
        with tempfile.TemporaryDirectory() as folder:
            path, expected = self.image(folder)
            expected[3] = expected[2]
            with self.assertRaises(audit.Rejected) as failure:
                audit.check_image(path, expected)
            self.assertEqual(failure.exception.guard, 'every-native-blob-byte')

    def test_nonempty_wal_is_rejected_before_immutable_open(self):
        with tempfile.TemporaryDirectory() as folder:
            path, expected = self.image(folder)
            Path(str(path) + '-wal').write_bytes(b'uncheckpointed bytes')
            with self.assertRaises(audit.Rejected) as failure:
                audit.check_image(path, expected)
            self.assertEqual(failure.exception.guard, 'closed-native-image')

    def test_corrupt_sqlite_header_fails_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            path, expected = self.image(folder)
            with path.open('r+b') as stream:
                stream.write(b'not-a-sqlite-file')
            original = path.read_bytes()
            with self.assertRaises(audit.Rejected) as failure:
                audit.check_image(path, expected)
            self.assertEqual(failure.exception.guard, 'native-integrity-check')
            self.assertEqual(path.read_bytes(), original)

    def test_symbolic_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path, _ = self.image(folder)
            alias = Path(folder) / 'alias.sqlite'
            alias.symlink_to(path)
            with self.assertRaises(audit.Rejected) as failure:
                audit.image_inventory(alias)
            self.assertEqual(failure.exception.guard, 'closed-native-image')


class OriginalHistoryTests(unittest.TestCase):
    def test_duplicate_original_json_key_rejected(self):
        with self.assertRaises(audit.Rejected) as failure:
            audit.parse('{"id":1,"id":2}')
        self.assertEqual(failure.exception.guard, 'original-file-format')

    def test_truncated_jsonl_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ledger.jsonl'
            path.write_text('{"id":1}')
            with self.assertRaises(audit.Rejected) as failure:
                audit.lines(path)
            self.assertEqual(failure.exception.guard, 'original-file-format')

    def test_missing_complete_response_rejected(self):
        with self.assertRaises(audit.Rejected) as failure:
            audit.pairs([{'event': 'client_invoked', 'worker': 1}])
        self.assertEqual(failure.exception.guard, 'client-call-denominator')

    def test_negative_mutation_cannot_change_original_aliases(self):
        original = {'history': [{'event': 'ack_audited', 'nested': {'bytes': [1, 2, 3]}}], 'acks': []}
        changed = audit.changed_history(original, lambda row: True, lambda row: row['nested']['bytes'].__setitem__(0, 9))
        self.assertEqual(original['history'][0]['nested']['bytes'], [1, 2, 3])
        self.assertEqual(changed['history'][0]['nested']['bytes'], [9, 2, 3])

    def test_duplicate_execute_cannot_be_collapsed_by_request_id(self):
        calls = [({'operation': 'session_execute', 'request_id': rid}, {}) for rid in range(1, 40)]
        calls.append(calls[-1])
        with self.assertRaises(audit.Rejected) as failure:
            audit.original_mutations(calls)
        self.assertEqual(failure.exception.guard, 'all-39-original-results')

    def test_original_unknown_cannot_be_resolved_by_ack_label_only(self):
        unknown = ({'worker': 1, 'pid': 101}, {'monotonic_ns': 100})
        with self.assertRaises(audit.Rejected) as failure:
            audit.original_unknown_lookup([], unknown, {'monotonic_ns': 200})
        self.assertEqual(failure.exception.guard, 'original-unknown-preserved')

    def test_warm_lookup_after_ack_is_not_resolution_evidence(self):
        unknown = ({'worker': 1, 'pid': 101}, {'monotonic_ns': 100})
        calls = [({'worker': 1, 'pid': 101, 'operation': 'lookup_identity', 'request_id': 39,
                   'request_epoch': 1, 'monotonic_ns': 201},
                  {'monotonic_ns': 202, 'ok': True, 'error': None, 'resolution': 'committed'})]
        with self.assertRaises(audit.Rejected) as failure:
            audit.original_unknown_lookup(calls, unknown, {'monotonic_ns': 200})
        self.assertEqual(failure.exception.guard, 'original-unknown-preserved')

    def test_delivery_log_cannot_precede_backend_response(self):
        with self.assertRaises(audit.Rejected) as failure:
            audit.response_order({'monotonic_ns': 1}, {'monotonic_ns': 2}, {'monotonic_ns': 4}, {'monotonic_ns': 3})
        self.assertEqual(failure.exception.guard, 'original-http-denominator')

    def test_post_send_log_may_legally_be_late(self):
        audit.response_order({'monotonic_ns': 1}, {'monotonic_ns': 2}, {'monotonic_ns': 3}, {'monotonic_ns': 100})

    def test_paired_unrelated_pid_is_not_an_owned_call(self):
        history = [{'event': 'worker_started', 'worker': 1, 'pid': 101, 'monotonic_ns': 1},
                   {'event': 'worker_stopped', 'worker': 1, 'pid': 101, 'monotonic_ns': 10}]
        calls = [({'worker': 1, 'pid': 999, 'monotonic_ns': 2}, {'worker': 1, 'pid': 999, 'monotonic_ns': 3})]
        with self.assertRaises(audit.Rejected) as failure:
            audit.bind_calls_to_processes(calls, history)
        self.assertEqual(failure.exception.guard, 'client-process-identity')

    def test_unplanned_execute_cannot_bypass_session_execute_filter(self):
        calls = [({'operation': operation}, {}) for operation, count in audit.FIXED_CALLS.items() for _ in range(count)]
        calls.append(({'operation': 'execute'}, {}))
        with self.assertRaises(audit.Rejected) as failure:
            audit.fixed_call_inventory(calls, {})
        self.assertEqual(failure.exception.guard, 'fixed-client-operation-denominator')

    def test_manifest_cannot_create_missing_wal_or_pollute_original_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence, repo = root / 'actual', root / 'repo'
            evidence.mkdir(); repo.mkdir()
            image, capture = root / 'database.sqlite', root / 'capture.json'
            for target in (Path(str(image) + '-wal'), evidence / 'new-file.json', repo / 'new-file.json', capture):
                with self.assertRaises(audit.Rejected) as failure:
                    audit.validate_manifest_destination(target, evidence, image, capture, repo)
                self.assertEqual(failure.exception.guard, 'read-only-output-boundary')
                self.assertFalse(target.exists())
            audit.validate_manifest_destination(root / 'audit-output.jsonl', evidence, image, capture, repo)


if __name__ == '__main__':
    unittest.main()
