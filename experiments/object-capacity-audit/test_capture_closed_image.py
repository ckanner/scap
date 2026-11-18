"""Small capture-boundary tests; synthetic histories never stand in for gib1."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capture_closed_image', Path(__file__).with_name('capture_closed_image.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def process_history():
    """A tiny, explicitly synthetic owned-lifecycle fixture with no data proof."""
    binary = {'path': '/synthetic/worker', 'sha256': 'a' * 64}
    usage = {'available': True, 'source': 'kernel_wait4_owned_child'}
    rows = []
    starts, stops = [], []
    for worker, begin, finish in ((1, 20, 60), (2, 30, 61), (3, 110, 150)):
        start = {'event': 'worker_started', 'worker': worker, 'pid': 100 + worker,
                 'pid_source': 'owned_Popen_child', 'spawn_monotonic_ns': begin,
                 'monotonic_ns': begin + 1, 'binary': binary}
        end = {key: value for key, value in start.items() if key not in ('event', 'binary')}
        end.update(event='worker_stopped', monotonic_ns=finish, wait_status=-9,
                   kernel_usage=usage.copy(), fault=worker != 3)
        starts.append(start); stops.append(end)
    rows += starts + stops
    rows.append({'event': 'all_compute_and_local_cache_lost', 'monotonic_ns': 70,
                 'local_cache_deleted': True, 'process_signal': 'SIGKILL',
                 'processes': [{key: value for key, value in row.items() if key != 'event'} for row in stops[:2]]})
    for epoch, first_event, last_event, begin, finish in (
        (0, 'backend_started', 'backend_processes_killed', 10, 80),
        (1, 'backend_restarted', 'backend_stopped', 100, 160),
    ):
        children = [{'role': role, 'pid': 200 + epoch * 10 + index, 'pid_source': 'owned_Popen_child',
                     'spawn_monotonic_ns': begin - 5 + index}
                    for index, role in enumerate(('master', 'volume', 'filer', 's3'))]
        rows.append({'event': first_event, 'monotonic_ns': begin, 'directory_identity': 'b' * 64,
                     'processes': children})
        rows.append({'event': last_event, 'monotonic_ns': finish, 'directory_identity': 'b' * 64,
                     'signal': 'SIGKILL', 'processes': [dict(child, wait_status=-9, kernel_usage=usage.copy()) for child in children]})
    return sorted(rows, key=lambda row: row['monotonic_ns']), binary


class CaptureBoundaryTests(unittest.TestCase):
    def image(self, directory):
        source = directory / 'database.sqlite'
        with sqlite3.connect(source) as database:
            database.execute('CREATE TABLE payloads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)')
            database.execute('INSERT INTO payloads VALUES (1, ?)', (b'small real SQLite fixture' * 100,))
        return source

    def paths(self, directory):
        actual, private = directory / 'actual', directory / 'private'
        actual.mkdir(); (private / 'compute' / 'recovered').mkdir(parents=True)
        source = self.image(private / 'compute' / 'recovered')
        destination = directory / 'closed-image'
        return actual, source, destination, destination / 'capture.json', private

    def test_real_closed_image_copy_preserves_all_originals_and_is_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = self.image(root)
            Path(str(source) + '-wal').touch(); Path(str(source) + '-shm').write_bytes(b'closed-sidecar')
            before = capture.image_inventory(source)
            signatures = {suffix: capture.stat_signature(Path(str(source) + suffix)) for suffix in capture.SIDE_SUFFIXES}
            image, original, after, copied = capture.copy_closed_files(source, root / 'closed')
            self.assertEqual(before, original); self.assertEqual(original, after); self.assertEqual(after, copied)
            self.assertEqual(signatures, {suffix: capture.stat_signature(Path(str(source) + suffix)) for suffix in capture.SIDE_SUFFIXES})
            self.assertNotEqual(source.stat().st_ino, image.stat().st_ino)
            connection = sqlite3.connect(image.as_uri() + '?mode=ro&immutable=1', uri=True)
            try:
                self.assertEqual(connection.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
                self.assertEqual(connection.execute('SELECT count(*) FROM payloads').fetchone(), (1,))
            finally:
                connection.close()
            self.assertEqual(capture.image_inventory(source), before)

    def test_nonempty_wal_or_journal_refuses_before_creating_output(self):
        for suffix in ('-wal', '-journal'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); source = self.image(root)
                Path(str(source) + suffix).write_bytes(b'not checkpointed')
                before = source.read_bytes()
                with self.assertRaisesRegex(capture.CaptureError, 'nonempty WAL/journal'):
                    capture.copy_closed_files(source, root / 'closed')
                self.assertEqual(source.read_bytes(), before)
                self.assertFalse((root / 'closed').exists())

    def test_symlink_source_sidecar_or_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = self.image(root)
            alias = root / 'alias.sqlite'; alias.symlink_to(source)
            parent = root / 'alias-directory'; parent.symlink_to(root, target_is_directory=True)
            for path in (alias, parent / 'database.sqlite'):
                with self.subTest(path=path), self.assertRaisesRegex(capture.CaptureError, 'symlink'):
                    capture.copy_closed_files(path, root / 'closed')
                self.assertFalse((root / 'closed').exists())
            Path(str(source) + '-shm').symlink_to(source)
            with self.assertRaisesRegex(capture.CaptureError, 'symlink'):
                capture.copy_closed_files(source, root / 'closed')
            self.assertFalse((root / 'closed').exists())

    def test_destination_cannot_pollute_original_trees_or_overwrite_attempt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); actual, source, destination, metadata, private = self.paths(root)
            before = capture.image_inventory(source)
            for target in (actual / 'extra', private / 'extra'):
                with self.subTest(target=target), self.assertRaisesRegex(capture.CaptureError, 'original evidence or private state'):
                    capture.validate_paths(actual, source, target, target / 'capture.json', private)
                self.assertFalse(target.exists())
            destination.mkdir(); (destination / 'sentinel').write_bytes(b'keep original attempt')
            with self.assertRaisesRegex(capture.CaptureError, 'already exists'):
                capture.validate_paths(actual, source, destination, metadata, private)
            self.assertEqual((destination / 'sentinel').read_bytes(), b'keep original attempt')
            self.assertEqual(capture.image_inventory(source), before)

    def test_metadata_cannot_escape_new_destination_or_create_source_sidecar(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); actual, source, destination, metadata, private = self.paths(root)
            for target in (actual / 'new.json', Path(str(source) + '-journal'), root / 'outside.json'):
                with self.subTest(target=target), self.assertRaisesRegex(capture.CaptureError, 'directly in the new destination'):
                    capture.validate_paths(actual, source, destination, target, private)
                self.assertFalse(target.exists())
            self.assertFalse(destination.exists())
            self.assertEqual(capture.validate_paths(actual, source, destination, metadata, private),
                             (actual, source, destination, metadata, private))

    def test_source_changed_during_copy_is_rejected_and_partial_output_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = self.image(root)
            original_copy = capture.copy_file

            def copy_then_change(incoming, outgoing, expected):
                original_copy(incoming, outgoing, expected)
                with incoming.open('ab') as stream:
                    stream.write(b'synthetic concurrent change')

            with patch.object(capture, 'copy_file', side_effect=copy_then_change):
                with self.assertRaisesRegex(capture.CaptureError, 'changed or copied bytes differ'):
                    capture.copy_closed_files(source, root / 'closed')
            self.assertTrue(source.exists()); self.assertTrue((root / 'closed/database.sqlite').exists())

    def test_byte_identical_source_replacement_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = self.image(root)
            original_copy = capture.copy_file

            def copy_then_replace(incoming, outgoing, expected):
                original_copy(incoming, outgoing, expected)
                replacement = incoming.with_name('replacement.sqlite')
                replacement.write_bytes(incoming.read_bytes()); replacement.replace(incoming)

            with patch.object(capture, 'copy_file', side_effect=copy_then_replace):
                with self.assertRaisesRegex(capture.CaptureError, 'identity changed'):
                    capture.copy_closed_files(source, root / 'closed')
            self.assertTrue(source.exists()); self.assertTrue((root / 'closed/database.sqlite').exists())


class OwnedExitTests(unittest.TestCase):
    def test_all_original_children_count_and_last_exit(self):
        history, binary = process_history()
        self.assertEqual(capture.owned_exits(history, binary), {
            'compute_incarnations': 3, 'backend_incarnations': 8, 'owned_wait4': 11,
            'last_exit_monotonic_ns': 160})

    def test_missing_compute_exit_or_non_kernel_wait_fails(self):
        history, binary = process_history()
        mutations = [
            [row for row in history if not (row['event'] == 'worker_stopped' and row['worker'] == 3)],
            deepcopy(history),
        ]
        last = next(row for row in mutations[1] if row['event'] == 'backend_stopped')
        last['processes'][0]['kernel_usage']['source'] = 'synthetic estimate'
        for rows in mutations:
            with self.subTest(rows=len(rows)), self.assertRaises(capture.CaptureError):
                capture.owned_exits(rows, binary)

    def test_start_after_exit_is_not_owned_lifecycle_proof(self):
        history, binary = process_history()
        next(row for row in history if row['event'] == 'worker_started' and row['worker'] == 3)['monotonic_ns'] = 151
        with self.assertRaisesRegex(capture.CaptureError, 'timestamps are out of order'):
            capture.owned_exits(history, binary)


if __name__ == '__main__':
    unittest.main()
