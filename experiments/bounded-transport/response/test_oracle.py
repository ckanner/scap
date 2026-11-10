"""Observer boundary controls, distinct from the real socket contract."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from oracle import common, deadline_case


class DeadlineOracle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def saved(self, name, value):
        (self.root / name).write_bytes(value)
        return {'file': name, 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}

    def history(self, name='stalled'):
        length = 22 * 1024 * 1024
        header = {'event': 'slow_headers', 'id': name, 'monotonic_ns': 1_000_000_000,
            'headers': self.saved(name + '.headers', f'HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n'.encode()),
            'content_length': length, 'status': 200, 'body_bytes_read': 0, 'receive_buffer': 8192}
        events = [header]
        if name == 'drip':
            events.extend({'event': 'slow_drip', 'id': name, 'ordinal': i,
                'monotonic_ns': 1_000_000_000 + i * 500_000_000,
                'response': self.saved(f'drip-{i}', b'x')} for i in (1, 2, 3))
        events.append({'event': 'slow_drain_started', 'id': name, 'body_bytes_read': 0,
                       'monotonic_ns': 3_300_000_000})
        request = {'monotonic_ns': 500_000_000}
        response = {'status': 200, 'monotonic_ns': 3_400_000_000, 'expected_bytes': length,
            'response': self.saved(name + '.body', b'partial'), 'complete': False,
            'peer_eof': True, 'peer_failure': None}
        return events, request, response

    def check(self, name, values):
        return deadline_case(self.root, values[0], name, values[1], values[2])

    def test_accepts_truncated_stall_drip_and_shutdown_observations(self):
        for name in ('stalled', 'drip', 'shutdown'):
            self.check(name, self.history(name))

    def test_rejects_complete_or_unobserved_peer_close(self):
        original = self.history()
        for field, value, rule in (('complete', True, 'peer-truncated'), ('peer_eof', False, 'peer-closed')):
            with self.subTest(field=field):
                history = copy.deepcopy(original)
                history[2][field] = value
                with self.assertRaisesRegex(common.Rejected, rule):
                    self.check('stalled', history)

    def test_rejects_renewed_or_premature_drain_window(self):
        original = self.history()
        for moment in (2_000_000_000, 4_900_000_000):
            history = copy.deepcopy(original)
            history[0][-1]['monotonic_ns'] = moment
            history[2]['monotonic_ns'] = moment + 100_000_000
            with self.assertRaisesRegex(common.Rejected, 'absolute-drain-window'):
                self.check('stalled', history)

    def test_rejects_late_peer_close(self):
        history = self.history()
        history[2]['monotonic_ns'] = 7_000_000_000
        with self.assertRaisesRegex(common.Rejected, 'peer-close-window'):
            self.check('stalled', history)

    def test_rejects_client_disconnect_as_server_expiry(self):
        history = self.history()
        history[0].append({'event': 'slow_disconnected', 'id': 'stalled'})
        with self.assertRaisesRegex(common.Rejected, 'no-client-disconnect'):
            self.check('stalled', history)

    def test_rejects_missing_or_late_drips(self):
        history = self.history('drip')
        history[0][1]['monotonic_ns'] = 3_000_000_000
        with self.assertRaisesRegex(common.Rejected, 'drip-time'):
            self.check('drip', history)
        history[0].pop(1)
        with self.assertRaisesRegex(common.Rejected, 'drip-count'):
            self.check('drip', history)

    def test_rejects_hidden_body_prefetch(self):
        history = self.history()
        history[0][0]['body_bytes_read'] = 1
        with self.assertRaisesRegex(common.Rejected, 'slow-consumer'):
            self.check('stalled', history)

    def test_rejects_duplicate_headers_or_changed_raw_body(self):
        history = self.history()
        history[0].insert(0, copy.deepcopy(history[0][0]))
        with self.assertRaisesRegex(common.Rejected, 'event-denominator'):
            self.check('stalled', history)
        history[0].pop(0)
        (self.root / 'stalled.body').write_bytes(b'wrong')
        with self.assertRaisesRegex(common.Rejected, 'raw-integrity'):
            self.check('stalled', history)


if __name__ == '__main__':
    unittest.main()
