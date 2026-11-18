"""Observer wrappers must preserve outcomes and immutable phase snapshots."""
import threading
import unittest

import causal


class CountersTests(unittest.TestCase):
    def test_wrapped_success_and_failure_keep_original_semantics(self):
        outcome, failure = object(), RuntimeError('original')
        class Target:
            def save(self, body):
                if body == b'fail':
                    raise failure
                return outcome
        target, counters = Target(), causal.Counters()
        counters.wrap(target, 'save', 'raw_save', body=True)
        self.assertIs(target.save(b'ok'), outcome)
        with self.assertRaises(RuntimeError) as caught:
            target.save(b'fail')
        self.assertIs(caught.exception, failure)
        row = counters.snapshot(None)['stages']['raw_save']
        self.assertEqual((row[0], row[3]), (2, 6))

    def test_before_snapshot_cannot_change_when_later_calls_finish(self):
        counters = causal.Counters()
        counters.record('stage', 0, 0, 7)
        before = counters.snapshot(None)
        counters.record('stage', 0, 0, 13)
        after = counters.snapshot(None)
        self.assertEqual((before['stages']['stage'][0], before['stages']['stage'][3]), (1, 7))
        self.assertEqual((after['stages']['stage'][0], after['stages']['stage'][3]), (2, 20))

    def test_observed_lock_releases_when_original_body_fails(self):
        lock, counters = threading.Lock(), causal.Counters()
        with self.assertRaises(ValueError):
            with causal.MeasuredLock(lock, counters, 'wait'):
                self.assertFalse(lock.acquire(blocking=False))
                raise ValueError('original')
        self.assertTrue(lock.acquire(blocking=False))
        lock.release()
        self.assertEqual(counters.snapshot(None)['stages']['wait'][0], 1)


if __name__ == '__main__':
    unittest.main()
