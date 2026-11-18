import copy
import unittest

from oracle import HEAD, OTHER_HEAD, client_moment, verify_intervals, verify_refresh


def fixture():
    events = [{"event": "fault_entered", "id": name, "request_serial": serial, "monotonic_ns": moment}
              for name, serial, moment in (("first", 1, 30), ("second", 2, 60))]
    events += [{"event": "fault_released", "id": name, "monotonic_ns": moment}
               for name, moment in (("first", 120), ("second", 160))]
    history = [{"event": "object_request", "request_serial": serial, "method": "GET", "path": HEAD,
                "worker": "pool", "monotonic_ns": moment} for serial, moment in ((1, 20), (2, 50))]
    intervals = {"first": (10, 140), "second": (40, 170), "queued": (65, 150),
                 "other": (70, 80), "write": (85, 95), "control": (100, 110)}
    calls = {index: {"request": {"monotonic_ns": interval[0]}, "response": {"monotonic_ns": interval[1]}}
             for index, interval in enumerate(intervals.values())}
    by_command = {name: [index] for index, name in enumerate(intervals)}
    return events, history, calls, by_command


def refresh_fixture():
    events = [{"event": "fault_entered", "id": name, "request_serial": serial, "monotonic_ns": stamp}
              for name, serial, stamp in (("park_first", 10, 225), ("park_second", 11, 245))]
    events += [{"event": "fault_released", "id": name, "monotonic_ns": stamp}
               for name, stamp in (("park_first", 340), ("park_second", 360))]
    history = [{"event": "object_request", "request_serial": serial, "method": "GET", "path": OTHER_HEAD,
                "worker": "pool", "monotonic_ns": stamp} for serial, stamp in ((10, 220), (11, 240))]
    history += [{"event": "object_request", "request_serial": 12 + index, "method": "GET", "path": HEAD,
                 "worker": "pool", "monotonic_ns": stamp} for index, stamp in enumerate((310, 315, 320))]
    intervals = {"park_first": (210, 350), "park_second": (230, 370),
                 "warm": (260, 270), "write_again": (280, 290), "refresh": (300, 330)}
    calls = {index: {"request": {"monotonic_ns": interval[0]}, "response": {"monotonic_ns": interval[1]}}
             for index, interval in enumerate(intervals.values())}
    by_command = {name: [index] for index, name in enumerate(intervals)}
    return events, history, calls, by_command


class IntervalOracleTests(unittest.TestCase):
    def test_sdk_clock_is_canonical_decimal_text_and_not_an_object_clock(self):
        self.assertEqual(client_moment({"monotonic_ns": "123456789"}), 123456789)
        for value in (0, 1, None, False, "", "0", "01", "-1", "1.0", " 1", "١"):
            with self.assertRaisesRegex(ValueError, "invalid SDK monotonic timestamp"):
                client_moment({"monotonic_ns": value})

    def test_complete_overlap_has_no_latency_or_tps_threshold(self):
        values = fixture()
        verify_intervals(*values)
        for rows in values[:2]:
            for row in rows:
                row["monotonic_ns"] *= 1000000
        for call in values[2].values():
            for row in call.values():
                row["monotonic_ns"] *= 1000000
        verify_intervals(*values)

    def test_sequential_reads_do_not_count_as_parallel(self):
        values = fixture()
        values[0][2]["monotonic_ns"] = 55
        with self.assertRaisesRegex(ValueError, "did not overlap"):
            verify_intervals(*values)

    def test_hold_must_belong_to_its_actual_query(self):
        values = fixture()
        values[2][1]["request"]["monotonic_ns"] = 51
        with self.assertRaisesRegex(ValueError, "outside original query"):
            verify_intervals(*values)

    def test_gate_checks_method_scope_and_worker(self):
        for field, value in (("method", "PUT"), ("path", HEAD + "-wrong"), ("worker", "other")):
            values = fixture()
            values[1][0][field] = value
            with self.assertRaisesRegex(ValueError, "held another operation"):
                verify_intervals(*values)

    def test_one_get_cannot_certify_two_readers(self):
        values = fixture()
        values[0][0].update(request_serial=2, monotonic_ns=55)
        with self.assertRaisesRegex(ValueError, "one GET counted twice"):
            verify_intervals(*values)

    def test_other_tenant_writer_and_controls_each_need_independent_progress(self):
        for name in ("other", "write", "control"):
            values = fixture()
            values[2][values[3][name][0]]["response"]["monotonic_ns"] = 121
            with self.assertRaisesRegex(ValueError, "blocked another tenant"):
                verify_intervals(*values)

    def test_queue_must_wait_for_active_reservation_release(self):
        values = fixture()
        values[2][values[3]["queued"][0]]["response"]["monotonic_ns"] = 119
        with self.assertRaisesRegex(ValueError, "escaped active quota"):
            verify_intervals(*values)

    def test_each_observation_is_unique(self):
        for index in (0, 1, 2, 3):
            values = fixture()
            values[0].append(copy.deepcopy(values[0][index]))
            with self.assertRaisesRegex(ValueError, "missing/duplicate"):
                verify_intervals(*values)

    def test_refresh_requires_two_other_tenant_readers_parked_for_all_three_commands(self):
        verify_refresh(*refresh_fixture())
        for name in ("warm", "write_again", "refresh"):
            values = refresh_fixture()
            values[2][values[3][name][0]]["response"]["monotonic_ns"] = 345
            with self.assertRaisesRegex(ValueError, "escaped the single remaining reader"):
                verify_refresh(*values)
        values = refresh_fixture()
        values[1][0]["path"] = HEAD
        with self.assertRaisesRegex(ValueError, "parking gate lacks"):
            verify_refresh(*values)

    def test_refresh_rejects_one_parked_worker_counted_twice(self):
        values = refresh_fixture()
        values[0][0].update(request_serial=11, monotonic_ns=242)
        with self.assertRaisesRegex(ValueError, "one parked worker twice"):
            verify_refresh(*values)

    def test_cold_worker_and_multiple_refreshes_cannot_satisfy_stale_refresh(self):
        for count in (1, 2, 4):
            values = refresh_fixture()
            values[1][:] = values[1][:2] + [dict(values[1][2], request_serial=12 + index, monotonic_ns=310 + index)
                                          for index in range(count)]
            with self.assertRaisesRegex(ValueError, "exactly one pre-SQL refresh"):
                verify_refresh(*values)


if __name__ == "__main__":
    unittest.main()
