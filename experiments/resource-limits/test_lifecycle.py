"""Synthetic observer counterexamples; never substitute for actual evidence."""
import copy
import unittest

import lifecycle_oracle as observer
import controls


def histogram(samples=0):
    return {'completed': str(samples), 'censored': '0', 'not_reached': '0',
            'total_us': str(samples), 'buckets': [str(samples)] + ['0'] * 18}


def snapshot(samples=0):
    return {'version': 1, 'valid': True, 'unit': 'microseconds',
            'histogram_upper_bounds_us': [str(n) for n in observer.BOUNDS],
            'lanes': [{'lane': name, 'acquired': str(samples), 'released': str(samples), 'active': '0',
                       'intervals': [{'interval': interval, **histogram(samples)} for interval in observer.INTERVALS]}
                      for name in observer.LANES],
            'groups': {**dict.fromkeys(('attempts', 'active', 'selected', 'consumed', 'declined', 'completed', 'incomplete'), '0'),
                       'duration': histogram(), 'selected_sizes': ['0'] * 64, 'consumed_sizes': ['0'] * 64}}


def cohort():
    phases = [('body-held', 5, 4, 0), ('body-released', 6, 6, 1),
              ('after-http-timeout', 8, 7, 1), ('worker-released', 9, 9, 2),
              ('slow-response', 12, 11, 5), ('response-released', 13, 13, 6),
              ('final', 14, 14, 6)]
    events = []
    for phase, acquired, released, control in phases:
        value = snapshot()
        for index, (got, freed) in enumerate(((acquired, released), (control, control), (2, 2), (0, 0), (0, 0))):
            lane = value['lanes'][index]
            lane.update(acquired=str(got), released=str(freed), active=str(got - freed))
            lane['intervals'] = [{'interval': interval, **histogram(freed)} for interval in observer.INTERVALS]
        events.append({'event': 'admission_observed', 'fields': {'id': phase + '-0', 'lifecycle': value}})
    calls = {name + str(index): {'body': {'operation': operation}}
             for name, operation, total in (('data', 'query', 14), ('control', 'status', 6), ('recovery', 'activate', 2))
             for index in range(total)}
    refused = {'refused0', 'refused1', 'refused2'}
    calls.update({name: {'body': {'operation': 'query'}} for name in refused})
    return events, calls, refused


class LifecycleObserver(unittest.TestCase):
    def test_complete_fixed_snapshot(self):
        for samples in (0, 1, 100):
            actual = observer.snapshot(snapshot(samples))
            self.assertEqual(actual['data']['released'], samples)

    def test_counter_syntax_and_u64_are_lossless(self):
        self.assertEqual(observer.count(str(2**64 - 1)), 2**64 - 1)
        for value in (True, 0, '', '01', '-1', str(2**64), '1.0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                observer.count(value)

    def test_snapshot_mutations_fail_closed(self):
        source = snapshot(1)
        mutations = []
        value = copy.deepcopy(source); value['valid'] = False; mutations.append(value)
        value = copy.deepcopy(source); value['version'] = True; mutations.append(value)
        value = copy.deepcopy(source); value['lanes'].reverse(); mutations.append(value)
        value = copy.deepcopy(source); value['lanes'][0]['active'] = '1'; mutations.append(value)
        value = copy.deepcopy(source); value['lanes'][0]['intervals'][0]['total_us'] = '101'; mutations.append(value)
        value = copy.deepcopy(source); value['lanes'][0]['intervals'][0]['buckets'][0] = '0'; mutations.append(value)
        value = copy.deepcopy(source); value['lanes'][0]['intervals'][-1]['completed'] = '0'; mutations.append(value)
        value = copy.deepcopy(source); value['groups']['attempts'] = '1'; mutations.append(value)
        for value in mutations:
            with self.assertRaises(ValueError):
                observer.snapshot(value)

    def test_complete_original_cohort_excludes_only_the_three_intake_refusals(self):
        events, calls, refused = cohort()
        self.assertEqual(len(calls), 25)
        self.assertEqual(observer.observations(events, calls, refused),
                         {'snapshots': 7, 'complete_http_cohort': 22,
                          'held_data_witnesses': 3, 'default_group_disabled': True})

    def test_counter_conservation_cannot_substitute_for_original_http_cohort(self):
        events, calls, refused = cohort()
        value = events[-1]['fields']['lifecycle']
        controls.add_completed_sample(value['lanes'][0], acquired=True)
        observer.snapshot(value)
        with self.assertRaisesRegex(ValueError, 'original HTTP cohort'):
            observer.observations(events, calls, refused)

    def test_consistent_premature_refund_does_not_prove_the_worker_finished(self):
        events, calls, refused = cohort()
        value = events[2]['fields']['lifecycle']
        controls.add_completed_sample(value['lanes'][0], acquired=False)
        observer.snapshot(value)
        with self.assertRaisesRegex(ValueError, 'lease ended before actual owner'):
            observer.observations(events, calls, refused)

    def test_late_missing_interval_and_cumulative_reset_remain_failures(self):
        events, calls, refused = cohort()
        interval = events[-1]['fields']['lifecycle']['lanes'][0]['intervals'][3]
        interval.update(completed='13', censored='1', total_us='13')
        interval['buckets'][0] = '13'
        observer.snapshot(events[-1]['fields']['lifecycle'])
        with self.assertRaisesRegex(ValueError, 'incomplete real lifecycle'):
            observer.observations(events, calls, refused)
        events, calls, refused = cohort()
        for _ in range(2):
            controls.add_completed_sample(events[0]['fields']['lifecycle']['lanes'][0], acquired=True)
        observer.snapshot(events[0]['fields']['lifecycle'])
        with self.assertRaisesRegex(ValueError, 'counter reset'):
            observer.observations(events, calls, refused)

    def test_observation_identity_and_sequence_are_bounded_and_canonical(self):
        self.assertEqual(observer.phase_id('final-99'), ('final', 99))
        for value in ('final-100', 'final-00', 'final--1', 'unknown-0', '', 0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                observer.phase_id(value)
        for mutation in ('gap', 'duplicate', 'missing'):
            events, calls, refused = cohort()
            if mutation == 'gap':
                events[0]['fields']['id'] = 'body-held-1'
            elif mutation == 'duplicate':
                events.insert(1, copy.deepcopy(events[0]))
            else:
                events.pop(0)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                observer.observations(events, calls, refused)

    def test_refund_before_aggregation_can_be_an_intermediate_poll_but_not_the_final_witness(self):
        events, calls, refused = cohort()
        intermediate = copy.deepcopy(events[1])
        lane = intermediate['fields']['lifecycle']['lanes'][0]
        lane.update(released='5', active='1')
        lane['intervals'] = [{'interval': interval, **histogram(5)} for interval in observer.INTERVALS]
        events[1]['fields']['id'] = 'body-released-1'
        events.insert(1, intermediate)
        self.assertEqual(observer.observations(events, calls, refused)['snapshots'], 8)
        events.pop(2)
        with self.assertRaisesRegex(ValueError, 'lease ended before actual owner'):
            observer.observations(events, calls, refused)


if __name__ == '__main__':
    unittest.main()
