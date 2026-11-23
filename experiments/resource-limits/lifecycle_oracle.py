"""Independent fixed lifecycle schema and completed-cohort conservation checks."""
import re

LANES = ('data', 'control', 'recovery', 'catalogue', 'restore')
INTERVALS = ('body', 'pre_enqueue', 'queue', 'invocation', 'encoding',
             'post_work_hold', 'post_http_hold', 'total_hold')
PHASES = ('body-held', 'body-released', 'after-http-timeout', 'worker-released',
          'slow-response', 'response-released', 'final')
BOUNDS = (100, 500, 1000, 5000, 10000, 50000, 100000, 500000,
          1000000, 2500000, 5000000, 10000000, 30000000, 60000000,
          300000000, 1800000000, 86400000000, 604800000000, 2**64 - 1)


def need(value, reason):
    if not value:
        raise ValueError('lifecycle: ' + reason)


def count(value):
    need(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is not None,
         'noncanonical counter')
    number = int(value)
    need(number <= 2**64 - 1, 'counter overflow')
    return number


def phase_id(value):
    need(isinstance(value, str), 'observation identity')
    match = re.fullmatch('(' + '|'.join(PHASES) + r')-(0|[1-9][0-9]?)', value)
    need(match is not None, 'unplanned observation identity')
    return match.group(1), int(match.group(2))


def histogram(value, released):
    need(set(value) == {'completed', 'censored', 'not_reached', 'total_us', 'buckets'}, 'histogram fields')
    numbers = {name: count(value[name]) for name in ('completed', 'censored', 'not_reached', 'total_us')}
    need(isinstance(value['buckets'], list) and len(value['buckets']) == len(BOUNDS), 'bucket shape')
    buckets = [count(number) for number in value['buckets']]
    need(sum(buckets) == numbers['completed'], 'bucket conservation')
    need(sum(numbers[name] for name in ('completed', 'censored', 'not_reached')) == released,
         'interval denominator')
    need(numbers['completed'] > 0 or numbers['total_us'] == 0, 'unobserved duration')
    lower = (0, *(upper + 1 for upper in BOUNDS[:-1]))
    need(sum(n * bound for n, bound in zip(buckets, lower)) <= numbers['total_us'] <=
         sum(n * bound for n, bound in zip(buckets, BOUNDS)), 'duration outside buckets')
    numbers['buckets'] = buckets
    return numbers


def snapshot(value):
    need(set(value) == {'version', 'valid', 'unit', 'histogram_upper_bounds_us', 'lanes', 'groups'}, 'snapshot fields')
    need(type(value['version']) is int and value['version'] == 1 and value['valid'] is True,
         'invalid version or incomplete counters')
    need(value['unit'] == 'microseconds' and value['histogram_upper_bounds_us'] == [str(v) for v in BOUNDS], 'time contract')
    need(isinstance(value['lanes'], list) and [lane['lane'] for lane in value['lanes']] == list(LANES), 'lane denominator')
    lanes = {}
    for lane in value['lanes']:
        need(set(lane) == {'lane', 'acquired', 'released', 'active', 'intervals'}, 'lane fields')
        row = {key: count(lane[key]) for key in ('acquired', 'released', 'active')}
        need(row['acquired'] == row['released'] + row['active'], 'acquire/release conservation')
        need([v['interval'] for v in lane['intervals']] == list(INTERVALS), 'interval denominator')
        row['intervals'] = {v['interval']: histogram({k: n for k, n in v.items() if k != 'interval'}, row['released'])
                            for v in lane['intervals']}
        need(row['intervals']['total_hold']['completed'] == row['released'], 'total holding samples')
        lanes[lane['lane']] = row
    groups = value['groups']
    need(set(groups) == {'attempts', 'active', 'selected', 'consumed', 'declined', 'completed', 'incomplete',
                        'duration', 'selected_sizes', 'consumed_sizes'}, 'group fields')
    # This actual fixture deliberately leaves group commit disabled.
    need(all(count(groups[key]) == 0 for key in ('attempts', 'active', 'selected', 'consumed', 'declined', 'completed', 'incomplete')),
         'unexpected group attempt')
    histogram(groups['duration'], 0)
    need(groups['selected_sizes'] == groups['consumed_sizes'] == ['0'] * 64, 'unexpected group member sizes')
    return lanes


def observations(events, calls, refused):
    previous = None
    selected = [row for row in events if row['event'] == 'admission_observed']
    phases = {phase: [] for phase in PHASES}
    for row in selected:
        phase, index = phase_id(row['fields']['id'])
        need(index == len(phases[phase]), 'observation index gap or duplicate')
        phases[phase].append(row)
        current = snapshot(row['fields']['lifecycle'])
        if previous is not None:
            for name in LANES:
                need(all(current[name][key] >= previous[name][key] for key in ('acquired', 'released')), 'counter reset')
                for interval in INTERVALS:
                    need(all(current[name]['intervals'][interval][key] >= previous[name]['intervals'][interval][key]
                             for key in ('completed', 'censored', 'not_reached', 'total_us')), 'interval reset')
                    need(all(now >= old for now, old in zip(current[name]['intervals'][interval]['buckets'],
                             previous[name]['intervals'][interval]['buckets'])), 'bucket reset')
        previous = current
    for phase, active in (('body-held', 1), ('after-http-timeout', 1), ('slow-response', 1),
                          ('body-released', 0), ('worker-released', 0), ('response-released', 0), ('final', 0)):
        matching = phases[phase]
        need(1 <= len(matching) <= 100, 'missing held/released observation')
        lanes = snapshot(matching[-1]['fields']['lifecycle'])
        need(lanes['data']['active'] == active and all(lanes[name]['active'] == 0 for name in LANES[1:]),
             'lease ended before actual owner')
    need(selected[-1]['fields']['id'].startswith('final-'), 'missing final quiescent observation')
    expected = dict.fromkeys(LANES, 0)
    for label, call in calls.items():
        if label not in refused:
            operation = call['body']['operation']
            lane = ('recovery' if operation == 'activate' else 'control' if operation in ('status', 'lookup', 'cancel') else 'data')
            expected[lane] += 1
    for name in LANES:
        need(previous[name]['acquired'] == previous[name]['released'] == expected[name], 'original HTTP cohort')
        for interval in INTERVALS:
            need(previous[name]['intervals'][interval]['completed'] == expected[name], 'incomplete real lifecycle')
    return {'snapshots': len(selected), 'complete_http_cohort': sum(expected.values()),
            'held_data_witnesses': 3, 'default_group_disabled': True}
