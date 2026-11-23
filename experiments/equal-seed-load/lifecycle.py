"""Independent strict lifecycle-v1 reader and quiescent cohort arithmetic.

No production serializers, state machines, SDK parsers or request identifiers
are imported. Synthetic records belong only to unit tests and controls.
"""
import re

import spec

U64_MAX = (1 << 64) - 1


class Invalid(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def require(value, rule):
    if not value:
        raise Invalid(rule)


def shape(value, keys, rule):
    require(type(value) is dict and set(value) == set(keys), rule)


def number(value):
    require(type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value) is not None
            and len(value) <= 20 and int(value) <= U64_MAX, 'lifecycle-integer')
    return int(value)


def histogram(value, named=False):
    names = ('completed', 'censored', 'not_reached', 'total_us', 'buckets')
    shape(value, (*names, 'interval') if named else names, 'lifecycle-interval-shape')
    result = {key: number(value[key]) for key in names if key != 'buckets'}
    require(type(value['buckets']) is list and len(value['buckets']) == len(spec.BUCKETS_US),
            'lifecycle-bucket-shape')
    result['buckets'] = [number(item) for item in value['buckets']]
    require(sum(result['buckets']) == result['completed'], 'lifecycle-histogram-denominator')
    lower = (0, *(bound + 1 for bound in spec.BUCKETS_US[:-1]))
    require(sum(count * bound for count, bound in zip(result['buckets'], lower)) <= result['total_us']
            <= sum(count * bound for count, bound in zip(result['buckets'], spec.BUCKETS_US)),
            'lifecycle-duration-range')
    return result


def parse(value):
    shape(value, ('version', 'valid', 'unit', 'histogram_upper_bounds_us', 'lanes', 'groups'),
          'lifecycle-shape')
    require(type(value['version']) is int and value['version'] == 1
            and type(value['valid']) is bool and value['unit'] == 'microseconds',
            'lifecycle-version')
    require(value['histogram_upper_bounds_us'] == [str(item) for item in spec.BUCKETS_US],
            'lifecycle-bounds')
    require(value['valid'], 'lifecycle-invalid')
    require(type(value['lanes']) is list and len(value['lanes']) == len(spec.LANES),
            'lifecycle-lanes')
    lanes = {}
    for expected, lane in zip(spec.LANES, value['lanes']):
        shape(lane, ('lane', 'acquired', 'released', 'active', 'intervals'), 'lifecycle-lane-shape')
        require(lane['lane'] == expected, 'lifecycle-lanes')
        entry = {key: number(lane[key]) for key in ('acquired', 'released', 'active')}
        require(entry['acquired'] == entry['released'] + entry['active'], 'lifecycle-lane-conservation')
        require(type(lane['intervals']) is list and len(lane['intervals']) == len(spec.INTERVALS),
                'lifecycle-intervals')
        entry['intervals'] = {}
        for name, interval in zip(spec.INTERVALS, lane['intervals']):
            parsed = histogram(interval, named=True)
            require(interval['interval'] == name, 'lifecycle-intervals')
            require(sum(parsed[key] for key in ('completed', 'censored', 'not_reached')) == entry['released'],
                    'lifecycle-interval-conservation')
            entry['intervals'][name] = parsed
        lanes[expected] = entry
    group = value['groups']
    shape(group, ('attempts', 'active', 'selected', 'consumed', 'declined', 'completed',
                  'incomplete', 'duration', 'selected_sizes', 'consumed_sizes'), 'lifecycle-group-shape')
    groups = {key: number(group[key]) for key in
              ('attempts', 'active', 'selected', 'consumed', 'declined', 'completed', 'incomplete')}
    require(groups['attempts'] == sum(groups[key] for key in ('active', 'declined', 'completed', 'incomplete')),
            'lifecycle-group-conservation')
    groups['duration'] = histogram(group['duration'])
    require(groups['duration']['completed'] == groups['completed'] + groups['declined']
            and groups['duration']['censored'] == groups['incomplete']
            and groups['duration']['not_reached'] == 0, 'lifecycle-group-duration')
    for key, count, members in (('selected_sizes', 'attempts', 'selected'),
                                ('consumed_sizes', 'completed', 'consumed')):
        require(type(group[key]) is list and len(group[key]) == 64, 'lifecycle-group-size-shape')
        sizes = [number(item) for item in group[key]]
        require(sum(sizes) == groups[count] and sum((index + 1) * value for index, value in enumerate(sizes))
                == groups[members], 'lifecycle-group-sizes')
        groups[key] = sizes
    require(groups['consumed'] <= groups['selected'], 'lifecycle-group-consumption')
    return {'lanes': lanes, 'groups': groups}


def quiescent(value):
    return all(lane['active'] == 0 for lane in value['lanes'].values()) and value['groups']['active'] == 0


def subtract(before, after):
    if type(before) is int and type(after) is int:
        require(after >= before, 'lifecycle-counter-regression')
        return after - before
    if type(before) is list and type(after) is list and len(before) == len(after):
        return [subtract(left, right) for left, right in zip(before, after)]
    require(type(before) is dict and type(after) is dict and set(before) == set(after),
            'lifecycle-delta-shape')
    return {key: subtract(before[key], after[key]) for key in before}


def cohort(before, after, expected):
    require(quiescent(before) and quiescent(after), 'lifecycle-nonquiescent')
    require(set(expected) == set(spec.LANES), 'lifecycle-cohort-lanes')
    delta = subtract(before, after)
    for lane in spec.LANES:
        actual = delta['lanes'][lane]
        require(actual['acquired'] == actual['released'] == expected[lane]
                and actual['active'] == 0, 'lifecycle-cohort-denominator')
        for interval in actual['intervals'].values():
            require(interval['completed'] + interval['censored'] + interval['not_reached'] == expected[lane]
                    and sum(interval['buckets']) == interval['completed'], 'lifecycle-cohort-histogram')
            lower = (0, *(bound + 1 for bound in spec.BUCKETS_US[:-1]))
            require(sum(count * bound for count, bound in zip(interval['buckets'], lower)) <= interval['total_us']
                    <= sum(count * bound for count, bound in zip(interval['buckets'], spec.BUCKETS_US)),
                    'lifecycle-cohort-duration-range')
        require(actual['intervals']['total_hold']['completed'] == expected[lane],
                'lifecycle-total-hold-complete')
    return delta
