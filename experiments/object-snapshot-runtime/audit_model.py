"""Independent S1 rules, composed with earlier independent wire witnesses.

No product, SDK, runner or runtime spec is imported. The legacy projection is
used only after every new HEAD9 field and its relation to the full HEAD has
been checked; it supplies the unchanged HEAD6--8 base-field predicates.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unicodedata

description = importlib.util.spec_from_file_location('snapshot_legacy_witness',
    Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime/audit_model.py')
legacy = importlib.util.module_from_spec(description)
description.loader.exec_module(legacy)
wire, need, Rejected, sha, uint, digest = legacy.wire, legacy.need, legacy.Rejected, legacy.sha, legacy.uint, legacy.digest
encoded, scope_key, prefix, envelope = legacy.encoded, legacy.scope_key, legacy.prefix, legacy.envelope
owner_input, owner_reference = legacy.owner_input, legacy.owner_reference
SCOPE, OWNER_INPUT = legacy.SCOPE, legacy.OWNER_INPUT
EXTRA = {'snapshots', 'snapshot_limits', 'restore_origin'}
REF = ('creator', 'operation', 'capture_serial', 'descriptor_hash')
POINT = ('data_root', 'page_count', 'sequence', 'source_revision')
INPUT = ('creator', 'operation', 'expected_revision', 'expected_head_serial', 'label')
BASE = ('head_hash', 'etag', 'revision', 'head_serial')
LIMITS = ('max_points', 'max_logical_bytes')


def ordered(value, fields):
    return {field: value[field] for field in fields}


def shape(value, fields, guard):
    need(isinstance(value, dict) and set(value) == set(fields), guard)
    return value


def label(value):
    need(isinstance(value, str) and 0 < len(value.encode('utf8')) <= 128
         and all(unicodedata.category(char) != 'Cc' for char in value), 'snapshot-label')


def limits(value):
    shape(value, LIMITS, 'snapshot-limits-shape')
    uint(value['max_points'], 64)
    uint(value['max_logical_bytes'], 64 * (2**32 - 2) * 4096)
    return value


def snapshot_input(value):
    shape(value, INPUT, 'snapshot-input-shape')
    for field in INPUT[:-1]:
        uint(value[field], minimum=1)
    need(value['expected_revision'] <= value['expected_head_serial'], 'snapshot-original-counter-order')
    label(value['label'])
    return value


def point(value):
    shape(value, POINT, 'snapshot-point-shape')
    digest(value['data_root'])
    uint(value['page_count'], 2**32 - 2)
    uint(value['sequence'])
    uint(value['source_revision'], minimum=1)
    return value


def entry(value):
    shape(value, ('reference', 'label', 'point'), 'snapshot-entry-shape')
    reference = shape(value['reference'], REF, 'snapshot-reference-shape')
    for field in REF[:-1]:
        uint(reference[field], minimum=1)
    digest(reference['descriptor_hash'])
    point(value['point'])
    label(value['label'])
    need(value['point']['source_revision'] < reference['capture_serial'], 'snapshot-source-before-capture')
    return value


def canonical_entry(value):
    return {'reference': ordered(value['reference'], REF), 'label': value['label'],
            'point': ordered(value['point'], POINT)}


def projection(value):
    """Base-field witness; never an S1 admission or an S1 transition by itself."""
    result = copy.deepcopy(value)
    if result['format'] == 9:
        for field in EXTRA:
            del result[field]
        result['format'] = 8 if 'owner_plan' in result else 7 if 'terminal' in result['storage'] else 6
        if result['storage']['plan'] is not None:
            for field in ('snapshots', 'snapshot_limits'):
                del result['storage']['plan']['basis'][field]
    return result


def canonical_head(value):
    base = wire.parse(legacy.canonical_head(value))
    if value['format'] != 9:
        return encoded(base)
    # All three S1 fields sit between owner_plan and active in the typed format.
    result = {}
    for field, item in base.items():
        if field == 'active':
            result.update(snapshots=[canonical_entry(item) for item in value['snapshots']],
                          snapshot_limits=ordered(value['snapshot_limits'], LIMITS), restore_origin=None)
        result[field] = item
    if value['storage']['plan'] is not None:
        basis = result['storage']['plan']['basis']
        actual = value['storage']['plan']['basis']
        basis['snapshots'] = [canonical_entry(item) for item in actual['snapshots']]
        basis['snapshot_limits'] = ordered(actual['snapshot_limits'], LIMITS)
    return encoded(result)


def held(value, serial, revision, sequence, policy):
    need(isinstance(value, list) and len(value) <= 64, 'snapshot-table-bound')
    identities, labels, previous, gross = set(), set(), 0, 0
    for item in value:
        entry(item)
        reference, position = item['reference'], item['point']
        identity = (reference['creator'], reference['operation'])
        need(identity not in identities and item['label'] not in labels, 'snapshot-unique-identity-label')
        need(previous < reference['capture_serial'] <= serial and position['source_revision'] <= revision
             and position['sequence'] <= sequence, 'snapshot-current-authority-bound')
        identities.add(identity); labels.add(item['label'])
        previous = reference['capture_serial']
        gross += position['page_count'] * 4096
    need(len(value) <= policy['max_points'] and gross <= policy['max_logical_bytes'], 'snapshot-gross-policy')


def cleanup(value):
    pending = value.get('owner_plan', {}).get('phase', {}).get('kind') in ('claimed', 'cancelling')
    nondeleted = value['lifecycle'] != 'deleted'
    storage = value['storage']
    sweep = storage['sweep']
    debt = 0 if sweep is None else 2 if any(item['disposition'] == 'pending' for item in sweep['entries']) else 1
    need(value['revision'] + int(pending) + int(nondeleted) <= 2**64 - 1, 'snapshot-business-cleanup-reserve')
    need(value['head_serial'] + len(value['snapshots']) + int(pending) + int(storage['plan'] is not None)
         + debt + int(nondeleted) + int('terminal' not in storage) <= 2**64 - 1, 'snapshot-physical-cleanup-reserve')


def head(raw, known):
    value = wire.parse(raw)
    if value.get('format') != 9:
        return legacy.head(raw, known)
    expected = legacy.HEAD | EXTRA | ({'owner_plan'} if 'owner_plan' in value else set())
    shape(value, expected, 'head9-exact-shape')
    need(len(raw) <= 262144 and value['restore_origin'] is None, 's1-null-origin-only')
    limits(value['snapshot_limits'])
    held(value['snapshots'], value['head_serial'], value['revision'], value['sequence'], value['snapshot_limits'])
    need(value['lifecycle'] != 'provisioning' or not value['snapshots'], 'provisioning-no-retained-points')
    need('terminal' not in value['storage'] or not value['snapshots'], 'terminal-no-held-roots')
    plan = value['storage']['plan']
    if plan is not None:
        basis = shape(plan['basis'], legacy.BASIS | {'snapshots', 'snapshot_limits'}, 'copy-basis-shape')
        need(basis['snapshots'] == value['snapshots'] and basis['snapshot_limits'] == value['snapshot_limits'],
             'copy-frozen-held-basis')
        held(basis['snapshots'], plan['serial'] - 1, basis['revision'], basis['sequence'], basis['snapshot_limits'])
    # Explicitly check the original unchanged base fields, without discarding
    # any S1 shape, cross-field bound, copy relation or cleanup reservation.
    legacy.head(encoded(projection(value)), known)
    cleanup(value)
    return value


def advance(previous, current):
    need(current['scope'] == previous['scope'], 'head-full-scope-immutable')
    need(current['head_serial'] == previous['head_serial'] + 1, 'physical-serial-step')
    need(previous['format'] != 9 or current['format'] == 9, 'head9-irreversible')
    old = previous.get('snapshots', [])
    new = current.get('snapshots', [])
    policy_changed = previous.get('snapshot_limits') != current.get('snapshot_limits')
    if old != new:
        need(current['format'] == 9 and not policy_changed and previous['storage']['plan'] is None
             and previous['storage']['sweep'] is None and 'terminal' not in previous['storage'], 'snapshot-idle-original')
        allowed = {'format', 'head_serial', 'snapshots', 'snapshot_limits', 'restore_origin'}
        need(all(previous.get(field) == current.get(field) for field in set(previous) | set(current) if field not in allowed),
             'snapshot-business-preserved')
        if len(new) == len(old) + 1:
            need(new[:-1] == old and new[-1]['reference']['capture_serial'] == current['head_serial']
                 and previous['lifecycle'] == 'ready', 'snapshot-capture-single-original')
            point_value = new[-1]['point']
            need(point_value['data_root'] == previous['data_root'] and point_value['sequence'] == previous['sequence']
                 and point_value['source_revision'] == previous['revision'], 'snapshot-capture-current-point')
            return 'snapshot_capture'
        need(len(new) + 1 == len(old) and all(item in old for item in new), 'snapshot-release-one-original')
        return 'snapshot_release'
    if policy_changed:
        need(current['format'] == 9 and current['revision'] == previous['revision'] + 1 and
             previous['lifecycle'] in ('ready', 'maintenance'), 'snapshot-limits-business-step')
        allowed = {'format', 'head_serial', 'revision', 'transition', 'snapshots', 'snapshot_limits', 'restore_origin'}
        need(all(previous.get(field) == current.get(field) for field in set(previous) | set(current) if field not in allowed),
             'snapshot-limits-preserve-authority')
        return 'snapshot_limits'
    need(previous.get('restore_origin') == current.get('restore_origin'), 's1-origin-preserved')
    return legacy.advance(projection(previous), projection(current))


def snapshot_key(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/(8201)/inc/(1)/gen/(1)/snapshot/v1/(descriptor|proof)/(11)/([1-9][0-9]*)', path)
    need(match is not None, 'snapshot-key-full-scope')
    database, incarnation, generation, kind, creator, operation = match.groups()
    return {'deployment': 1, 'tenant': 7, 'database': int(database), 'incarnation': int(incarnation),
            'generation': int(generation)}, kind, int(creator), int(operation)


def descriptor(raw, path):
    logical, kind, creator, operation = snapshot_key(path)
    value = wire.parse(raw)
    shape(value, ('version', 'scope', 'input', 'base', 'point', 'limits', 'input_digest'), 'snapshot-descriptor-shape')
    need(kind == 'descriptor' and len(raw) <= 16384 and type(value['version']) is int and value['version'] == 1
         and value['scope'] == logical, 'snapshot-descriptor-scope')
    original, base, position, policy = snapshot_input(value['input']), value['base'], point(value['point']), limits(value['limits'])
    shape(base, BASE, 'snapshot-original-base-shape')
    digest(base['head_hash'])
    need(isinstance(base['etag'], str) and re.fullmatch(r'"[!#-~]{0,1022}"', base['etag']), 'snapshot-original-etag')
    need(original['creator'] == creator and original['operation'] == operation, 'snapshot-original-slot')
    need(original['expected_revision'] == base['revision'] == position['source_revision']
         and original['expected_head_serial'] == base['head_serial'] < 2**64 - 1, 'snapshot-descriptor-original-position')
    need(policy['max_points'] > 0 and position['page_count'] * 4096 <= policy['max_logical_bytes'], 'snapshot-descriptor-policy')
    fixed = {'version': 1, 'scope': ordered(logical, SCOPE), 'input': ordered(original, INPUT),
             'base': ordered(base, BASE), 'point': ordered(position, POINT), 'limits': ordered(policy, LIMITS)}
    need(value['input_digest'] == sha(encoded(list(fixed.values()))), 'snapshot-input-digest')
    fixed['input_digest'] = value['input_digest']
    reference = {'creator': creator, 'operation': operation, 'capture_serial': base['head_serial'] + 1,
                 'descriptor_hash': sha(encoded(fixed))}
    return value, {'reference': reference, 'label': original['label'], 'point': position}


def proof(raw, path):
    logical, kind, creator, operation = snapshot_key(path)
    value = wire.parse(raw)
    shape(value, ('version', 'scope', 'entry'), 'snapshot-proof-shape')
    need(kind == 'proof' and len(raw) <= 8192 and type(value['version']) is int and value['version'] == 1
         and value['scope'] == logical, 'snapshot-proof-scope')
    entry(value['entry'])
    need(value['entry']['reference']['creator'] == creator and value['entry']['reference']['operation'] == operation,
         'snapshot-proof-identity')
    return value


class Graph(legacy.Graph):
    def complete(self, value):
        result = self.closure(value)
        held_images = []
        for retained in value.get('snapshots', []):
            tree = Graph(self.objects, self.logical, self.generation)
            try:
                image = tree.data(retained['point']['data_root'])
            except Rejected as error:
                raise Rejected('held-root-complete-closure') from error
            need(len(image) == retained['point']['page_count'] * 4096, 'held-root-page-count')
            result['dependencies'].update(tree.dependencies)
            held_images.append((retained, image, tree.dependencies))
        result['held'] = held_images
        return result
