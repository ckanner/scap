"""Independent v1 HTTP diagnostic reader; no product or SDK parser imports.

Each counted observation describes only the first rejecting counter under its
original lock. It is not a simultaneous snapshot of every resource pool.
"""
from collections import Counter
import re

U64_MAX = (1 << 64) - 1
HEADER_BYTES = 256
DECIMAL = r'(?:0|[1-9][0-9]*)'
COUNTED = {
    **{f'intake_{kind}_{budget}': 'BACKPRESSURE'
       for kind in ('data', 'control', 'recovery', 'catalogue')
       for budget in ('requests_global', 'requests_tenant', 'body_global', 'body_tenant')},
    **{f'queue_{scope}_{kind}': 'BACKPRESSURE'
       for scope in ('global', 'tenant', 'database') for kind in ('total', 'data')},
    **{f'actors_{scope}': 'BACKPRESSURE' for scope in ('global', 'tenant')},
    **{f'output_base_{kind}_{scope}': 'BACKPRESSURE'
       for kind in ('shared', 'control') for scope in ('global', 'tenant')},
    **{f'{kind}_queue_{scope}': 'BACKPRESSURE'
       for kind in ('catalogue', 'restore') for scope in ('global', 'tenant', 'name')},
    **{f'discovery_{scope}': 'BACKPRESSURE' for scope in ('global', 'tenant', 'threads')},
    **{f'output_growth_{scope}': 'LIMIT' for scope in ('global', 'tenant')},
    **{f'restore_staging_{scope}': 'RECOVERY_BUSY' for scope in ('global', 'tenant')},
}
SOURCE_ONLY = {'actor_draining': 'BACKPRESSURE', 'output_base_allocation': 'BACKPRESSURE',
               'output_growth_allocation': 'LIMIT', 'native_recovery_busy': 'RECOVERY_BUSY',
               'native_recovery_closed': 'RECOVERY_BUSY'}


class Invalid(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def require(condition, rule):
    if not condition:
        raise Invalid(rule)


def parse(header, code):
    """Fail closed for this explicitly enabled candidate, preserve decimal text."""
    if header is None:
        require(code not in ('BACKPRESSURE', 'RECOVERY_BUSY'), 'rejection-missing')
        return None
    require(type(header) is str and header.isascii() and 0 < len(header) <= HEADER_BYTES,
            'rejection-header-bound')
    match = re.fullmatch(r'v=1;reason=([a-z_]+)(?:;used=(' + DECIMAL + r');limit=(' +
                         DECIMAL + r');requested=(' + DECIMAL + r'))?', header)
    require(match is not None, 'rejection-header-format')
    reason, used, limit, requested = match.groups()
    require(reason in COUNTED or reason in SOURCE_ONLY, 'rejection-reason')
    require((used is not None) == (reason in COUNTED), 'rejection-counter-shape')
    require(code == (COUNTED | SOURCE_ONLY)[reason], 'rejection-code')
    result = {'version': 1, 'reason': reason}
    if used is not None:
        require(all(int(value) <= U64_MAX for value in (used, limit, requested))
                and int(limit) > 0 and int(used) <= int(limit), 'rejection-counter-range')
        # Python integers deliberately retain an overflow of used + requested.
        require(int(requested) > 0 and int(used) + int(requested) > int(limit), 'rejection-not-triggered')
        result.update(used=used, limit=limit, requested=requested)
    return result


def effective_limits(config):
    """Independently resolve the frozen fixture's omitted v1 profiles."""
    admission, output = config['admission'], config['output']
    result = {}
    for kind in ('data', 'control', 'recovery'):
        total, maximum = admission[kind + '_intake'], admission['max_body_bytes']
        profile = admission.get(kind + '_profile') or {
            'requests_per_tenant': max(total // 2, 1),
            'body_bytes': min(total * maximum, 256 * 1024**2),
            'body_bytes_per_tenant': min(total * maximum, 128 * 1024**2)}
        for name, limit, request in (
                ('requests_global', total, 1), ('requests_tenant', profile['requests_per_tenant'], 1),
                ('body_global', profile['body_bytes'], maximum),
                ('body_tenant', profile['body_bytes_per_tenant'], maximum)):
            result[f'intake_{kind}_{name}'] = (limit, request)
    for scope, key in (('global', 'queued_total'), ('tenant', 'queued_per_tenant'),
                       ('database', 'queued_per_database')):
        result[f'queue_{scope}_total'] = (admission[key], 1)
        result[f'queue_{scope}_data'] = (admission[key] - admission['reserved_controls'], 1)
    for scope, suffix in (('global', ''), ('tenant', '_per_tenant')):
        result[f'actors_{scope}'] = (admission['active_database_actors' + suffix], 1)
        shared = output['bytes' + suffix] - output['control_bytes' + suffix]
        result[f'output_base_shared_{scope}'] = (shared, 65536)
        result[f'output_base_control_{scope}'] = (output['control_bytes' + suffix], 65536)
        result[f'output_growth_{scope}'] = (shared, None)
    return result


def admission_class(operation):
    require(operation in ('create', 'activate', 'execute', 'status', 'query', 'lookup', 'cancel'),
            'rejection-operation')
    if operation == 'activate':
        return 'recovery'
    return 'data' if operation in ('create', 'execute', 'query') else 'control'


def bind(value, operation, admission, config):
    """Check original request class and actual configuration, never infer cause."""
    require(admission == admission_class(operation), 'http-admission-class')
    if value is None:
        return
    reason = value['reason']
    limits = effective_limits(config)
    # The fixed /v1 workload does not enable controller/discovery/restore routes.
    require(reason in limits or reason in SOURCE_ONLY, 'rejection-route')
    if reason.startswith('intake_'):
        require(reason.startswith('intake_' + admission + '_'), 'rejection-admission-class')
    if reason.startswith('queue_') and reason.endswith('_data'):
        require(admission != 'control', 'rejection-admission-class')
    if reason.startswith('output_base_shared_'):
        require(admission == 'data', 'rejection-admission-class')
    if reason.startswith('output_base_control_'):
        require(admission != 'data', 'rejection-admission-class')
    if reason == 'actor_draining' or reason.startswith('actors_'):
        require(admission != 'control', 'rejection-admission-class')
    if reason.startswith('native_recovery_'):
        # Recreating a native session for execute/query can also acquire the
        # recovery semaphore; the header carries no invented occupancy.
        require(operation in ('activate', 'execute', 'query'), 'rejection-admission-class')
    if reason in limits:
        limit, requested = limits[reason]
        require(value['limit'] == str(limit), 'rejection-config-limit')
        if requested is not None:
            require(value['requested'] == str(requested), 'rejection-config-requested')


def unit(reason):
    if reason.startswith('queue_'):
        return 'charged credits, including group credits not yet released'
    if reason.startswith(('catalogue_queue_', 'restore_queue_')):
        return 'charged queue credits; name scopes include known and unknown reservations'
    if reason == 'discovery_threads':
        return 'native thread handles'
    if '_body_' in reason or reason.startswith('output_') or reason.startswith('restore_staging_'):
        return 'reserved bytes'
    return 'active database actors' if reason.startswith('actors_') else 'request reservations'


def summary(values):
    by_reason = {}
    for value in values:
        if value is None:
            continue
        reason = value['reason']
        entry = by_reason.setdefault(reason, {'count': 0, 'code': (COUNTED | SOURCE_ONLY)[reason],
                                              'counted': reason in COUNTED})
        entry['count'] += 1
        if reason in COUNTED:
            entry['unit'] = unit(reason)
            for name in ('used', 'limit', 'requested'):
                entry.setdefault(name, Counter())[value[name]] += 1
    return {reason: {key: dict(value) if isinstance(value, Counter) else value
                     for key, value in entry.items()} for reason, entry in sorted(by_reason.items())}
