"""Owned lifetimes and raw proc observations; sampling is never a hard limit."""
from collections import Counter
import re

import oracle as o
import spec


def process_stat(raw):
    o.need(type(raw) is str and ' (' in raw and ')' in raw, 'proc-stat')
    try:
        pid = int(raw.split(' (', 1)[0])
        values = raw[raw.rfind(')') + 2:].split()
        start = int(values[19])
    except (ValueError, IndexError):
        raise o.Rejected('proc-stat') from None
    o.need(pid > 0 and start > 0, 'proc-stat')
    return pid, start


def audit(directory, events, inputs):
    start = o.one([r for r in events if r['event'] == 'service_started'], 'service-lifetimes')
    stop = o.one([r for r in events if r['event'] == 'service_stopped'], 'service-lifetimes')
    launch = o.one([r for r in events if r['event'] == 'service_start_requested'], 'service-launch')
    o.same(start['identity'], stop['identity'], 'owned-process-identity')
    o.same(start['binary'], inputs['tools']['scapd'], 'running-binary')
    o.same(launch['initial_cache'], {'logical_bytes': 0, 'allocated_bytes': 0, 'files': 0, 'races': 0}, 'fresh-cache')
    o.need(start['cache'] == launch['cache'] and start['worker_instance'] == launch['worker_instance'] == str(spec.WORKER),
           'worker-startup-identity')
    identity = start['identity']
    o.need(start['proof']['source'] == identity['proc_source'] == 'owned_pre_exec_proc_self_fd'
           and process_stat(start['proof']['stat']) == (identity['proc_pid'], identity['start_ticks'])
           and start['proof']['boot_id'] == identity['boot_id'], 'owned-proc-handoff')
    o.need(stop['status'] == 0 and stop['forced'] is False
           and stop['usage']['source'] == 'kernel_wait4_owned_child', 'owned-service-exit')
    samples = o.rows(directory / 'resources.jsonl')
    o.need(samples and len(samples) <= spec.BOUNDS['samples'] and
           [r['sample'] for r in samples] == list(range(1, len(samples) + 1)), 'resource-samples')
    rss, hwm, fds, threads, cache, backend = [], [], [], [], [], []
    for row in samples:
        o.same(row['identity'], identity, 'resource-process-identity')
        o.need(process_stat(row['stat_raw']) == (identity['proc_pid'], identity['start_ticks']), 'resource-start-ticks')
        values = {}
        for line in row['status_raw'].splitlines():
            if ':' not in line:
                continue
            key, text = line.split(':', 1)
            if key not in ('Pid', 'Threads', 'VmRSS', 'VmHWM'):
                continue
            parts = text.split()
            o.need(key not in values and parts and parts[0].isdecimal(), 'resource-status')
            factor = 1024 if key.startswith('Vm') else 1
            o.need(parts[1:] == (['kB'] if factor == 1024 else []), 'resource-units')
            values[key] = int(parts[0]) * factor
        o.need(set(values) == {'Pid', 'Threads', 'VmRSS', 'VmHWM'} and min(values.values()) > 0, 'resource-unavailable')
        o.same(row['metrics'], values, 'resource-derived-metrics')
        o.need(values['Pid'] == identity['proc_pid'], 'resource-status-pid')
        for name in ('fd_names', 'task_names'):
            names = row[name]
            o.need(type(names) is list and names and len(names) == len(set(names))
                   and all(type(name) is str and name.isdecimal() for name in names), 'resource-directory-list')
        o.need(o.moment(start) <= o.moment(row) < row['completed_ns'] < o.moment(stop), 'resource-lifetime')
        o.need(row['filesystem_free_bytes'] >= spec.BOUNDS['minimum_free_bytes'], 'disk-space-guard')
        for name in ('cache', 'backend'):
            o.need(set(row[name]) == {'logical_bytes', 'allocated_bytes', 'files', 'races'}
                   and all(type(value) is int and value >= 0 for value in row[name].values()), 'disk-sample')
        rss.append(values['VmRSS']); hwm.append(values['VmHWM'])
        fds.append(len(row['fd_names'])); threads.append(values['Threads'])
        cache.append(row['cache']['allocated_bytes']); backend.append(row['backend']['allocated_bytes'])
    gaps = [(o.moment(b) - o.moment(a)) / 1e6 for a, b in zip(samples, samples[1:])]
    o.need(all(gap > 0 for gap in gaps), 'resource-sample-order')
    for phase in spec.PHASES:
        first = o.one([r for r in events if r['event'] == 'phase_started' and r['phase'] == phase], 'phase-process-start')
        last = o.one([r for r in events if r['event'] == 'phase_finished' and r['phase'] == phase], 'phase-process-end')
        begin = o.one([r for r in events if r['event'] == 'node_started' and r['phase'] == phase], 'owned-sdk-start')
        end = o.one([r for r in events if r['event'] == 'node_stopped' and r['phase'] == phase], 'owned-sdk-exit')
        o.same(begin['identity'], end['identity'], 'owned-sdk-identity')
        o.same(begin['binary'], inputs['tools']['node'], 'owned-sdk-binary')
        o.need(o.moment(start) < o.moment(first) <= begin['spawn_requested_ns'] < o.moment(begin)
               < o.moment(end) < o.moment(last) < o.moment(stop), 'owned-sdk-lifetime')
        o.need(end['status'] == 0 and end['forced'] is False and end['usage']['source'] == 'kernel_wait4_owned_child',
               'owned-sdk-exit')
    o.need(Counter(r['phase'] for r in events if r['event'] == 'node_stopped') == Counter(spec.PHASES), 'owned-sdk-denominator')
    proxy = o.one([r for r in events if r['event'] == 'proxy_stopped'], 'proxy-cleanup')
    o.need(proxy['joined'] is True and proxy['errors'] == [], 'proxy-cleanup')
    back = o.one([r for r in events if r['event'] == 'backend_stopped'], 'backend-cleanup')
    o.need(len(back['processes']) == 4 and all(p['wait_status'] == -9 and
           p['kernel_usage']['source'] == 'kernel_wait4_owned_child' for p in back['processes']), 'backend-cleanup')
    created = o.one([r for r in events if r['event'] == 'private_created'], 'private-lifecycle')
    removed = o.one([r for r in events if r['event'] == 'private_removed'], 'private-lifecycle')
    for key in ('path', 'device', 'inode'):
        o.same(created[key], removed[key], 'private-identity')
    o.need(removed['exists'] is False and o.moment(created) < o.moment(start)
           < o.moment(stop) < o.moment(back) < o.moment(removed), 'private-cleanup')
    space = o.one([r for r in events if r['event'] == 'startup_space'], 'startup-space')
    o.need(space['required_bytes'] == spec.BOUNDS['startup_free_bytes'] and
           space['filesystem_free_bytes'] >= space['required_bytes'], 'startup-space')
    unsigned = o.one([r for r in events if r['event'] == 'unsigned_probe'], 'signed-backend')
    o.need(unsigned['status'] == 403, 'signed-backend')
    o.raw(directory, unsigned['response'])
    files = list((directory / 'raw').iterdir())
    o.need(all(p.is_file() and not p.is_symlink() and re.fullmatch('[0-9a-f]{64}', p.name) for p in files), 'raw-directory')
    raw_bytes = sum(p.stat().st_size for p in files)
    o.need(raw_bytes <= int((directory / 'raw-budget').read_text()) <= spec.BOUNDS['raw_bytes'], 'raw-budget')
    return {'samples': len(samples), 'maximum_sample_gap_ms': max(gaps, default=None),
            'first_sample_delay_ms': (o.moment(samples[0]) - o.moment(start)) / 1e6,
            'last_sample_to_exit_ms': (o.moment(stop) - samples[-1]['completed_ns']) / 1e6,
            'sampled_rss_peak_bytes': max(rss), 'sampled_hwm_max_bytes': max(hwm),
            'observed_hwm_decreases': sum(b < a for a, b in zip(hwm, hwm[1:])),
            'sampled_fd_peak': max(fds), 'sampled_thread_peak': max(threads),
            'sampled_cache_allocated_peak_bytes': max(cache),
            'sampled_backend_allocated_peak_bytes': max(backend),
            'kernel_lifetime_maxrss_bytes': stop['usage']['maxrss_bytes'],
            'raw_evidence_unique_bytes': raw_bytes, 'hard_peak_or_limit_proved': False}
