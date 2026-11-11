"""Assemble unchanged product processes; all database operations use public APIs."""
import json
import shutil

import spec
import support as io

OwnerHarness = io.load('snapshot_owner_harness', io.HERE.parent / 'object-owner-plan-runtime/harness.py').Harness


class Harness(OwnerHarness):
    def __init__(self, args, evidence, private):
        super().__init__(args, evidence, private, profile=spec,
                         plan_path='experiments/object-snapshot-runtime/PLAN.md')

    def setup(self):
        super().setup()
        # This is a separate original input, not a verdict or a runtime-selected denominator.
        io.save(self.evidence / 'snapshot-plan.json', io.encoded({
            'points': spec.POINTS, 'limits': spec.SNAPSHOT_LIMITS, 'faults': spec.FAULTS,
            'expected': spec.EXPECTED}))

    def seed_native(self):
        self.phase('native-original-acknowledgements')
        cache = self.private / 'native-seed-cache'
        cache.mkdir(mode=0o700)
        configuration = {'endpoint': self.proxies['seed'].endpoint, 'region': 'us-east-1',
            'bucket': 'scap-test', 'access_key': self.backend.access, 'secret_key': self.backend.secret,
            'scope': {key: int(value) for key, value in spec.SCOPE.items()},
            'worker': spec.NATIVE_WORKER, 'principal': 11, 'provision': True,
            'cache_root': str(cache), 'fixture_limits': spec.LIMITS, 'resource_log': None}
        path = self.private / 'native-seed.private.json'
        io.save(path, io.encoded(configuration))
        io.save(self.evidence / 'native-seed-config.json', io.encoded({
            key: value for key, value in configuration.items() if key not in ('access_key', 'secret_key')}))
        worker = self.child([str(self.args.worker), str(path)], 'native-seed', interactive=True)
        assert worker.read()['ready'] is True

        def command(value):
            worker.send(value)
            result = worker.read()
            assert result['ok'] is True, (value, result)
            return result['value']

        head = command({'op': 'create', 'nonce': int(self.next_nonce())})
        command({'op': 'activate_session', 'revision': head['revision'],
                 'nonce': int(self.next_nonce()), 'directory': 'native'})
        for original in self.specs[:2]:
            answer = command({'op': 'session_execute', 'epoch': int(original['epoch']),
                'id': int(original['request_id']), 'budget_ms': 8000,
                'statements': [{'sql': row['sql'], 'parameters': []} for row in original['statements']]})
            raw = bytes(answer['result']['encoded'])
            value = {'receipt': answer['receipt'], 'result': self.trace.raw(raw)}
            self.originals[original['name']] = value
            self.trace.emit('native_original_ack', name=original['name'], **value)
        self.trace.emit('seed_completed', scope_name='bulk', head=command({'op': 'status'}))
        command({'op': 'session_close'})
        worker.close()
        shutil.rmtree(cache)
        self.trace.emit('native_cache_removed', path=str(cache), absent=not cache.exists())

    def save_snapshot(self, point, head):
        original = {key: point[key] for key in ('creator', 'operation', 'label')}
        original.update(expected_revision=head['revision'], expected_head_serial=head['head_serial'])
        return self.call('C', point['name'] + '-save', 'snapshot_save',
                         intent=point['name'], input=original)

    def sweep(self, generation, label):
        after = None
        self.trace.emit('sweep_round_started', scope_name='bulk', generation=generation, label=label, after=None)
        for page in range(spec.MAX_SWEEP_PAGES):
            identifier = f'{label}-{page}'
            # Generation 1 is retired while this Scope remains Ready. The
            # storage_status route is specifically the Deleted metadata API.
            head = self.call('C', identifier + '-storage', 'status' if generation == 1 else 'storage_status')
            report = self.call('C', identifier + '-prepare', 'gc_prepare', input={
                'expectedHeadSerial': head['head_serial'], 'generation': str(generation), 'after': after})
            batch = report['status']['storage']['sweep']
            if batch is not None:
                self.call('C', identifier + '-resume', 'gc_resume', input={'batchSerial': batch['serial']})
            self.trace.emit('sweep_page_finished', label=label, page=page, report=report)
            if report['exhausted']:
                self.trace.emit('sweep_round_finished', label=label, pages=page + 1)
                return
            assert report['next_after'] is not None and (after is None or after < report['next_after'])
            after = report['next_after']
        raise AssertionError('fixed 32-page sweep budget')

    def saved_results(self):
        assert set(self.originals) == {row['name'] for row in self.specs}
        io.save(self.evidence / 'original-results.json', io.encoded(self.originals))
