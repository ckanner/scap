#!/usr/bin/env python3
"""Compose real production processes and existing raw observers; no fleet implementation."""
from __future__ import annotations

import argparse
from copy import deepcopy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
PREVIOUS = HERE.parent / 'object-controller-runtime'
sys.path.insert(0, str(PREVIOUS))
specification = importlib.util.spec_from_file_location('dynamic_fleet_original_runtime', PREVIOUS / 'run.py')
base = importlib.util.module_from_spec(specification)
specification.loader.exec_module(base)
io = base.io


class Harness(base.Harness):
    def setup(self):
        super().setup()
        original = json.loads(self.controller_config.read_bytes())['scopes'][0]['policy']
        second = deepcopy(original)
        second['workers'].append({'workerInstance': '9603', 'endpoint': self.http['C'].endpoint + '/v1', 'rank': 2})
        second['retiredWorkers'] = ['9601']
        third = deepcopy(second)
        third['retiredWorkers'] = ['9601', '9602']
        fourth = deepcopy(third)
        fourth['workers'].append({'workerInstance': '9604', 'endpoint': self.http['A'].endpoint + '/v1', 'rank': 3})
        fourth['retiredWorkers'] = ['9601', '9602', '9603']
        self.policies = [original, second, third, fourth]
        self.configure('initial', '1', 0)
        io.save(self.evidence / 'dynamic-inputs.json', io.encoded({
            'version': 1, 'plan': 'experiments/object-dynamic-fleet-runtime/PLAN.md',
            'plan_sha256': io.build.digest(HERE / 'PLAN.md'), 'replacement_worker': '9604',
            'whole_seconds': 180, 'stage_seconds': 75, 'controller_processes': 1,
            'mutations': {'owner_prepare': 3, 'owner_claim': 3, 'owner_resume': 2, 'owner_abort': 1},
        }))

    def child(self, command, name, environment=None):
        if str(command[0]) == str(self.node):
            path = Path(command[1]).resolve()
            self.trace.emit('dynamic_node_source', id=name, entry=str(path),
                            relative=path.relative_to(io.ROOT).as_posix(), sha256=io.build.digest(path))
        elif name.startswith('service-'):
            path = Path(command[1]).resolve()
            self.trace.emit('dynamic_service_configuration', id=name, path=str(path), config=self.trace.raw(path.read_bytes()))
        return super().child(command, name, environment)

    def configure(self, label, revision, policy_index, child=None, revived=False):
        current = deepcopy(self.policies[policy_index])
        if revived:
            current['retiredWorkers'].remove('9603')
        document = {'version': 2, 'revision': revision, 'scopes': [{
            'policy': current, 'previousPolicies': deepcopy(self.policies[:policy_index]),
            'tokenEnv': 'SCAP_CONTROLLER_RUNTIME_TOKEN'}]}
        if revived:
            document['scopes'][0]['previousPolicies'].append(deepcopy(self.policies[policy_index]))
        raw = io.encoded(document)
        next_path = self.private / ('controller-' + label + '.next')
        io.save(next_path, raw)
        os.replace(next_path, self.controller_config)
        directory = os.open(self.private, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.trace.emit('dynamic_configuration', label=label, revision=revision, config=self.trace.raw(raw))
        if child is not None:
            child.process.send_signal(signal.SIGHUP)
            self.trace.emit('dynamic_reload_requested', label=label, id=child.id, revision=revision)

    def mark(self, child):
        raw = child.log.read_bytes()
        return raw.rfind(b'\n') + 1

    def report(self, child, after, label, predicate):
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            raw = child.log.read_bytes()
            assert len(raw) <= 1048576, 'bounded controller output'
            for line in raw[after:].splitlines(keepends=True):
                if line.endswith(b'\n'):
                    value = json.loads(line)
                    if predicate(value):
                        self.trace.emit('dynamic_report_observed', id=child.id, label=label,
                                        after=after, report=value)
                        return value
            if child.process.poll() is not None:
                raise RuntimeError('controller exited before ' + label)
            time.sleep(.02)
        raise TimeoutError('fixed stage bound: ' + label)

    def replacement(self):
        old, cache = self.services['A']
        old.close()
        existed = cache.is_dir()
        shutil.rmtree(cache)
        self.trace.emit('cache_removed', id=old.id, path=str(cache), existed=existed, absent=not cache.exists())
        original = json.loads((self.private / 'service-A.json').read_bytes())
        new_cache = self.private / 'cache-A-2'
        new_cache.mkdir(mode=0o700)
        info = new_cache.stat()
        self.trace.emit('replacement_cache_created', path=str(new_cache), empty=not any(new_cache.iterdir()),
                        device=info.st_dev, inode=info.st_ino)
        original['worker_instance'] = '9604'
        original['cache_directory'] = str(new_cache)
        configuration = self.private / 'service-A-2.json'
        io.save(configuration, io.encoded(original))
        io.save(self.evidence / configuration.name, io.encoded(original))
        environment = dict(os.environ, SCAP_RECLAIM_ACCESS=self.backend.access,
                           SCAP_RECLAIM_SECRET=self.backend.secret)
        child = self.child([str(self.args.server), str(configuration)], 'service-A-2', environment)
        self.services['A'] = (child, new_cache)
        port = int(original['listen'].rsplit(':', 1)[1])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
            try:
                connection.request('GET', '/healthz')
                response = connection.getresponse()
                if response.status == 200 and json.loads(response.read(4097)) == {'status': 'alive', 'protocol': 1}:
                    self.trace.emit('service_ready', role='A', incarnation=2, worker='9604', id=child.id)
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.02)
        raise TimeoutError('replacement readiness')

    def revoke(self):
        configuration = self.private / 'business-revoke.json'
        io.save(configuration, io.encoded({'endpoint': self.http['A'].endpoint,
                                        'token': self.tokens['11'], 'scope': base.SCOPE}))
        child = self.child([str(self.node), str(HERE / 'revoke.mjs'), str(configuration),
                            str(self.evidence)], 'business-revoke')
        status, usage = io.network.wait_child(child.process, 45)
        self.trace.emit('child_stopped', id=child.id, identity=child.identity, status=status,
                        usage=usage, crash=False, forced=False, stderr=self.trace.raw(child.log.read_bytes()))
        assert status == 0, child.log.read_text()

    def history(self):
        self.phase('initialize'); self.business('initialize', 'A')
        self.phase('business-unknown')
        loss = self.http['A'].arm('business-ack-loss', 'execute')
        self.business('unknown', 'A')
        assert loss.arrived.is_set() and loss.finished.wait(5) and loss.used == 1
        self.phase('healthy')
        controller = self.start_controller('controller-dynamic')
        self.report(controller, 0, 'initial-healthy', lambda row: row.get('state') == 'healthy')

        self.phase('retire-A')
        cut = self.http['B'].arm('claim-ack-loss', 'owner_claim')
        after = self.mark(controller); self.configure('retire-A', '2', 1, controller)
        self.report(controller, after, 'reload-2', lambda row: row.get('event') == 'fleet_reloaded' and row.get('revision') == '2')
        unknown = self.report(controller, after, 'claim-unknown', lambda row: row.get('state') == 'unknown')
        assert unknown['lastUncertainCall']['operation'] == 'owner_claim'
        assert cut.arrived.is_set() and cut.finished.wait(5) and cut.used == 1

        self.phase('retire-B-pending')
        after = self.mark(controller); self.configure('retire-B', '3', 2, controller)
        self.report(controller, after, 'reload-3', lambda row: row.get('event') == 'fleet_reloaded' and row.get('revision') == '3')
        self.report(controller, after, 'original-B-aborted', lambda row: row.get('state') == 'aborted')
        active = self.report(controller, after, 'C-active', lambda row: row.get('state') == 'active_observed' and
                             row.get('currentAuthority', {}).get('owner_instance') == '9603')
        assert active['pastUnknown'] and active['lastUncertainCall'] == unknown['lastUncertainCall']

        self.phase('endpoint-mismatch')
        after = self.mark(controller); self.configure('retire-C-register-D', '4', 3, controller)
        self.report(controller, after, 'D-mismatch', lambda row: row.get('reason') == 'TARGET_MISMATCH')
        self.phase('endpoint-replacement'); self.replacement()
        after = self.mark(controller); self.configure('D-ready', '5', 3, controller)
        self.report(controller, after, 'D-active', lambda row: row.get('state') == 'active_observed' and
                    row.get('currentAuthority', {}).get('owner_instance') == '9604')

        self.phase('rollback-rejected')
        after = self.mark(controller); self.configure('rollback', '2', 1, controller)
        rejected = self.report(controller, after, 'rollback-rejected', lambda row: row.get('event') == 'fleet_reload_rejected')
        assert rejected['revision'] == '5'
        self.phase('revival-rejected')
        after = self.mark(controller); self.configure('revival', '6', 3, controller, revived=True)
        rejected = self.report(controller, after, 'revival-rejected', lambda row: row.get('event') == 'fleet_reload_rejected')
        assert rejected['revision'] == '5'

        self.phase('authority-revoked'); after = self.mark(controller); self.revoke()
        self.report(controller, after, 'revoked', lambda row: row.get('reason') == 'DENIED')
        self.stop_controller(controller)
        self.phase('cold-verification'); self.business('verify', 'A')


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('real validation requires assertions')
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--build-record', required=True, type=Path)
    parser.add_argument('--weed', required=True, type=Path)
    parser.add_argument('--node', default='node')
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    args.server, args.weed = args.server.resolve(), args.weed.resolve()
    base.Harness = Harness
    raise SystemExit(base.main(args))

