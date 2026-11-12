"""Owned raw observers and fixed inputs for the production controller matrix."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


shared = load('controller_matrix_raw', HERE.parent / 'object-owner-plan-runtime/support.py')
http = load('controller_matrix_http', HERE.parent / 'object-owner-plan-runtime/http_proxy.py')
configuration = load('controller_matrix_config', HERE.parent / 'object-reclamation-runtime/spec.py').configuration
Trace, Child, Proxy = shared.Trace, shared.Child, shared.Proxy
network, build = shared.network, shared.service_build
save, encoded, sha = shared.save, shared.encoded, shared.sha

CASE_IDS = (
    'C1_same_policy_prepare_restart', 'C2_same_creator_policy', 'C2_different_creators',
    'C2_manual_marker', 'C3_claimed_abort', 'C3_cancelling_restart', 'C3_healthy_original',
    'C4_revoked_authority', 'C4_worker_mismatch', 'C4_resource_refusal',
    'C4_s3_unavailable', 'C5_shutdown_deadline',
)
WORKERS = {'A': 9601, 'B': 9602, 'C': 9603, 'M': 9605}
LIMITS = {'tick_ms': 5000, 'failure_count': 3, 'failure_interval_ms': 1000,
          'failure_span_ms': 5000, 'probe_ms': 1000, 'tick_deadline_ms': 30000,
          'recovery_deadline_ms': 60000, 'http_per_tick': 8, 'mutation_per_tick': 1,
          'stage_seconds': 75, 'business_seconds': 45, 'post_fault_reports': 2}


def scenario(identifier):
    index = CASE_IDS.index(identifier)
    return {'version': 1, 'case_id': identifier,
            'scope': {'deployment': '1', 'tenant': '7', 'database': str(8701 + index),
                      'incarnation': '1', 'generation': '1'},
            'workers': WORKERS, 'limits': LIMITS,
            'whole_seconds': 240 if identifier in (
                'C1_same_policy_prepare_restart', 'C3_claimed_abort') else 180,
            'sql_requests': 3, 'client_acks': 2, 'business_unknowns': 1,
            'snapshots': 1, 'source_authority': 'signed-local-s3',
            'worker_b_actual': 9604 if identifier == 'C4_worker_mismatch' else 9602,
            'zero_recovery_budget': identifier == 'C4_resource_refusal',
            'control_intake_occupant': identifier == 'C4_resource_refusal',
            'metadata_s3_timeout_ms': 15000 if identifier == 'C4_resource_refusal' else 5000,
            'metadata_routes': 2 if identifier == 'C4_s3_unavailable' else 1,
            'three_rank_workers': identifier in (
                'C1_same_policy_prepare_restart', 'C2_same_creator_policy')}


class HTTPProxy(http.HTTPProxy):
    """Real TCP cuts, retaining the original bounded HTTP observer and payloads.

    No product response is constructed. A cut closes the actual caller socket
    before backend forwarding. A lost held response records the genuine backend
    bytes before closing that caller socket. All owned handlers retain the base
    proxy's bounds and join behavior.
    """

    def __init__(self, *args):
        self.cuts, self.cut_serial, self.queued_holds = {}, 0, []
        super().__init__(*args)

    def hold_pair(self, first_id, second_id, operation):
        """Arm both racers before either caller can arrive at the listener."""
        with self.lock:
            if self.queued_holds or len(self.gates) > http.MAX_GATES - 2:
                raise ValueError('queued hold unavailable')
            if (not isinstance(second_id, str) or not http.re.fullmatch(r'[A-Za-z0-9_-]{1,128}', second_id)
                    or second_id == first_id or any(g.id == second_id for g in self.gates)):
                raise ValueError('invalid second hold')
            first = self.arm(first_id, operation, mode='hold', stage='before_forward')
            second = http.Gate(second_id, operation, 'hold', 'before_forward', 1)
            self.gates.append(second)
            self.queued_holds.append(second)
            self.trace.emit('http_proxy_fault_armed', role=self.role, id=second.id,
                operation=operation, mode='hold', stage='before_forward', occurrence=1,
                origin='queued_before_forward_hold')
            return first, second

    def cut_status(self, identifier, count=None):
        if (not isinstance(identifier, str) or not http.re.fullmatch(r'[A-Za-z0-9_-]{1,80}', identifier)
                or count is not None and (type(count) is not int or not 1 <= count <= 32)):
            raise ValueError('invalid bounded status transport cut')
        with self.lock:
            if self.closing or 'status' in self.cuts:
                raise ValueError('status cut unavailable')
            self.cuts['status'] = [identifier, count]
            self.trace.emit('http_proxy_cut_started', role=self.role, id=identifier,
                            operation='status', count=count)

    def restore_status(self):
        with self.lock:
            old = self.cuts.pop('status', None)
            if old is None:
                raise ValueError('status cut not active')
            self.trace.emit('http_proxy_cut_ended', role=self.role, id=old[0],
                            operation='status', remaining=old[1])

    def _select(self, connection):
        with self.lock:
            selected = super()._select(connection)
            if selected is not None:
                if self.gate is None and self.queued_holds:
                    self.gate = self.queued_holds.pop(0)
                return selected
            operation = connection.fields['operation']
            cut = self.cuts.get(operation)
            if cut is None:
                return None
            if len(self.gates) >= http.MAX_GATES:
                raise http.ProxyError('transport_cut_bound')
            self.cut_serial += 1
            gate = http.Gate(f'{cut[0]}-{self.cut_serial}', operation, 'drop', 'before_forward', 1)
            gate.used = gate.seen = 1
            self.gates.append(gate)
            connection.gate = gate
            if cut[1] is not None:
                cut[1] -= 1
                if cut[1] == 0:
                    del self.cuts[operation]
            self.trace.emit('http_proxy_fault_armed', role=self.role, id=gate.id,
                operation=operation, mode='drop', stage='before_forward', occurrence=1,
                origin='bounded_status_transport_cut')
            return gate

    def release_lost(self, gate):
        with self.lock:
            if gate.mode != 'hold' or gate.stage != 'before_forward':
                raise ValueError('expected original before-forward hold')
            gate.discard_response = True
            self.trace.emit('http_proxy_response_loss_requested', role=self.role, id=gate.id)
        self.release(gate)

    def _deliver(self, connection, status, headers, body, raw):
        gate = connection.gate
        if gate is not None and getattr(gate, 'discard_response', False):
            self.trace.emit('http_proxy_delivery_suppressed', id=gate.id,
                stage='after_response', mode='drop', aborted=False, **connection.fields)
            self._shutdown(connection.client)
            return
        super()._deliver(connection, status, headers, body, raw)
