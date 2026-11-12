"""Behavioral regressions and checker anti-vacuity tests, separate from exploration."""
from copy import deepcopy
import unittest

import cases
from controls import controls
from model import World, policy
from oracle import audit, expected_names, Violation


class ControllerModelTests(unittest.TestCase):
    def checked(self, world, name):
        return audit(world.trace(name), strict=True)

    def test_inventory_has_402_unique_named_histories(self):
        rows = cases.cases()
        self.assertEqual({c.name for c in rows}, expected_names())
        self.assertEqual(sum(c.family == 'prepare-race' for c in rows), 360)

    def test_policy_binds_modes_and_principal(self):
        values = [policy(), policy(cancel=False), policy(principal=12), policy(domain='b')]
        self.assertEqual(len({p['digest'] for p in values}), 4)
        for value in values:
            self.assertEqual(len(set(value['nonces'].values())), 4)
            self.assertTrue(all(value['nonces'].values()))

    def test_real_two_put_extremes_adopt_first_winner(self):
        for name in ('race-same-0-00', 'race-same-0-59'):
            row = next(c for c in cases.cases() if c.name == name)
            self.assertEqual(self.checked(row.build(), name)['restarts'], 4)

    def test_distinct_creators_compete_original_claims(self):
        row = next(c for c in cases.cases() if c.name == 'race-other-creator-0-30')
        self.assertEqual(self.checked(row.build(), row.name)['mutations'], 7)

    def test_foreign_policy_stops_after_restart(self):
        row = next(c for c in cases.cases() if c.name == 'race-other-policy-1-30')
        result = self.checked(row.build(), row.name)
        self.assertEqual((result['mutations'], result['core_unknowns']), (5, 1))

    def test_late_prepare_wins_after_local_inputs_lost(self):
        self.assertEqual(self.checked(cases.late_prepare(), 'late-prepare')['core_unknowns'], 1)

    def test_old_claim_unknown_after_cancel_stays_unknown(self):
        for before in (False, True):
            self.assertEqual(self.checked(cases.late_claim(before), 'late-claim-'+str(int(before)))['core_unknowns'], 1)

    def test_cancel_then_activate_preserves_worker_epoch(self):
        w = cases.cancel_then_activate()
        self.checked(w, 'cancel-then-activate')
        self.assertEqual(w.core.head()['owner'], {'instance': 1, 'epoch': 1})

    def test_restart_does_not_retrofit_recovery_budget(self):
        self.checked(cases.restart_pending('claimed'), 'restart-claimed')

    def test_one_business_execution_retains_original_unknown(self):
        self.assertEqual(self.checked(cases.sql_unknown(), 'sql-unknown')['core_unknowns'], 1)

    def test_window_requires_interval_and_total_span(self):
        self.assertEqual(self.checked(cases.intervals(), 'intervals')['mutations'], 1)

    def test_nondeath_errors_never_create_suspicion(self):
        for code in ('INVALID', 'DENIED', 'BUSY', 'LIMIT', 'TARGET', 'LIFECYCLE', 'CORRUPT'):
            result = self.checked(cases.no_suspicion(code), 'nondeath-'+code.lower())
            self.assertEqual((result['mutations'], result['probe_failures']), (0, 4))

    def test_original_caps_prevent_extra_invocation(self):
        for kind in ('calls', 'deadline', 'mutations'):
            self.checked(cases.bounded(kind), 'bound-'+kind)

    def test_actual_authority_changes_fail_closed(self):
        for kind in ('stale-inspection', 'revoked-admin', 'replacement-worker'):
            self.checked(cases.authority_change(kind), kind)

    def test_40_negative_controls_reject_at_declared_boundary(self):
        for row in controls():
            with self.subTest(control=row.name):
                with self.assertRaises(Violation) as failure:
                    audit(row.build())
                self.assertEqual(failure.exception.rule, row.rule)

    def test_checker_rejects_vacuous_renamed_history(self):
        trace = cases.healthy().trace('late-prepare')
        with self.assertRaises(Violation) as failure:
            audit(trace, strict=True)
        self.assertEqual(failure.exception.rule, 'mandatory-late-prepare')

    def test_checker_ignores_fabricated_summary(self):
        trace = cases.cancel_then_activate().trace('cancel-then-activate')
        expected = audit(trace, strict=True)
        other = deepcopy(trace); other['summary'] = {'passed': False, 'native_session': True, 'old_ack': True}
        self.assertEqual(audit(other, strict=True), expected)

    def test_report_reason_does_not_change_window_knowledge(self):
        trace = cases.reset_window('invalid').trace('reset-invalid')
        expected = audit(trace, strict=True)
        for event in trace['controller']:
            if event['event'] == 'report': event['reason'] = 'arbitrary-human-label'
        self.assertEqual(audit(trace, strict=True), expected)

    def test_controller_history_cannot_be_replaced_by_summary(self):
        trace = cases.claimed().trace('custom')
        trace['controller'] = []
        trace['summary'] = {'passed': True}
        with self.assertRaises(Violation) as failure:
            audit(trace)
        self.assertEqual(failure.exception.rule, 'closed-controller-history')


if __name__ == '__main__':
    unittest.main()
