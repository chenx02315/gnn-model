"""Pure in-memory plan slots, not a durable quota or actual worker."""
import copy
import unittest

from src.data.prospective_stage_budget_v1 import DeclaredTaskBudget


def node(uid, kind='TESSENT_STAGE', stage='H', pin='a', deps=None):
    return dict(task_uid=uid, kind=kind, stage=stage, request_sha256=pin*64,
        depends_on=[] if deps is None else deps, timeout_ns=10, cleanup_ns=2)


def plan():
    return [node('h'), node('f-translation', 'STATUS_TRANSLATION', 'F', 'b'),
            node('f', stage='F', pin='b', deps=['f-translation'])]


class BudgetTests(unittest.TestCase):
    def test_debit_before_token_and_translation_paid_separately(self):
        value = DeclaredTaskBudget(plan(), 2, 1, 36)
        token = value.reserve('h')
        self.assertEqual(value.snapshot()['consumed_counts']['TESSENT_STAGE'], 1)
        self.assertIsNone(value.snapshot()['asserted_elapsed_ns_sum'])
        self.assertFalse(token['launch_authorized'])
        value.settle(token, 'SUCCESS', 3, True)
        token = value.reserve('f-translation')
        value.settle(token, 'SUCCESS', 4, True)
        token = value.reserve('f')
        result = value.settle(token, 'SUCCESS', 5, True)
        self.assertEqual(result['consumed_counts'], dict(TESSENT_STAGE=2, STATUS_TRANSLATION=1))
        self.assertEqual(result['reserved_envelope_ns'], 36)
        self.assertEqual(result['asserted_elapsed_ns_sum'], 12)
        self.assertTrue(result['declared_plan_complete'])
        self.assertFalse(result['durable_debit_ack_verified'])

    def test_failure_timeout_cancelled_never_refund_or_retry(self):
        for status in ('FAILED', 'TIMEOUT', 'CANCELLED'):
            value = DeclaredTaskBudget(plan(), 2, 1, 36)
            token = value.reserve('h')
            result = value.settle(token, status, 7, True)
            self.assertEqual(result['consumed_counts']['TESSENT_STAGE'], 1)
            self.assertEqual(result['reserved_envelope_ns'], 12)
            self.assertEqual(result['asserted_elapsed_ns_sum'], 7)
            self.assertEqual(result['stopped_reason'], 'STOP_FAILED_TASK_NO_RETRY')
            with self.assertRaises(ValueError):
                value.reserve('h-new-id')

    def test_unresolved_and_overrun_block_following_slots(self):
        for status, elapsed, cleanup in [('UNKNOWN', 2, True), ('SUCCESS', None, True),
                                        ('SUCCESS', 2, False), ('SUCCESS', 13, True)]:
            value = DeclaredTaskBudget(plan(), 2, 1, 36)
            token = value.reserve('h')
            result = value.settle(token, status, elapsed, cleanup)
            if status == 'UNKNOWN' or elapsed is None or not cleanup:
                self.assertIsNone(result['asserted_elapsed_ns_sum'])
            else:
                self.assertEqual(result['asserted_elapsed_ns_sum'], 13)
            with self.assertRaises(ValueError):
                value.reserve('f-translation')

    def test_budget_exhaustion_is_censored_not_d95_failure(self):
        for cap in (11, 24):
            value = DeclaredTaskBudget(plan(), 2, 1, cap)
            if cap >= 12:
                value.settle(value.reserve('h'), 'SUCCESS', 1, True)
                value.settle(value.reserve('f-translation'), 'SUCCESS', 1, True)
                next_uid = 'f'
            else:
                next_uid = 'h'
            with self.assertRaisesRegex(ValueError, 'CENSORED_DECLARED_BUDGET_EXHAUSTED'):
                value.reserve(next_uid)
            self.assertNotIn('d95', value.snapshot())
        value = DeclaredTaskBudget(plan(), 1, 0, 100)
        value.settle(value.reserve('h'), 'SUCCESS', 1, True)
        with self.assertRaisesRegex(ValueError, 'CENSORED'):
            value.reserve('f-translation')

    def test_immutable_plan_exact_slots_and_token_types(self):
        supplied = plan()
        value = DeclaredTaskBudget(supplied, 2, 1, 36)
        supplied[0]['task_uid'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'EXACT_NEXT_SLOT'):
            value.reserve('changed')
        token = value.reserve('h')
        mutated = copy.deepcopy(token); mutated['launch_authorized'] = 0
        with self.assertRaisesRegex(ValueError, 'EXACT_ACTIVE_TOKEN'):
            value.settle(mutated, 'SUCCESS', 1, True)
        with self.assertRaises(ValueError):
            value.reserve('f-translation')
        value.settle(token, 'SUCCESS', 1, True)
        with self.assertRaises(ValueError):
            value.reserve('h')

    def test_duplicate_bindings_missing_translation_and_bool_caps_reject(self):
        with self.assertRaises(ValueError):
            DeclaredTaskBudget([node('h'), node('renamed')], 2, 0, 36)
        with self.assertRaises(ValueError):
            DeclaredTaskBudget([node('f', stage='F')], 1, 0, 36)
        bad = plan(); bad[-1]['request_sha256'] = 'c'*64
        with self.assertRaises(ValueError):
            DeclaredTaskBudget(bad, 2, 1, 36)
        for args in ((True, 1, 36), (2, False, 36), (2, 1, True)):
            with self.assertRaises(ValueError):
                DeclaredTaskBudget(plan(), *args)


if __name__ == '__main__':
    unittest.main()
