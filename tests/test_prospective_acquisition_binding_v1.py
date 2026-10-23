"""Opaque in-memory fixtures only; no runner, report, graph, or source I/O."""
import copy
import unittest

from src.data import prospective_acquisition_binding_v1 as m
from src.data import prospective_acquisition_pilot_v1 as pilot


class AcquisitionBindingTests(unittest.TestCase):
    def setUp(self):
        self.plan = pilot.build_plan()
        self.binder = m.Binder(self.plan, 'aes_core')
        self.tasks = self.plan['phases'][0]['tasks']

    def payload(self, task):
        return ('opaque-test-bytes:' + task['task_uid']).encode('ascii')

    def receipt(self, binding, data):
        return dict(task_uid=binding['task_uid'],
                    binding_sha256=binding['binding_sha256'],
                    output_sha256=m.sha(data), status='SUCCESS',
                    live_acknowledged_claim=True,
                    output_authenticated_claim=True)

    def advance(self, task):
        binding = self.binder.bind_next(task['task_uid'])
        return self.binder.commit_next(binding,
                                       self.receipt(binding, self.payload(task)),
                                       self.payload(task))

    def test_valid_h_translation_f_and_h_translation_m_translation_f(self):
        first = self.tasks[:3]
        self.assertEqual([t['kind'] for t in first],
                         ['TESSENT', 'TRANSLATION', 'TESSENT'])
        for task in first:
            binding = self.binder.bind_next(task['task_uid'])
            self.assertFalse(binding['compilation_ready'])
            self.assertIsNone(binding['recipe'])
            self.advance(task)
        f = self.binder.snapshot()['receipts'][2]
        self.assertEqual(f['parent_task_uid'], first[0]['task_uid'])
        self.assertEqual(f['translation_task_uid'], first[1]['task_uid'])
        hmf_start = next(i for i, task in enumerate(self.tasks)
                         if task['kind'] == 'TESSENT' and
                         task['stage'] == 'H' and ':HMF:' in task['action_uid'])
        for task in self.tasks[3:hmf_start]:
            self.advance(task)
        next_five = self.tasks[hmf_start:hmf_start + 5]
        self.assertEqual([t['kind'] for t in next_five],
                         ['TESSENT', 'TRANSLATION', 'TESSENT',
                          'TRANSLATION', 'TESSENT'])
        for task in next_five:
            self.advance(task)
        final = self.binder.snapshot()['receipts'][hmf_start + 4]
        self.assertEqual(final['parent_task_uid'], next_five[2]['task_uid'])
        self.assertEqual(final['translation_task_uid'], next_five[3]['task_uid'])
        self.assertEqual(final['target_mode'], 'F')

    def test_wrong_or_cross_action_parent_never_advances(self):
        self.advance(self.tasks[0])
        next_task = self.tasks[1]
        self.binder._receipts[self.tasks[0]['task_uid']]['action_uid'] = 'spi:other'
        before = self.binder.snapshot()
        with self.assertRaisesRegex(ValueError, 'EXACT_PARENT_ACTION'):
            self.binder.bind_next(next_task['task_uid'])
        self.assertEqual(self.binder.snapshot(), before)

    def test_wrong_translation_parent_or_target_never_advances(self):
        self.advance(self.tasks[0])
        self.advance(self.tasks[1])
        target = self.tasks[2]['task_uid']
        translation_uid = self.tasks[1]['task_uid']
        original = copy.deepcopy(self.binder._receipts[translation_uid])
        for field, value in (('parent_result_sha256', 'f' * 64),
                             ('target_mode', 'M')):
            self.binder._receipts[translation_uid][field] = value
            with self.assertRaisesRegex(ValueError, 'EXACT_TRANSLATION'):
                self.binder.bind_next(target)
            self.assertEqual(self.binder.snapshot()['next_slot'], 2)
            self.binder._receipts[translation_uid] = copy.deepcopy(original)

    def test_missing_or_failed_live_ack_never_advances(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        data = self.payload(task)
        for change in ({'live_acknowledged_claim': False},
                       {'output_authenticated_claim': False},
                       {'status': 'FAILED'}):
            receipt = self.receipt(binding, data)
            receipt.update(change)
            with self.assertRaisesRegex(ValueError, 'UNVERIFIED'):
                self.binder.commit_next(binding, receipt, data)
            self.assertEqual(self.binder.snapshot()['next_slot'], 0)

    def test_altered_bytes_or_digest_never_advances(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        data = self.payload(task)
        receipt = self.receipt(binding, data)
        with self.assertRaisesRegex(ValueError, 'UNVERIFIED'):
            self.binder.commit_next(binding, receipt, data + b'altered')
        self.assertEqual(self.binder.snapshot()['next_slot'], 0)

    def test_replay_and_out_of_order_rejected(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        data = self.payload(task)
        receipt = self.receipt(binding, data)
        with self.assertRaisesRegex(ValueError, 'EXACT_NEXT_TASK'):
            self.binder.bind_next(self.tasks[1]['task_uid'])
        self.binder.commit_next(binding, receipt, data)
        with self.assertRaisesRegex(ValueError, 'EXACT_NEXT_TASK'):
            self.binder.commit_next(binding, receipt, data)
        self.assertEqual(self.binder.snapshot()['next_slot'], 1)

    def test_plan_and_binding_mutation_cannot_change_internal_state(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        self.plan['phases'][0]['tasks'][0]['control']['value'] = 999
        binding['control']['value'] = 999
        with self.assertRaisesRegex(ValueError, 'BINDING_CHANGED'):
            self.binder.commit_next(binding, self.receipt(binding, self.payload(task)),
                                    self.payload(task))
        self.assertEqual(self.binder.snapshot()['next_slot'], 0)
        fresh = self.binder.bind_next(task['task_uid'])
        self.assertEqual(fresh['control']['value'], 1)

    def test_receipt_and_snapshot_aliasing_blocked(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        data = self.payload(task)
        receipt = self.receipt(binding, data)
        self.binder.commit_next(binding, receipt, data)
        receipt['output_sha256'] = 'f' * 64
        snapshot = self.binder.snapshot()
        snapshot['receipts'][0]['output_sha256'] = 'e' * 64
        next_binding = self.binder.bind_next(self.tasks[1]['task_uid'])
        self.assertEqual(next_binding['parent_result_sha256'], m.sha(data))

    def test_extra_and_wrong_typed_receipt_fields_rejected(self):
        task = self.tasks[0]
        binding = self.binder.bind_next(task['task_uid'])
        data = self.payload(task)
        for change in ({'extra': 1}, {'live_acknowledged_claim': 1},
                       {'task_uid': None}):
            receipt = self.receipt(binding, data)
            receipt.update(change)
            with self.assertRaises(ValueError):
                self.binder.commit_next(binding, receipt, data)
        self.assertEqual(self.binder.snapshot()['next_slot'], 0)

    def test_no_invented_graph_or_recipe(self):
        binding = self.binder.bind_next(self.tasks[0]['task_uid'])
        self.assertIsNone(binding['freeze_sha256'])
        self.assertIsNone(binding['request'])
        self.assertIsNone(binding['recipe'])
        self.assertFalse(binding['execution_ready'])
        self.assertFalse(binding['training_release'])

    def test_malformed_frozen_plan_rejected_before_state(self):
        changed = copy.deepcopy(self.plan)
        changed['phases'][0]['tasks'][0]['stage'] = 'X'
        with self.assertRaisesRegex(ValueError, 'PROTOCOL_CHANGED'):
            m.Binder(changed, 'aes_core')


if __name__ == '__main__':
    unittest.main()
