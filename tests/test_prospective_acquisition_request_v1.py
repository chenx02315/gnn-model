"""Pure request and opaque-byte fixtures; no graph, report, process, or I/O."""
import copy
import unittest

from src.data import prospective_acquisition_request_v1 as m
from src.data import prospective_acquisition_binding_v1 as binding
from src.data import prospective_acquisition_pilot_v1 as pilot
from src.data import prospective_tessent_stage_v1 as stage


class AcquisitionRequestTests(unittest.TestCase):
    def setUp(self):
        self.plan = pilot.build_plan()
        self.manifest_pin_claim = 'a' * 64

    def freeze(self, circuit='aes_core'):
        return m.freeze_acquisition(self.plan, circuit, 1, self.manifest_pin_claim)

    def test_graphless_freeze_exact_schema_and_no_outcome_or_model_fields(self):
        frozen = self.freeze()
        self.assertEqual(m.validate_freeze(frozen), frozen)
        original_h = frozen['requested_roster'][0]['h_request']
        self.plan['phases'][0]['requested_roster'][0]['h_request'] = 999
        self.assertEqual(frozen['requested_roster'][0]['h_request'], original_h)
        self.assertFalse(frozen['input_manifest_bytes_authenticated'])
        self.assertFalse(frozen['model_features_generated'])
        self.assertFalse(frozen['execution_ready'])
        self.assertFalse(frozen['training_release'])
        self.assertFalse(any('graph' in key or 'checkpoint' in key
                             for key in frozen if key not in
                             ('graph_required_for_acquisition',
                              'graph_or_checkpoint_present')))
        self.assertFalse(any(key in frozen for key in
                             ('cycles', 'elapsed_ns', 'generated_patterns',
                              'detected_common_faults', 'result_sha256')))

    def test_both_circuits_complete_exact_39_slot_chains(self):
        for circuit in ('aes_core', 'spi'):
            frozen = self.freeze(circuit)
            worker = binding.Binder(self.plan, circuit, frozen, 'test-run')
            tasks = next(p['tasks'] for p in self.plan['phases']
                         if p['circuit'] == circuit)
            self.assertEqual(len(tasks), 39)
            for task in tasks:
                bound = worker.bind_next(task['task_uid'])
                self.assertEqual(bound['compilation_ready'],
                                 task['kind'] == 'TESSENT')
                if task['kind'] == 'TESSENT':
                    self.assertEqual(bound['recipe']['stage'], task['stage'])
                    self.assertEqual(bound['recipe']['request_sha256'],
                                     stage.digest(bound['request']))
                    self.assertFalse(bound['recipe']['execution_ready'])
                    if task['stage'] != 'H':
                        self.assertEqual(bound['recipe']['required_tasks'][0]
                                         ['parent_result_sha256'],
                                         bound['parent_result_sha256'])
                else:
                    self.assertIsNone(bound['request'])
                    self.assertIsNone(bound['recipe'])
                opaque = ('opaque-fixture:' + task['task_uid']).encode('ascii')
                receipt = dict(task_uid=task['task_uid'],
                    binding_sha256=bound['binding_sha256'],
                    output_sha256=binding.sha(opaque), status='SUCCESS',
                    live_acknowledged_claim=True,
                    output_authenticated_claim=True)
                worker.commit_next(bound, receipt, opaque)
            state = worker.snapshot()
            self.assertEqual(state['next_slot'], 39)
            self.assertFalse(state['execution_ready'])
            self.assertFalse(state['os_authenticated'])

    def test_tamper_extra_graph_outcome_or_wrong_type_rejected(self):
        original = self.freeze()
        for key, value in (('graph_sha256', 'b' * 64), ('cycles', 1),
                           ('checkpoint', None), ('common_fault_count', True),
                           ('requested_max_h', 99), ('freeze_sha256', 'f' * 64)):
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.assertRaises(ValueError):
                m.validate_freeze(changed)

    def test_unrelated_plan_or_roster_rejected(self):
        changed = copy.deepcopy(self.plan)
        changed['phases'][0]['tasks'][0]['control']['value'] = 99
        with self.assertRaisesRegex(ValueError, 'PROTOCOL_CHANGED'):
            m.freeze_acquisition(changed, 'aes_core', 1, self.manifest_pin_claim)
        frozen = self.freeze()
        frozen['requested_roster'][0]['h_request'] = 99
        with self.assertRaisesRegex(ValueError, 'ACQUISITION_FREEZE_CHANGED'):
            m.validate_freeze(frozen)

    def test_bad_manifest_pin_or_common_count_rejected(self):
        for count, pin in ((0, self.manifest_pin_claim),
                           (True, self.manifest_pin_claim),
                           (1, 'not-a-sha')):
            with self.assertRaises(ValueError):
                m.freeze_acquisition(self.plan, 'aes_core', count, pin)

    def test_mismatch_cannot_advance_binder(self):
        frozen = self.freeze('aes_core')
        worker = binding.Binder(self.plan, 'aes_core', frozen, 'test-run')
        first = self.plan['phases'][0]['tasks'][0]
        bound = worker.bind_next(first['task_uid'])
        changed = copy.deepcopy(bound)
        changed['freeze_sha256'] = 'f' * 64
        opaque = b'opaque-fixture'
        receipt = dict(task_uid=first['task_uid'],
            binding_sha256=bound['binding_sha256'],
            output_sha256=binding.sha(opaque), status='SUCCESS',
            live_acknowledged_claim=True,
            output_authenticated_claim=True)
        with self.assertRaisesRegex(ValueError, 'BINDING_CHANGED'):
            worker.commit_next(changed, receipt, opaque)
        self.assertEqual(worker.snapshot()['next_slot'], 0)
        with self.assertRaises(ValueError):
            binding.Binder(self.plan, 'spi', frozen, 'test-run')


if __name__ == '__main__':
    unittest.main()
