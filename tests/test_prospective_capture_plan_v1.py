import copy
import json
from pathlib import Path
import unittest
from src.data.prospective_capture_plan_v1 import assess_plan


class ProspectivePlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((Path(__file__).resolve().parents[1] /
            'contracts/prospective_capture_plan_v1.template.json').read_text(encoding='utf-8'))

    def test_real_template_is_explicitly_unready(self):
        result = assess_plan(self.plan)
        self.assertTrue(result['schema_valid'])
        self.assertFalse(result['configuration_complete'])
        self.assertEqual(len(result['missing_fields']), 21)
        self.assertFalse(result['execution_ready'])

    def test_even_filled_dummy_hashes_do_not_grant_execution(self):
        self.plan['freeze_components'] = dict.fromkeys(self.plan['freeze_components'], 'a' * 64)
        for key in ('memory_limit_bytes', 'attempt_wall_timeout_s', 'max_physical_attempts', 'candidate_count'):
            self.plan['limits'][key] = 1
        self.plan['comparison']['epsilon'] = 0.05
        result = assess_plan(self.plan)
        self.assertTrue(result['configuration_complete'])
        for key in ('execution_ready', 'training_release', 'artifact_contents_verified',
                    'preregistration_authenticated', 'execution_authority_verified'):
            self.assertFalse(result[key])

    def test_scope_modes_and_policy_cannot_be_silently_changed(self):
        mutations = [('execution_ready', True), ('status', 'REGISTERED'),
                     ('quality_floor', 'D90'), ('objective', 'ate_cycles'), ('extra', 1)]
        for key, value in mutations:
            plan = copy.deepcopy(self.plan); plan[key] = value
            with self.assertRaises(ValueError): assess_plan(plan)
        for circuit in ('wb_dma', 'tv80', 'b20'):
            plan = copy.deepcopy(self.plan); plan['scope']['circuits'][0] = circuit
            with self.assertRaises(ValueError): assess_plan(plan)

    def test_resource_bool_nan_or_retries_rejected(self):
        for key, value in (('workers', True), ('automatic_retries', 1),
                           ('candidate_count', True), ('memory_limit_bytes', -1)):
            plan = copy.deepcopy(self.plan); plan['limits'][key] = value
            with self.assertRaises(ValueError): assess_plan(plan)
        for value in (True, float('nan'), float('inf'), -0.1):
            plan = copy.deepcopy(self.plan); plan['comparison']['epsilon'] = value
            with self.assertRaises(ValueError): assess_plan(plan)

    def test_pins_are_exact_and_no_unknown_fields_accepted(self):
        for value in ('bad', True, 12):
            plan = copy.deepcopy(self.plan); plan['freeze_components']['driver_sha256'] = value
            with self.assertRaises(ValueError): assess_plan(plan)
        plan = copy.deepcopy(self.plan); plan['scope']['blind_open'] = True
        with self.assertRaises(ValueError): assess_plan(plan)


if __name__ == '__main__':
    unittest.main()
