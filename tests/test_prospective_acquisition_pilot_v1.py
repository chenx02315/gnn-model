import copy
import unittest

from src.data import prospective_acquisition_pilot_v1 as pilot


class AcquisitionPilotTests(unittest.TestCase):
    def test_literal_roster_and_budgets(self):
        plan = pilot.build_plan()
        self.assertEqual(pilot.validate_plan(plan)['max_total_tasks'], 78)
        for phase in plan['phases']:
            rows = phase['requested_roster']
            self.assertEqual(len(rows), 9)
            self.assertEqual(sum(r['scheme'] == 'HF' for r in rows), 3)
            self.assertEqual(sum(r['scheme'] == 'HMF' for r in rows), 6)
            tasks = phase['tasks']
            self.assertEqual(len(tasks), 39)
            self.assertEqual(sum(t['kind'] == 'TESSENT' for t in tasks), 24)
            self.assertEqual(sum(t['kind'] == 'TRANSLATION' for t in tasks), 15)
            self.assertLessEqual(len(tasks), 64)  # E83 per-phase bound.

    def test_every_increment_has_exact_charged_translation_and_parent(self):
        for phase in pilot.build_plan()['phases']:
            seen = {}
            for task in phase['tasks']:
                self.assertNotIn(task['task_uid'], seen)
                for dep in task['depends_on']:
                    self.assertIn(dep, seen)
                    self.assertEqual(seen[dep]['action_uid'], task['action_uid'])
                if task['kind'] == 'TESSENT' and task['stage'] != 'H':
                    parent, translator = task['depends_on']
                    self.assertEqual(parent, task['parent_result_task_uid'])
                    self.assertEqual(seen[translator]['kind'], 'TRANSLATION')
                    self.assertEqual(seen[translator]['depends_on'], [parent])
                    self.assertEqual(seen[translator]['target_mode'], task['stage'])
                seen[task['task_uid']] = task

    def test_exact_one_f_control_without_unknown_result_pin(self):
        for phase in pilot.build_plan()['phases']:
            f_tasks = [t for t in phase['tasks'] if t.get('stage') == 'F']
            self.assertEqual(len(f_tasks), 9)
            for task in f_tasks:
                self.assertEqual(task['control'], {'kind': 'COVERAGE_PERCENT', 'value': '95'})
                self.assertEqual(task['stage_index'], 1)
                self.assertIsNone(task['parent_result_sha256'])

    def test_independent_fresh_plans_and_no_checkpoint_dependency(self):
        first, second = pilot.build_plan(), pilot.build_plan()
        self.assertEqual(first, second)
        first['phases'][0]['tasks'][0]['control']['value'] = 99
        self.assertEqual(second, pilot.build_plan())
        self.assertFalse(second['checkpoint_required'])
        self.assertFalse(second['graph_required_to_launch_atpg'])
        self.assertTrue(second['graph_required_before_structure_ablation'])

    def test_injected_outcome_or_legacy_feature_rejected(self):
        for key, value in [('h_patterns', 2), ('cycles', 100), ('runtime_s', 2),
                           ('is_positive', True)]:
            plan = pilot.build_plan()
            plan['phases'][0]['requested_roster'][0][key] = value
            with self.assertRaisesRegex(ValueError, 'PROTOCOL_CHANGED'):
                pilot.validate_plan(plan)

    def test_no_cap_invention_or_claim_release(self):
        plan = pilot.build_plan()
        for phase in plan['phases']:
            for key in ('memory_limit_bytes', 'attempt_timeout_s', 'disk_bytes_limit',
                        'authenticated_input_manifest_sha256'):
                self.assertIsNone(phase[key])
        for key in ('execution_ready', 'training_release', 'formal_generalization_claim',
                    'f_boundary_minimality_proven'):
            self.assertFalse(plan[key])

    def test_same_numeric_alias_cannot_mutate_frozen_protocol(self):
        plan = pilot.build_plan()
        plan['sessions_per_circuit'] = True
        with self.assertRaises(ValueError):
            pilot.validate_plan(plan)
        plan = pilot.build_plan()
        plan['phases'][0]['requested_roster'][0]['h_request'] = 1.0
        with self.assertRaises(ValueError):
            pilot.validate_plan(plan)

    def test_safety_and_cost_semantics_preserved(self):
        plan = pilot.build_plan()
        self.assertIn('union', plan['acceptance']['unique_faults'])
        self.assertIn('including failures', plan['accounting']['charge'])
        self.assertEqual(plan['accounting']['unknown_elapsed'], 'INCOMPLETE_NO_IMPUTATION')
        self.assertFalse(plan['cross_action_prefix_reuse'])
        changed = copy.deepcopy(plan)
        changed['automatic_retries'] = 1
        with self.assertRaises(ValueError):
            pilot.validate_plan(changed)


if __name__ == '__main__':
    unittest.main()
