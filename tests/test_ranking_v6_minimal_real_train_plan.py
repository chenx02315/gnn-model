"""E30 plan-only arithmetic and authority checks, no data/model/optimizer."""
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1]/'contracts/ranking_v6_minimal_real_train_plan_v1.json'


class MinimalPlanTests(unittest.TestCase):
    def test_plan_is_not_execution_authority(self):
        p = json.loads(PATH.read_text())
        for key in ('real_training_release', 'real_label_reads_allowed', 'optimizer_execution_allowed',
                    'blind_allowed', 'lsf_tessent_allowed'):
            self.assertIs(p[key], False)
        self.assertEqual(p['current_formal_fits'], 0)
        self.assertEqual(len(p['release_gates']), 8)
        self.assertTrue(all(g['state'] == 'UNRESOLVED' for g in p['release_gates']))

    def test_budget_and_paired_paths(self):
        p = json.loads(PATH.read_text())
        b = p['planned_budget']
        self.assertEqual(b['total_fits'], len(p['train_families'])*len(p['seeds'])*len(p['arms']))
        self.assertEqual(b['total_updates'], b['total_fits']*p['optimizer_plan']['full_batch_macro_updates_per_fit'])
        for arm in p['arms']:
            self.assertEqual(arm['risk_main_paths_per_task_update']+arm['risk_pilot_paths_per_task_update'], 512)
        self.assertEqual(b['maximum_task_paths_per_fit'], 120*5*512)
        self.assertEqual(b['maximum_total_task_paths'], 120*5*512*36)
        self.assertEqual(p['resources']['memory_bytes'], 1073741824)
        self.assertEqual(p['resources']['automatic_retries'], 0)

    def test_quality_cost_denominators_and_held_gates_explicit(self):
        p = json.loads(PATH.read_text())
        self.assertEqual(len(p['features']), 7)
        self.assertEqual(len(p['train_families']), 6)
        self.assertEqual(len(p['informative_hit_families']), 5)
        self.assertEqual(p['seeds'], [20260824,20260825,20260826])
        self.assertFalse(p['d95_head'])
        self.assertEqual(p['common_training_objective']['risk_weight'], .5)
        self.assertEqual(p['common_training_objective']['normalized_cost_weight'], 1.)
        self.assertIn('N*max', p['common_training_objective']['B'])
        self.assertTrue(p['normalizer']['held_fit_forbidden'])
        self.assertIn('v5', p['historical_v5_difference'])

    def test_fresh_sampler_schedule_disjoint_and_paired(self):
        p = json.loads(PATH.read_text())
        main = [2*(((s*6+h)*120+epoch)*6+task)
                for s in range(3) for h in range(6) for epoch in range(120)
                for task in range(6) if task != h]
        pilot = [seed ^ 0x9E3779B9 for seed in main]
        self.assertEqual(len(main), 10800)
        self.assertEqual(len(set(main)), len(main))
        self.assertEqual(len(set(pilot)), len(pilot))
        self.assertFalse(set(main) & set(pilot))
        self.assertTrue(all(0 <= seed <= 2**32-1 for seed in main+pilot))
        self.assertTrue(p['sampler_schedule']['no_reset_to_same_seed_per_update'])

    def test_descriptive_family_unit_and_censoring_limits(self):
        evaluation = json.loads(PATH.read_text())['evaluation']
        self.assertIn('no noninformative', evaluation['censoring_limit'])
        self.assertIn('family is the unit', evaluation['aggregation'])
        self.assertIn('hit by BOTH', evaluation['prospective_success_criterion'])
        self.assertIn('all fifteen', evaluation['prospective_success_criterion'])


if __name__ == '__main__':
    unittest.main()
