"""Paired no-prior implementation checks; no actual Torch fit."""
import copy
import inspect
import unittest
from unittest.mock import patch
from src.models import ranking_v6_synthetic_fit as old
from src.models import ranking_v6_synthetic_fit_no_prior as new
from tests.test_ranking_v6_synthetic_fit import FakeSession,FakeTorch

class PairedNoPriorTests(unittest.TestCase):
    def test_only_task_offsets_differ(self):
        a,b=old._tasks(),new._tasks()
        for x,y in zip(a,b):
            self.assertEqual(y['offsets'],{u:0. for u in y['uids']})
            x,y=copy.deepcopy(x),copy.deepcopy(y)
            del x['offsets'];del y['offsets']
            self.assertEqual(x,y)
        self.assertEqual(old.TASK_VECTORS,new.TASK_VECTORS)

    def test_training_and_sampling_sources_unchanged(self):
        for name in ('_TorchSession','_fit_step','_run_synthetic_fit','_comparison_scores'):
            self.assertEqual(inspect.getsource(getattr(old,name)),inspect.getsource(getattr(new,name)),name)
        self.assertEqual(old.SEEDS,new.SEEDS)
        self.assertEqual(old.NAMESPACE,new.NAMESPACE)
        self.assertIs(old.control,new.control)
        self.assertIn("case_id = 'e12-'",inspect.getsource(new._fit_step))

    def test_frozen_budget_and_non_rare_scope(self):
        config=new._protocol(24,32,32)
        self.assertFalse(config['rare_guard_required'])
        self.assertEqual(config['nominal_sampling_work'],165888)
        self.assertEqual(config['seeds'],[11,29,47])
        self.assertEqual(config['steps'],24)
        self.assertEqual(config['learning_rate'],.2)
        self.assertEqual(config['scalar_objective'],'0.5*risk+0.5*cost/(K*max_cost)')
        self.assertEqual(config['source_sha256']['factory'],old._protocol(24,32,32)['source_sha256']['factory'])
        self.assertNotIn('import torch',inspect.getsource(new))

    def test_zero_prior_controls_are_duplicates_not_new_evidence(self):
        task=new._tasks()[0]
        states=new._comparison_scores(task,{u:0. for u in task['uids']},{u:0. for u in task['uids']})
        self.assertEqual(states['PRIOR_ONLY_PL'],states['UNIFORM_PL'])
        self.assertEqual(states['COST_PLUS_PRIOR_PL'],states['COST_PRIOR_PL'])

    def test_three_shared_models_and_no_rare_failure(self):
        FakeSession.instances,FakeSession.events=[],[]
        def oracle(scores,positives,costs,*,k):
            self.assertEqual(sum(s.steps for s in FakeSession.instances),3)
            return dict(probability_mass=1.,expected_miss_probability=.5,
                        expected_truncated_static_cost=.4*k*max(costs.values()))
        with patch.object(new,'_TorchSession',FakeSession),patch.object(new.oracle,'enumerate_exact_gradient',side_effect=oracle) as exact:
            result=new._run_synthetic_fit(FakeTorch(),steps=1,baseline_samples=1,main_samples=1)
        self.assertTrue(result['protocol_completed'])
        self.assertFalse(result['rare_initial_guard_pass'])
        self.assertFalse(result['rare_guard_required'])
        self.assertEqual(result['scientific_status'],'NO_JOINT_IMPROVEMENT')
        self.assertEqual(result['optimizer_steps'],3)
        self.assertEqual(exact.call_count,72)
        self.assertEqual(len(FakeSession.instances),3)
        self.assertTrue(result['all_parameters_restored'])
        self.assertFalse(result['train_release'])

if __name__=='__main__':unittest.main()
