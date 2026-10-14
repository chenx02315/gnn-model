import importlib.util
import itertools
import math
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('e15_diag',Path(__file__).resolve().parents[1]/'scripts/diagnose_v6_first_hit_cost_alignment.py')
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)

class CostAlignmentChecks(unittest.TestCase):
    def test_two_action_censoring_counterexample(self):
        initial=diag.stopped_and_complete_cost({'n':0.,'p':0.},'p',{'n':1.,'p':100.},1)
        near_first=diag.stopped_and_complete_cost({'n':-20.,'p':20.},'p',{'n':1.,'p':100.},1)
        self.assertAlmostEqual(initial['truncated_cost'],50.5)
        self.assertAlmostEqual(initial['complete_first_hit_cost'],100.5)
        self.assertGreater(near_first['truncated_cost'],initial['truncated_cost'])
        self.assertLess(near_first['complete_first_hit_cost'],initial['complete_first_hit_cost'])
        self.assertEqual(near_first['existing_equivalent_miss_penalty'],100.)

    def test_independent_full_permutations(self):
        scores={'0':-.3,'1':.2,'2':-.7,'3':.4};costs={'0':1.,'1':4.,'2':3.,'3':8.}
        expected_full=[];expected_cut=[];miss=[]
        w={u:math.exp(v) for u,v in scores.items()}
        for order in itertools.permutations(scores):
            remaining=set(scores);prob=1.
            for u in order:prob*=w[u]/math.fsum(w[v] for v in remaining);remaining.remove(u)
            hit=order.index('3')+1
            expected_full.append(prob*math.fsum(costs[u] for u in order[:hit]))
            expected_cut.append(prob*math.fsum(costs[u] for u in order[:min(hit,2)]))
            miss.append(prob*int(hit>2))
        value=diag.stopped_and_complete_cost(scores,'3',costs,2)
        self.assertAlmostEqual(value['complete_first_hit_cost'],math.fsum(expected_full),places=12)
        self.assertAlmostEqual(value['truncated_cost'],math.fsum(expected_cut),places=12)
        self.assertAlmostEqual(value['miss_probability'],math.fsum(miss),places=12)

    def test_full_horizon_tail_zero_and_scaling(self):
        scores={'0':0.,'1':0.,'2':0.};costs={'0':1.,'1':2.,'2':3.}
        a=diag.stopped_and_complete_cost(scores,'2',costs,3)
        b=diag.stopped_and_complete_cost(scores,'2',{u:c*5 for u,c in costs.items()},3)
        self.assertEqual(a['expected_continuation_tail'],0.)
        self.assertEqual(a['miss_probability'],0.)
        self.assertAlmostEqual(b['complete_first_hit_cost'],5*a['complete_first_hit_cost'])
        with self.assertRaises(ValueError):diag.stopped_and_complete_cost(scores,'x',costs,2)

    def test_pairwise_gradient_and_uniform_formula(self):
        scores={'0':-.3,'1':.2,'2':-.7,'3':.4};costs={'0':1.,'1':4.,'2':3.,'3':8.}
        pair=diag.singleton_complete_cost_gradient(scores,'3',costs)
        full=diag.stopped_and_complete_cost(scores,'3',costs,2)
        self.assertAlmostEqual(pair['complete_first_hit_cost'],full['complete_first_hit_cost'],places=12)
        self.assertLess(pair['score_gradient']['3'],0.)
        for uid in scores:
            plus=dict(scores);minus=dict(scores);plus[uid]+=1e-6;minus[uid]-=1e-6
            difference=(diag.singleton_complete_cost_gradient(plus,'3',costs)['complete_first_hit_cost']-
                        diag.singleton_complete_cost_gradient(minus,'3',costs)['complete_first_hit_cost'])/2e-6
            self.assertAlmostEqual(difference,pair['score_gradient'][uid],delta=2e-8)
        uniform=diag.singleton_complete_cost_gradient({u:0. for u in scores},'3',costs)
        self.assertAlmostEqual(uniform['complete_first_hit_cost'],8.+.5*(1+4+3))
        shifted=diag.singleton_complete_cost_gradient({u:s+5 for u,s in scores.items()},'3',costs)
        self.assertAlmostEqual(pair['complete_first_hit_cost'],shifted['complete_first_hit_cost'],places=12)

    def test_invalid_cost_domains(self):
        scores={'0':0.,'1':0.};costs={'0':1.,'1':2.}
        for bad in ({'0':0.,'1':2.},{'0':1.,'1':float('inf')},{'0':1.}):
            with self.assertRaises(ValueError):diag.stopped_and_complete_cost(scores,'1',bad,1)
        with self.assertRaises(ValueError):diag.singleton_complete_cost_gradient({'0':float('nan'),'1':0.},'1',costs)

if __name__=='__main__':unittest.main()
