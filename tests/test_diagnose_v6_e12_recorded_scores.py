"""Tiny analytic math only: no E12 fit, Torch or evidence traversal."""
import importlib.util
import math
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1]/'scripts/diagnose_v6_e12_recorded_scores.py'
spec = importlib.util.spec_from_file_location('e13_diag',path)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)

class GradientChecks(unittest.TestCase):
    def test_uniform_risk_and_shift_invariance(self):
        scores = {str(i):0. for i in range(4)}; costs = dict(zip(scores,[1.,2.,4.,8.]))
        a=diag.exact_score_values_gradients(scores,'3',costs,2)
        b=diag.exact_score_values_gradients({u:5. for u in scores},'3',costs,2)
        self.assertAlmostEqual(a['risk'],.5,places=14)
        self.assertEqual(a,b)
        self.assertAlmostEqual(math.fsum(a['risk_score_gradient'].values()),0.,places=14)
        self.assertAlmostEqual(math.fsum(a['cost_score_gradient'].values()),0.,places=14)

    def test_score_gradients_central_difference(self):
        scores={'0':-.7,'1':.2,'2':-.4,'3':-3.};costs={'0':1.,'1':4.,'2':2.,'3':8.}
        base=diag.exact_score_values_gradients(scores,'3',costs,2)
        for uid in scores:
            plus=dict(scores);minus=dict(scores);plus[uid]+=1e-6;minus[uid]-=1e-6
            p=diag.exact_score_values_gradients(plus,'3',costs,2)
            m=diag.exact_score_values_gradients(minus,'3',costs,2)
            for metric,gradient in (('risk','risk_score_gradient'),('normalized_cost','cost_score_gradient')):
                self.assertAlmostEqual((p[metric]-m[metric])/2e-6,base[gradient][uid],delta=2e-9)

    def test_cost_scaling_and_invalid_domains(self):
        scores={'0':.1,'1':-.2,'2':-.5};costs={'0':1.,'1':2.,'2':3.}
        a=diag.exact_score_values_gradients(scores,'2',costs,2)
        b=diag.exact_score_values_gradients(scores,'2',{u:c*5 for u,c in costs.items()},2)
        self.assertAlmostEqual(a['normalized_cost'],b['normalized_cost'],places=14)
        for u in scores:self.assertAlmostEqual(a['cost_score_gradient'][u],b['cost_score_gradient'][u],places=14)
        with self.assertRaises(ValueError):diag.exact_score_values_gradients(scores,'x',costs,2)
        with self.assertRaises(ValueError):diag.exact_score_values_gradients(dict(scores,**{'2':float('nan')}),'2',costs,2)

    def test_count_includes_rank_three_and_rejects_mismatch(self):
        phases=('prior_initial','prior_final','reconstructed_no_prior_initial','reconstructed_no_prior_final')
        rows=[dict(split=split,**{p:{'positive_rank':rank,'top_k_hit':int(rank<=3)} for p in phases})
              for split,rank in (('fit',3),('unseen',4),('unseen',1))]
        counts=diag.hit_counts(rows)
        for p in phases:self.assertEqual(counts[p],{'all':2,'fit':1,'unseen':1})
        rows[0]['prior_initial']['top_k_hit']=0
        with self.assertRaisesRegex(ValueError,'TOP3_COUNT_RANK_MISMATCH'):diag.hit_counts(rows)

if __name__=='__main__':unittest.main()
