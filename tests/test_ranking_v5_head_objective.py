import ast
import copy
import math
from pathlib import Path
import unittest
from src.models.ranking_v5_head_objective import build_recipe, family_logs, loss_reference, fitting_log_record


def fixture(negatives=100):
    rows=[{'action_uid':'p','family':'fit','total_cycles':100}]
    rows += [{'action_uid':f'n{i:03}','family':'fit','total_cycles':110} for i in range(negatives)]
    return build_recipe(rows,heldout_family='held')


class HeadObjectiveTests(unittest.TestCase):
    def test_old_counterexample_is_ordered_correctly(self):
        recipe=fixture()
        hit={'p':0.,**{f'n{i:03}':-1. for i in range(100)}}
        miss={'p':0.,**{f'n{i:03}':.01 if i<10 else -10. for i in range(100)}}
        self.assertLess(loss_reference(hit,recipe),loss_reference(miss,recipe))
        self.assertEqual((1,0),(family_logs(hit,recipe)[0]['hit_at_10'],family_logs(miss,recipe)[0]['hit_at_10']))

    def test_positive_gradient_direction_by_finite_difference_no_fit(self):
        recipe=fixture(10); scores={'p':0.,**{f'n{i:03}':1. for i in range(10)}}
        eps=1e-5; base=loss_reference(scores,recipe)
        better=dict(scores,p=eps)
        self.assertLess(loss_reference(better,recipe),base)
        self.assertAlmostEqual((loss_reference(better,recipe)-base)/eps,-1/(1+math.exp(-1)),places=5)

    def test_top10_boundary_and_stable_uid_ties(self):
        recipe=fixture(10); scores={'p':0.,**{f'n{i:03}':0. for i in range(10)}}
        row=family_logs(scores,recipe)[0]
        self.assertEqual(11,row['first_positive_rank'])
        self.assertTrue(row['tie_at_boundary']); self.assertFalse(row['strict_score_hit_certificate'])
        scores['p']=.001
        self.assertTrue(family_logs(scores,recipe)[0]['strict_score_hit_certificate'])

    def test_guaranteed_small_family_zero_signal_not_fake_learning(self):
        recipe=fixture(9); scores={'p':-100.,**{f'n{i:03}':100. for i in range(9)}}
        row=family_logs(scores,recipe)[0]
        self.assertEqual(10,row['first_positive_rank']); self.assertEqual(0.,loss_reference(scores,recipe))
        record=fitting_log_record(scores,recipe,epoch=0,phase='INITIAL')
        self.assertEqual(0,record['objective_signal_families']); self.assertIsNone(row['head_gap'])

    def test_exact_integer_epsilon_and_any_positive(self):
        rows=[{'action_uid':'p','family':'fit','total_cycles':100}, {'action_uid':'p2','family':'fit','total_cycles':101}]
        rows += [{'action_uid':f'n{i:03}','family':'fit','total_cycles':102} for i in range(10)]
        recipe=build_recipe(rows,heldout_family='held')
        self.assertEqual(('p','p2'),recipe['families']['fit']['positive'])
        scores={'p':-100.,'p2':1.,**{f'n{i:03}':0. for i in range(10)}}
        self.assertEqual(1,family_logs(scores,recipe)[0]['first_positive_rank'])

    def test_macro_equal_weight(self):
        a=fixture(10); b=fixture(100)
        g=b['families']['fit']; g={**g,'positive':tuple('b'+u for u in g['positive']),
            'negative':tuple('b'+u for u in g['negative']),'cycles':{'b'+u:c for u,c in g['cycles'].items()}}
        both={**a,'families':{'big':g,'fit':a['families']['fit']}}
        scores={u:(1. if u=='p' else -1. if u=='bp' else 0.) for group in both['families'].values() for u in group['cycles']}
        self.assertAlmostEqual((math.log1p(math.exp(-1))+math.log1p(math.exp(1)))/2,loss_reference(scores,both))

    def test_fail_closed_inputs(self):
        for rows in ([],[{'action_uid':'p','family':'held','total_cycles':100}],
                     [{'action_uid':'p','family':'fit','total_cycles':100}],
                     [{'action_uid':'p','family':'fit','total_cycles':True}],
                     [{'action_uid':'p','family':'fit','total_cycles':100,'runtime':1}]):
            with self.assertRaises(ValueError): build_recipe(rows,heldout_family='held')
        recipe=fixture(10); scores={'p':0.,**{f'n{i:03}':0. for i in range(10)}}
        for bad in ({'p':0.},dict(scores,p=float('nan')),dict(scores,extra=0.)):
            with self.assertRaises(ValueError): family_logs(bad,recipe)

    def test_forged_partition_held_membership_and_overflow_refuse(self):
        recipe=fixture(10); scores={'p':0.,**{f'n{i:03}':0. for i in range(10)}}
        bad=copy.deepcopy(recipe); bad['families']['fit']['positive']=()
        with self.assertRaises(ValueError): family_logs(scores,bad)
        bad=copy.deepcopy(recipe); bad['heldout_family_forbidden']='fit'
        with self.assertRaises(ValueError): family_logs(scores,bad)
        extreme={u:(1e308 if u=='p' else -1e308) for u in scores}
        with self.assertRaises(ValueError): family_logs(extreme,recipe)

    def test_no_training_or_io_and_logs_no_uid_scores(self):
        source=Path('src/models/ranking_v5_head_objective.py').read_text()
        called={getattr(n.func,'id',getattr(n.func,'attr','')) for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call)}
        self.assertFalse(called & {'open','fit_neural','backward','step','save','load','write_text'})
        recipe=fixture(10); scores={'p':0.,**{f'n{i:03}':1. for i in range(10)}}
        record=fitting_log_record(scores,recipe,epoch=120,phase='FINAL')
        self.assertNotIn('scores',record); self.assertNotIn('positive',record['families'][0])


if __name__=='__main__': unittest.main()
