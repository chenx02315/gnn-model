"""Small independent full-PL oracle and control-variate boundaries."""
import math
import random
import unittest
from unittest import mock

from src.models import ranking_v6_conditional_control_reference as control
from src.models import ranking_v6_conditional_survival_reference as frozen
from src.models import ranking_v6_first_hit_exact_gradient as full


class ConditionalControlTests(unittest.TestCase):
    def setUp(self):
        self.scores = {'a': -.7, 'b': .4, 'c': 1.2, 'p': -.2}
        self.costs = {'a': 1., 'b': 9., 'c': .2, 'p': 5.}

    def assert_matches(self, left, right):
        for key in ('expected_miss_probability', 'expected_truncated_static_cost'):
            self.assertAlmostEqual(left[key], right[key], delta=1e-10)
        for key in ('miss_score_gradient', 'cost_score_gradient'):
            for uid in left[key]:
                self.assertAlmostEqual(left[key][uid], right[key][uid], delta=1e-10)

    def test_arbitrary_fixed_baselines_preserve_all_uid_expectations(self):
        for k in (1, 2, 3):
            expected = full.enumerate_exact_gradient(self.scores, {'p'}, self.costs, k=k)
            bound = k * max(self.costs.values())
            for br, bc in ((0., 0.), (1., bound), (.37, .42 * bound)):
                result = control.enumerate_exact_gradient(self.scores, {'p'}, self.costs, k=k,
                                                          risk_baseline=br, cost_baseline=bc)
                self.assert_matches(result, expected)

    def test_components_and_zero_baseline_match_frozen_per_trajectory(self):
        prepared = frozen._validate(self.scores, {'p'}, self.costs, 2, 7)
        import itertools
        for order in itertools.permutations(prepared[4], 2):
            old = frozen._trajectory(*prepared[1:], 2, order=order)
            parts = control._components(*prepared[1:], 2, order=order)
            new = control._controlled(parts, 0., 0.)
            for a, b in zip(old[:3], new[:3]):
                self.assertAlmostEqual(a, b, delta=1e-12)
            for old_gradient, new_gradient in zip(old[3:], new[3:]):
                for a, b in zip(old_gradient, new_gradient):
                    self.assertAlmostEqual(a, b, delta=1e-12)
            pos = prepared[3][0]
            changed = control._controlled(parts, .5, 10.)
            self.assertEqual(parts[5][pos], 0.)
            self.assertEqual(new[3][pos], changed[3][pos])
            self.assertEqual(new[4][pos], changed[4][pos])

    def test_independent_pilot_seed_pins_and_frozen_means(self):
        kwargs = dict(k=2, seed=31, case_id='small', pilot_samples=5, main_samples=7)
        result = control.estimate(self.scores, {'p'}, self.costs, **kwargs)
        self.assertEqual(result, control.estimate(self.scores, {'p'}, self.costs, **kwargs))
        pins = result['derived_seed_sha256']
        self.assertNotEqual(pins['pilot'], pins['main'])
        self.assertNotEqual(control._pin(31, 'small', 'main'), control._pin(31, 'other', 'main'))
        self.assertNotEqual(pins['main'], control._pin(32, 'small', 'main'))
        prepared = frozen._validate(self.scores, {'p'}, self.costs, 2, 7)
        pilot = random.Random(int(pins['pilot'], 16))
        values = [control._components(*prepared[1:], 2, rng=pilot) for _ in range(5)]
        self.assertAlmostEqual(result['baseline_risk'], sum(v[1] for v in values) / 5, places=14)
        self.assertAlmostEqual(result['baseline_static_cost'], sum(v[2] for v in values) / 5, places=14)
        main = random.Random(int(pins['main'], 16))
        total = [0., 0., [0.] * 4, [0.] * 4]
        for _ in range(7):
            frozen._accumulate(total, control._controlled(control._components(*prepared[1:], 2, rng=main),
                               result['baseline_risk'], result['baseline_static_cost']), 1.)
        for i, uid in enumerate(prepared[0]):
            self.assertEqual(result['miss_score_gradient'][uid], total[2][i] / 7)
            self.assertEqual(result['cost_score_gradient'][uid], total[3][i] / 7)
        self.assertEqual(result['work_bound'], 4 * 2 * (5 + 7))

    def test_shift_and_gradient_sum_zero(self):
        kwargs = dict(k=2, seed=9, case_id='shift', pilot_samples=5, main_samples=8)
        result = control.estimate(self.scores, {'p'}, self.costs, **kwargs)
        shifted = control.estimate({u: s + 8 for u, s in self.scores.items()}, {'p'}, self.costs, **kwargs)
        self.assert_matches(result, shifted)
        for key in ('miss_score_gradient', 'cost_score_gradient'):
            self.assertAlmostEqual(math.fsum(result[key].values()), 0., delta=1e-12)

    def test_fixed_baseline_finite_difference_all_uids(self):
        kwargs = dict(k=2, risk_baseline=.37, cost_baseline=7.)
        result = control.enumerate_exact_gradient(self.scores, {'p'}, self.costs, **kwargs)
        for uid in self.scores:
            plus, minus = self.scores.copy(), self.scores.copy()
            plus[uid] += 1e-6
            minus[uid] -= 1e-6
            p = control.enumerate_exact_gradient(plus, {'p'}, self.costs, **kwargs)
            m = control.enumerate_exact_gradient(minus, {'p'}, self.costs, **kwargs)
            for obj, grad in [('expected_miss_probability', 'miss_score_gradient'),
                              ('expected_truncated_static_cost', 'cost_score_gradient')]:
                self.assertAlmostEqual(result[grad][uid], (p[obj] - m[obj]) / 2e-6, delta=1e-7)

    def test_zero_cost_branch_and_conservative_bounds(self):
        result = control.estimate(self.scores, {'p'}, {u: 0. for u in self.scores},
                                  k=3, seed=2, case_id='zero', pilot_samples=3, main_samples=4)
        self.assertTrue(result['all_zero_costs'])
        self.assertEqual(result['cost_normalization_B'], 1.)
        self.assertEqual(result['baseline_static_cost'], 0.)
        self.assertTrue(all(v == 0. for v in result['cost_score_gradient'].values()))
        prepared = frozen._validate(self.scores, {'p'}, self.costs, 3, 7)
        import itertools
        bound = 3 * max(self.costs.values())
        for order in itertools.permutations(prepared[4], 3):
            parts = control._components(*prepared[1:], 3, order=order)
            for br, bc in ((0., 0.), (1., bound)):
                values = control._controlled(parts, br, bc)
                self.assertTrue(all(abs(g) <= 6 for g in values[3]))
                self.assertTrue(all(abs(g) <= 9 * bound for g in values[4]))
                pos = prepared[3][0]
                for i in range(len(self.scores)):
                    risk_range = (-3, 0) if i == pos else (-4, 4)
                    cost_range = (-3, 1) if i == pos else (-5, 4)
                    self.assertTrue(risk_range[0] <= values[3][i] <= risk_range[1])
                    self.assertTrue(cost_range[0] <= values[4][i] / bound <= cost_range[1])

    def test_reject_before_rng(self):
        base = dict(scores=self.scores, positive_uids={'p'}, costs=self.costs,
                    k=2, seed=1, case_id='reject', pilot_samples=1, main_samples=1)
        changes = [{'seed': True}, {'seed': -1}, {'seed': 2**32}, {'case_id': ''},
                   {'case_id': 'a/b'}, {'case_id': 'x' * 65}, {'pilot_samples': 0},
                   {'main_samples': 65537}, {'main_samples': True}, {'positive_uids': set()},
                   {'positive_uids': {'a', 'p'}}, {'k': 4}, {'k': True},
                   {'scores': dict(self.scores, a=float('nan'))},
                   {'scores': dict(self.scores, a=20.1)}, {'costs': dict(self.costs, a=-1.)}]
        large = {str(i): 0. for i in range(1024)}
        changes.append({'scores': large, 'positive_uids': {'0'}, 'costs': {u: 1. for u in large},
                        'k': 10, 'pilot_samples': 1000, 'main_samples': 1000})
        for change in changes:
            with self.subTest(keys=list(change)), mock.patch.object(control.random, 'Random') as rng:
                with self.assertRaises(ValueError):
                    control.estimate(**dict(base, **change))
                rng.assert_not_called()

    def test_invalid_fixed_baselines(self):
        for br, bc in [(-.1, 0.), (1.1, 0.), (float('nan'), 0.), (True, 0.),
                       (.5, -1.), (.5, 18.1), (.5, float('inf')), (.5, 10**1000)]:
            with self.subTest(br=br, bc_type=type(bc)), self.assertRaises(ValueError):
                control.enumerate_exact_gradient(self.scores, {'p'}, self.costs, k=2,
                                                  risk_baseline=br, cost_baseline=bc)

    def test_small_seven_action_exact_bound(self):
        scores = {str(i): (i - 3.) / 2 for i in range(7)}
        costs = {u: float(int(u) + 1) for u in scores}
        result = control.enumerate_exact_gradient(scores, {'0'}, costs, k=6,
                                                  risk_baseline=.4, cost_baseline=20.)
        self.assert_matches(result, full.enumerate_exact_gradient(scores, {'0'}, costs, k=6))
        self.assertEqual(result['trajectory_count'], 720)


if __name__ == '__main__':
    unittest.main()
