"""Bounded synthetic-only exact enumeration and derivative checks."""
import math
import unittest

from src.models import ranking_v6_first_hit_exact_gradient as exact


class ExactGradientTests(unittest.TestCase):
    def test_finite_differences_separate_objectives(self):
        scores = {'a': .3, 'b': -.7, 'hit': 1.1, 'hit2': -.1}
        costs = {'a': 1., 'b': 10., 'hit': 5., 'hit2': 9.}
        positives = {'hit', 'hit2'}
        for k in (1, 2, 3, 10):
            result = exact.enumerate_exact_gradient(scores, positives, costs, k=k)
            for uid in scores:
                plus, minus = scores.copy(), scores.copy()
                plus[uid] += 1e-5
                minus[uid] -= 1e-5
                p = exact.enumerate_exact_gradient(plus, positives, costs, k=k)
                m = exact.enumerate_exact_gradient(minus, positives, costs, k=k)
                for objective, gradient in [('expected_miss_probability', 'miss_score_gradient'),
                                             ('expected_truncated_static_cost', 'cost_score_gradient')]:
                    finite_difference = (p[objective] - m[objective]) / 2e-5
                    self.assertAlmostEqual(result[gradient][uid], finite_difference, delta=2e-8)

    def test_shift_invariance_and_gradient_sum_zero(self):
        scores, costs = {'a': -3., 'b': 2., 'hit': 1.}, {'a': 1., 'b': 2., 'hit': 5.}
        result = exact.enumerate_exact_gradient(scores, {'hit'}, costs, k=2)
        shifted = exact.enumerate_exact_gradient({u: s + 8 for u, s in scores.items()}, {'hit'}, costs, k=2)
        for name in ('expected_miss_probability', 'expected_truncated_static_cost'):
            self.assertAlmostEqual(result[name], shifted[name], places=12)
        for name in ('miss_score_gradient', 'cost_score_gradient'):
            self.assertAlmostEqual(math.fsum(result[name].values()), 0., delta=1e-12)
            for uid in scores:
                self.assertAlmostEqual(result[name][uid], shifted[name][uid], places=12)

    def test_single_action_and_all_negative(self):
        for positives, risk in [(set(), 1.), ({'a'}, 0.)]:
            result = exact.enumerate_exact_gradient({'a': 20.}, positives, {'a': 7.})
            self.assertEqual(result['expected_miss_probability'], risk)
            self.assertEqual(result['expected_truncated_static_cost'], 7.)
            self.assertEqual(result['miss_score_gradient'], {'a': 0.})
            self.assertEqual(result['cost_score_gradient'], {'a': 0.})
        result = exact.enumerate_exact_gradient({'a': 0., 'b': 0., 'c': 0.}, set(),
                                                {'a': 1., 'b': 2., 'c': 3.}, k=2)
        self.assertAlmostEqual(result['expected_miss_probability'], 1.)
        self.assertAlmostEqual(result['expected_truncated_static_cost'], 4.)
        self.assertTrue(all(abs(v) < 1e-12 for v in result['miss_score_gradient'].values()))

    def test_k_truncation_and_hit_itself_charged(self):
        scores, costs = {'a': 0., 'hit': 0.}, {'a': 2., 'hit': 10.}
        first = exact.enumerate_exact_gradient(scores, {'hit'}, costs, k=1)
        full = exact.enumerate_exact_gradient(scores, {'hit'}, costs, k=2)
        self.assertEqual((first['expected_miss_probability'], first['expected_truncated_static_cost']), (.5, 6.))
        self.assertEqual((full['expected_miss_probability'], full['expected_truncated_static_cost']), (0., 11.))
        self.assertEqual(first['miss_score_gradient'], {'a': .25, 'hit': -.25})
        self.assertEqual(first['cost_score_gradient'], {'a': -2., 'hit': 2.})

    def test_cheap_miss_keeps_separate_risk_signal(self):
        result = exact.enumerate_exact_gradient({'cheap': 0., 'hit': 0.}, {'hit'},
                                                {'cheap': .01, 'hit': 1000.}, k=1)
        self.assertLess(result['miss_score_gradient']['hit'], 0.)
        self.assertGreater(result['cost_score_gradient']['hit'], 0.)
        self.assertFalse(result['scalar_loss_implemented'])
        self.assertFalse(result['training_estimator_implemented'])
        self.assertFalse(result['online_cost_replay'])
        self.assertEqual(result['status'], 'DRAFT_SYNTHETIC_GRADIENT_NOT_TRAINER')

    def test_bounds_and_bad_joins(self):
        cases = [({}, set(), {}, 1), ({str(i): 0. for i in range(8)}, set(), {str(i): 1. for i in range(8)}, 1),
                 ({'a': 0.}, {'missing'}, {'a': 1.}, 1), ({'a': 0.}, ['a', 'a'], {'a': 1.}, 1),
                 ({'a': 0.}, set(), {'b': 1.}, 1), ({'a': 0.}, set(), {'a': 1., 'extra': 1.}, 1),
                 ({'': 0.}, set(), {'': 1.}, 1), ({1: 0.}, set(), {1: 1.}, 1)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                exact.enumerate_exact_gradient(*case)
        for score in (True, float('nan'), float('inf'), 20.01, -20.01, '1', 10**1000):
            with self.subTest(score_type=type(score)), self.assertRaises(ValueError):
                exact.enumerate_exact_gradient({'a': score}, set(), {'a': 1.})
        for cost in (True, float('nan'), float('inf'), 0., -1., 1e9 + 1, '1', 10**1000):
            with self.subTest(cost_type=type(cost)), self.assertRaises(ValueError):
                exact.enumerate_exact_gradient({'a': 0.}, set(), {'a': cost})
        for k in (True, 0, -1, 11, 1.):
            with self.subTest(k=k), self.assertRaises(ValueError):
                exact.enumerate_exact_gradient({'a': 0.}, set(), {'a': 1.}, k=k)

    def test_seven_action_bound_and_extreme_scores(self):
        scores = {str(i): (-20. if i % 2 else 20.) for i in range(7)}
        result = exact.enumerate_exact_gradient(scores, {'1'}, {u: 1e9 for u in scores}, k=10)
        self.assertEqual(result['permutation_count'], 5040)
        self.assertAlmostEqual(result['probability_mass'], 1., places=12)
        self.assertAlmostEqual(result['expected_miss_probability'], 0., places=12)
        self.assertTrue(all(math.isfinite(v) for v in result['cost_score_gradient'].values()))

    def test_positive_subnormal_cost_expectation_stays_positive(self):
        minimum = float.fromhex('0x0.0000000000001p-1022')
        result = exact.enumerate_exact_gradient({'a': 0., 'b': 0.}, {'a', 'b'},
                                                {'a': minimum, 'b': minimum}, k=1)
        self.assertEqual(result['expected_truncated_static_cost'], minimum)
        self.assertEqual(result['expected_miss_probability'], 0.)

    def test_constant_all_positive_objectives_zero_gradients(self):
        scores = {'a': -.4, 'b': .8, 'c': .1}
        result = exact.enumerate_exact_gradient(scores, set(scores), {u: 1. for u in scores}, k=3)
        self.assertAlmostEqual(result['expected_truncated_static_cost'], 1., places=14)
        self.assertEqual(result['expected_miss_probability'], 0.)
        self.assertTrue(all(abs(v) < 1e-13 for v in result['cost_score_gradient'].values()))


if __name__ == '__main__':
    unittest.main()
