"""Pure synthetic fixtures only; no package readers or model predictions."""
import math
import unittest

from src.models import ranking_v6_first_hit_reference as reference


class FirstHitReferenceTests(unittest.TestCase):
    def test_includes_hit_and_prefix_and_distinguishes_rank(self):
        costs = {'a': 2., 'b': 20., 'hit': 5.}
        first = reference.evaluate_order(['hit', 'a', 'b'], {'hit'}, costs)
        later = reference.evaluate_order(['a', 'hit', 'b'], {'hit'}, costs)
        expensive = reference.evaluate_order(['b', 'hit', 'a'], {'hit'}, costs)
        self.assertEqual((first['first_hit_rank'], first['truncated_static_cost']), (1, 5.))
        self.assertEqual((later['first_hit_rank'], later['truncated_static_cost']), (2, 7.))
        self.assertEqual(expensive['truncated_static_cost'], 25.)
        self.assertEqual(later['miss_indicator'], expensive['miss_indicator'])
        self.assertLess(later['objective_key'], expensive['objective_key'])

    def test_cheap_all_miss_cannot_beat_expensive_hit(self):
        costs = {'cheap': .01, 'hit': 1000.}
        miss = reference.evaluate_order(['cheap', 'hit'], {'hit'}, costs, k=1)
        hit = reference.evaluate_order(['hit', 'cheap'], {'hit'}, costs, k=1)
        self.assertLess(miss['truncated_static_cost'], hit['truncated_static_cost'])
        self.assertLess(hit['objective_key'], miss['objective_key'])
        self.assertIsNone(miss['first_hit_rank'])

    def test_k_boundary_exhaustion_and_empty_positives(self):
        costs = {'a': 2., 'b': 3., 'hit': 7.}
        order = ['a', 'b', 'hit']
        self.assertEqual(reference.evaluate_order(order, {'hit'}, costs, k=2)['truncated_static_cost'], 5.)
        at_k = reference.evaluate_order(order, {'hit'}, costs, k=3)
        self.assertEqual((at_k['hit'], at_k['tried_count'], at_k['truncated_static_cost']), (True, 3, 12.))
        for k in (3, 10):
            miss = reference.evaluate_order(order, set(), costs, k=k)
            self.assertEqual((miss['hit'], miss['tried_count'], miss['truncated_static_cost']), (False, 3, 12.))

    def test_exact_distribution_expectation_not_a_loss(self):
        result = reference.aggregate_distribution([(.25, ['hit', 'a']), (.75, ['a', 'hit'])],
                                                   {'hit'}, {'hit': 100., 'a': 2.}, k=1)
        self.assertEqual(result['expected_miss_probability'], .75)
        self.assertEqual(result['expected_truncated_static_cost'], 26.5)
        self.assertEqual(result['objective_key'], (.75, 26.5))
        self.assertFalse(result['training_estimator_implemented'])
        self.assertFalse(result['online_cost_replay'])
        self.assertEqual(result['status'], 'DRAFT_DESIGN_NOT_TRAINER')

    def test_uid_k_and_cost_rejections(self):
        cases = [(['a', 'a'], {'a'}, {'a': 1.}, 10),
                 (['a'], ['a', 'a'], {'a': 1.}, 10),
                 (['a'], {'missing'}, {'a': 1.}, 10),
                 (['a'], set(), {}, 10), (['a'], set(), {'a': 1., 'extra': 2.}, 10),
                 ([], set(), {}, 10), (['a'], set(), {'a': 1.}, True),
                 (['a'], set(), {'a': 1.}, 0), (['a'], set(), {'a': 1.}, 1.)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                reference.evaluate_order(*case)
        for value in (float('nan'), float('inf'), 0., -1., True, '2', 10**1000):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError):
                reference.evaluate_order(['a'], {'a'}, {'a': value})
        with self.assertRaises(ValueError):
            reference.evaluate_order(['a', 'b'], set(), {'a': 1.7e308, 'b': 1.7e308})

    def test_weight_and_distribution_rejections(self):
        costs = {'a': 1., 'hit': 3.}
        for weight in (float('nan'), float('inf'), 0., -.1, True, '1', 2., 10**1000):
            with self.subTest(weight_type=type(weight)), self.assertRaises(ValueError):
                reference.aggregate_distribution([(weight, ['a', 'hit'])], {'hit'}, costs)
        for distribution in ([], [(1.,)], [(.4, ['a', 'hit'])],
                             [(1., ['a'])], [(.5, ['a', 'hit']), (.50000001, ['hit', 'a'])]):
            with self.subTest(distribution=distribution), self.assertRaises(ValueError):
                reference.aggregate_distribution(distribution, {'hit'}, costs)

    def test_weight_sum_tolerance_fixed(self):
        orders = [(.5, ['a']), (.5 + 5e-13, ['a'])]
        result = reference.aggregate_distribution(orders, {'a'}, {'a': 1.})
        self.assertTrue(math.isclose(result['weight_sum'], 1., abs_tol=reference.WEIGHT_SUM_ABS_TOL))
        self.assertEqual(result['expected_truncated_static_cost'], 1.)
        miss = reference.aggregate_distribution(orders, set(), {'a': 1.})
        self.assertEqual(miss['expected_miss_probability'], 1.)
        with self.assertRaises(ValueError):
            reference.aggregate_distribution([(.5, ['a']), (.5 + 2e-12, ['a'])], {'a'}, {'a': 1.})

    def test_floatmax_cost_valid_weight_roundoff_is_stable(self):
        maximum = float.fromhex('0x1.fffffffffffffp+1023')
        orders = [(.5, ['a']), (.5 + 5e-13, ['a'])]
        result = reference.aggregate_distribution(orders, {'a'}, {'a': maximum})
        self.assertEqual(result['expected_truncated_static_cost'], maximum)
        self.assertEqual(result['expected_miss_probability'], 0.)
        miss = reference.aggregate_distribution(orders, set(), {'a': maximum})
        self.assertEqual(miss['expected_miss_probability'], 1.)
        self.assertTrue(math.isfinite(miss['expected_truncated_static_cost']))

    def test_wide_cost_range_preserves_small_weighted_terms(self):
        orders = [(5e-324, ['expensive', 'cheap']), (1., ['cheap', 'expensive'])]
        costs = {'expensive': 1e308, 'cheap': 1e-16}
        result = reference.aggregate_distribution(orders, set(costs), costs, k=1)
        expected = math.fsum([5e-324 * 1e308, 1e-16])
        self.assertEqual(result['expected_truncated_static_cost'], expected)
        self.assertEqual(result['expected_miss_probability'], 0.)

    def test_minimum_subnormal_cost_stays_positive(self):
        minimum = float.fromhex('0x0.0000000000001p-1022')
        result = reference.aggregate_distribution([(.5, ['a']), (.5, ['a'])], {'a'}, {'a': minimum})
        self.assertEqual(result['expected_truncated_static_cost'], minimum)
        self.assertGreater(result['expected_truncated_static_cost'], 0.)


if __name__ == '__main__':
    unittest.main()
