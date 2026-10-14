"""Independent bounded PL enumeration and singleton analytic kernel gates."""
import itertools
import math
import unittest

from src.models import ranking_v6_complete_first_hit_reference as kernel
from src.models import ranking_v6_conditional_control_reference as control


def full_permutation_oracle(scores, positive, costs):
    """No pairwise formula: full PL probability and full log-prob derivative."""
    weights = {u: math.exp(s) for u, s in scores.items()}
    weighted_costs, mass, terms = [], [], {u: [] for u in scores}
    for order in itertools.permutations(scores):
        remaining = list(scores)
        probability, charge, hit = 1., 0., False
        dlog = {u: 0. for u in scores}
        for chosen in order:
            denominator = math.fsum(weights[u] for u in remaining)
            probability *= weights[chosen] / denominator
            for u in remaining:
                dlog[u] -= weights[u] / denominator
            dlog[chosen] += 1.
            if not hit:
                charge += costs[chosen]
                hit = chosen == positive
            remaining.remove(chosen)
        mass.append(probability)
        weighted_costs.append(probability * charge)
        for u in scores:
            terms[u].append(probability * charge * dlog[u])
    return math.fsum(mass), math.fsum(weighted_costs), {u: math.fsum(v) for u, v in terms.items()}


class CompleteFirstHitTests(unittest.TestCase):
    def evaluate(self, scores=None, costs=None, positives=('p',), **kwargs):
        return kernel.evaluate(scores if scores is not None else {'a': -.7, 'b': .4, 'p': -.2},
                               positives, costs if costs is not None else {'a': 1., 'b': 9., 'p': 5.},
                               synthetic_only=True, **kwargs)

    def test_independent_full_permutations_n2_through_n7(self):
        for n in range(2, 8):
            scores = {f'u{i}': (i % 3 - 1) * .63 for i in range(n)}
            costs = {f'u{i}': .3 + i * 1.7 for i in range(n)}
            positive = f'u{n // 2}'
            result = self.evaluate(scores, costs, (positive,))
            mass, raw, gradient = full_permutation_oracle(scores, positive, costs)
            self.assertAlmostEqual(mass, 1., delta=1e-12)
            self.assertAlmostEqual(result['complete_first_hit_cost'], raw, delta=1e-11)
            for u in scores:
                self.assertAlmostEqual(result['cost_score_gradient'][u], gradient[u], delta=1e-11)
                self.assertAlmostEqual(result['normalized_cost_score_gradient'][u],
                                       gradient[u] / result['cost_normalization_B'], delta=1e-12)

    def test_finite_difference_every_coordinate_raw_and_normalized(self):
        scores, costs = {'a': -.7, 'b': .4, 'p': -.2}, {'a': 1., 'b': 9., 'p': 5.}
        result = self.evaluate(scores, costs)
        for uid in scores:
            plus, minus = scores.copy(), scores.copy()
            plus[uid] += 1e-5
            minus[uid] -= 1e-5
            p, m = self.evaluate(plus, costs), self.evaluate(minus, costs)
            for objective, gradient in [('complete_first_hit_cost', 'cost_score_gradient'),
                                        ('normalized_complete_first_hit_cost', 'normalized_cost_score_gradient')]:
                self.assertAlmostEqual(result[gradient][uid], (p[objective] - m[objective]) / 2e-5,
                                       delta=2e-9)
            self.assertEqual(p['cost_normalization_B'], m['cost_normalization_B'])

    def test_score_shift_cost_scale_and_insertion_order(self):
        scores, costs = {'a': -.7, 'b': .4, 'p': -.2}, {'a': 1., 'b': 9., 'p': 5.}
        original = self.evaluate(scores, costs)
        shifted = self.evaluate({u: s + 9 for u, s in reversed(list(scores.items()))}, costs)
        scaled = self.evaluate(scores, {u: c * 3 for u, c in costs.items()})
        self.assertAlmostEqual(original['complete_first_hit_cost'], shifted['complete_first_hit_cost'])
        self.assertAlmostEqual(original['normalized_complete_first_hit_cost'], scaled['normalized_complete_first_hit_cost'])
        self.assertAlmostEqual(scaled['complete_first_hit_cost'], 3 * original['complete_first_hit_cost'])
        for u in scores:
            self.assertAlmostEqual(original['cost_score_gradient'][u], shifted['cost_score_gradient'][u])
            self.assertAlmostEqual(original['normalized_cost_score_gradient'][u], scaled['normalized_cost_score_gradient'][u])
            self.assertAlmostEqual(scaled['cost_score_gradient'][u], 3 * original['cost_score_gradient'][u])
        self.assertEqual(scores, {'a': -.7, 'b': .4, 'p': -.2})
        self.assertEqual(costs, {'a': 1., 'b': 9., 'p': 5.})

    def test_uniform_score_identity_and_bounds(self):
        costs = {'a': 1., 'b': 9., 'p': 5.}
        result = self.evaluate({u: 0. for u in costs}, costs)
        self.assertEqual(result['complete_first_hit_cost'], 10.)
        self.assertEqual(result['cost_score_gradient'], {'a': .25, 'b': 2.25, 'p': -2.5})
        self.assertEqual(result['cost_normalization_B'], 27.)
        self.assertAlmostEqual(math.fsum(result['cost_score_gradient'].values()), 0., delta=1e-15)
        for u, g in result['cost_score_gradient'].items():
            lower, upper = result['raw_score_gradient_bounds'][u]
            self.assertLessEqual(lower, g)
            self.assertLessEqual(g, upper)

    def test_extreme_gaps_preserve_nonzero_derivative(self):
        for negative, positive in ((20., -20.), (-20., 20.)):
            result = self.evaluate({'a': negative, 'p': positive}, {'a': 1e9, 'p': 1.})
            z = math.exp(-40.)
            expected = 1e9 * z / (1 + z) ** 2
            self.assertGreater(result['cost_score_gradient']['a'], 0.)
            self.assertEqual(result['cost_score_gradient']['a'], expected)
            self.assertEqual(result['cost_score_gradient']['p'], -expected)
            self.assertGreaterEqual(result['complete_first_hit_cost'], 1.)
            self.assertLessEqual(result['complete_first_hit_cost'], 1e9 + 1.)
            self.assertLessEqual(result['normalized_complete_first_hit_cost'], 1.)

    def test_n_minus_one_plus_forced_positive_old_control_identity(self):
        for n in range(2, 8):
            scores = {f'u{i}': (i % 3 - 1) * .4 for i in range(n)}
            costs = {f'u{i}': .5 + i * 1.3 for i in range(n)}
            positive = 'u0'
            result = self.evaluate(scores, costs, (positive,))
            old = control.enumerate_exact_gradient(scores, {positive}, costs, k=n - 1,
                                                  risk_baseline=.37, cost_baseline=.42 * (n - 1) * max(costs.values()))
            continued_cost = old['expected_truncated_static_cost'] + costs[positive] * old['expected_miss_probability']
            self.assertAlmostEqual(result['complete_first_hit_cost'], continued_cost, delta=1e-11)
            for u in scores:
                continued_gradient = old['cost_score_gradient'][u] + costs[positive] * old['miss_score_gradient'][u]
                self.assertAlmostEqual(result['cost_score_gradient'][u], continued_gradient, delta=1e-11)

    def test_singleton_and_maximum_work_metadata(self):
        result = self.evaluate({'p': 20.}, {'p': 1e9})
        self.assertEqual(result['complete_first_hit_cost'], 1e9)
        self.assertEqual(result['normalized_complete_first_hit_cost'], 1.)
        self.assertEqual(result['cost_score_gradient'], {'p': 0.})
        scores = {f'u{i}': 0. for i in range(1024)}
        result = self.evaluate(scores, {u: 1. for u in scores}, ('u0',))
        self.assertEqual(result['work_bound'], 1024)
        self.assertEqual(result['pairwise_terms'], 1023)
        self.assertEqual(result['complete_first_hit_cost'], 512.5)
        self.assertFalse(result['online_cost_replay'])
        self.assertFalse(result['model_fitting_implemented'])

    def test_gate_schema_and_domains_fail_closed(self):
        scores, costs = {'a': 0., 'p': 0.}, {'a': 1., 'p': 1.}
        for gate in (False, None, 1, 'true'):
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY_GATE'):
                kernel.evaluate(scores, ('p',), costs, synthetic_only=gate)
        with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY_GATE'):
            kernel.evaluate(scores, ('p',), costs)
        for bad in (True, None, '0', float('nan'), float('inf'), -float('inf'), 20.001, -20.001, 10**1000):
            with self.assertRaises(ValueError):
                self.evaluate({'a': bad, 'p': 0.}, costs)
        for bad in (True, None, '1', 0., -1., float('nan'), float('inf'), 1e9 + 1., 10**1000):
            with self.assertRaises(ValueError):
                self.evaluate(scores, {'a': bad, 'p': 1.})
        for bad in ((), ('p', 'p'), ('a', 'p'), ('missing',), 'p', {1}, None):
            with self.assertRaises(ValueError):
                self.evaluate(scores, costs, bad)
        for bad in ({}, [], {'../p': 0.}, {'p\n': 0.}, {True: 0.}, {'x' * 65: 0.},
                    {f'u{i}': 0. for i in range(1025)}):
            with self.assertRaises(ValueError):
                self.evaluate(bad, costs)
        for bad in ([], {}, {'a': 1.}, {'a': 1., 'p': 1., 'x': 1.}):
            with self.assertRaises(ValueError):
                self.evaluate(scores, bad)

    def test_numerical_underflow_is_explicitly_rejected(self):
        with self.assertRaisesRegex(ValueError, 'NUMERIC_UNDERFLOW'):
            self.evaluate({'a': 0., 'p': 0.}, {'a': 5e-324, 'p': 1.})
        with self.assertRaisesRegex(ValueError, 'NORMALIZED_NUMERIC_UNDERFLOW'):
            self.evaluate({'a': 0., 'p': 0.}, {'a': 1e-320, 'p': 1e9})

    def test_subnormal_bound_double_rounding_is_fail_closed(self):
        # Raw-then-normalize can round to 5e-324 while the true normalized
        # derivative and its bound round to zero. Reject rather than return
        # a false containing interval or silently accept derivative loss.
        with self.assertRaisesRegex(ValueError, 'NORMALIZED_NUMERIC_UNDERFLOW'):
            self.evaluate({'a': 0., 'p': 0.}, {'a': 1.5e-323, 'p': .9})

    def test_conservative_subnormal_region_rejection(self):
        # Even direct normalized evaluation can double-round a true value
        # below half the minimum subnormal upward. The whole subnormal
        # derivative region is conservatively outside the accepted domain.
        with self.assertRaisesRegex(ValueError, 'GRADIENT_SUBNORMAL_REPRESENTABILITY'):
            self.evaluate({'a': .5, 'p': -.5}, {'a': 1.5e-323, 'p': .6})
        with self.assertRaisesRegex(ValueError, 'GRADIENT_SUBNORMAL_REPRESENTABILITY'):
            self.evaluate({'a': 0., 'p': 0.}, {'a': 1e-310, 'p': 1.})


if __name__ == '__main__':
    unittest.main()
