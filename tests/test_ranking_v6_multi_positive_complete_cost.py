"""Bounded independent full-order PL oracle; no training or real data."""
import itertools
import math
import unittest
from decimal import Decimal, localcontext

from src.models import ranking_v6_complete_first_hit_reference as singleton
from src.models import ranking_v6_multi_positive_complete_cost as kernel


def permutation_oracle(scores, positives, costs):
    """Stream all n! complete permutations, retaining only O(n) accumulators."""
    weights = {u: math.exp(s) for u, s in scores.items()}
    total_mass, expected, gradients = 0., 0., {u: 0. for u in scores}
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
                hit = chosen in positives
            remaining.remove(chosen)
        total_mass += probability
        expected += probability * charge
        for u in scores:
            gradients[u] += probability * charge * dlog[u]
    return total_mass, expected, gradients


class MultiPositiveCompleteCostTests(unittest.TestCase):
    def evaluate(self, scores, positives, costs):
        return kernel.evaluate(scores, positives, costs, synthetic_only=True)

    def test_independent_full_permutations_n1_through_n6(self):
        for n in range(1, 7):
            scores = {f'u{i}': (i % 3 - 1) * .71 for i in range(n)}
            costs = {f'u{i}': .4 + 1.3 * i for i in range(n)}
            for positives in ({'u0'}, set(scores), {u for i, u in enumerate(scores) if i % 2 == 0}):
                result = self.evaluate(scores, positives, costs)
                mass, expected, gradient = permutation_oracle(scores, positives, costs)
                self.assertAlmostEqual(mass, 1., delta=1e-12)
                self.assertAlmostEqual(result['complete_first_hit_cost'], expected, delta=1e-11)
                for u in scores:
                    self.assertAlmostEqual(result['cost_score_gradient'][u], gradient[u], delta=1e-11)
                    self.assertAlmostEqual(result['normalized_cost_score_gradient'][u],
                                           gradient[u] / result['cost_normalization_B'], delta=1e-12)

    def test_finite_differences_raw_and_normalized(self):
        scores, costs = {'a': -.7, 'b': .2, 'c': 1., 'd': -.3}, {'a': 1., 'b': 9., 'c': 4., 'd': 2.}
        for positives in ({'a', 'b'}, set(scores), {'a'}):
            result = self.evaluate(scores, positives, costs)
            for u in scores:
                plus, minus = scores.copy(), scores.copy()
                plus[u] += 1e-5
                minus[u] -= 1e-5
                p, m = self.evaluate(plus, positives, costs), self.evaluate(minus, positives, costs)
                for field, grad in (('complete_first_hit_cost', 'cost_score_gradient'),
                                    ('normalized_complete_first_hit_cost', 'normalized_cost_score_gradient')):
                    self.assertAlmostEqual(result[grad][u], (p[field] - m[field]) / 2e-5, delta=3e-9)

    def test_expensive_positive_can_have_positive_gradient(self):
        result = self.evaluate({'cheap': 0., 'expensive': 0., 'negative': 0.},
                               ('cheap', 'expensive'), {'cheap': 1., 'expensive': 11., 'negative': 1.})
        self.assertGreater(result['cost_score_gradient']['expensive'], 0.)
        self.assertLess(result['cost_score_gradient']['cheap'], 0.)
        self.assertAlmostEqual(result['complete_first_hit_cost'], 6. + 1. / 3.)

    def test_all_positive_equal_cost_constant_and_unequal_softmax(self):
        scores = {'a': -.2, 'b': .7, 'c': 1.1}
        result = self.evaluate(scores, set(scores), dict.fromkeys(scores, 3.))
        self.assertEqual(result['complete_first_hit_cost'], 3.)
        self.assertEqual(result['cost_score_gradient'], dict.fromkeys(scores, 0.))
        costs = {'a': 1., 'b': 3., 'c': 9.}
        result = self.evaluate(scores, set(scores), costs)
        expected = sum(math.exp(scores[u]) * costs[u] for u in scores) / sum(map(math.exp, scores.values()))
        self.assertAlmostEqual(result['complete_first_hit_cost'], expected)
        self.assertEqual(result['negative_precedence_terms'], 0)

    def test_singleton_matches_existing_kernel_ordinary_domain(self):
        for n in range(1, 25):
            scores = {f'u{i}': (i % 5 - 2) * .4 for i in range(n)}
            costs = {f'u{i}': .3 + i * 1.7 for i in range(n)}
            old = singleton.evaluate(scores, ('u0',), costs, synthetic_only=True)
            new = self.evaluate(scores, ('u0',), costs)
            self.assertAlmostEqual(old['complete_first_hit_cost'], new['complete_first_hit_cost'], delta=1e-11)
            for u in scores:
                self.assertAlmostEqual(old['cost_score_gradient'][u], new['cost_score_gradient'][u], delta=1e-12)

    def test_permutation_shift_scale_and_gradient_sum(self):
        scores, costs = {'a': -.7, 'b': .3, 'c': 1.2, 'd': -.2}, {'a': 1., 'b': 4., 'c': 9., 'd': 3.}
        before_scores, before_costs = scores.copy(), costs.copy()
        result = self.evaluate(scores, ['a', 'c'], costs)
        transformed = self.evaluate({u: s + 8. for u, s in reversed(list(scores.items()))},
                                    ['c', 'a'], {u: c * 3. for u, c in costs.items()})
        self.assertAlmostEqual(math.fsum(result['cost_score_gradient'].values()), 0., delta=1e-14)
        self.assertAlmostEqual(math.fsum(result['normalized_cost_score_gradient'].values()), 0., delta=1e-15)
        self.assertAlmostEqual(result['complete_first_hit_cost'] * 3., transformed['complete_first_hit_cost'])
        for u in scores:
            self.assertAlmostEqual(result['cost_score_gradient'][u] * 3., transformed['cost_score_gradient'][u])
            self.assertAlmostEqual(result['normalized_cost_score_gradient'][u], transformed['normalized_cost_score_gradient'][u])
        self.assertEqual(scores, before_scores)
        self.assertEqual(costs, before_costs)
        self.assertEqual(list(result['cost_score_gradient']), list(scores))

    def test_maximum_n_extreme_scores_and_bounds(self):
        scores = {f'u{i}': 20. if i % 2 else -20. for i in range(1024)}
        costs = {u: 1. + i * 1000 for i, u in enumerate(scores)}
        result = self.evaluate(scores, ['u0', 'u1'], costs)
        self.assertEqual(result['work_bound'], 1024)
        self.assertEqual(result['positive_count'], 2)
        lower, upper = result['raw_cost_bounds']
        self.assertLessEqual(lower, result['complete_first_hit_cost'])
        self.assertLessEqual(result['complete_first_hit_cost'], upper)
        self.assertGreater(result['cost_score_gradient']['u2'], 0.)
        self.assertTrue(math.isclose(math.fsum(result['cost_score_gradient'].values()), 0., abs_tol=1e-6))

    def test_gate_and_unknown_scope(self):
        for gate in (False, None, 1, 'true'):
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY_GATE'):
                kernel.evaluate({'a': 0.}, ['a'], {'a': 1.}, synthetic_only=gate)
        with self.assertRaises(TypeError):
            kernel.evaluate({'a': 0.}, ['a'], {'a': 1.}, synthetic_only=True, scope='real')
        result = self.evaluate({'a': 0.}, ['a'], {'a': 1.})
        self.assertIn('NOT_TRAINER', result['status'])
        self.assertEqual(result['scope'], 'synthetic_multi_positive_fixed_additive_costs_only')
        for field in ('online_cost_replay', 'training_estimator_implemented', 'model_fitting_implemented',
                      'stochastic_estimator_implemented', 'r_at_k_computed', 'normalization_derivative_taken'):
            self.assertFalse(result[field])

    def test_hostile_inputs(self):
        class Numeric(float):
            pass
        for value in (True, False, float('nan'), float('inf'), -float('inf'), '0', Numeric(0), 10 ** 1000):
            with self.subTest(score=type(value)):
                with self.assertRaises(ValueError):
                    self.evaluate({'a': value}, ['a'], {'a': 1.})
        for value in (True, False, 0., -1., float('nan'), float('inf'), 1e9 + 1., '1', Numeric(1), 10 ** 1000):
            with self.assertRaises(ValueError):
                self.evaluate({'a': 0.}, ['a'], {'a': value})
        for positives in ([], (), set(), ['a', 'a'], ['b'], [True], [[]], 'a', {'a': 0}):
            with self.assertRaises(ValueError):
                self.evaluate({'a': 0.}, positives, {'a': 1.})
        for scores, costs in (({}, {}), ({'bad uid': 0.}, {'bad uid': 1.}),
                               ({True: 0.}, {True: 1.}), ({'a': 0.}, {'b': 1.}),
                               ({'a': 20.01}, {'a': 1.}), ({'a': -20.01}, {'a': 1.})):
            with self.assertRaises(ValueError):
                self.evaluate(scores, ['a'], costs)
        scores = {f'u{i}': 0. for i in range(1025)}
        with self.assertRaises(ValueError):
            self.evaluate(scores, ['u0'], dict.fromkeys(scores, 1.))

    def test_conservative_tiny_cost_rejection(self):
        with self.assertRaisesRegex(ValueError, 'NUMERIC_REPRESENTABILITY'):
            self.evaluate({'a': -20., 'b': 20.}, ['b'], {'a': 5e-324, 'b': 1.})
        with self.assertRaisesRegex(ValueError, 'NUMERIC_REPRESENTABILITY'):
            self.evaluate({'a': 0., 'b': 0.}, ['a', 'b'], {'a': 5e-324, 'b': 1.})

    def test_dominant_positive_preserves_small_gradient_decimal_oracle(self):
        # Regression: subtracting a rounded mean used to return zero for the
        # dominant expensive positive, despite its real gradient being ~4e-9.
        for scores, costs in (
                ({'a': -20., 'b': 20.}, {'a': 1., 'b': 1e9}),
                ({'a': 20., 'b': -20.}, {'a': 1., 'b': 1e9}),
                ({'a': -20., 'b': 20., 'c': -19.},
                 {'a': 1., 'b': 1e9, 'c': 5.}),
                ({'a': 20., 'b': -20., 'c': -19.},
                 {'a': 1., 'b': 1e9, 'c': 5.})):
            result = self.evaluate(scores, set(scores), costs)
            with localcontext() as context:
                context.prec = 100
                weights = {u: Decimal(str(s)).exp() for u, s in scores.items()}
                total = sum(weights.values())
                mean = sum(Decimal(str(costs[u])) * weights[u] for u in scores) / total
                for u in scores:
                    expected = float(weights[u] / total * (Decimal(str(costs[u])) - mean))
                    self.assertNotEqual(expected, 0.)
                    self.assertTrue(math.isclose(result['cost_score_gradient'][u], expected,
                                                 rel_tol=2e-14, abs_tol=1e-23), u)
                    self.assertTrue(math.isclose(result['normalized_cost_score_gradient'][u],
                                                 expected / result['cost_normalization_B'],
                                                 rel_tol=2e-14, abs_tol=1e-32), u)
            self.assertAlmostEqual(math.fsum(result['cost_score_gradient'].values()),
                                   0., delta=1e-20)


if __name__ == '__main__':
    unittest.main()
