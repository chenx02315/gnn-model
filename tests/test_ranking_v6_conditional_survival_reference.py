"""Independent full-PL oracle, derivatives and fail-before-RNG boundaries."""
import math
import unittest
from unittest import mock

from src.models import ranking_v6_conditional_survival_reference as conditional
from src.models import ranking_v6_first_hit_exact_gradient as full


class ConditionalSurvivalTests(unittest.TestCase):
    def assert_matches(self, result, expected, delta=2e-11):
        for key in ('expected_miss_probability', 'expected_truncated_static_cost'):
            self.assertAlmostEqual(result[key], expected[key], delta=delta)
        for key in ('miss_score_gradient', 'cost_score_gradient'):
            self.assertEqual(set(result[key]), set(expected[key]))
            for uid in result[key]:
                self.assertAlmostEqual(result[key][uid], expected[key][uid], delta=delta)

    def test_nonuniform_varying_cost_full_pl_oracle_all_k(self):
        scores = {'a': -.7, 'b': .4, 'c': 1.2, 'hit': -.2, 'd': -1.1}
        costs = {'a': 1., 'b': 9., 'c': .2, 'hit': 5., 'd': 2.}
        for k in range(1, 5):
            with self.subTest(k=k):
                result = conditional.enumerate_exact_gradient(scores, {'hit'}, costs, k=k)
                expected = full.enumerate_exact_gradient(scores, {'hit'}, costs, k=k)
                self.assert_matches(result, expected)
                self.assertAlmostEqual(result['probability_mass'], 1., places=13)
                self.assertEqual(result['trajectory_count'], math.perm(4, k))

    def test_finite_differences_all_uids_both_objectives(self):
        scores = {'a': -.7, 'b': .4, 'c': 1.2, 'hit': -.2}
        costs = {'a': 1., 'b': 9., 'c': .2, 'hit': 5.}
        for k in (1, 2, 3):
            result = conditional.enumerate_exact_gradient(scores, {'hit'}, costs, k=k)
            for uid in scores:
                plus, minus = scores.copy(), scores.copy()
                plus[uid] += 1e-6
                minus[uid] -= 1e-6
                p = conditional.enumerate_exact_gradient(plus, {'hit'}, costs, k=k)
                m = conditional.enumerate_exact_gradient(minus, {'hit'}, costs, k=k)
                for objective, gradient in [('expected_miss_probability', 'miss_score_gradient'),
                                             ('expected_truncated_static_cost', 'cost_score_gradient')]:
                    self.assertAlmostEqual(result[gradient][uid],
                                           (p[objective] - m[objective]) / 2e-6, delta=1e-7)

    def test_shift_invariance_and_gradient_sum_zero(self):
        scores = {'a': -3., 'b': 2., 'c': .1, 'hit': 1.}
        costs = {'a': 1., 'b': 2., 'c': 3., 'hit': 5.}
        shifted = {uid: value + 8. for uid, value in scores.items()}
        for call, options in [(conditional.enumerate_exact_gradient, {}),
                              (conditional.estimate, {'seed': 7, 'samples': 20})]:
            result = call(scores, {'hit'}, costs, k=2, **options)
            other = call(shifted, {'hit'}, costs, k=2, **options)
            self.assert_matches(result, other)
            for key in ('miss_score_gradient', 'cost_score_gradient'):
                self.assertAlmostEqual(math.fsum(result[key].values()), 0., delta=2e-12)

    def test_seven_action_and_extreme_moderate_scores(self):
        scores = {str(i): (20. if i % 2 else -20.) for i in range(7)}
        costs = {uid: float(int(uid) + 1) for uid in scores}
        result = conditional.enumerate_exact_gradient(scores, {'0'}, costs, k=6)
        expected = full.enumerate_exact_gradient(scores, {'0'}, costs, k=6)
        self.assert_matches(result, expected)
        self.assertEqual(result['trajectory_count'], 720)

    def test_zero_costs_and_one_step_hit_charged(self):
        scores, costs = {'n': 0., 'p': 0.}, {'n': 2., 'p': 10.}
        result = conditional.estimate(scores, {'p'}, costs, k=1, seed=3, samples=1)
        self.assert_matches(result, full.enumerate_exact_gradient(scores, {'p'}, costs, k=1))
        result = conditional.estimate(scores, {'p'}, {'n': 0., 'p': 0.},
                                      k=1, seed=3, samples=1)
        self.assertEqual(result['expected_truncated_static_cost'], 0.)
        self.assertEqual(result['cost_score_gradient'], {'n': 0., 'p': 0.})

    def test_proposal_derivative_is_material(self):
        prepared = conditional._validate({'a': -.7, 'b': .4, 'hit': -.2},
                                          {'hit'}, {'a': 1., 'b': 9., 'hit': 5.}, 2, 7)
        weights = prepared[1]
        a, b = prepared[4]
        value = conditional._trajectory(*prepared[1:], 2, order=(a, b))
        # q picks the first negative with w_a/(w_a+w_b); its score derivative
        # is nonzero. Omitting F*dlogq changes both returned gradients.
        proposal_a = 1. - weights[a] / (weights[a] + weights[b])
        self.assertGreater(abs(value[1] * proposal_a), .01)
        self.assertGreater(abs(value[2] * proposal_a), .1)

    def test_deterministic_local_rng_and_flags(self):
        scores, costs = {'a': -.4, 'b': .3, 'p': -2.}, {'a': 1., 'b': 8., 'p': 3.}
        first = conditional.estimate(scores, {'p'}, costs, k=2, seed=31, samples=30)
        self.assertEqual(first, conditional.estimate(scores, {'p'}, costs, k=2, seed=31, samples=30))
        self.assertTrue(first['proposal_score_term_included'])
        self.assertFalse(first['trajectories_retained'])
        self.assertFalse(first['trainer_implemented'])
        self.assertFalse(first['real_data_access'])

    def test_reject_domains_before_rng(self):
        base = dict(scores={'a': 0., 'b': 0., 'p': 0.}, positive_uids={'p'},
                    costs={'a': 1., 'b': 2., 'p': 3.}, k=2, seed=1, samples=1)
        changes = [{'positive_uids': set()}, {'positive_uids': {'a', 'p'}},
                   {'positive_uids': ['p', 'p']}, {'positive_uids': {'missing'}},
                   {'k': 3}, {'k': 0}, {'k': 11}, {'k': True},
                   {'samples': 0}, {'samples': 65537}, {'samples': True},
                   {'seed': -1}, {'seed': 2**32}, {'seed': True},
                   {'costs': {'a': 1., 'b': 2.}}]
        for bad in (True, float('inf'), float('nan'), 20.1, -20.1, 10**1000):
            changes.append({'scores': dict(base['scores'], a=bad)})
        for bad in (True, float('inf'), float('nan'), -1., 1e9 + 1, 10**1000):
            changes.append({'costs': dict(base['costs'], a=bad)})
        large = {str(i): 0. for i in range(1025)}
        changes.append({'scores': large, 'costs': {u: 1. for u in large}, 'positive_uids': {'0'}})
        within = {str(i): 0. for i in range(1024)}
        changes.append({'scores': within, 'costs': {u: 1. for u in within},
                        'positive_uids': {'0'}, 'k': 10, 'samples': 1954})
        for change in changes:
            with self.subTest(keys=list(change)), mock.patch.object(conditional.random, 'Random') as rng:
                with self.assertRaises(ValueError):
                    conditional.estimate(**dict(base, **change))
                rng.assert_not_called()

    def test_1024_boundary_tiny_smoke(self):
        scores = {str(i): float(i % 3) - 1. for i in range(1024)}
        result = conditional.estimate(scores, {'0'}, {u: 1. for u in scores},
                                      k=10, seed=8, samples=1)
        self.assertEqual(result['work_bound'], 10240)
        self.assertEqual(len(result['miss_score_gradient']), 1024)
        self.assertTrue(0 <= result['expected_miss_probability'] <= 1)
        self.assertAlmostEqual(math.fsum(result['miss_score_gradient'].values()), 0., delta=1e-12)


if __name__ == '__main__':
    unittest.main()
