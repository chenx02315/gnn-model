"""Enumerate every small negative prefix; no empirical extrema in helper."""
import inspect
import itertools
import math
import random
import unittest
from unittest import mock

from src.models import ranking_v6_conditional_control_reference as control
from src.models import ranking_v6_conditional_survival_reference as frozen
from src.models import ranking_v6_first_hit_exact_gradient as full
from src.models import ranking_v6_prior_risk_ranges as prior


class PriorRiskRangeTests(unittest.TestCase):
    def check_all_trajectories(self, scores, k, br):
        result = prior.prior_risk_gradient_ranges(scores, {'p'}, k=k, risk_baseline=br)
        costs = {uid: float(i + 1) for i, uid in enumerate(scores)}
        prepared = frozen._validate(scores, {'p'}, costs, k, 7)
        totals, mass = [0.] * len(scores), 0.
        c = result['constants']
        for order in itertools.permutations(prepared[4], k):
            parts = control._components(*prepared[1:], k, order=order)
            values = control._controlled(parts, br, 0.)
            self.assertLessEqual(c['Smin'] - 1e-12, parts[1])
            self.assertLessEqual(parts[1], c['Smax'] + 1e-12)
            mass += values[0]
            for i, uid in enumerate(prepared[0]):
                lo, hi = result['risk_score_gradient_ranges'][uid]
                self.assertTrue(lo <= values[3][i] <= hi, (scores, k, br, order, uid, lo, values[3][i], hi))
                totals[i] += values[0] * values[3][i]
                info = result['coordinate_derivation'][uid]
                elo, ehi = info['proposal_gradient_range']
                self.assertTrue(elo - 1e-12 <= parts[5][i] <= ehi + 1e-12)
                if info['role'] == 'negative':
                    self.assertTrue(-1e-12 <= parts[3][i] <= info['D_i'] + 1e-12)
        self.assertAlmostEqual(mass, 1., delta=1e-12)
        oracle = full.enumerate_exact_gradient(scores, {'p'}, costs, k=k)
        for i, uid in enumerate(prepared[0]):
            self.assertAlmostEqual(totals[i], oracle['miss_score_gradient'][uid], delta=1e-11)
            lo, hi = result['risk_score_gradient_ranges'][uid]
            self.assertTrue(lo <= oracle['miss_score_gradient'][uid] <= hi)

    def test_all_permutations_nonuniform_moderate_and_extreme(self):
        cases = [
            {'p': -.2, 'a': -.7, 'b': .4, 'c': 1.2},
            {'p': -20., 'a': -20., 'b': 20., 'c': 0.},
            {'p': 20., 'a': -20., 'b': -19., 'c': -18.},
            {'p': 0., **{str(i): (i - 3.) * 1.7 for i in range(6)}},
        ]
        for scores in cases:
            for k in range(1, len(scores)):
                for br in (0., .5, 1.):
                    with self.subTest(scores=scores, k=k, baseline=br):
                        self.check_all_trajectories(scores, k, br)

    def test_uniform_positive_range_collapses_analytically(self):
        scores = {'p': .8, **{str(i): -.3 for i in range(6)}}
        for k in range(1, 7):
            result = prior.prior_risk_gradient_ranges(scores, {'p'}, k=k, risk_baseline=.5)
            lo, hi = result['unpadded_analytic_ranges']['p']
            self.assertEqual(lo, hi)
            prepared = frozen._validate(scores, {'p'}, {u: 1. for u in scores}, k, 7)
            parts = control._components(*prepared[1:], k, order=prepared[4][:k])
            self.assertAlmostEqual(lo, parts[3][prepared[3][0]], delta=1e-12)
            plo, phi = result['risk_score_gradient_ranges']['p']
            self.assertAlmostEqual(phi - plo, 2e-12, delta=1e-16)

    def test_shift_invariance_and_order_independence(self):
        scores = {'p': -.2, 'a': -.7, 'b': .4, 'c': 1.2}
        a = prior.prior_risk_gradient_ranges(scores, {'p'}, k=3, risk_baseline=.5)
        b = prior.prior_risk_gradient_ranges({u: s + 8 for u, s in reversed(list(scores.items()))},
                                            {'p'}, k=3, risk_baseline=.5)
        for uid in scores:
            for x, y in zip(a['risk_score_gradient_ranges'][uid], b['risk_score_gradient_ranges'][uid]):
                self.assertAlmostEqual(x, y, delta=1e-12)

    def test_baseline_rejected_before_any_softmax(self):
        for br in (-.1, 1.1, True, None, float('nan'), float('inf'), 10**1000):
            with self.subTest(baseline_type=type(br)), mock.patch.object(frozen.math, 'exp') as exp:
                with self.assertRaisesRegex(ValueError, 'PRIOR_RISK_RANGES_RISK_BASELINE'):
                    prior.prior_risk_gradient_ranges({'p': 0., 'a': 0.}, {'p'}, k=1, risk_baseline=br)
                exp.assert_not_called()

    def test_invalid_schema_rejected_before_softmax(self):
        base = dict(scores={'p': 0., 'a': 0.}, positive_uids={'p'}, k=1, risk_baseline=.5)
        changes = [{'scores': None}, {'scores': {}}, {'scores': {'': 0., 'p': 0.}},
                   {'scores': {1: 0., 'p': 0.}}, {'scores': {'p': True, 'a': 0.}},
                   {'scores': {'p': float('nan'), 'a': 0.}},
                   {'scores': {'p': float('inf'), 'a': 0.}},
                   {'scores': {'p': 20.1, 'a': 0.}}, {'scores': {'p': 10**1000, 'a': 0.}},
                   {'positive_uids': set()}, {'positive_uids': {'p', 'a'}},
                   {'positive_uids': ['p', 'p']}, {'positive_uids': {'x'}},
                   {'positive_uids': 'p'}, {'k': True}, {'k': 0}, {'k': 2}, {'k': 11},
                   {'scores': {str(i): 0. for i in range(1025)}, 'positive_uids': {'0'}}]
        for change in changes:
            with self.subTest(change_keys=list(change)), mock.patch.object(frozen.math, 'exp') as exp:
                with self.assertRaises(ValueError):
                    prior.prior_risk_gradient_ranges(**dict(base, **change))
                exp.assert_not_called()

    def test_pure_prior_api_no_rng_no_sample_or_moment_inputs(self):
        self.assertEqual(set(inspect.signature(prior.prior_risk_gradient_ranges).parameters),
                         {'scores', 'positive_uids', 'k', 'risk_baseline'})
        with mock.patch.object(random, 'Random') as rng, mock.patch.object(random, 'random') as draw:
            result = prior.prior_risk_gradient_ranges({'p': 0., 'a': 0.}, {'p'}, k=1, risk_baseline=.5)
            rng.assert_not_called()
            draw.assert_not_called()
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['does_not_release_ci'])
        self.assertFalse(result['confidence_interval_implemented'])
        self.assertFalse(result['rounding_guard_is_formal_proof'])
        self.assertEqual(result['constants']['numerical_padding'], 1e-12)
        self.assertTrue(all(math.isfinite(x) for pair in result['risk_score_gradient_ranges'].values()
                            for x in pair))
        for extra in ('main_samples', 'outcomes', 'moments', 'costs'):
            with self.assertRaises(TypeError):
                prior.prior_risk_gradient_ranges({'p': 0., 'a': 0.}, {'p'}, k=1,
                                                risk_baseline=.5, **{extra: []})


if __name__ == '__main__':
    unittest.main()
