"""Small exhaustive oracle checks only; no Monte Carlo or formal run."""
import inspect
import itertools
import math
import random
import unittest
from unittest import mock

from src.models import ranking_v6_conditional_control_reference as control
from src.models import ranking_v6_conditional_survival_reference as frozen
from src.models import ranking_v6_first_hit_exact_gradient as full
from src.models import ranking_v6_prior_cost_ranges as prior


def _full_pl_normalized_gradient(scores, costs, k, scale):
    """Independent full-PL prefix oracle allowing zero charges.

    The legacy full oracle rejects zero costs. Enumerate full action prefixes,
    charge through first positive, and differentiate their full-PL likelihood.
    This oracle is only used in tests, never to construct PRIOR envelopes.
    """
    uids = sorted(scores)
    shift = max(scores.values())
    weights = {u: math.exp(scores[u] - shift) for u in uids}
    terms = {u: [] for u in uids}
    for order in itertools.permutations(uids, k):
        remaining, logq = list(uids), {u: 0. for u in uids}
        probability, cost, hit = 1., 0., False
        for chosen in order:
            total = math.fsum(weights[u] for u in remaining)
            probability *= weights[chosen] / total
            for u in remaining:
                logq[u] += int(u == chosen) - weights[u] / total
            remaining.remove(chosen)
            if not hit:
                cost += costs[chosen] / scale
                hit = chosen == 'p'
        for u in uids:
            terms[u].append(probability * cost * logq[u])
    return {u: math.fsum(terms[u]) for u in uids}


class PriorCostRangeTests(unittest.TestCase):
    def check_orders(self, scores, costs, k, bc):
        result = prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
            k=k, normalized_cost_baseline=bc)
        prepared = frozen._validate(scores, {'p'}, costs, k, 7)
        scale = result['cost_normalization_B']
        totals = [0.] * len(scores)
        c = result['constants']
        for order in itertools.permutations(prepared[4], k):
            parts = control._components(*prepared[1:], k, order=order)
            values = control._controlled(parts, .5, bc * scale)
            flo, fhi = c['normalized_cost_range']
            self.assertTrue(flo - 1e-12 <= parts[2] / scale <= fhi + 1e-12)
            for i, uid in enumerate(prepared[0]):
                lo, hi = result['normalized_cost_score_gradient_ranges'][uid]
                g = values[4][i] / scale
                self.assertTrue(lo <= g <= hi, (scores, costs, k, bc, order, uid, lo, g, hi))
                dlo, dhi = result['coordinate_derivation'][uid]['direct_derivative_range']
                self.assertTrue(dlo - 1e-12 <= parts[4][i] / scale <= dhi + 1e-12)
                totals[i] += values[0] * g
        oracle = _full_pl_normalized_gradient(scores, costs, k, scale)
        if min(costs.values()) > 0:
            legacy = full.enumerate_exact_gradient(scores, {'p'}, costs, k=k)
            for uid in scores:
                self.assertAlmostEqual(oracle[uid], legacy['cost_score_gradient'][uid] / scale, delta=1e-11)
        for i, uid in enumerate(prepared[0]):
            self.assertAlmostEqual(totals[i], oracle[uid], delta=1e-11)
            lo, hi = result['normalized_cost_score_gradient_ranges'][uid]
            self.assertTrue(lo <= oracle[uid] <= hi)

    def test_exhaustive_variable_costs_scores_and_baselines(self):
        cases = [
            ({'p': -.2, 'a': -.7, 'b': .4, 'c': 1.2}, {'p': 5., 'a': 1., 'b': 9., 'c': .2}),
            ({'p': -20., 'a': -20., 'b': 20., 'c': 0.}, {'p': 1e9, 'a': 0., 'b': 1., 'c': 1e-6}),
            ({'p': 20., 'a': -20., 'b': -19., 'c': -18.}, {'p': 0., 'a': 1e9, 'b': .1, 'c': 8.}),
            ({'p': 0., **{str(i): (i - 3.) * 1.7 for i in range(6)}},
             {'p': 7., **{str(i): (0., .1, 9., 1., 3., 5.)[i] for i in range(6)}}),
            ({'p': .8, 'a': -.3, 'b': -.3, 'c': -.3}, {'p': 2., 'a': 2., 'b': 2., 'c': 2.}),
        ]
        for scores, costs in cases:
            for k in range(1, len(scores)):
                for bc in (0., .5, 1.):
                    with self.subTest(scores=scores, k=k, bc=bc):
                        self.check_orders(scores, costs, k, bc)

    def test_zero_cost_exact_branch(self):
        scores = {'p': -.2, 'a': -.7, 'b': .4, 'c': 1.2}
        costs = {uid: 0. for uid in scores}
        for k in (1, 2, 3):
            self.check_orders(scores, costs, k, 0.)
            result = prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
                k=k, normalized_cost_baseline=0.)
            self.assertTrue(result['all_zero_costs'])
            self.assertEqual(result['cost_upper_bound'], 0.)
            self.assertEqual(result['cost_normalization_B'], 1.)
            self.assertFalse(result['constants']['padding_applied'])
            self.assertTrue(all(pair == [0., 0.] for pair in result['normalized_cost_score_gradient_ranges'].values()))
        for bc in (.5, 1.):
            with self.assertRaisesRegex(ValueError, 'ZERO_COST_BASELINE'):
                prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
                    k=1, normalized_cost_baseline=bc)

    def test_shift_order_and_cost_scale_invariance(self):
        scores = {'p': -.2, 'a': -.7, 'b': .4, 'c': 1.2}
        costs = {'p': 5., 'a': 1., 'b': 9., 'c': .2}
        a = prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
            k=3, normalized_cost_baseline=.5)
        b = prior.prior_normalized_cost_gradient_ranges(
            {u: s + 8 for u, s in reversed(list(scores.items()))}, {'p'},
            {u: c * 100 for u, c in reversed(list(costs.items()))}, k=3, normalized_cost_baseline=.5)
        for uid in scores:
            for x, y in zip(a['normalized_cost_score_gradient_ranges'][uid], b['normalized_cost_score_gradient_ranges'][uid]):
                self.assertAlmostEqual(x, y, delta=1e-12)

    def test_reject_bad_baseline_before_softmax(self):
        for bc in (-.1, 1.1, True, None, float('nan'), float('inf'), 10**1000):
            with mock.patch.object(frozen.math, 'exp') as exp:
                with self.assertRaisesRegex(ValueError, 'NORMALIZED_COST_BASELINE'):
                    prior.prior_normalized_cost_gradient_ranges({'p': 0., 'a': 0.}, {'p'},
                        {'p': 1., 'a': 1.}, k=1, normalized_cost_baseline=bc)
                exp.assert_not_called()

    def test_unsupported_tiny_positive_cost_rejected_before_exp(self):
        # Includes the concrete raw-cost underflow counterexample; it is a
        # rejection test, not claimed successful gradient containment.
        for value in (5e-324, 1e-300, 1e-9, 5e-7, math.nextafter(1e-6, 0.)):
            with self.subTest(cost=value), mock.patch.object(frozen.math, 'exp') as exp:
                with self.assertRaisesRegex(ValueError, 'POSITIVE_COST_BELOW_SUPPORTED_MIN'):
                    prior.prior_normalized_cost_gradient_ranges(
                        {'p': 0., 'a': 0.}, {'p'}, {'p': 0., 'a': value},
                        k=1, normalized_cost_baseline=0.)
                exp.assert_not_called()
        for costs in ({'p': 0., 'a': 1e-6}, {'p': 1e-6, 'a': 0.},
                      {'p': 1e-6, 'a': 1e-6}, {'p': 0., 'a': 1e9}):
            self.check_orders({'p': 0., 'a': 0.}, costs, 1, .5)

    def test_invalid_inputs_rejected_before_softmax(self):
        base = dict(scores={'p': 0., 'a': 0.}, positive_uids={'p'}, costs={'p': 1., 'a': 1.},
                    k=1, normalized_cost_baseline=.5)
        changes = [{'scores': None}, {'scores': {}}, {'scores': {'p': 0., '': 0.}},
                   {'scores': {'p': 0., 1: 0.}}, {'scores': {'p': True, 'a': 0.}},
                   {'scores': {'p': float('nan'), 'a': 0.}},
                   {'scores': {'p': float('inf'), 'a': 0.}}, {'scores': {'p': 20.1, 'a': 0.}},
                   {'costs': None}, {'costs': {'p': 1.}}, {'costs': {'p': 1., 'x': 1.}},
                   {'costs': {'p': -1., 'a': 1.}}, {'costs': {'p': True, 'a': 1.}},
                   {'costs': {'p': float('nan'), 'a': 1.}}, {'costs': {'p': float('inf'), 'a': 1.}},
                   {'costs': {'p': 1e9 + 1., 'a': 1.}}, {'costs': {'p': 10**1000, 'a': 1.}},
                   {'positive_uids': set()}, {'positive_uids': {'p', 'a'}},
                   {'positive_uids': ['p', 'p']}, {'positive_uids': {'x'}}, {'positive_uids': 'p'},
                   {'k': True}, {'k': 0}, {'k': 2}, {'k': 11}]
        for change in changes:
            with self.subTest(keys=list(change)), mock.patch.object(frozen.math, 'exp') as exp:
                with self.assertRaises(ValueError):
                    prior.prior_normalized_cost_gradient_ranges(**dict(base, **change))
                exp.assert_not_called()

    def test_prior_api_zero_rng_and_metadata(self):
        self.assertEqual(set(inspect.signature(prior.prior_normalized_cost_gradient_ranges).parameters),
                         {'scores', 'positive_uids', 'costs', 'k', 'normalized_cost_baseline'})
        scores = {'p': 0., 'a': 0.}
        costs = {'p': 1., 'a': 2.}
        with mock.patch.object(random, 'Random') as rng, mock.patch.object(random, 'random') as draw:
            result = prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
                k=1, normalized_cost_baseline=.5)
            rng.assert_not_called()
            draw.assert_not_called()
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['does_not_release_ci'])
        self.assertFalse(result['confidence_interval_implemented'])
        self.assertFalse(result['rounding_guard_is_formal_proof'])
        self.assertEqual(result['constants']['numerical_padding'], 1e-12)
        self.assertEqual(result['min_positive_cost'], 1e-6)
        self.assertEqual(result['supported_cost_domain'],
                         {'zero_allowed': True, 'min_positive_cost': 1e-6, 'max_cost': 1e9})
        self.assertTrue(all(math.isfinite(x) for pair in result['normalized_cost_score_gradient_ranges'].values() for x in pair))
        for extra in ('main_samples', 'outcomes', 'moments'):
            with self.assertRaises(TypeError):
                prior.prior_normalized_cost_gradient_ranges(scores, {'p'}, costs,
                    k=1, normalized_cost_baseline=.5, **{extra: []})


if __name__ == '__main__':
    unittest.main()
