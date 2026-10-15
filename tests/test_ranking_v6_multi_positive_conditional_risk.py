"""Independent full-PL oracle, numerical derivatives and synthetic boundaries."""
import itertools
from decimal import Decimal, localcontext
import math
import random
import unittest
from unittest import mock

from src.models import ranking_v6_multi_positive_conditional_risk as multi
from src.models import ranking_v6_conditional_survival_reference as singleton
from src.models import ranking_v6_multi_positive_complete_cost as complete_cost
from src.models import ranking_v6_synthetic_real_bridge_adapter as bridge


def full_pl_oracle(scores, positives, k):
    """Enumerate FULL permutations, using independent full-PL log-density.

    Deliberately does not use the conditional implementation or negative-only q.
    """
    uids = tuple(scores)
    weights = {u: math.exp(scores[u]) for u in uids}
    risk, gradient, mass = 0., dict.fromkeys(uids, 0.), 0.
    for order in itertools.permutations(uids):
        remaining = list(uids)
        probability, log_gradient = 1., dict.fromkeys(uids, 0.)
        for chosen in order:
            denominator = math.fsum(weights[u] for u in remaining)
            probability *= weights[chosen] / denominator
            for u in remaining:
                log_gradient[u] -= weights[u] / denominator
            log_gradient[chosen] += 1.
            remaining.remove(chosen)
        mass += probability
        if not set(order[:k]) & set(positives):
            risk += probability
            for u in uids:
                gradient[u] += probability * log_gradient[u]
    return risk, gradient, mass


class MultiPositiveRiskTests(unittest.TestCase):
    def assert_close(self, first, second, delta=2e-11):
        self.assertAlmostEqual(first['mean_risk'], second['mean_risk'], delta=delta)
        self.assertEqual(set(first['uid_gradient']), set(second['uid_gradient']))
        for u in first['uid_gradient']:
            self.assertAlmostEqual(first['uid_gradient'][u], second['uid_gradient'][u], delta=delta)

    def test_independent_full_pl_oracle_multiple_positive_counts_all_k(self):
        scores = {'a': -.7, 'b': .4, 'c': 1.2, 'd': -.2, 'e': -1.1}
        for positives in ({'a'}, {'a', 'd'}, {'b', 'd', 'e'}, set(scores)):
            for k in range(1, 7):
                with self.subTest(positives=positives, k=k):
                    actual = multi.enumerate_exact_gradient(scores, positives, k=k, synthetic_only=True)
                    risk, gradient, mass = full_pl_oracle(scores, positives, k)
                    self.assertAlmostEqual(mass, 1., places=12)
                    self.assert_close(actual, dict(mean_risk=risk, uid_gradient=gradient))

    def test_finite_difference_all_scores(self):
        scores = {'a': -.7, 'b': .4, 'c': 1.2, 'd': -.2, 'e': -1.1}
        for k in (1, 2, 3):
            actual = multi.enumerate_exact_gradient(scores, {'a', 'd'}, k=k, synthetic_only=True)
            for u in scores:
                plus, minus = scores.copy(), scores.copy()
                plus[u] += 1e-6
                minus[u] -= 1e-6
                p = multi.enumerate_exact_gradient(plus, {'a', 'd'}, k=k, synthetic_only=True)['mean_risk']
                m = multi.enumerate_exact_gradient(minus, {'a', 'd'}, k=k, synthetic_only=True)['mean_risk']
                self.assertAlmostEqual(actual['uid_gradient'][u], (p-m)/2e-6, delta=1e-8)

    def test_singleton_matches_legacy_risk(self):
        scores = {'a': -.7, 'b': .4, 'c': 1.2, 'p': -.2}
        costs = dict.fromkeys(scores, 1.)
        for k in (1, 2, 3):
            old = singleton.enumerate_exact_gradient(scores, {'p'}, costs, k=k)
            new = multi.enumerate_exact_gradient(scores, {'p'}, k=k, synthetic_only=True)
            self.assert_close(new, dict(mean_risk=old['expected_miss_probability'],
                                        uid_gradient=old['miss_score_gradient']))

    def test_positive_derivatives_survive_rounded_mass(self):
        result = multi.enumerate_exact_gradient({'a': 20., 'p': -20., 'q': -19.},
                                                {'p', 'q'}, k=1, synthetic_only=True)
        for u in ('p', 'q'):
            self.assertLess(result['uid_gradient'][u], 0.)
            self.assertAlmostEqual(result['uid_gradient'][u] / -math.exp(
                (-20. if u == 'p' else -19.) - 20.), 1., places=12)

    def test_decimal100_extreme_full_pl_gradient_oracle(self):
        cases = [({'n': 20., 'p': -20.}, {'p'}, 1),
                 ({'n': -20., 'p': 20.}, {'p'}, 1),
                 ({'n': 20., 'p': -20., 'q': -19.}, {'p', 'q'}, 1),
                 ({'n': 20., 'm': -20., 'p': -19.}, {'p'}, 2),
                 ({'n': 20., 'm': 19., 'p': -20., 'q': -19.}, {'p', 'q'}, 2)]
        for scores, positives, k in cases:
            with self.subTest(scores=scores, k=k), localcontext() as context:
                context.prec = 100
                weights = {u: Decimal(str(s)).exp() for u, s in scores.items()}
                risk, gradient = Decimal(0), dict.fromkeys(scores, Decimal(0))
                for order in itertools.permutations(scores):
                    remaining = list(scores)
                    probability = Decimal(1)
                    log_gradient = dict.fromkeys(scores, Decimal(0))
                    for chosen in order:
                        denominator = sum((weights[u] for u in remaining), Decimal(0))
                        probability *= weights[chosen] / denominator
                        for u in remaining:
                            log_gradient[u] -= weights[u] / denominator
                        log_gradient[chosen] += 1
                        remaining.remove(chosen)
                    if not set(order[:k]) & positives:
                        risk += probability
                        for u in scores:
                            gradient[u] += probability * log_gradient[u]
                actual = multi.enumerate_exact_gradient(scores, positives, k=k, synthetic_only=True)
                self.assertEqual(actual['arithmetic'], 'decimal80_reference')
                self.assertAlmostEqual(actual['mean_risk'], float(risk), delta=2e-14)
                for u in scores:
                    expected = float(gradient[u])
                    self.assertAlmostEqual(actual['uid_gradient'][u], expected,
                                           delta=max(abs(expected)*2e-12, 1e-30))
                if len(scores) == 2:
                    sampled = multi.estimate(scores, positives, k=k, seed=0,
                                             samples=4, synthetic_only=True)
                    self.assert_close(actual, sampled, delta=1e-30)

    def test_explicit_opt_in_required_before_rng(self):
        with mock.patch.object(multi.random, 'Random', side_effect=AssertionError('RNG')):
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY'):
                multi.estimate({'n': 0., 'p': 0.}, {'p'}, k=1, seed=0)
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY'):
                multi.enumerate_exact_gradient({'n': 0., 'p': 0.}, {'p'}, k=1)

    def test_uid_domain_matches_complete_cost_and_bridge(self):
        for uid in ('a', '_', '.', '-', '.first', '-first', 'A_0.z-9', 'x'*64):
            bridge._identifier(uid)
            scores = {uid: 0., 'positive': 0.}
            complete_cost.evaluate(scores, {'positive'}, dict.fromkeys(scores, 1.), synthetic_only=True)
            multi.estimate(scores, {'positive'}, k=1, seed=0, samples=1, synthetic_only=True)
        for uid in ('', 'x'*65, 'a:b', 'bad/uid', 'bad\n', '中文'):
            with self.subTest(uid=uid):
                with self.assertRaises(ValueError):
                    bridge._identifier(uid)
                scores = {uid: 0., 'positive': 0.}
                with self.assertRaises(ValueError):
                    complete_cost.evaluate(scores, {'positive'}, dict.fromkeys(scores, 1.), synthetic_only=True)
                with self.assertRaises(ValueError):
                    multi.estimate(scores, {'positive'}, k=1, seed=0, samples=1, synthetic_only=True)

    def test_extreme_exact_risk_range_all_small_sizes(self):
        for n in range(2, 8):
            scores = {str(i): (-20. if i == 0 else 20.) for i in range(n)}
            for k in range(1, n):
                with self.subTest(n=n, k=k):
                    result = multi.enumerate_exact_gradient(scores, {'0'}, k=k, synthetic_only=True)
                    self.assertTrue(0. <= result['mean_risk'] <= 1.)
                    self.assertLess(result['uid_gradient']['0'], 0.)

    def test_guaranteed_hit_zero_without_rng_and_nominal_budget(self):
        for scores, positives, k in [({'p': 0.}, {'p'}, 10),
                                     ({'a': 0., 'p': 1., 'q': 2.}, {'p', 'q'}, 2)]:
            with mock.patch.object(multi.random, 'Random', side_effect=AssertionError('RNG')):
                result = multi.estimate(scores, positives, k=k, seed=7, samples=8, synthetic_only=True)
                exact = multi.enumerate_exact_gradient(scores, positives, k=k, synthetic_only=True)
            self.assertTrue(result['guaranteed_hit'])
            self.assertEqual(result['trajectory_count'], 0)
            self.assertEqual(result['mean_risk'], 0.)
            self.assertEqual(result['uid_gradient'], dict.fromkeys(scores, 0.))
            self.assertEqual(result['nominal_work'], len(scores)*k*8)
            self.assert_close(result, exact)

    def test_permutation_shift_and_zero_gradient_sum(self):
        scores = {'a': -3., 'b': 2., 'p': .1, 'q': 1., 'c': -.6}
        permuted = dict(reversed(tuple(scores.items())))
        shifted = {u: s+5 for u, s in scores.items()}
        for call, options in [(multi.estimate, dict(seed=31, samples=64)),
                               (multi.enumerate_exact_gradient, {})]:
            first = call(scores, {'p', 'q'}, k=2, synthetic_only=True, **options)
            self.assertEqual(first, call(permuted, ['q', 'p'], k=2, synthetic_only=True, **options))
            self.assert_close(first, call(shifted, {'p', 'q'}, k=2, synthetic_only=True, **options))
            self.assertAlmostEqual(math.fsum(first['uid_gradient'].values()), 0., delta=2e-12)

    def test_proposal_term_is_material(self):
        prepared = multi._validate({'a': -.7, 'b': .4, 'p': -.2, 'q': .8},
                                   {'p', 'q'}, 2, True, 7)
        _, weights, positives, negatives = prepared
        _, survival, gradient = multi._trajectory(weights, positives, negatives, 2,
                                                  order=tuple(negatives))
        a, b = negatives
        proposal = weights[b]/(weights[a]+weights[b])
        self.assertGreater(abs(survival * proposal), .001)
        # Conditional derivative alone is positive for a; full sample also
        # includes the nonzero proposal term above.
        self.assertGreater(gradient[a], survival * proposal)

    def test_stable_sample_gradient_equals_explicit_product_recursion(self):
        scores = {'a': -.7, 'b': .4, 'p': -.2, 'q': .8, 'c': -1.1}
        _, weights, positives, negatives = multi._validate(scores, {'p', 'q'}, 2, True, 7)
        for order in itertools.permutations(negatives, 2):
            n = len(weights)
            remaining = list(negatives)
            p = math.fsum(weights[i] for i in positives)
            survival, ds, logq = 1., [0.]*n, [0.]*n
            for chosen in order:
                a = math.fsum(weights[i] for i in remaining)
                r, hit = a/(a+p), p/(a+p)
                dr = [0.]*n
                for i in remaining:
                    dr[i] = r*hit*weights[i]/a
                    logq[i] -= weights[i]/a
                for i in positives:
                    dr[i] = -r*hit*weights[i]/p
                logq[chosen] += 1.
                ds = [ds[i]*r + survival*dr[i] for i in range(n)]
                survival *= r
                remaining.remove(chosen)
            _, actual_risk, actual_gradient = multi._trajectory(weights, positives,
                                                                 negatives, 2, order=order)
            self.assertAlmostEqual(actual_risk, survival, places=14)
            for i in range(n):
                self.assertAlmostEqual(actual_gradient[i], ds[i]+survival*logq[i], places=14)

    def test_invalid_schema_rejected_before_rng(self):
        class DerivedInt(int):
            pass

        class DerivedFloat(float):
            pass

        base = dict(scores={'a': 0., 'p': 0.}, positive_uids={'p'}, k=1, seed=3, synthetic_only=True)
        invalid = [dict(synthetic_only=v) for v in (False, None, 1, 'true')]
        invalid += [dict(scores=v) for v in ({}, {'p': True}, {'p': DerivedInt(0)},
                    {'p': DerivedFloat(0.)}, {'p': float('nan')}, {'p': float('inf')},
                    {'p': 21}, {'p': 10**1000}, {'bad/uid': 0}, {'a'*65: 0},
                    {'bad\n': 0}, {'a:b': 0}, {str(i): 0 for i in range(1025)})]
        invalid += [dict(positive_uids=v) for v in ([], ['p', 'p'], ['x'], [True], 'p')]
        invalid += [dict(k=v) for v in (True, 0, 11, 1.0, DerivedInt(1))]
        invalid += [dict(samples=v) for v in (True, 0, 65537, 1.0)]
        invalid += [dict(seed=v) for v in (True, -1, 2**32, 1.0)]
        with mock.patch.object(multi.random, 'Random', side_effect=AssertionError('RNG')):
            for override in invalid:
                with self.subTest(override=repr(override)[:100]):
                    with self.assertRaises(ValueError):
                        multi.estimate(**(base | override))

    def test_exact_schema_gate_and_size(self):
        for overrides in (dict(synthetic_only=False), dict(k=True),
                          dict(positive_uids=[]), dict(scores={str(i): 0. for i in range(8)},
                                                       positive_uids={'0'})):
            with self.assertRaises(ValueError):
                multi.enumerate_exact_gradient(**(dict(scores={'a': 0., 'p': 0.},
                                                        positive_uids={'p'}, k=1, synthetic_only=True) | overrides))

    def test_work_cap_even_guaranteed_hit_before_rng(self):
        scores = {str(i): 0. for i in range(1024)}
        with mock.patch.object(multi.random, 'Random', side_effect=AssertionError('RNG')):
            for positives in ({'0'}, set(scores)):
                with self.assertRaisesRegex(ValueError, 'WORK_BOUND'):
                    multi.estimate(scores, positives, k=10, seed=0, samples=1954, synthetic_only=True)

    def test_large_determinism_only_not_accuracy_evidence(self):
        scores = {f'u{i}': ((i % 31)-15)/3 for i in range(736)}
        positives = {'u0', 'u301', 'u735'}
        before = random.getstate()
        first = multi.estimate(scores, positives, k=10, seed=2**32-1, samples=4, synthetic_only=True)
        self.assertEqual(first, multi.estimate(scores, positives, k=10, seed=2**32-1, samples=4, synthetic_only=True))
        self.assertEqual(random.getstate(), before)
        self.assertEqual(first['nominal_work'], 736*10*4)
        self.assertEqual(first['trajectory_count'], 4)
        self.assertEqual(first['positive_count'], 3)
        self.assertEqual(first['arithmetic'], 'binary64_monte_carlo')
        for flag in ('positive_stopping_integrated', 'proposal_score_term_included'):
            self.assertTrue(first[flag])
        for flag in ('trainer_implemented', 'online_cost_replay', 'real_data_access',
                     'trajectories_retained'):
            self.assertFalse(first[flag])
        self.assertTrue(all(math.isfinite(v) for v in first['uid_gradient'].values()))

    def test_maximum_n_and_sample_boundaries(self):
        scores = {str(i): 0. for i in range(1024)}
        result = multi.estimate(scores, {'0', '1'}, k=10, seed=0, samples=4, synthetic_only=True)
        self.assertEqual(result['action_count'], 1024)
        guaranteed = multi.estimate({'p': 0.}, {'p'}, k=1, seed=0, samples=65536, synthetic_only=True)
        self.assertEqual(guaranteed['trajectory_count'], 0)
        exact = multi.enumerate_exact_gradient({str(i): 0. for i in range(7)}, {'0'}, k=6, synthetic_only=True)
        self.assertEqual(exact['trajectory_count'], 720)


if __name__ == '__main__':
    unittest.main()
