"""Synthetic control estimator: independent full-PL oracle and stream gates."""
import itertools
import math
import random
import unittest
from unittest import mock

from src.models import ranking_v6_multi_positive_risk_control as control
from src.models import ranking_v6_multi_positive_conditional_risk as raw


def full_pl(scores, positives, k):
    """Full PL permutations and full log-density, no negative-only formulas."""
    weights = {u: math.exp(s) for u, s in scores.items()}
    risk, gradient = 0., dict.fromkeys(scores, 0.)
    for order in itertools.permutations(scores):
        remaining = list(scores)
        probability, log_gradient = 1., dict.fromkeys(scores, 0.)
        for chosen in order:
            denominator = math.fsum(weights[u] for u in remaining)
            probability *= weights[chosen] / denominator
            for u in remaining:
                log_gradient[u] -= weights[u] / denominator
            log_gradient[chosen] += 1.
            remaining.remove(chosen)
        if not set(order[:k]) & set(positives):
            risk += probability
            for u in scores:
                gradient[u] += probability * log_gradient[u]
    return risk, gradient


class RiskControlTests(unittest.TestCase):
    SCORES = {'a': -.7, 'b': .4, 'c': 1.2, 'p': -.2, 'q': -1.1}

    def call(self, **overrides):
        return control.estimate(**(dict(scores=self.SCORES, positive_uids={'p', 'q'},
                                       k=2, seed=83, pilot_samples=7, samples=13,
                                       synthetic_only=True) | overrides))

    def test_fixed_baseline_expectation_full_pl_and_zero_score_expectation(self):
        for positives in ({'p'}, {'p', 'q'}, {'p', 'q', 'a'}):
            for k in range(1, len(self.SCORES) - len(positives) + 1):
                uids, weights, pos, neg = control._validate(self.SCORES, positives, k, True)
                risk, expected = full_pl(self.SCORES, positives, k)
                paths = [control._trajectory(weights, pos, neg, k, order=order)
                         for order in itertools.permutations(neg, k)]
                self.assertAlmostEqual(math.fsum(p for p, _, _, _ in paths), 1., places=14)
                self.assertAlmostEqual(math.fsum(p*s for p, s, _, _ in paths), risk, places=13)
                for i, u in enumerate(uids):
                    self.assertAlmostEqual(math.fsum(p*l[i] for p, _, _, l in paths), 0., places=14)
                    for baseline in (0., .25, .3, .9):
                        gradient = math.fsum(p*(d[i]+(s-baseline)*l[i])
                                             for p, s, d, l in paths)
                        self.assertAlmostEqual(gradient, expected[u], places=13)

    def test_finite_difference_independent_oracle(self):
        uids, weights, pos, neg = control._validate(self.SCORES, {'p', 'q'}, 2, True)
        paths = [control._trajectory(weights, pos, neg, 2, order=order)
                 for order in itertools.permutations(neg, 2)]
        for i, u in enumerate(uids):
            plus, minus = self.SCORES.copy(), self.SCORES.copy()
            plus[u] += 1e-6
            minus[u] -= 1e-6
            numeric = (full_pl(plus, {'p', 'q'}, 2)[0]
                       - full_pl(minus, {'p', 'q'}, 2)[0]) / 2e-6
            actual = math.fsum(p*(d[i]+(s-.3)*l[i]) for p, s, d, l in paths)
            self.assertAlmostEqual(actual, numeric, delta=1e-9)

    def test_extreme_two_actions_tiny_derivatives(self):
        for n, p in ((20., -20.), (-20., 20.)):
            scores = {'n': n, 'p': p}
            actual = self.call(scores=scores, positive_uids={'p'}, k=1)
            reference = raw.enumerate_exact_gradient(scores, {'p'}, k=1, synthetic_only=True)
            self.assertAlmostEqual(actual['mean_risk'], reference['mean_risk'], delta=1e-30)
            for u in scores:
                self.assertNotEqual(actual['uid_gradient'][u], 0.)
                self.assertAlmostEqual(actual['uid_gradient'][u], reference['uid_gradient'][u],
                                       delta=abs(reference['uid_gradient'][u])*1e-13)

    def test_guarantees_no_rng_and_explicit_zero_baseline(self):
        cases = [({'p': 0.}, {'p'}, 10), (self.SCORES, set(self.SCORES), 1),
                 ({'a': 0., 'p': 1., 'q': 2.}, {'p', 'q'}, 2)]
        with mock.patch.object(control.random, 'Random', side_effect=AssertionError('RNG')):
            for scores, positives, k in cases:
                actual = self.call(scores=scores, positive_uids=positives, k=k)
                self.assertTrue(actual['guaranteed_hit'])
                self.assertEqual(actual['mean_risk'], 0.)
                self.assertEqual(actual['uid_gradient'], dict.fromkeys(scores, 0.))
                self.assertEqual(actual['pilot_baseline'], 0.)
                self.assertTrue(actual['structural_zero_baseline'])
                for field in ('trajectory_count', 'main_trajectory_count',
                              'pilot_trajectory_count', 'total_trajectory_count'):
                    self.assertEqual(actual[field], 0)
                self.assertEqual(actual['nominal_work'], len(scores)*k*20)

    def test_pilot_all_paths_frozen_before_main_and_distinct_rng_objects(self):
        original_random, original_path = random.Random, control._trajectory
        objects, events, pilot_values = [], [], []

        def factory(seed):
            events.append(('rng', seed))
            rng = original_random(seed)
            objects.append(rng)
            return rng

        def path(*args, **kwargs):
            result = original_path(*args, **kwargs)
            is_pilot = kwargs['rng'] is objects[0]
            events.append(('path', 'pilot' if is_pilot else 'main'))
            if is_pilot:
                pilot_values.append(result[1])
            return result

        with mock.patch.object(control.random, 'Random', side_effect=factory), \
                mock.patch.object(control, '_trajectory', side_effect=path):
            actual = self.call()
        self.assertEqual(len(objects), 2)
        self.assertIsNot(objects[0], objects[1])
        self.assertEqual(events[:9], [('rng', 83 ^ control.PILOT_SEED_XOR)]
                         + [('path', 'pilot')]*7 + [('rng', 83)])
        self.assertEqual(events[9:], [('path', 'main')]*13)
        self.assertEqual(actual['pilot_baseline'], math.fsum(pilot_values)/7)
        self.assertTrue(actual['baseline_frozen_before_main'])
        self.assertFalse(actual['baseline_main_adaptation'])

    def test_main_stream_change_cannot_change_pilot_baseline(self):
        # Intervene only on main RNG; the public seed binds both domains.
        original_random = random.Random

        def run(main_seed):
            def factory(seed):
                return original_random(main_seed if seed == 83 else seed)
            with mock.patch.object(control.random, 'Random', side_effect=factory):
                return self.call()

        first, second = run(101), run(137)
        self.assertEqual(first['pilot_baseline'], second['pilot_baseline'])
        self.assertNotEqual(first['uid_gradient'], second['uid_gradient'])
        self.assertEqual(self.call(samples=1)['pilot_baseline'], first['pilot_baseline'])

    def test_risk_is_unadjusted_main_mean_and_gradient_direct_formula(self):
        prepared = control._validate(self.SCORES, {'p', 'q'}, 2, True)
        pilot_rng = random.Random(83 ^ control.PILOT_SEED_XOR)
        baseline = math.fsum(control._trajectory(*prepared[1:], 2, rng=pilot_rng)[1]
                             for _ in range(7)) / 7
        main_rng = random.Random(83)
        paths = [control._trajectory(*prepared[1:], 2, rng=main_rng) for _ in range(13)]
        actual = self.call()
        self.assertEqual(actual['mean_risk'], math.fsum(s for _, s, _, _ in paths)/13)
        for i, u in enumerate(prepared[0]):
            expected = math.fsum(d[i]+(s-baseline)*l[i] for _, s, d, l in paths)/13
            self.assertAlmostEqual(actual['uid_gradient'][u], expected, delta=1e-16)

    def test_invalid_types_schema_and_default_gate_before_rng(self):
        class DerivedInt(int):
            pass

        class DerivedFloat(float):
            pass

        class DerivedDict(dict):
            pass

        invalid = [dict(synthetic_only=v) for v in (False, None, 1, 'true')]
        invalid += [dict(scores=v) for v in ({}, DerivedDict(p=0), {'p': True},
                    {'p': DerivedInt(0)}, {'p': DerivedFloat(0)}, {'p': float('nan')},
                    {'p': float('inf')}, {'p': 21}, {'p': 10**1000}, {'bad/uid': 0},
                    {'a'*65: 0}, {'bad\n': 0}, {'a:b': 0}, {'中文': 0},
                    {str(i): 0 for i in range(1025)})]
        invalid += [dict(positive_uids=v) for v in ([], ['p', 'p'], ['x'], [True], 'p')]
        invalid += [dict(k=v) for v in (True, 0, 11, 1., DerivedInt(1))]
        for field in ('samples', 'pilot_samples'):
            invalid += [{field: v} for v in (True, 0, 65537, 1., DerivedInt(1))]
        invalid += [dict(seed=v) for v in (True, -1, 2**32, 1., DerivedInt(1))]
        with mock.patch.object(control.random, 'Random', side_effect=AssertionError('RNG')):
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_ONLY'):
                control.estimate({'n': 0., 'p': 0.}, {'p'}, k=1, seed=0)
            for override in invalid:
                with self.subTest(override=repr(override)[:80]), self.assertRaises(ValueError):
                    self.call(**override)

    def test_work_budget_includes_pilot_even_guaranteed(self):
        scores = {str(i): 0. for i in range(1024)}
        with mock.patch.object(control.random, 'Random', side_effect=AssertionError('RNG')):
            for positives in ({'0'}, set(scores)):
                with self.assertRaisesRegex(ValueError, 'WORK_BOUND'):
                    self.call(scores=scores, positive_uids=positives, k=10,
                              pilot_samples=32, samples=1922)

    def test_uid_shift_permutation_and_gradient_zero_sum(self):
        first = self.call()
        self.assertEqual(first, self.call(scores=dict(reversed(tuple(self.SCORES.items()))),
                                          positive_uids=['q', 'p']))
        shifted = self.call(scores={u: s+5 for u, s in self.SCORES.items()})
        self.assertAlmostEqual(first['mean_risk'], shifted['mean_risk'], places=14)
        for u in self.SCORES:
            self.assertAlmostEqual(first['uid_gradient'][u], shifted['uid_gradient'][u], places=14)
        self.assertAlmostEqual(math.fsum(first['uid_gradient'].values()), 0., places=14)
        for uid in ('_', '.', '-', '.first', '-first', 'A_0.z-9', 'x'*64):
            self.call(scores={uid: 0., 'p': 0.}, positive_uids={'p'}, k=1)

    def test_large_determinism_global_rng_and_flags_only(self):
        scores = {f'u{i}': ((i % 31)-15)/3 for i in range(736)}
        before = random.getstate()
        args = dict(scores=scores, positive_uids={'u0', 'u301', 'u735'}, k=10,
                    seed=2**32-1, pilot_samples=2, samples=3)
        actual = self.call(**args)
        self.assertEqual(actual, self.call(**args))
        self.assertEqual(random.getstate(), before)
        self.assertEqual(actual['nominal_work'], 736*10*5)
        self.assertEqual(actual['total_samples'], 5)
        self.assertEqual(actual['main_trajectory_count'], 3)
        self.assertEqual(actual['pilot_trajectory_count'], 2)
        self.assertEqual(actual['total_trajectory_count'], 5)
        self.assertEqual(actual['expected_miss_probability'], actual['mean_risk'])
        self.assertEqual(actual['miss_score_gradient'], actual['uid_gradient'])
        self.assertTrue(actual['independent_prng_stream_model'])
        for flag in ('trainer_implemented', 'online_cost_replay', 'real_data_access',
                     'trajectories_retained', 'scalar_loss_implemented',
                     'prng_independence_empirically_certified',
                     'confidence_interval_implemented', 'universal_variance_reduction_claim'):
            self.assertFalse(actual[flag])
        self.assertTrue(all(math.isfinite(v) for v in actual['uid_gradient'].values()))

    def test_sample_boundaries_without_sampling_guarantee(self):
        actual = self.call(scores={'p': 0.}, positive_uids={'p'}, k=1,
                           pilot_samples=65536, samples=65536)
        self.assertEqual(actual['total_samples'], 131072)
        self.assertEqual(actual['pilot_seed'], 83 ^ 0x9E3779B9)


if __name__ == '__main__':
    unittest.main()
