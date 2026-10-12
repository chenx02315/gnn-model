"""Fixed-seed bounded synthetic-only estimator checks, never seed selection."""
import random
import tracemalloc
import unittest
from unittest.mock import patch

from src.models import ranking_v6_streaming_estimator as streaming
from src.models import ranking_v6_first_hit_exact_gradient as exact


class StreamingTests(unittest.TestCase):
    def test_deterministic_local_rng_and_phase_pins(self):
        scores, costs = {'a': 0., 'hit': .5}, {'a': 1., 'hit': 5.}
        state = random.getstate()
        kwargs = dict(k=2, seed=11, case_id='determinism', pilot_samples=32, main_samples=128)
        first = streaming.estimate(scores, {'hit'}, costs, **kwargs)
        second = streaming.estimate(dict(reversed(list(scores.items()))), {'hit'}, costs, **kwargs)
        self.assertEqual(first, second)
        self.assertEqual(random.getstate(), state)
        self.assertNotEqual(first['derived_seed_sha256']['pilot'], first['derived_seed_sha256']['main'])
        changed = streaming.estimate(scores, {'hit'}, costs, **dict(kwargs, pilot_samples=33))
        self.assertEqual(first['derived_seed_sha256'], changed['derived_seed_sha256'])
        self.assertEqual(first['expected_truncated_static_cost'], changed['expected_truncated_static_cost'])

    def test_all_negative_and_all_positive(self):
        scores, costs = {'a': 0., 'b': 0.}, {'a': 2., 'b': 2.}
        for positives, risk, cost in [(set(), 1., 4.), (set(scores), 0., 2.)]:
            result = streaming.estimate(scores, positives, costs, k=2, seed=29, case_id='constant',
                                        pilot_samples=16, main_samples=64)
            self.assertEqual(result['expected_miss_probability'], risk)
            self.assertEqual(result['expected_truncated_static_cost'], cost)
            self.assertTrue(all(g == 0. for g in result['miss_score_gradient'].values()))
            self.assertTrue(all(g == 0. for g in result['cost_score_gradient'].values()))

    def test_no_repeated_actions_and_k_exhaustion(self):
        scores, costs = {'a': 20., 'b': -20.}, {'a': 2., 'b': 5.}
        result = streaming.estimate(scores, set(), costs, k=10, seed=47, case_id='exhaustion',
                                    pilot_samples=16, main_samples=64)
        self.assertEqual(result['expected_truncated_static_cost'], 7.)
        first = streaming.estimate(scores, {'a'}, costs, k=1, seed=47, case_id='first',
                                   pilot_samples=16, main_samples=64)
        self.assertEqual(first['expected_truncated_static_cost'], 2.)
        self.assertEqual(first['expected_miss_probability'], 0.)

    def test_exact_oracle_four_preregistered_seeds(self):
        scores, costs, positives = {'a': -.3, 'b': .2, 'hit': .6}, {'a': 1., 'b': 2., 'hit': 4.}, {'hit'}
        oracle = exact.enumerate_exact_gradient(scores, positives, costs, k=2)
        # Fixed all-four gate; no seed selection. Broad finite-sampling tolerances:
        # risk .06, expected cost .15, risk gradient .06, raw cost gradient .15.
        for seed in (11, 29, 47, 83):
            result = streaming.estimate(scores, positives, costs, k=2, seed=seed, case_id='small-oracle',
                                        pilot_samples=128, main_samples=4096)
            with self.subTest(seed=seed):
                self.assertAlmostEqual(result['expected_miss_probability'], oracle['expected_miss_probability'], delta=.06)
                self.assertAlmostEqual(result['expected_truncated_static_cost'], oracle['expected_truncated_static_cost'], delta=.15)
                for uid in scores:
                    self.assertAlmostEqual(result['miss_score_gradient'][uid], oracle['miss_score_gradient'][uid], delta=.06)
                    self.assertAlmostEqual(result['cost_score_gradient'][uid], oracle['cost_score_gradient'][uid], delta=.15)

    def test_invalid_inputs_before_rng_or_sampling(self):
        base = dict(scores={'a': 0.}, positive_uids={'a'}, costs={'a': 1.}, k=1,
                    seed=11, case_id='bounds', pilot_samples=1, main_samples=1)
        mutations = [dict(scores={}), dict(scores={str(i): 0. for i in range(257)}),
                     dict(scores={'a': True}), dict(scores={'a': float('nan')}),
                     dict(scores={'a': 20.1}), dict(costs={'a': True}), dict(costs={'a': float('inf')}),
                     dict(costs={'a': 0.}), dict(costs={'a': 1e-7}), dict(costs={'a': 1e9+1}),
                     dict(costs={}), dict(costs={'a': 1., 'b': 2.}), dict(positive_uids={'missing'}),
                     dict(positive_uids=['a', 'a']), dict(k=True), dict(k=0), dict(k=11),
                     dict(seed=True), dict(seed=-1), dict(seed=2**32), dict(case_id='中文'),
                     dict(case_id=''), dict(case_id='a'*65), dict(main_samples=True),
                     dict(main_samples=0), dict(pilot_samples=65537),
                     dict(scores={str(i): 0. for i in range(256)}, costs={str(i): 1. for i in range(256)},
                          positive_uids=set(), k=10, pilot_samples=65536, main_samples=65536)]
        with patch.object(streaming.random, 'Random', side_effect=AssertionError('RNG')), \
                patch.object(streaming, '_sample', side_effect=AssertionError('sampling')):
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    streaming.estimate(**dict(base, **mutation))

    def test_n256_streaming_memory_and_flags(self):
        scores = {str(i): 0. for i in range(256)}
        tracemalloc.start()
        try:
            result = streaming.estimate(scores, {'0'}, {u: 1. for u in scores}, k=10, seed=83,
                                        case_id='memory-256', pilot_samples=4, main_samples=16)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8*1024*1024)
        self.assertEqual(result['work_bound'], 256*10*20)
        self.assertTrue(result['synthetic_only'])
        for flag in ('scalar_loss_implemented', 'trainer_implemented', 'real_data_access',
                     'online_cost_replay', 'trajectories_retained'):
            self.assertFalse(result[flag])


if __name__ == '__main__':
    unittest.main()
