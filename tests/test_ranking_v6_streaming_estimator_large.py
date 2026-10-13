"""Synthetic-only v2 large-domain checks; no formal n736 runtime smoke."""
import hashlib
import json
import random
import unittest
from unittest.mock import patch

from src.models import ranking_v6_streaming_estimator as old
from src.models import ranking_v6_streaming_estimator_large as streaming
from src.models import ranking_v6_first_hit_exact_gradient as exact


class LargeStreamingTests(unittest.TestCase):
    def test_deterministic_local_rng_and_phase_pins(self):
        scores, costs = {'a': 0., 'hit': .5}, {'a': 1., 'hit': 5.}
        state = random.getstate()
        kwargs = dict(k=2, seed=11, case_id='determinism', pilot_samples=32, main_samples=128)
        first = streaming.estimate(scores, {'hit'}, costs, **kwargs)
        second = streaming.estimate(dict(reversed(list(scores.items()))), {'hit'}, costs, **kwargs)
        self.assertEqual(first, second)
        self.assertEqual(random.getstate(), state)
        self.assertNotEqual(first['derived_seed_sha256']['pilot'], first['derived_seed_sha256']['main'])
        for phase in ('pilot', 'main'):
            raw = json.dumps(['v6-synthetic-stream-v2-large-domain', 11, 'determinism', phase],
                             separators=(',', ':'), ensure_ascii=True).encode('ascii')
            self.assertEqual(first['derived_seed_sha256'][phase], hashlib.sha256(raw).hexdigest())
            self.assertNotEqual(first['derived_seed_sha256'][phase], old._seed_pin(11, 'determinism', phase))
        changed = streaming.estimate(scores, {'hit'}, costs, **dict(kwargs, pilot_samples=33))
        self.assertEqual(first['derived_seed_sha256'], changed['derived_seed_sha256'])
        self.assertEqual(first['expected_truncated_static_cost'], changed['expected_truncated_static_cost'])
        self.assertEqual(first['expected_miss_probability'], changed['expected_miss_probability'])

    def test_old_small_domain_math_exactly_preserved(self):
        scores, costs = {'a': -.3, 'b': .2, 'hit': .6}, {'a': 1., 'b': 2., 'hit': 4.}
        kwargs = dict(k=2, seed=29, case_id='same-math', pilot_samples=32, main_samples=128)
        result = streaming.estimate(scores, {'hit'}, costs, **kwargs)
        # Align only seed namespace to compare identical trajectories, never
        # monkeypatch a domain/work bound or use the old entrypoint for n>256.
        with patch.object(old, '_seed_pin', streaming._seed_pin):
            expected = old.estimate(scores, {'hit'}, costs, **kwargs)
        expected['seed_derivation'] = result['seed_derivation']
        self.assertEqual(result, expected)

    def test_exact_oracle_four_preregistered_seeds(self):
        scores, costs, positives = {'a': -.3, 'b': .2, 'hit': .6}, {'a': 1., 'b': 2., 'hit': 4.}, {'hit'}
        oracle = exact.enumerate_exact_gradient(scores, positives, costs, k=2)
        # Fixed all-four gate, inherited tolerances, no seed selection.
        for seed in (11, 29, 47, 83):
            result = streaming.estimate(scores, positives, costs, k=2, seed=seed, case_id='small-oracle',
                                        pilot_samples=128, main_samples=4096)
            with self.subTest(seed=seed):
                self.assertAlmostEqual(result['expected_miss_probability'], oracle['expected_miss_probability'], delta=.06)
                self.assertAlmostEqual(result['expected_truncated_static_cost'], oracle['expected_truncated_static_cost'], delta=.15)
                for uid in scores:
                    self.assertAlmostEqual(result['miss_score_gradient'][uid], oracle['miss_score_gradient'][uid], delta=.06)
                    self.assertAlmostEqual(result['cost_score_gradient'][uid], oracle['cost_score_gradient'][uid], delta=.15)
                    self.assertEqual(result['cost_score_gradient'][uid],
                                     result['normalized_cost_score_gradient'][uid] * result['cost_normalization_B'])

    def test_invalid_inputs_before_rng_sampling_or_softmax(self):
        base = dict(scores={'a': 0.}, positive_uids={'a'}, costs={'a': 1.}, k=1,
                    seed=11, case_id='bounds', pilot_samples=1, main_samples=1)
        mutations = [dict(scores={}), dict(scores={str(i): 0. for i in range(1025)},
                                         costs={str(i): 1. for i in range(1025)}, positive_uids=set()),
                     dict(scores={'a': True}), dict(scores={'a': float('nan')}),
                     dict(scores={'a': 20.1}), dict(costs={'a': True}), dict(costs={'a': float('inf')}),
                     dict(costs={'a': 0.}), dict(costs={'a': 1e-7}), dict(costs={'a': 1e9+1}),
                     dict(costs={}), dict(costs={'a': 1., 'b': 2.}), dict(positive_uids={'missing'}),
                     dict(positive_uids=['a', 'a']), dict(k=True), dict(k=0), dict(k=11),
                     dict(seed=True), dict(seed=-1), dict(seed=2**32), dict(case_id='中文'),
                     dict(case_id=''), dict(case_id='a'*65), dict(main_samples=True),
                     dict(main_samples=0), dict(pilot_samples=65537),
                     dict(scores={str(i): 0. for i in range(736)}, costs={str(i): 1. for i in range(736)},
                          positive_uids=set(), k=10, pilot_samples=64, main_samples=2654)]
        with patch.object(streaming.random, 'Random', side_effect=AssertionError('RNG')), \
                patch.object(streaming, '_seed_pin', side_effect=AssertionError('seed derivation')), \
                patch.object(streaming, '_sample', side_effect=AssertionError('sampling')), \
                patch.object(streaming.math, 'exp', side_effect=AssertionError('softmax')):
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    streaming.estimate(**dict(base, **mutation))

    def test_n736_tiny_sample_no_io_and_no_old_entrypoint(self):
        scores = {str(i): 0. for i in range(736)}
        with patch('builtins.open', side_effect=AssertionError('file IO')), \
                patch('os.open', side_effect=AssertionError('file IO')), \
                patch('socket.socket', side_effect=AssertionError('network IO')), \
                patch('subprocess.Popen', side_effect=AssertionError('process IO')), \
                patch.object(old, 'estimate', side_effect=AssertionError('old n256 entrypoint')):
            result = streaming.estimate(scores, {'0'}, {u: 1. for u in scores}, k=10, seed=83,
                                        case_id='tiny-736', pilot_samples=2, main_samples=4)
        self.assertEqual(result['action_count'], 736)
        self.assertEqual(len(result['cost_score_gradient']), 736)
        self.assertEqual(result['work_bound'], 736*10*6)
        self.assertEqual(result['max_work'], 20_000_000)
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['baselines_frozen_before_main'])
        for flag in ('scalar_loss_implemented', 'trainer_implemented', 'real_data_access',
                     'online_cost_replay', 'trajectories_retained'):
            self.assertFalse(result[flag])
        with self.assertRaisesRegex(ValueError, 'SCORES_SCHEMA'):
            old.estimate(scores, {'0'}, {u: 1. for u in scores}, k=10, seed=83,
                         case_id='old-bound', pilot_samples=1, main_samples=1)

    def test_all_negative_positive_and_k_exhaustion(self):
        scores, costs = {'a': 0., 'b': 0.}, {'a': 2., 'b': 2.}
        for positives, risk, cost in [(set(), 1., 4.), (set(scores), 0., 2.)]:
            result = streaming.estimate(scores, positives, costs, k=10, seed=29, case_id='constant',
                                        pilot_samples=16, main_samples=64)
            self.assertEqual(result['expected_miss_probability'], risk)
            self.assertEqual(result['expected_truncated_static_cost'], cost)
            self.assertTrue(all(g == 0. for g in result['miss_score_gradient'].values()))
            self.assertTrue(all(g == 0. for g in result['cost_score_gradient'].values()))


if __name__ == '__main__':
    unittest.main()
