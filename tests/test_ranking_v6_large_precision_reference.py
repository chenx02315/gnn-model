"""Small synthetic reference tests only; never the formal n736 precision run."""
import importlib
import math
import random
import statistics
import unittest
from unittest.mock import patch

from src.models import ranking_v6_large_precision_reference as precision
from src.models import ranking_v6_first_hit_exact_gradient as exact


class LargePrecisionTests(unittest.TestCase):
    def test_closed_form_complete_maps_against_exact_n2_to_n7(self):
        for n in range(2, 8):
            scores = {str(i): 0. for i in range(n)}
            costs = {u: 1. for u in scores}
            for k in sorted({1, min(n, 3), n}):
                closed = precision.uniform_closed_form(n, k)
                oracle = exact.enumerate_exact_gradient(scores, {'0'}, costs, k=k)
                with self.subTest(n=n, k=k):
                    self.assertEqual(closed['survival_probability_by_draw'], [(n-j)/n for j in range(k+1)])
                    for key in ('expected_miss_probability', 'expected_truncated_static_cost'):
                        self.assertAlmostEqual(closed[key], oracle[key], delta=1e-12)
                    for key in ('miss_score_gradient', 'cost_score_gradient'):
                        self.assertEqual(set(closed[key]), set(scores))
                        self.assertAlmostEqual(math.fsum(closed[key].values()), 0., delta=1e-12)
                        for uid in scores:
                            self.assertAlmostEqual(closed[key][uid], oracle[key][uid], delta=1e-12)
                    for uid in scores:
                        self.assertEqual(closed['normalized_cost_score_gradient'][uid],
                                         closed['cost_score_gradient'][uid] / k)
                    if k == n:
                        self.assertEqual(closed['expected_miss_probability'], 0.)
                        self.assertTrue(all(g == 0. for g in closed['miss_score_gradient'].values()))
                        self.assertLess(closed['cost_score_gradient']['0'], 0.)

    def test_closed_form_every_uid_finite_difference_n2_to_n7(self):
        epsilon = 1e-5
        for n in range(2, 8):
            scores, costs = {str(i): 0. for i in range(n)}, {str(i): 1. for i in range(n)}
            k = min(n, 3)
            closed = precision.uniform_closed_form(n, k)
            for uid in scores:
                upper = exact.enumerate_exact_gradient(dict(scores, **{uid: epsilon}), {'0'}, costs, k=k)
                lower = exact.enumerate_exact_gradient(dict(scores, **{uid: -epsilon}), {'0'}, costs, k=k)
                with self.subTest(n=n, k=k, uid=uid):
                    for metric, gradient in [('expected_miss_probability', 'miss_score_gradient'),
                                             ('expected_truncated_static_cost', 'cost_score_gradient')]:
                        difference = (upper[metric]-lower[metric]) / (2*epsilon)
                        self.assertAlmostEqual(closed[gradient][uid], difference, delta=1e-8)

    def test_welford_unbiased_variance_and_radius(self):
        observations = [(1., 2.), (2., 5.), (4., 8.), (7., 3.)]
        moments = precision._Welford(2)
        for row in observations:
            moments.add(row)
        self.assertEqual(moments.count, 4)
        for i in range(2):
            values = [row[i] for row in observations]
            self.assertAlmostEqual(moments.mean[i], statistics.mean(values))
            self.assertAlmostEqual(moments.sample_variance(i), statistics.variance(values))
        log_term = math.log(4*24/.01)
        expected = math.sqrt(2*3*log_term/4) + 7*2*log_term/(3*3)
        self.assertEqual(precision._radius(3., 2., 4, log_term), expected)
        with self.assertRaisesRegex(ValueError, 'VARIANCE_COUNT'):
            precision._Welford(1).sample_variance(0)

    def test_determinism_local_rng_pilot_main_independence_no_increase(self):
        kwargs = dict(n=6, k=3, pilot_samples=4, main_samples=16)
        state = random.getstate()
        with patch.object(precision.streaming, '_sample', wraps=precision.streaming._sample) as sampler:
            first = precision.run_uniform_precision(**kwargs)
            self.assertEqual(sampler.call_count, 4*(4+16))
        second = precision.run_uniform_precision(**kwargs)
        changed = precision.run_uniform_precision(**dict(kwargs, pilot_samples=5))
        self.assertEqual(first, second)
        self.assertEqual(random.getstate(), state)
        self.assertEqual(first['status'], 'INCONCLUSIVE_PRECISION')
        self.assertEqual(first['config']['main_samples'], 16)
        self.assertEqual(first['comparison_count'], 4*(2+2*6))
        self.assertAlmostEqual(first['log_term'], math.log(4*first['comparison_count']/.01))
        for before, after in zip(first['per_seed'], changed['per_seed']):
            self.assertNotEqual(before['derived_seed_sha256']['pilot'], before['derived_seed_sha256']['main'])
            self.assertEqual(before['derived_seed_sha256'], after['derived_seed_sha256'])
            self.assertEqual(before['main_observation_count'], 16)
            self.assertEqual(before['comparison_count'], 14)
            self.assertEqual(before['expected_truncated_static_cost_estimate'],
                             after['expected_truncated_static_cost_estimate'])
            before_rows = before['scalar_and_named_positive_negative_rows'][:2]
            after_rows = after['scalar_and_named_positive_negative_rows'][:2]
            self.assertEqual(before_rows, after_rows)
            self.assertTrue(before['baselines_frozen_before_main'])
        self.assertFalse(first['adaptive_sampling'])
        self.assertFalse(first['trajectories_retained'])
        self.assertFalse(first['generalizes_to_nonuniform_or_real_data'])

    def test_centered_moments_and_conditional_frozen_pilot(self):
        main = [(1, 2., [-.5, .5]), (0, 1., [.5, -.5]), (1, 2., [-.5, .5])]
        def fake_sample(values, positives, costs, k, rng, gradients):
            if not gradients:
                return 1, 2., [0., 0.]
            position = calls[id(rng)]
            calls[id(rng)] += 1
            return main[position]
        from collections import defaultdict
        calls = defaultdict(int)
        with patch.object(precision.streaming, '_sample', side_effect=fake_sample):
            result = precision.run_uniform_precision(n=2, k=2, pilot_samples=2, main_samples=3)
        for seed in result['per_seed']:
            self.assertEqual(seed['baseline_risk'], 1.)
            self.assertEqual(seed['baseline_normalized_cost'], 1.)
            for row in seed['scalar_and_named_positive_negative_rows']:
                if row['metric'] in ('miss_probability', 'normalized_cost'):
                    data = [r if row['metric'] == 'miss_probability' else c/2 for r, c, _ in main]
                else:
                    index = int(row['uid'])
                    data = [((r-1.) if row['metric'] == 'miss_score_gradient' else (c/2-1.))*g[index]
                            for r, c, g in main]
                self.assertAlmostEqual(row['estimate'], statistics.mean(data))
                self.assertAlmostEqual(row['sample_variance'], statistics.variance(data))

    def test_invalid_config_before_rng_hash_or_sampling(self):
        base = dict(n=6, k=3, pilot_samples=2, main_samples=4)
        mutations = [dict(n=True), dict(n=1), dict(n=1025), dict(k=True), dict(k=0), dict(k=7),
                     dict(n=20, k=11), dict(seeds=(11, 29, 47)), dict(seeds=(11, 29, 47, 84)),
                     dict(pilot_samples=True), dict(pilot_samples=0), dict(pilot_samples=65537),
                     dict(main_samples=1), dict(main_samples=True), dict(main_samples=65537),
                     dict(alpha=0), dict(alpha=float('nan')), dict(alpha=True), dict(alpha=1.1),
                     dict(max_radius=0), dict(max_radius=float('inf')), dict(max_radius=True),
                     dict(n=736, k=10, pilot_samples=64, main_samples=2654)]
        with patch.object(precision.random, 'Random', side_effect=AssertionError('RNG')), \
                patch.object(precision.streaming, '_seed_pin', side_effect=AssertionError('hash')), \
                patch.object(precision.streaming, '_sample', side_effect=AssertionError('sample')):
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    precision.run_uniform_precision(**dict(base, **mutation))

    def test_fail_precedes_insufficient_precision_and_every_component_checked(self):
        # Isolate gate logic using a deliberately tightened radius; the
        # actual CI formula is independently tested above, never tuned here.
        with patch.object(precision, '_radius', return_value=.0001):
            result = precision.run_uniform_precision(n=3, k=2, pilot_samples=1,
                                                     main_samples=2, max_radius=.00001)
        self.assertEqual(result['status'], 'FAIL')
        self.assertGreater(result['error_bound_violations'], 0)
        self.assertEqual(result['precision_violations'], result['comparison_count'])
        self.assertEqual(result['comparison_count'], 32)
        for seed in result['per_seed']:
            self.assertEqual(seed['comparison_count'], 8)
            self.assertEqual(seed['groups']['miss_score_gradient']['comparison_count'], 3)
            self.assertEqual(seed['groups']['normalized_cost_score_gradient']['comparison_count'], 3)
            self.assertEqual(len(seed['comparison_sha256']), 64)

    def test_positive_subnormal_alpha_stable_log_bound(self):
        result = precision.run_uniform_precision(n=2, k=1, pilot_samples=1,
                                                 main_samples=2, alpha=5e-324)
        self.assertTrue(math.isfinite(result['log_term']))
        self.assertEqual(result['status'], 'INCONCLUSIVE_PRECISION')

    def test_import_and_tiny_execution_no_io(self):
        with patch('builtins.open', side_effect=AssertionError('file IO')), \
                patch('os.open', side_effect=AssertionError('file IO')), \
                patch('socket.socket', side_effect=AssertionError('network IO')), \
                patch('subprocess.Popen', side_effect=AssertionError('process IO')):
            with patch.object(precision.random, 'Random', side_effect=AssertionError('import RNG')), \
                    patch.object(precision.streaming, '_sample', side_effect=AssertionError('import sample')):
                importlib.reload(precision)
            result = precision.run_uniform_precision(n=18, k=2, pilot_samples=1, main_samples=2)
        self.assertEqual(result['config']['positive_uid'], '17')
        self.assertEqual(result['comparison_count'], 4*(2+2*18))
        self.assertEqual(result['status'], 'INCONCLUSIVE_PRECISION')
        self.assertFalse(result['real_data_access'])
        self.assertFalse(result['trainer_implemented'])


if __name__ == '__main__':
    unittest.main()
