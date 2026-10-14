"""Tiny-count tests only: never invoke the fixed formal precision run."""
import importlib
import itertools
import json
import math
import random
import statistics
import unittest
from unittest.mock import patch

from src.models import ranking_v6_nonuniform_precision_v3 as precision
from src.models import ranking_v6_nonuniform_precision_reference as v1
from src.models import ranking_v6_nonuniform_precision_v2 as v2


class NonuniformPrecisionV3Tests(unittest.TestCase):
    def tiny(self, **kwargs):
        return precision._run_fixed_fixtures(**dict(pilot_samples=3, main_samples=8, **kwargs))

    def test_v3_fresh_namespace_budget_and_no_v1_reclassification(self):
        result = self.tiny()
        config = result['config']
        self.assertEqual(config['method_version'], 3)
        self.assertEqual(config['freshnamespace'], 'nonuniform-precision-v3-')
        self.assertEqual(config['freshnamespace_type'], 'SHA_PIN_CASE_ID_PREFIX')
        self.assertFalse(config['seed_derivation_namespace_changed'])
        self.assertEqual(config['seed_namespace'], precision.control.SEED_NAMESPACE)
        self.assertEqual(config['risk_range_source'], 'PRIOR_ANALYTIC_SCORES_K_FROZEN_BR_V2')
        self.assertEqual(config['cost_range_source'], 'PRIOR_ANALYTIC_SCORES_COSTS_K_FROZEN_BC_V3')
        self.assertEqual(config['risk_numerical_padding'], 1e-12)
        self.assertFalse(config['risk_padding_is_formal_floating_point_proof'])
        for name in ('N', 'K', 'PILOT_SAMPLES', 'MAIN_SAMPLES', 'ALPHA', 'MAX_RADIUS',
                     'COMPARISON_COUNT', 'SEEDS', 'FIXTURES', 'MAX_WORK', 'MAX_TOTAL_WORK'):
            self.assertEqual(getattr(precision, name), getattr(v1, name))
        for summary in result['per_case_seed']:
            self.assertEqual(summary['seed_case_id'], 'nonuniform-precision-v3-' + summary['case_id'])
            for phase in ('pilot', 'main'):
                old_pin = precision.control._pin(summary['seed'],
                    'nonuniform-precision-v1-' + summary['case_id'], phase)
                self.assertNotEqual(old_pin, summary['derived_seed_sha256'][phase])
        self.assertFalse(result['train_release'])
        self.assertEqual(config['min_positive_cost'], 1e-6)
        self.assertFalse(config['cost_padding_is_formal_floating_point_proof'])
        self.assertIs(precision.prior, v2.prior)
        for summary in result['per_case_seed']:
            for phase in ('pilot', 'main'):
                self.assertNotEqual(summary['derived_seed_sha256'][phase],
                    precision.control._pin(summary['seed'],
                        'nonuniform-precision-v2-' + summary['case_id'], phase))

    def test_bounded_compact_receipt_and_no_retained_observations(self):
        result = self.tiny()
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        self.assertLessEqual(len(encoded), 262144)
        self.assertEqual(len(result['rows']), 144)
        for flag in ('adaptive_sampling', 'trajectories_retained', 'real_data_access',
                     'trainer_implemented', 'optimizer_implemented', 'train_release'):
            self.assertFalse(result[flag])
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['fixed_sample_iid_conditional_on_independent_pilot'])
        for summary in result['per_case_seed']:
            self.assertNotIn('observations', summary)
            self.assertNotIn('trajectories', summary)
            self.assertEqual(summary['main_observation_count'], 8)

    def test_cost_domain_preflight_rejects_before_any_rng(self):
        fixture_id, scores, _ = precision.FIXTURES[0]
        for charges, code in (((0.,) * 6, 'ZERO_COST_FIXTURE'),
                              ((5e-324,) + (1.,) * 5, 'POSITIVE_COST_BELOW_SUPPORTED_MIN'),
                              ((1e-9,) + (1.,) * 5, 'POSITIVE_COST_BELOW_SUPPORTED_MIN')):
            with self.subTest(charges=charges), \
                    patch.object(precision, 'FIXTURES', ((fixture_id, scores, charges),)), \
                    patch.object(precision.random, 'Random', side_effect=AssertionError('RNG')):
                with self.assertRaisesRegex(ValueError, code):
                    self.tiny()

    def test_all_prior_ranges_payload_hashes_and_costs_frozen_before_main(self):
        events = []
        original_rng, original_hash = random.Random, precision._hash
        original_prior = precision.prior.prior_risk_gradient_ranges
        original_cost_prior = precision.cost_prior.prior_normalized_cost_gradient_ranges
        def rng(seed):
            events.append('rng')
            return original_rng(seed)
        def prior(*args, **kwargs):
            events.append('prior')
            self.assertEqual(set(kwargs), {'k', 'risk_baseline'})
            return original_prior(*args, **kwargs)
        def hash_payload(payload):
            if 'comparison_ranges' in payload:
                events.append('freeze')
                self.assertIn('risk_prior_bound_payload', payload)
                self.assertEqual(payload['risk_prior_bound_sha256'],
                                 original_hash(payload['risk_prior_bound_payload']))
                self.assertEqual(payload['cost_prior_bound_sha256'],
                                 original_hash(payload['cost_prior_bound_payload']))
            return original_hash(payload)
        def cost_prior(*args, **kwargs):
            events.append('cost_prior')
            self.assertEqual(set(kwargs), {'k', 'normalized_cost_baseline'})
            return original_cost_prior(*args, **kwargs)
        with patch.object(precision.random, 'Random', side_effect=rng), \
                patch.object(precision.prior, 'prior_risk_gradient_ranges', side_effect=prior), \
                patch.object(precision.cost_prior, 'prior_normalized_cost_gradient_ranges', side_effect=cost_prior), \
                patch.object(precision, '_hash', side_effect=hash_payload):
            result = self.tiny()
        self.assertEqual(events, ['cost_prior'] * 2 + ['rng', 'prior', 'cost_prior', 'freeze', 'rng'] * 8)
        changed_main = precision._run_fixed_fixtures(pilot_samples=3, main_samples=7)
        for summary, changed in zip(result['per_case_seed'], changed_main['per_case_seed']):
            fixture = next(f for f in result['fixtures'] if f['case_id'] == summary['case_id'])
            uids = sorted(fixture['scores'])
            expected = original_prior(fixture['scores'], {'5'}, k=3,
                                      risk_baseline=summary['baseline_risk'])
            self.assertNotIn('risk_prior_bound_payload', summary)
            self.assertNotIn('cost_prior_bound_payload', summary)
            self.assertEqual(summary['risk_prior_bound_sha256'], original_hash(expected))
            freeze = summary['pilot_freeze_payload']
            self.assertEqual(freeze['risk_prior_bound_payload'], expected)
            self.assertEqual(freeze['risk_prior_bound_sha256'], original_hash(expected))
            self.assertEqual(summary['pilot_freeze_sha256'], original_hash(freeze))
            self.assertEqual(summary['pilot_freeze_payload'], changed['pilot_freeze_payload'])
            self.assertEqual(summary['pilot_freeze_sha256'], changed['pilot_freeze_sha256'])
            self.assertTrue(summary['risk_ranges_frozen_before_main'])
            rows = summary['rows']
            for index, row in enumerate(rows):
                self.assertEqual([row['range_lower'], row['range_upper']],
                                 list(freeze['comparison_ranges'][index]))
                if row['metric'] == 'miss_score_gradient':
                    self.assertEqual([row['range_lower'], row['range_upper']],
                                     expected['risk_score_gradient_ranges'][row['uid']])
            cost_expected = precision.cost_prior.prior_normalized_cost_gradient_ranges(
                fixture['scores'], {'5'}, fixture['costs'], k=3,
                normalized_cost_baseline=summary['baseline_normalized_cost'])
            self.assertEqual(freeze['cost_prior_bound_payload'], cost_expected)
            self.assertEqual(freeze['cost_prior_bound_sha256'], original_hash(cost_expected))
            self.assertEqual(summary['cost_prior_bound_sha256'], original_hash(cost_expected))
            self.assertTrue(summary['cost_ranges_frozen_before_main'])
            for row in rows:
                if row['metric'] == 'normalized_cost_score_gradient':
                    self.assertEqual([row['range_lower'], row['range_upper']],
                                     cost_expected['normalized_cost_score_gradient_ranges'][row['uid']])
                if row['metric'] == 'normalized_cost_projection':
                    expected_range = v1._projection_range(
                        [cost_expected['normalized_cost_score_gradient_ranges'][u] for u in uids],
                        list(summary['frozen_directions'][row['direction']].values()))
                    self.assertEqual((row['range_lower'], row['range_upper']), expected_range)

    def test_fixed_entry_and_config(self):
        with patch.object(precision, '_run_fixed_fixtures', return_value={}) as runner:
            precision.run_nonuniform_precision_v3()
            runner.assert_called_once_with(pilot_samples=64, main_samples=16384)
        with self.assertRaises(TypeError):
            precision.run_nonuniform_precision_v3(main_samples=8)
        self.assertEqual(2 * 4 * 6 * 3 * (64 + 16384), 2368512)

    def test_every_uid_oracle_fixed_baseline_and_finite_difference(self):
        for case_id, values, charges in precision.FIXTURES:
            scores = dict(zip(map(str, range(6)), values))
            costs = dict(zip(scores, charges))
            oracle = precision.full_oracle.enumerate_exact_gradient(scores, {'5'}, costs, k=3)
            controlled = precision.control.enumerate_exact_gradient(
                scores, {'5'}, costs, k=3, risk_baseline=.6, cost_baseline=7.)
            for metric in ('expected_miss_probability', 'expected_truncated_static_cost'):
                self.assertAlmostEqual(oracle[metric], controlled[metric], delta=1e-12)
            for uid in scores:
                upper, lower = dict(scores), dict(scores)
                upper[uid] += 1e-5
                lower[uid] -= 1e-5
                hi = precision.full_oracle.enumerate_exact_gradient(upper, {'5'}, costs, k=3)
                lo = precision.full_oracle.enumerate_exact_gradient(lower, {'5'}, costs, k=3)
                for metric, gradient in (('expected_miss_probability', 'miss_score_gradient'),
                                         ('expected_truncated_static_cost', 'cost_score_gradient')):
                    with self.subTest(case=case_id, uid=uid, metric=metric):
                        self.assertAlmostEqual(oracle[gradient][uid], controlled[gradient][uid], delta=1e-12)
                        self.assertAlmostEqual(oracle[gradient][uid], (hi[metric]-lo[metric])/2e-5,
                                               delta=2e-8)

    def test_known_ranges_cover_all_orders_and_signed_projections(self):
        direction = [.2, -.1, .3, -.2, .1, -.1]
        for _, values, charges in precision.FIXTURES:
            scores = dict(zip(map(str, range(6)), values))
            costs = dict(zip(scores, charges))
            prepared = precision.control.frozen._validate(scores, {'5'}, costs, 3, 7)
            bound = 3 * max(charges)
            for br, bc in itertools.product((0., 1.), (0., bound)):
                for order in itertools.permutations(prepared[4], 3):
                    _, _, _, gr, gc = precision.control._controlled(
                        precision.control._components(*prepared[1:], 3, order=order), br, bc)
                    for objective, vector in (('risk', gr), ('cost', [g/bound for g in gc])):
                        ranges = ([precision.prior.prior_risk_gradient_ranges(
                            scores, {'5'}, k=3, risk_baseline=br)['risk_score_gradient_ranges'][u]
                            for u in prepared[0]] if objective == 'risk' else
                            [precision.cost_prior.prior_normalized_cost_gradient_ranges(
                                scores, {'5'}, costs, k=3, normalized_cost_baseline=bc / bound)
                             ['normalized_cost_score_gradient_ranges'][u] for u in prepared[0]])
                        for value, (lower, upper) in zip(vector, ranges):
                            self.assertTrue(lower <= value <= upper)
                        lower, upper = precision._projection_range(ranges, direction)
                        self.assertTrue(lower <= precision._dot(vector, direction) <= upper)
                        self.assertAlmostEqual(upper-lower,
                                               sum(abs(d)*(hi-lo) for d, (lo, hi) in zip(direction, ranges)))


    def test_welford_and_eb_formula(self):
        observations = [[1., 4.], [2., 3.], [5., 8.]]
        moments = precision._Welford(2)
        for values in observations:
            moments.add(values)
        for i in range(2):
            self.assertAlmostEqual(moments.mean[i], statistics.mean(row[i] for row in observations))
            self.assertAlmostEqual(moments.sample_variance(i), statistics.variance(row[i] for row in observations))
        logarithm = math.log(4*144/.01)
        self.assertEqual(precision._radius(3., 9., 8, logarithm),
                         math.sqrt(2*3*logarithm/8) + 7*9*logarithm/(3*7))
        with self.assertRaisesRegex(ValueError, 'VARIANCE_COUNT'):
            precision._Welford(1).sample_variance(0)

    def test_deterministic_all_rows_no_adaptation_and_independent_pilot(self):
        state = random.getstate()
        with patch.object(precision.control, '_components', wraps=precision.control._components) as component:
            result = self.tiny()
            self.assertEqual(component.call_count, 8*(3+8) + 2*60)
        self.assertEqual(result, self.tiny())
        self.assertEqual(state, random.getstate())
        changed = precision._run_fixed_fixtures(pilot_samples=4, main_samples=8)
        self.assertEqual(result['status'], 'INCONCLUSIVE_PRECISION')
        self.assertEqual(result['comparison_count'], 144)
        self.assertEqual(len(result['rows']), 144)
        self.assertEqual(result['total_work'], 8*6*3*11)
        self.assertAlmostEqual(result['log_term'], math.log(4*144/.01))
        self.assertFalse(result['train_release'])
        self.assertFalse(result['adaptive_sampling'])
        for before, after in zip(result['per_case_seed'], changed['per_case_seed']):
            self.assertEqual(before['derived_seed_sha256'], after['derived_seed_sha256'])
            self.assertNotEqual(before['derived_seed_sha256']['pilot'], before['derived_seed_sha256']['main'])
            self.assertEqual(before['rows'][:2], after['rows'][:2])
            self.assertEqual(before['comparison_count'], 18)
            projections = [r for r in before['rows'] if r['direction']]
            self.assertEqual(len(projections), 4)
            self.assertEqual(sum(r['same_objective_projection'] for r in projections), 2)
            for name, direction in before['frozen_directions'].items():
                self.assertAlmostEqual(sum(abs(d) for d in direction.values()), 1.)
                gradient_key = 'pilot_gradient_risk' if name == 'risk' else 'pilot_gradient_normalized_cost'
                self.assertLess(precision._dot(list(before[gradient_key].values()), list(direction.values())), 0.)
            for row in projections:
                vector_key = 'miss_score_gradient' if row['metric'].startswith('risk') else 'cost_score_gradient'
                fixture = next(f for f in result['fixtures'] if f['case_id'] == row['case_id'])
                vector = list(fixture['exact_original_pl'][vector_key].values())
                if vector_key == 'cost_score_gradient':
                    vector = [v/fixture['cost_normalization_B'] for v in vector]
                self.assertAlmostEqual(row['exact'], precision._dot(vector, list(before['frozen_directions'][row['direction']].values())))

    def test_zero_direction_failclosed_and_error_precedence(self):
        self.assertEqual(precision._direction([0.] * 6), ([0.] * 6, False))
        with patch.object(precision, '_direction', return_value=([0.] * 6, False)):
            result = self.tiny()
        self.assertEqual(result['direction_status'], 'INCONCLUSIVE_DIRECTION')
        self.assertFalse(result['same_objective_direction_certified'])
        with patch.object(precision, '_radius', return_value=1e-12):
            result = self.tiny(max_radius=1e-13)
        self.assertEqual(result['status'], 'FAIL_NUMERICAL')
        self.assertGreater(result['error_bound_violations'], 0)
        self.assertEqual(result['precision_violations'], 144)
        self.assertFalse(result['train_release'])
        self.assertEqual(result['direction_status'], 'BLOCKED_NUMERICAL_FAILURE')
        self.assertFalse(result['same_objective_direction_certified'])
        self.assertTrue(all(not s['same_objective_direction_certified'] for s in result['per_case_seed']))

    def test_direction_strict_ucb_and_cross_report_only(self):
        for same, expected in ((-1., 'PASS_FIXED_SYNTHETIC_DIRECTION_ONLY'),
                               (0., 'INCONCLUSIVE_DIRECTION'), (1., 'INCONCLUSIVE_DIRECTION')):
            dots = itertools.cycle((same, 1., 1., same))
            widths = itertools.cycle([100.] * 14 + [0.] * 4)
            with patch.object(precision, '_dot', side_effect=lambda *_: next(dots)), \
                    patch.object(precision, '_radius', side_effect=lambda *_: next(widths)):
                result = self.tiny()
            self.assertEqual(result['direction_status'], expected)
            self.assertEqual(result['error_bound_violations'], 0)
            self.assertEqual(result['precision_status'], 'INCONCLUSIVE_PRECISION')
            self.assertFalse(result['train_release'])

    def test_main_vector_moments_and_frozen_baseline_formula(self):
        recorded = []
        original = precision.control._controlled
        def record(parts, br, bc):
            values = original(parts, br, bc)
            recorded.append((parts, br, bc, values))
            return values
        with patch.object(precision.control, '_controlled', side_effect=record):
            result = self.tiny()
        for index, summary in enumerate(result['per_case_seed']):
            fixture = next(f for f in result['fixtures'] if f['case_id'] == summary['case_id'])
            bound = fixture['cost_normalization_B']
            offset = 2*60 + index*11
            pilot = recorded[offset:offset+3]
            main = recorded[offset+3:offset+11]
            vectors = []
            for parts, br, bc, (_, risk, cost, gr, gc) in main:
                self.assertEqual(br, summary['baseline_risk'])
                self.assertEqual(bc, summary['baseline_static_cost'])
                self.assertEqual(gr, [parts[3][i]+(parts[1]-br)*parts[5][i] for i in range(6)])
                self.assertEqual(gc, [parts[4][i]+(parts[2]-bc)*parts[5][i] for i in range(6)])
                gc = [g/bound for g in gc]
                row = [risk, cost/bound] + gr + gc
                row += [precision._dot(v, list(d.values())) for v in (gr, gc)
                        for d in summary['frozen_directions'].values()]
                vectors.append(row)
            pilot_vectors = [[v[3][1], v[3][2]/bound] + v[3][3] + [g/bound for g in v[3][4]]
                             for v in pilot]
            for data, name in ((pilot_vectors, 'pilot_observation_sha256'),
                               (vectors, 'main_observation_sha256')):
                digest = precision.hashlib.sha256()
                for vector in data:
                    precision._observe_hash(digest, vector)
                self.assertEqual(summary[name], digest.hexdigest())
            self.assertEqual(summary['pilot_freeze_sha256'], precision._hash(summary['pilot_freeze_payload']))
            self.assertEqual(summary['pilot_freeze_payload']['directions'], summary['frozen_directions'])
            for coordinate, row in enumerate(summary['rows']):
                self.assertAlmostEqual(row['estimate'], statistics.mean(v[coordinate] for v in vectors))
                self.assertAlmostEqual(row['sample_variance'], statistics.variance(v[coordinate] for v in vectors))

    def test_dual_oracle_check_before_rng(self):
        result = self.tiny()
        for fixture in result['fixtures']:
            self.assertTrue(fixture['exact_oracle_crosscheck']['passed'])
            self.assertEqual(fixture['exact_oracle_crosscheck']['comparison_count'], 14)
            self.assertLessEqual(fixture['exact_oracle_crosscheck']['max_absolute_error'], 1e-10)
        original = precision.full_oracle.enumerate_exact_gradient
        def mismatch(*args, **kwargs):
            truth = original(*args, **kwargs)
            truth['cost_score_gradient']['3'] += .01
            return truth
        with patch.object(precision.full_oracle, 'enumerate_exact_gradient', side_effect=mismatch), \
                patch.object(precision.random, 'Random', side_effect=AssertionError('RNG')):
            with self.assertRaisesRegex(ValueError, 'EXACT_ORACLE_MISMATCH'):
                self.tiny()

    def test_invalid_config_before_rng_hash_or_oracle(self):
        changes = [dict(pilot_samples=True), dict(pilot_samples=0), dict(pilot_samples=65537),
                   dict(main_samples=1), dict(main_samples=True), dict(main_samples=65537),
                   dict(alpha=0), dict(alpha=True), dict(alpha=float('nan')), dict(alpha=1.1),
                   dict(alpha=10**1000), dict(max_radius=10**1000),
                   dict(max_radius=0), dict(max_radius=True), dict(max_radius=float('inf'))]
        with patch.object(precision.random, 'Random', side_effect=AssertionError('RNG')), \
                patch.object(precision.control, '_pin', side_effect=AssertionError('PIN')), \
                patch.object(precision.full_oracle, 'enumerate_exact_gradient', side_effect=AssertionError('ORACLE')):
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    precision._run_fixed_fixtures(**dict(dict(pilot_samples=2, main_samples=3), **change))
            with patch.object(precision, 'MAX_WORK', 1), self.assertRaisesRegex(ValueError, 'WORK_BOUND'):
                self.tiny()
            with patch.object(precision, 'MAX_TOTAL_WORK', 1), self.assertRaisesRegex(ValueError, 'TOTAL_WORK_BOUND'):
                self.tiny()

    def test_positive_subnormal_alpha_and_no_io(self):
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('os.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('subprocess.Popen', side_effect=AssertionError('PROCESS')):
            with patch.object(precision.random, 'Random', side_effect=AssertionError('IMPORT RNG')):
                importlib.reload(precision)
            result = precision._run_fixed_fixtures(pilot_samples=1, main_samples=2, alpha=5e-324)
        self.assertTrue(math.isfinite(result['log_term']))
        self.assertFalse(result['real_data_access'])
        self.assertFalse(result['optimizer_implemented'])


if __name__ == '__main__':
    unittest.main()
