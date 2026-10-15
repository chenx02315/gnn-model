"""E27 runner tests: no formal output or real large sampling/reference calls."""
import contextlib
import copy
import io
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import diagnose_v6_nonuniform_risk as diagnostic
from src.models import ranking_v6_grouped_risk_reference as grouped
from src.models import ranking_v6_multi_positive_conditional_risk as raw_kernel
from src.models import ranking_v6_multi_positive_risk_control as control_kernel


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.contract = diagnostic.load_contract(diagnostic.CONTRACT, diagnostic.CONTRACT_SHA)

    @staticmethod
    def reference(*args, k, synthetic_only):
        counts, scores = args[:3], args[3:]
        if sum(counts) <= 7:
            return grouped.reference(*args, k=k, synthetic_only=synthetic_only)
        # Large reference is deliberately a test fixture, not a formal DP run.
        m, a, b = counts
        per_class = {'positive': -(a*1e-5+b*3e-5)/m,
                     'negative_a': 1e-5, 'negative_b': 3e-5}
        return dict(expected_miss_probability=.7, miss_per_individual_score_gradient=per_class,
                    counts=dict(zip(('positive', 'negative_a', 'negative_b'), counts)),
                    scores=dict(zip(('positive', 'negative_a', 'negative_b'), scores)),
                    synthetic_only=True, real_data_access=False, optimizer_implemented=False,
                    trainer_implemented=False, trajectories_retained=False)

    @classmethod
    def stub(cls, scores, positives, *, k, seed, samples, synthetic_only, pilot_samples=None):
        controlled = pilot_samples is not None
        counts = [len(positives), sum(u.startswith('a') for u in scores),
                  sum(u.startswith('b') for u in scores)]
        ref = cls.reference(*counts, scores[next(iter(positives))], -1., 1.,
                            k=k, synthetic_only=synthetic_only)
        classes = {u: ('positive' if u in positives else
                       'negative_a' if u.startswith('a') else 'negative_b') for u in scores}
        gradient = diagnostic.reference_gradient(ref, classes)
        noise = 1e-6 if controlled else 1e-3
        delta = {}
        for i, u in enumerate(u for u in scores if u not in positives):
            delta[u] = noise if i % 2 == 0 else -noise
            gradient[u] += delta[u]
        gradient[min(positives)] -= math.fsum(delta.values())
        # Controlled risk is intentionally LESS accurate; it must be descriptive.
        risk = .95 if controlled else .8
        result = dict(expected_miss_probability=risk, mean_risk=risk,
                      miss_score_gradient=gradient, uid_gradient=gradient.copy(),
                      synthetic_only=True, trainer_implemented=False, scalar_loss_implemented=False,
                      real_data_access=False, online_cost_replay=False, trajectories_retained=False,
                      positive_stopping_integrated=True, proposal_score_term_included=True,
                      action_count=len(scores), positive_count=len(positives), k=k,
                      temperature=1, guaranteed_hit=False, work_bound=3768320, max_work=20000000,
                      seed=seed, samples=samples, nominal_work=3768320, trajectory_count=samples)
        if controlled:
            result.update(pilot_samples=32, total_samples=512, main_seed=seed,
                          pilot_seed=seed ^ diagnostic.PILOT_SEED_XOR, main_trajectory_count=480,
                          pilot_trajectory_count=32, total_trajectory_count=512,
                          pilot_baseline=.7, baseline_frozen_before_main=True,
                          baseline_main_adaptation=False, baseline_derivative_included=False,
                          pilot_uses_all_samples=True, independent_prng_stream_model=True,
                          prng_independence_empirically_certified=False,
                          confidence_interval_implemented=False, universal_variance_reduction_claim=False)
        return result

    def run_stubbed(self, raw=None, control=None):
        with patch.object(raw_kernel, 'estimate', side_effect=AssertionError('real raw sample')), \
                patch.object(control_kernel, 'estimate', side_effect=AssertionError('real control sample')):
            return diagnostic.run_diagnostic(self.contract, raw_fn=raw or self.stub,
                                             control_fn=control or self.stub,
                                             reference_fn=self.reference)

    def test_fixed_counts_uid_join_work_all_rows_and_unthresholded_risk(self):
        calls = []
        def stub(scores, positives, **kw):
            calls.append((dict(scores), set(positives), dict(kw)))
            return self.stub(scores, positives, **kw)
        result = self.run_stubbed(stub, stub)
        self.assertEqual(result['status'], diagnostic.PASS)
        self.assertEqual(len(calls), 12)
        expected = [(m, score, seed) for m in (1, 6)
                    for score, seed in ((-2., 149), (0., 173), (2., 197)) for _ in range(2)]
        for (scores, pos, kw), (m, score, seed) in zip(calls, expected):
            a = (736-m)//2; b = 736-m-a
            self.assertEqual(set(pos), {f'p{i:03d}' for i in range(m)})
            self.assertEqual({u for u in scores if u.startswith('a')}, {f'a{i:03d}' for i in range(a)})
            self.assertEqual({u for u in scores if u.startswith('b')}, {f'b{i:03d}' for i in range(b)})
            self.assertTrue(all(scores[u] == score for u in pos))
            self.assertTrue(all(scores[u] == -1. for u in scores if u.startswith('a')))
            self.assertTrue(all(scores[u] == 1. for u in scores if u.startswith('b')))
            self.assertEqual(kw['seed'], seed)
            self.assertIs(kw['synthetic_only'], True)
            self.assertEqual(kw['samples']+kw.get('pilot_samples', 0), 512)
        self.assertEqual(sum(kw['samples']+kw.get('pilot_samples', 0) for _, _, kw in calls), 6144)
        self.assertEqual(sum(len(s)*kw['k']*(kw['samples']+kw.get('pilot_samples', 0))
                             for s, _, kw in calls), 45219840)
        self.assertEqual(len(result['small_reference_cases']), 3)
        self.assertTrue(all(row['pass'] for row in result['small_reference_cases']))
        for row in result['small_reference_cases']:
            self.assertLessEqual(row['risk_absolute_error'], 1e-11)
            self.assertLessEqual(row['gradient_max_absolute_error'], 1e-11)
            self.assertEqual(set(row['reference_uid_gradient']), set(row['decimal80_oracle']['uid_gradient']))
        self.assertEqual(len(result['large_pairs']), 6)
        for row in result['large_pairs']:
            self.assertEqual(set(row['uid_class']), set(row['reference_uid_gradient']))
            self.assertEqual(len(row['uid_class']), 736)
            for arm in ('raw', 'controlled'):
                self.assertEqual(set(row[arm]['uid_gradient']), set(row['uid_class']))
                self.assertTrue(row[arm+'_summary']['shift_gradient_sum_pass'])
            self.assertGreater(row['controlled_summary']['risk_absolute_error'],
                               row['raw_summary']['risk_absolute_error'])
            self.assertTrue(row['pass'])
        self.assertLess(len(diagnostic.encode_capped(result)), diagnostic.MAX_JSON_BYTES)
        for flag in ('risk_and_positive_errors_thresholded', 'confidence_interval_claim',
                     'universal_variance_reduction_claim', 'arbitrary_nonuniformity_certified',
                     'real_training_ready'):
            self.assertIs(result[flag], False)

    def test_scientific_failure_retains_all_pairs_no_retry(self):
        calls = []
        def same_noise(scores, positives, **kw):
            calls.append(kw['seed'])
            result = self.stub(scores, positives, **kw)
            other = self.stub(scores, positives, **(kw | {'pilot_samples': None, 'samples': 512}))
            result['uid_gradient'] = other['uid_gradient']
            result['miss_score_gradient'] = other['miss_score_gradient']
            return result
        result = self.run_stubbed(control=same_noise)
        self.assertEqual(result['status'], diagnostic.FAIL)
        self.assertEqual(len(calls), 6)
        self.assertEqual(len(result['large_pairs']), 6)
        self.assertTrue(all(not row['pass'] for row in result['large_pairs']))

    def test_shift_gradient_sum_is_gate_not_early_abort(self):
        def bad_sum(scores, positives, **kw):
            result = self.stub(scores, positives, **kw)
            result['miss_score_gradient'][min(positives)] += .001
            result['uid_gradient'] = result['miss_score_gradient'].copy()
            return result
        result = self.run_stubbed(control=bad_sum)
        self.assertEqual(result['status'], diagnostic.FAIL)
        self.assertEqual(len(result['large_pairs']), 6)
        self.assertTrue(all(not row['controlled_summary']['shift_gradient_sum_pass']
                            and not row['pass'] for row in result['large_pairs']))

    def test_summary_reports_all_coordinate_errors(self):
        result = {'expected_miss_probability': .6,
                  'miss_score_gradient': {'p': -.3, 'a': -.2, 'b': .6}}
        summary = diagnostic.summarize(result, {'p'}, {'p': -.2, 'a': .05, 'b': .15}, .7)
        self.assertAlmostEqual(summary['risk_absolute_error'], .1)
        self.assertAlmostEqual(summary['positive_mean_absolute_error'], .1)
        self.assertAlmostEqual(summary['positive_max_absolute_error'], .1)
        self.assertAlmostEqual(summary['negative_mean_absolute_error'], .35)
        self.assertAlmostEqual(summary['negative_max_absolute_error'], .45)
        self.assertEqual(summary['negative_nonpositive_count'], 1)
        self.assertAlmostEqual(summary['full_gradient_l2_error'], math.sqrt(.1**2+.25**2+.45**2))
        self.assertAlmostEqual(summary['gradient_sum'], .1)
        self.assertFalse(summary['shift_gradient_sum_pass'])

    def test_fixed_contract_hash_and_types(self):
        for flag in diagnostic.FALSE_FLAGS:
            for bad in (True, 0, None):
                contract = copy.deepcopy(self.contract); contract[flag] = bad
                with self.assertRaises(ValueError): diagnostic.validate_contract(contract)
        changes = [('actions', True), ('k', 9), ('positive_counts', [1, 5]),
                   ('conditions', diagnostic.CONDITIONS[::-1]), ('raw_samples', 513),
                   ('controlled_pilot_samples', 33), ('control_coefficient', 2),
                   ('total_paths', 6145), ('total_nominal_work', 1),
                   ('small_reference_absolute_tolerance', 1e-10),
                   ('gradient_sum_absolute_tolerance', 1e-11), ('automatic_retries', 1)]
        for key, value in changes:
            contract = copy.deepcopy(self.contract); contract[key] = value
            with self.assertRaises(ValueError): diagnostic.validate_contract(contract)
        with self.assertRaises(ValueError): diagnostic.load_contract(diagnostic.CONTRACT, 'bad')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'bad.json'; path.write_bytes(b'{}')
            with self.assertRaises(ValueError): diagnostic.load_contract(path, diagnostic.CONTRACT_SHA)

    def test_schema_finiteness_flags_alias_and_full_join(self):
        scores, pos, _ = diagnostic.fixture([1, 367, 368], [-2., -1., 1.])
        good = self.stub(scores, pos, k=10, seed=149, samples=480,
                         pilot_samples=32, synthetic_only=True)
        for key, bad in [('pilot_seed', 149), ('seed', 173), ('samples', 512),
                         ('total_samples', True), ('pilot_baseline', float('nan')),
                         ('pilot_baseline', -1.), ('trainer_implemented', True),
                         ('real_data_access', True), ('proposal_score_term_included', False),
                         ('baseline_main_adaptation', True), ('action_count', 735),
                         ('positive_count', 2), ('work_bound', 3768321), ('mean_risk', .5)]:
            changed = copy.deepcopy(good); changed[key] = bad
            with self.assertRaises(ValueError): diagnostic.check_arm(changed, scores, 149, True)
        for mapping in ({'p000': 0.}, dict(good['miss_score_gradient'], p000=float('inf')),
                        dict(good['miss_score_gradient'], p000=True)):
            changed = copy.deepcopy(good); changed['miss_score_gradient'] = mapping
            with self.assertRaises(ValueError): diagnostic.check_arm(changed, scores, 149, True)
        ref = self.reference(1, 367, 368, -2., -1., 1., k=10, synthetic_only=True)
        for key, bad in [('counts', {'positive': 2, 'negative_a': 367, 'negative_b': 368}),
                         ('trainer_implemented', True), ('expected_miss_probability', float('nan')),
                         ('miss_per_individual_score_gradient', {'positive': 0.})]:
            changed = copy.deepcopy(ref); changed[key] = bad
            with self.assertRaises(ValueError):
                diagnostic.reference_gradient(changed, {u: 'positive' if u in pos else
                    'negative_a' if u.startswith('a') else 'negative_b' for u in scores})

    def test_once_before_compute_source_closure_digest_and_rerun_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'once'
            def runner(contract):
                once = json.loads((output/'once.json').read_bytes())
                self.assertEqual(set(once['source_sha256']), set(map(str, diagnostic.source_paths())))
                self.assertIn('python', once); self.assertIn('platform', once)
                return {'status': diagnostic.PASS}
            summary, code = diagnostic.execute_once(self.contract, output, runner=runner)
            self.assertEqual(code, 0)
            self.assertEqual(summary['artifact_sha256'], diagnostic.sha((output/'result.json').read_bytes()))
            self.assertEqual((output/'result.sha256').read_text().strip(), summary['artifact_sha256'])
            with self.assertRaises(FileExistsError):
                diagnostic.execute_once(self.contract, output, runner=runner)

    def test_failure_persistence_cap_and_no_retry(self):
        for mode in ('exception', 'criterion', 'oversize', 'schema'):
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder)/'once'
                def runner(contract):
                    if mode == 'exception': raise RuntimeError('expected failure')
                    return {'status': diagnostic.FAIL if mode == 'criterion' else
                            ('bad' if mode == 'schema' else diagnostic.PASS),
                            'data': 'x'*diagnostic.MAX_JSON_BYTES if mode == 'oversize' else ''}
                summary, code = diagnostic.execute_once(self.contract, output, runner=runner)
                self.assertEqual(code, 1); self.assertEqual(summary['status'], diagnostic.FAIL)
                self.assertFalse(json.loads((output/'failure.json').read_bytes())['retry_allowed'])
                self.assertEqual((output/'result.json').exists(), mode == 'criterion')
                with self.assertRaises(FileExistsError):
                    diagnostic.execute_once(self.contract, output, runner=runner)
        for value in ({'data': 'x'*diagnostic.MAX_JSON_BYTES}, {'value': float('nan')}):
            with self.assertRaises(ValueError): diagnostic.encode_capped(value)

    def test_cli_execute_hash_and_no_overrides(self):
        with patch.object(diagnostic, 'execute_once') as execute:
            for args in ([], ['--execute'], ['--contract-sha256', diagnostic.CONTRACT_SHA],
                         ['--execute', '--contract-sha256', diagnostic.CONTRACT_SHA, '--output', 'elsewhere'],
                         ['--execute', '--contract-sha256', diagnostic.CONTRACT_SHA, '--samples', '999']):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    diagnostic.main(args)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--execute', '--contract-sha256', 'bad']), 1)
            execute.assert_not_called()
            execute.return_value = ({'status': diagnostic.PASS}, 0)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--execute', '--contract-sha256', diagnostic.CONTRACT_SHA]), 0)
            execute.assert_called_once_with(self.contract, diagnostic.OUTPUT)


if __name__ == '__main__':
    unittest.main()
