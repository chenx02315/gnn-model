"""No real large calls: fixed-large execution is always stubbed."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import diagnose_v6_multi_risk_control as diagnostic


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.contract = diagnostic.load_contract(diagnostic.CONTRACT, diagnostic.CONTRACT_SHA)

    @staticmethod
    def stub(scores, positives, *, k, seed, samples, synthetic_only, pilot_samples=None):
        previous, _, _ = diagnostic._imports()
        ref = previous.uniform_reference(len(scores), len(positives), k)
        controlled = pilot_samples is not None
        gradient = {u: ref['positive_gradient_each'] if u in positives else
                    ref['negative_gradient_each'] + (1e-6 if controlled else 1e-3)
                    for u in scores}
        result = dict(expected_miss_probability=ref['risk'], miss_score_gradient=gradient,
                      synthetic_only=True, trainer_implemented=False, scalar_loss_implemented=False,
                      real_data_access=False, online_cost_replay=False, trajectories_retained=False,
                      positive_stopping_integrated=True, proposal_score_term_included=True,
                      seed=seed, samples=samples, nominal_work=3768320, trajectory_count=samples)
        if controlled:
            result.update(pilot_samples=32, total_samples=512, main_seed=seed,
                          pilot_seed=seed ^ diagnostic.PILOT_SEED_XOR, main_trajectory_count=480,
                          pilot_trajectory_count=32, total_trajectory_count=512,
                          pilot_baseline=ref['risk'], baseline_frozen_before_main=True,
                          baseline_main_adaptation=False, baseline_derivative_included=False,
                          pilot_uses_all_samples=True, independent_prng_stream_model=True,
                          prng_independence_empirically_certified=False,
                          confidence_interval_implemented=False, universal_variance_reduction_claim=False)
        return result

    def run_stubbed(self, control=None):
        return diagnostic.run_diagnostic(self.contract, raw_fn=self.stub, control_fn=control or self.stub)

    def test_fixed_loop_work_small_oracle_and_all_coordinates(self):
        calls = []

        def stub(scores, positives, **kwargs):
            calls.append((len(scores), len(positives), kwargs))
            return self.stub(scores, positives, **kwargs)

        result = diagnostic.run_diagnostic(self.contract, raw_fn=stub, control_fn=stub)
        self.assertEqual(result['status'], diagnostic.PASS)
        self.assertEqual(len(calls), 12)
        self.assertEqual([(n, m, kw['seed']) for n, m, kw in calls],
                         [(736, m, s) for m in (1, 6) for s in (83, 101, 137) for _ in range(2)])
        self.assertEqual(sum(kw['samples'] + kw.get('pilot_samples', 0) for _, _, kw in calls), 6144)
        self.assertEqual(sum(n * kw['k'] * (kw['samples'] + kw.get('pilot_samples', 0))
                             for n, _, kw in calls), 45219840)
        self.assertTrue(all(n * kw['k'] * (kw['samples'] + kw.get('pilot_samples', 0)) == 3768320
                            for n, _, kw in calls))
        self.assertEqual(len(result['small_cases']), 12)
        self.assertTrue(all(row['pass'] for row in result['small_cases']))
        self.assertEqual([r['result']['structural_zero'] for r in result['small_cases']],
                         [False] * 6 + [True] * 6)
        for row in result['large_pairs']:
            self.assertEqual(len(row['raw']['miss_score_gradient']), 736)
            self.assertEqual(len(row['controlled']['miss_score_gradient']), 736)
        self.assertLess(len(diagnostic.encode_capped(result)), diagnostic.MAX_JSON_BYTES)
        for flag in ('confidence_interval_claim', 'universal_variance_reduction_claim',
                     'nonuniform_large_precision_claim', 'real_training_ready'):
            self.assertIs(result[flag], False)

    def test_structural_zero_without_trajectory(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('must not enumerate')
        result = diagnostic.small_expectation({'a': 0., 'b': 0.}, {'a'}, 2, .9,
                                              trajectory_fn=forbidden)
        self.assertEqual(result['prefix_count'], 0)
        self.assertEqual(result['gradient'], {'a': 0., 'b': 0.})

    def test_failed_criterion_retains_every_row_no_retries(self):
        calls = []
        def worse(scores, positives, **kwargs):
            calls.append(kwargs['seed'])
            result = self.stub(scores, positives, **kwargs)
            for u in scores:
                if u not in positives:
                    result['miss_score_gradient'][u] = -1.
            return result
        result = self.run_stubbed(worse)
        self.assertEqual(result['status'], diagnostic.FAIL)
        self.assertEqual(len(result['large_pairs']), 6)
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(not row['pass'] for row in result['large_pairs']))

    def test_contract_flags_fixed_fields_and_hash(self):
        for flag in diagnostic.FALSE_FLAGS:
            for invalid in (True, 0, None):
                contract = copy.deepcopy(self.contract)
                contract[flag] = invalid
                with self.assertRaises(ValueError):
                    diagnostic.validate_contract(contract)
        for key, value in [('formal_runs', True), ('automatic_retries', 1),
                           ('total_large_paths', 6145), ('small_fixed_baselines', [0., .5, .9]),
                           ('raw_arm', {'samples': 513}), ('large_pairs', 7)]:
            contract = copy.deepcopy(self.contract)
            contract[key] = value
            with self.assertRaises(ValueError):
                diagnostic.validate_contract(contract)
        with self.assertRaises(ValueError):
            diagnostic.load_contract(diagnostic.CONTRACT, '0' * 64)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.json'
            path.write_bytes(b'{}')
            with self.assertRaises(ValueError):
                diagnostic.load_contract(path, diagnostic.CONTRACT_SHA)

    def test_arm_schema_flags_baseline_and_seed_checks(self):
        scores = {'a': 0., 'b': 0.}
        good = self.stub(scores, {'a'}, k=1, seed=83, samples=480,
                         pilot_samples=32, synthetic_only=True)
        for key, bad in [('pilot_baseline', -1.), ('pilot_baseline', float('nan')),
                         ('pilot_seed', 83), ('main_seed', 84), ('samples', 512),
                         ('pilot_samples', 31), ('total_samples', True),
                         ('baseline_frozen_before_main', False), ('trainer_implemented', True),
                         ('proposal_score_term_included', False), ('real_data_access', True)]:
            changed = copy.deepcopy(good)
            changed[key] = bad
            with self.assertRaises(ValueError):
                diagnostic.check_arm(changed, scores, 83, True)
        for change in ({'miss_score_gradient': {'a': 0.}},
                       {'expected_miss_probability': float('inf')},
                       {'miss_score_gradient': {'a': float('nan'), 'b': 0.}}):
            changed = dict(good, **change)
            with self.assertRaises(ValueError):
                diagnostic.check_arm(changed, scores, 83, True)

    def test_once_metadata_before_runner_source_closure_and_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'once'
            def runner(contract):
                once = json.loads((output / 'once.json').read_bytes())
                self.assertIn('python', once)
                self.assertEqual(set(once['source_sha256']), set(map(str, diagnostic.source_paths())))
                return {'status': diagnostic.PASS}
            summary, code = diagnostic.execute_once(self.contract, output, runner=runner)
            self.assertEqual(code, 0)
            self.assertEqual(summary['artifact_sha256'], diagnostic.sha((output / 'result.json').read_bytes()))
            with self.assertRaises(FileExistsError):
                diagnostic.execute_once(self.contract, output, runner=runner)

    def test_failure_persisted_no_retry_and_cap(self):
        for mode in ('exception', 'criterion', 'oversize', 'schema'):
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / 'once'
                def runner(contract):
                    if mode == 'exception':
                        raise RuntimeError('expected failure')
                    return {'status': diagnostic.FAIL if mode == 'criterion' else
                            ('bad' if mode == 'schema' else diagnostic.PASS),
                            'data': 'x' * diagnostic.MAX_JSON_BYTES if mode == 'oversize' else ''}
                summary, code = diagnostic.execute_once(self.contract, output, runner=runner)
                self.assertEqual(code, 1)
                self.assertEqual(summary['status'], diagnostic.FAIL)
                self.assertFalse(json.loads((output / 'failure.json').read_bytes())['retry_allowed'])
                self.assertEqual((output / 'result.json').exists(), mode == 'criterion')
                with self.assertRaises(FileExistsError):
                    diagnostic.execute_once(self.contract, output, runner=runner)
        with self.assertRaises(ValueError):
            diagnostic.encode_capped({'data': 'x' * diagnostic.MAX_JSON_BYTES})

    def test_cli_gates_and_no_output_override(self):
        with patch.object(diagnostic, 'execute_once') as execute:
            for args in ([], ['--execute'], ['--contract-sha256', diagnostic.CONTRACT_SHA],
                         ['--execute', '--contract-sha256', diagnostic.CONTRACT_SHA, '--output', 'elsewhere']):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    diagnostic.main(args)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--execute', '--contract-sha256', 'bad']), 1)
            execute.assert_not_called()
            execute.return_value = ({'status': diagnostic.PASS}, 0)
            with contextlib.redirect_stdout(io.StringIO()) as capture:
                self.assertEqual(diagnostic.main(['--execute', '--contract-sha256', diagnostic.CONTRACT_SHA]), 0)
            execute.assert_called_once_with(self.contract, diagnostic.OUTPUT)
            self.assertEqual(json.loads(capture.getvalue()), {'status': diagnostic.PASS})


if __name__ == '__main__':
    unittest.main()
