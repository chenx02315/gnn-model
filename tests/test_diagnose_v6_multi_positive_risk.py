"""No formal large estimate calls: six-large loop uses an analytic stub."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import diagnose_v6_multi_positive_risk as diagnostic
from src.models.ranking_v6_multi_positive_conditional_risk import enumerate_exact_gradient
from src.models.ranking_v6_first_hit_exact_gradient import enumerate_exact_gradient as old_oracle


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.contract = diagnostic.load_contract(diagnostic.CONTRACT, diagnostic.CONTRACT_SHA)

    @staticmethod
    def analytic_stub(scores, positives, *, k, seed, samples, synthetic_only):
        ref = diagnostic.uniform_reference(len(scores), len(positives), k)
        return dict(expected_miss_probability=ref['risk'],
                    miss_score_gradient={u: ref['positive_gradient_each'] if u in positives
                                         else ref['negative_gradient_each'] for u in scores},
                    synthetic_only=True, trainer_implemented=False, scalar_loss_implemented=False,
                    real_data_access=False, online_cost_replay=False, trajectories_retained=False,
                    positive_stopping_integrated=True, proposal_score_term_included=True)

    def test_fixed_loop_and_small_full_pl_oracle(self):
        calls = []

        def stub(scores, positives, **kwargs):
            calls.append((len(scores), len(positives), kwargs))
            return self.analytic_stub(scores, positives, **kwargs)

        result = diagnostic.run_diagnostic(self.contract, estimate_fn=stub,
                                           exact_fn=enumerate_exact_gradient, oracle_fn=old_oracle)
        self.assertEqual(result['status'], 'PASS_CORRECTNESS_AND_POSITIVE_SIGNAL_ONLY')
        self.assertEqual(len(calls), 6)
        self.assertEqual([(n, m, kw['seed']) for n, m, kw in calls],
                         [(736, m, seed) for m in (1, 6) for seed in (11, 29, 47)])
        self.assertTrue(all(kw == dict(k=10, seed=kw['seed'], samples=512, synthetic_only=True)
                            for _, _, kw in calls))
        self.assertTrue(all(len(row['result']['miss_score_gradient']) == 736 for row in result['large_cases']))
        self.assertEqual([r['structural_zero_required'] for r in result['small_exact_cases']],
                         [False, False, False, True, True])
        self.assertTrue(all(r['structural_zero_pass'] for r in result['small_exact_cases']))
        self.assertFalse(result['negative_direction_certified'])

    def test_uniform_reference_and_negative_reporting(self):
        ref = diagnostic.uniform_reference(6, 2, 3)
        self.assertAlmostEqual(ref['risk'], .2)
        self.assertAlmostEqual(ref['positive_gradient_each'], -.2 * (1/6 + 1/5 + 1/4))
        self.assertAlmostEqual(ref['negative_gradient_each'], .2 * .5 * (1/6 + 1/5 + 1/4))
        scores = {str(i): 0. for i in range(6)}
        positives = {'0', '1'}
        result = self.analytic_stub(scores, positives, k=3, seed=11, samples=512, synthetic_only=True)
        result['miss_score_gradient']['2'] = -1.
        summary = diagnostic.summarize_large(result, scores, positives, ref, 1e-12)
        self.assertTrue(summary['risk_and_positive_signal_pass'])
        self.assertFalse(summary['full_gradient_precision_certified'])
        self.assertFalse(summary['negative_direction_certified'])
        self.assertEqual(summary['negative_wrong_sign_count'], 1)
        self.assertAlmostEqual(summary['negative_max_absolute_error'], 1 + ref['negative_gradient_each'])
        self.assertAlmostEqual(summary['negative_mean_absolute_error'], (1 + ref['negative_gradient_each']) / 4)
        self.assertEqual(diagnostic.uniform_reference(4, 4, 3)['risk'], 0.)

    def test_wrong_contract_flags_and_budgets_fail_closed(self):
        for flag in diagnostic.FALSE_FLAGS:
            for invalid in (True, 0, None):
                contract = copy.deepcopy(self.contract)
                contract[flag] = invalid
                with self.assertRaises(ValueError):
                    diagnostic.validate_contract(contract)
        for field, invalid in [('formal_runs', 2), ('automatic_retries', 1)]:
            contract = copy.deepcopy(self.contract)
            contract[field] = invalid
            with self.assertRaises(ValueError):
                diagnostic.validate_contract(contract)
        contract = copy.deepcopy(self.contract)
        contract['large_cases']['samples_per_seed'] = 1024
        with self.assertRaises(ValueError):
            diagnostic.validate_contract(contract)

    def test_hash_gate(self):
        with self.assertRaises(ValueError):
            diagnostic.load_contract(diagnostic.CONTRACT, '0' * 64)
        with tempfile.TemporaryDirectory() as folder:
            altered = Path(folder) / 'altered.json'
            altered.write_text('{}', encoding='utf-8')
            with self.assertRaises(ValueError):
                diagnostic.load_contract(altered, diagnostic.CONTRACT_SHA)

    def test_kernel_flags_and_nonfinite_fail_closed(self):
        scores = {'0': 0., '1': 0.}
        result = self.analytic_stub(scores, {'0'}, k=1, seed=11, samples=512, synthetic_only=True)
        for key in ('synthetic_only', 'trainer_implemented', 'real_data_access',
                    'proposal_score_term_included', 'trajectories_retained'):
            bad = copy.deepcopy(result)
            bad[key] = not bad[key]
            with self.assertRaises(ValueError):
                diagnostic.check_result(bad, scores)
        result['miss_score_gradient']['0'] = float('nan')
        with self.assertRaises(ValueError):
            diagnostic.check_result(result, scores)

    def test_once_root_refusal_and_sha(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'only-once'
            calls = []

            def stub(contract):
                calls.append(True)
                return {'status': 'PASS_CORRECTNESS_AND_POSITIVE_SIGNAL_ONLY'}

            summary, code = diagnostic.execute_once(self.contract, output, runner=stub,
                                                     sources=[diagnostic.CONTRACT])
            self.assertEqual(code, 0)
            self.assertEqual(summary['artifact_sha256'], diagnostic.sha((output / 'result.json').read_bytes()))
            self.assertTrue(json.loads((output / 'once.json').read_bytes())['once'])
            with self.assertRaises(FileExistsError):
                diagnostic.execute_once(self.contract, output, runner=stub)
            self.assertEqual(len(calls), 1)

    def test_failure_persisted_no_retry_and_size_cap(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'failed-once'

            def fail(contract):
                raise RuntimeError('fixture failure')

            _, code = diagnostic.execute_once(self.contract, output, runner=fail,
                                               sources=[diagnostic.CONTRACT])
            self.assertEqual(code, 1)
            failure = json.loads((output / 'failure.json').read_bytes())
            self.assertFalse(failure['retry_allowed'])
            self.assertFalse((output / 'result.json').exists())
            with self.assertRaises(FileExistsError):
                diagnostic.execute_once(self.contract, output, runner=fail)
        with self.assertRaises(ValueError):
            diagnostic.encode_capped({'data': 'x' * diagnostic.MAX_JSON_BYTES})

    def test_cli_requires_both_gates_without_execution(self):
        with patch.object(diagnostic, 'execute_once') as execute:
            for args in ([], ['--execute'], ['--contract-sha256', diagnostic.CONTRACT_SHA]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    diagnostic.main(args)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--execute', '--contract-sha256', 'bad']), 1)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
