import contextlib
import ast
import inspect
import io
from pathlib import Path
import tempfile
import unittest
from scripts import verify_v6_joint_wiring_stage as runner


class WiringStageTests(unittest.TestCase):
    def test_no_optimized_away_production_assertions(self):
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(ast.parse(inspect.getsource(runner)))))
        with self.assertRaisesRegex(ValueError, 'E28_TEST'):
            runner.require(False, 'TEST')

    def test_fixed_checks_no_mc_or_torch(self):
        result = runner.run_checks()
        self.assertEqual(len(result['cases']), 3)
        self.assertEqual(len(result['score_finite_difference_proofs']), 18)
        self.assertEqual(result['mc_estimator_calls'], 0)
        self.assertEqual(result['corrupt_readback_loader_calls'], 0)
        self.assertEqual(result['held_proof']['loader_calls'], 1)

    def test_once_and_failure_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'one'
            def fail():
                self.assertTrue((output/'once.json').exists())
                raise ValueError('injected')
            with self.assertRaises(ValueError):
                runner.execute_once(output, checks=fail)
            self.assertTrue((output/'failure.json').exists())
            with self.assertRaises(FileExistsError):
                runner.execute_once(output, checks=lambda: {})

    def test_cli_cap_and_no_override(self):
        for args in (['--contract-sha256', runner.CONTRACT_SHA],
                     ['--execute', '--contract-sha256', '0'*64],
                     ['--execute', '--contract-sha256', runner.CONTRACT_SHA, '--output', 'x']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main(args)
        with self.assertRaisesRegex(ValueError, 'CAP'):
            runner.encode('x'*65536)
        self.assertEqual(len(runner.sources()), 10)


if __name__ == '__main__':
    unittest.main()
