"""Runner protocol mocks only; never consume the formal fixed sampling run."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models import ranking_v6_nonuniform_precision_v3 as numerical

spec = importlib.util.spec_from_file_location('nonuniform_v3_runner',
    Path(__file__).resolve().parents[1] / 'scripts/check_ranking_v6_nonuniform_precision_v3.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def fake_result(status='INCONCLUSIVE_PRECISION'):
    return dict(status=status, direction_status='INCONCLUSIVE_DIRECTION',
                comparison_count=144, error_bound_violations=int(status == 'FAIL_NUMERICAL'),
                precision_violations=1, per_case_seed=[{'same_objective_direction_certified': False}])


class RunnerProtocolTests(unittest.TestCase):
    def test_inconclusive_is_completed_not_retried(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_nonuniform_precision_v3', return_value=fake_result()) as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 0)
                with self.assertRaises(FileExistsError):
                    runner.main()
                run.assert_called_once()
            self.assertTrue((destination / 'once.json').exists())
            self.assertEqual(json.loads((destination / 'result.json').read_text())['status'], 'INCONCLUSIVE_PRECISION')

    def test_numerical_fail_exit_is_one_and_result_retained(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_nonuniform_precision_v3', return_value=fake_result('FAIL_NUMERICAL')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 1)
            self.assertTrue((destination / 'result.json').exists())

    def test_execution_failure_is_sealed_without_retry(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_nonuniform_precision_v3', side_effect=ValueError('synthetic_failure')) as run:
                with self.assertRaisesRegex(ValueError, 'synthetic_failure'):
                    runner.main()
                run.assert_called_once()
            self.assertEqual(json.loads((destination / 'failure.json').read_text())['status'], 'FAIL_EXECUTION')

    def test_contract_pin_before_numeric(self):
        with patch.object(Path, 'read_bytes', return_value=b'{}'), \
             patch.object(numerical, 'run_nonuniform_precision_v3') as run:
            with self.assertRaisesRegex(ValueError, 'CONTRACT_PIN'):
                runner.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
