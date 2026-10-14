"""Runner protocol mocks only; never execute E10's formal pilots."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models import ranking_v6_joint_score_update_reference as numerical

spec = importlib.util.spec_from_file_location('joint_score_runner',
    Path(__file__).resolve().parents[1] / 'scripts/check_ranking_v6_joint_score_update.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def fake_result(status='PARTIAL_SAFE_REJECTION'):
    return dict(status=status, config={'baseline_samples': 32, 'gradient_samples': 32},
                total_work=9216, exact_oracle_calls=16, per_case_seed=[{} for _ in range(8)],
                train_release=False, actual_parameter_updates=False, accepted_count=4,
                rejected_count=4, proposal_count=8, numerical_guard_failures=0,
                all_committed_updates_safe=True)


class JointRunnerProtocolTests(unittest.TestCase):
    def test_partial_result_retained_and_no_second_run(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_joint_score_update', return_value=fake_result()) as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 0)
                with self.assertRaises(FileExistsError):
                    runner.main()
                run.assert_called_once()
            self.assertEqual(json.loads((destination / 'result.json').read_text())['accepted_count'], 4)

    def test_false_pass_is_sealed(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_joint_score_update', return_value=fake_result('PASS_FIXED_SCORE_SPACE_JOINT_UPDATES_ONLY')):
                with self.assertRaisesRegex(ValueError, 'FALSE_PASS'):
                    runner.main()
            self.assertEqual(json.loads((destination / 'failure.json').read_text())['status'], 'FAIL_EXECUTION')

    def test_numeric_failure_exit_and_preservation(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'new'
            with patch.object(runner, 'DESTINATION', destination), \
                 patch.object(numerical, 'run_joint_score_update', return_value=fake_result('FAIL_NUMERICAL')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 1)
            self.assertTrue((destination / 'result.json').exists())

    def test_contract_pin_before_numeric(self):
        with patch.object(Path, 'read_bytes', return_value=b'{}'), \
             patch.object(numerical, 'run_joint_score_update') as run:
            with self.assertRaisesRegex(ValueError, 'CONTRACT_PIN'):
                runner.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
