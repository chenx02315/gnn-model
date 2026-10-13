"""Protocol-only checks: never execute the fixed precision sample run."""
import unittest
from unittest.mock import patch
from scripts import check_ranking_v6_large_precision_gate as gate


class ProtocolTests(unittest.TestCase):
    def test_pass_exit_zero(self):
        self.assertEqual(gate.exit_code_for({'status': 'PASS'}), 0)

    def test_failure_and_inconclusive_nonzero(self):
        for status in ('FAIL', 'INCONCLUSIVE_PRECISION', 'PASS_UNKNOWN'):
            self.assertEqual(gate.exit_code_for({'status': status}), 1)

    def test_bad_contract_before_sampling(self):
        with patch.object(gate.Path, 'read_bytes', return_value=b'wrong'), \
                patch.object(gate, 'run_uniform_precision', side_effect=AssertionError('sampling')):
            with self.assertRaisesRegex(ValueError, 'CONTRACT_PIN'):
                gate.run()
