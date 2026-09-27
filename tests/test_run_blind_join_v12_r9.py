import hashlib
import os
import unittest

from src.data import run_blind_join_v12_r9 as runner


class RunBlindJoinV12R9Tests(unittest.TestCase):
    def test_fixed_argv_refuses(self):
        self.assertEqual(2, runner.main(["--attacker"]))

    def test_fresh_output_root(self):
        self.assertTrue(runner.OUTPUT_ROOT.endswith("/21_blind_runtime_join_v12_r9"))
        self.assertNotEqual(runner.OUTPUT_ROOT, runner.prior.OUTPUT_ROOT)

    def test_all_runtime_bundle_dependencies_are_contract_artifacts(self):
        self.assertIn(runner.RECOVERY_CLOSEOUT_RELATIVE, runner.REQUIRED_ARTIFACTS)
        self.assertIn(runner.R8_FAILURE_RELATIVE, runner.REQUIRED_ARTIFACTS)
        self.assertEqual(runner.base.CLOSEOUT_RELATIVE, runner.RECOVERY_CLOSEOUT_RELATIVE)

    def test_recovery_closeout_exists_and_matches_frozen_digest(self):
        path = os.path.join(runner.BUNDLE_ROOT, *runner.RECOVERY_CLOSEOUT_RELATIVE.split("/"))
        self.assertTrue(os.path.isfile(path))
        with open(path, "rb") as stream:
            actual = hashlib.sha256(stream.read()).hexdigest()
        self.assertEqual(runner.base.CLOSEOUT_SHA256, actual)


if __name__ == "__main__":
    unittest.main()
