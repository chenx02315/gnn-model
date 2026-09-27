import unittest

from src.data import run_blind_join_v12_r7 as runner


class RunBlindJoinV12R7Tests(unittest.TestCase):
    def test_fixed_argv_refuses(self):
        self.assertEqual(2, runner.main(["--attacker"]))

    def test_corrected_execution_audit_anchor_is_lower_hex_64(self):
        self.assertTrue(runner._is_sha256(runner.EXECUTION_AUDIT_SHA256))
        self.assertEqual(
            "38f2f99dd50da71ddfc20445edd40dfa6a82bb2177e195a38900620de4c56de9",
            runner.EXECUTION_AUDIT_SHA256)

    def test_fresh_output_root(self):
        self.assertTrue(runner.OUTPUT_ROOT.endswith("/19_blind_runtime_join_v12_r7"))
        self.assertNotEqual(runner.OUTPUT_ROOT, runner.base.OUTPUT_ROOT)


if __name__ == "__main__":
    unittest.main()
