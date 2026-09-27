import hashlib
import unittest

from src.data import run_blind_join_v12_r8 as runner


class RunBlindJoinV12R8Tests(unittest.TestCase):
    def test_fixed_argv_refuses(self):
        self.assertEqual(2, runner.main(["--attacker"]))

    def test_fresh_output_root(self):
        self.assertTrue(runner.OUTPUT_ROOT.endswith("/20_blind_runtime_join_v12_r8"))
        self.assertNotEqual(runner.OUTPUT_ROOT, runner.prior.OUTPUT_ROOT)

    def test_receipt_set_algorithm_matches_sealed_v3_canonicalization(self):
        named = [("001_H_a.json", b"alpha\n"), ("002_M_b.json", b"beta\n")]
        lines = [name + " " + hashlib.sha256(raw).hexdigest() for name, raw in named]
        expected = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
        self.assertEqual(expected, runner._receipt_set_sha256(named))
        self.assertNotEqual(hashlib.sha256(b"alpha\nbeta\n").hexdigest(), expected)

    def test_all_recovery_anchors_are_lower_hex_64(self):
        self.assertEqual(6, len(runner.REQUIRED_RECOVERY_ANCHORS))
        self.assertTrue(all(runner.prior._is_sha256(value)
                            for value in runner.REQUIRED_RECOVERY_ANCHORS.values()))


if __name__ == "__main__":
    unittest.main()
