import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import build_runtime_recovery_closeout_v10 as closeout


class RuntimeRecoveryCloseoutV10Test(unittest.TestCase):
    def copy_sources(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        for relative in closeout.SOURCES.values():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return temporary, root

    def test_checked_in_closeout_rebuilds_byte_identically(self):
        expected = (ROOT / "data" / "manifests" / "runtime_recovery_closeout_v10.json").read_text(encoding="utf-8")
        self.assertEqual(expected, closeout._canonical(closeout.build_closeout(str(ROOT))))

    def assert_mutation_rejected(self, label, mutate):
        temporary, root = self.copy_sources()
        try:
            path = root / closeout.SOURCES[label]
            payload = json.loads(path.read_text(encoding="utf-8"))
            mutate(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(closeout.CloseoutError, "^SOURCE_DIGEST_" + label + "$"):
                closeout.build_closeout(str(root))
        finally:
            temporary.cleanup()

    def test_each_source_state_or_count_drift_hits_its_own_digest_gate(self):
        self.assert_mutation_rejected("nonblind_join_audit", lambda item: item["aggregate"].update({"ambiguity_count": 1}))
        self.assert_mutation_rejected("source_ledger", lambda item: item["external_readback"].update({"matched_count": 72}))
        self.assert_mutation_rejected("blind_inventory", lambda item: item["circuits"]["s9234"].update({"driver_log_count": 1}))
        self.assert_mutation_rejected("v10_failure", lambda item: item.update({"exit_code": 0}))
        self.assert_mutation_rejected("gate_assessment", lambda item: item["checks"]["R07"].update({"status": "PASS"}))

    def test_semantic_attacks_cannot_sync_the_derived_closeout_digest(self):
        self.assert_mutation_rejected("nonblind_join_audit", lambda item: item.update({"formal_runtime_membership_sha256": "0" * 64}))
        self.assert_mutation_rejected("blind_inventory", lambda item: item["circuits"]["s9234"].update({"driver_log_file_set_sha256": "0" * 64}))


if __name__ == "__main__":
    unittest.main()
