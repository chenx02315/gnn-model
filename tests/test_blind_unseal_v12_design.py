import json
import pathlib
import shutil
import tempfile
import unittest

from src.data.validate_blind_unseal_v12_design import validate


ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = (
    "contracts/blind_runtime_unseal_v12_design.json",
    "contracts/blind_inventory_ordering_v2.json",
    "data/manifests/blind_input_inventory_freeze_v2.json",
    "data/manifests/blind_inventory_drift_provenance_v1.json",
    "data/manifests/blind_runtime_unseal_v11_failure_20260923.json",
    "src/data/blind_inventory_v12.py",
    "tests/test_blind_inventory_v12.py",
)


class BlindUnsealV12DesignTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        for relative in FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return temporary, root

    def test_checked_in_design_passes_without_execution_authority(self):
        result = validate(str(ROOT))
        self.assertEqual(result, {"status": "PASS", "execution_authorized": False, "training_allowed": False})

    def test_frozen_input_digest_mutation_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "data/manifests/blind_input_inventory_freeze_v2.json"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "DIGEST_DUAL_INVENTORY"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_execution_authority_escalation_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_runtime_unseal_v12_design.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["execution_authorized"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EXECUTION_AUTHORITY"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_inventory_module_digest_mutation_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "src/data/blind_inventory_v12.py"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "DIGEST_INVENTORY_MODULE"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_single_lane_acceptance_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_runtime_unseal_v12_design.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["inventory_algorithm"]["acceptance"] = "Historical lane only."
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DUAL_ACCEPTANCE"):
                validate(str(root))
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
