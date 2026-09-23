import json
import pathlib
import shutil
import tempfile
import unittest

from src.data.validate_blind_inventory_ordering_v2 import validate


ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = (
    "contracts/blind_inventory_ordering_v2.json",
    "data/manifests/blind_input_inventory_freeze_v1.json",
    "data/manifests/blind_input_inventory_freeze_v2.json",
    "data/manifests/blind_runtime_unseal_v11_failure_20260923.json",
    "data/manifests/blind_inventory_drift_provenance_v1.json",
)


class BlindInventoryOrderingV2Tests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        for relative in FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return temporary, root

    def test_repository_evidence_passes(self):
        self.assertEqual(validate(str(ROOT))["status"], "PASS")

    def test_mutated_bytewise_digest_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "data/manifests/blind_input_inventory_freeze_v2.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["circuits"]["s9234"]["bytewise_ordered_sha256"] = "0" * 64
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "BYTEWISE_DIGEST_s9234"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_authority_escalation_is_rejected(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_inventory_ordering_v2.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["execution_authorized"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EXECUTION_AUTHORITY"):
                validate(str(root))
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
