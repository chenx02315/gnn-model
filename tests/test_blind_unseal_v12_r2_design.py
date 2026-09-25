import json
import pathlib
import shutil
import tempfile
import unittest

from src.data.validate_blind_unseal_v12_r2_design import validate


ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = (
    "contracts/blind_runtime_unseal_v12_r2_design.json",
    "src/data/blind_inventory_v12_r2.py",
    "tests/test_blind_inventory_v12_r2.py",
    "tests/test_blind_inventory_v12_r2_linux.py",
    "data/manifests/blind_inventory_v12_r2_linux_gate_execution.json",
    "data/manifests/blind_inventory_v12_r2_linux_gate_execution.log",
    "data/manifests/blind_inventory_v12_r2_linux_gate_closeout.json",
)


class BlindUnsealV12R2DesignTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        for relative in FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return temporary, root

    def test_checked_in_synthetic_linux_validation_passes_without_authority(self):
        self.assertEqual(validate(str(ROOT)), {"status": "PASS", "execution_authorized": False, "training_allowed": False})

    def test_module_digest_mutation_refuses(self):
        temporary, root = self.fixture()
        try:
            module = root / "src/data/blind_inventory_v12_r2.py"
            module.write_bytes(module.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "DIGEST_INVENTORY_MODULE"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_authority_escalation_refuses(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_runtime_unseal_v12_r2_design.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["authority"]["training_allowed"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "AUTHORITY_TRAINING_ALLOWED"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_contract_cannot_claim_external_review_binding(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_runtime_unseal_v12_r2_design.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["external_review_request_binding"] = "SELF_ASSERTED"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EXTERNAL_REVIEW_BINDING"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_contract_cannot_revert_linux_platform_evidence(self):
        temporary, root = self.fixture()
        try:
            path = root / "contracts/blind_runtime_unseal_v12_r2_design.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["platform_positive_integration"] = "PENDING_LINUX_ONLY"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "PLATFORM_STATE"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_linux_execution_receipt_mutation_refuses(self):
        temporary, root = self.fixture()
        try:
            path = root / "data/manifests/blind_inventory_v12_r2_linux_gate_execution.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["gate_summary"]["gate_pass"] = False
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DIGEST_LINUX_EXECUTION_RECEIPT"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_closeout_cannot_authorize_training(self):
        temporary, root = self.fixture()
        try:
            path = root / "data/manifests/blind_inventory_v12_r2_linux_gate_closeout.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["authority"]["training"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CLOSEOUT_AUTHORITY"):
                validate(str(root))
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
