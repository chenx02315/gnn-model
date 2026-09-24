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

    def test_checked_in_design_is_design_only_and_passes(self):
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


if __name__ == "__main__":
    unittest.main()
