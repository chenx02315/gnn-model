import copy
import json
import pathlib
import tempfile
import unittest

from src.data.validate_blind_inventory_review_v12 import RECEIPT, validate


REPO = pathlib.Path(__file__).resolve().parents[1]


class BlindInventoryReviewV12Tests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        for relative in (RECEIPT, "contracts/blind_inventory_independent_review_v12_request.json"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / relative).read_bytes())
        return temporary, root

    def test_checked_in_failure_receipt_is_valid_and_non_authorizing(self):
        result = validate(str(REPO))
        self.assertEqual(result, {"status": "FAIL", "p0_unlocked": False, "execution_allowed": False})

    def test_pass_or_authority_escalation_is_invalid(self):
        for field in ("execution_allowed", "training_allowed", "p0_unlocked"):
            temporary, root = self.fixture()
            try:
                path = root / RECEIPT
                receipt = json.loads(path.read_text(encoding="utf-8"))
                receipt[field] = True
                path.write_text(json.dumps(receipt), encoding="utf-8")
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "AUTHORITY"):
                    validate(str(root))
            finally:
                temporary.cleanup()

        temporary, root = self.fixture()
        try:
            path = root / RECEIPT
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["status"] = "PASS"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "STATUS"):
                validate(str(root))
        finally:
            temporary.cleanup()

    def test_removing_material_finding_is_invalid(self):
        temporary, root = self.fixture()
        try:
            path = root / RECEIPT
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["findings"] = receipt["findings"][1:]
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "FINDINGS"):
                validate(str(root))
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
