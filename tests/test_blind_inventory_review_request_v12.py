import copy
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from src.data.validate_blind_inventory_review_request_v12 import REQUEST_PATH, validate


REPO = pathlib.Path(__file__).resolve().parents[1]


class BlindInventoryReviewRequestV12Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        request_path = self.root / REQUEST_PATH
        request_path.parent.mkdir(parents=True)
        request_path.write_bytes((REPO / REQUEST_PATH).read_bytes())
        self.request_path = request_path
        self.request = json.loads(request_path.read_text(encoding="utf-8"))
        self.blobs = {
            relative: (REPO / relative).read_bytes()
            for relative in self.request["reviewed_artifacts"]
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write_request(self, request):
        self.request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")

    def validate_with_frozen_blobs(self):
        with mock.patch(
            "src.data.validate_blind_inventory_review_request_v12._git_blob",
            side_effect=lambda root, commit, relative: self.blobs[relative],
        ):
            return validate(str(self.root))

    def test_checked_in_request_is_pending_and_has_no_authority(self):
        result = self.validate_with_frozen_blobs()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["review_status"], "PENDING_INDEPENDENT_READ_ONLY_REVIEW")
        self.assertFalse(result["execution_allowed"])

    def test_premature_pass_or_authority_escalation_refuses(self):
        for path, value in (
            (("status",), "PASS"),
            (("execution_allowed_before_review_pass",), True),
            (("held_job_registration_allowed",), True),
            (("training_allowed",), True),
            (("future_pass_requirements", "execution_allowed"), True),
        ):
            mutated = copy.deepcopy(self.request)
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.write_request(mutated)
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate_with_frozen_blobs()

    def test_commit_or_blob_substitution_refuses(self):
        mutated = copy.deepcopy(self.request)
        mutated["review_target_commit"] = "a" * 40
        self.write_request(mutated)
        with self.assertRaisesRegex(ValueError, "FUTURE_COMMIT_BINDING"):
            self.validate_with_frozen_blobs()

        self.write_request(self.request)
        relative = next(iter(self.blobs))
        original = self.blobs[relative]
        self.blobs[relative] = original + b"\n"
        with self.assertRaisesRegex(ValueError, "ARTIFACT_BLOB"):
            self.validate_with_frozen_blobs()

    def test_artifact_set_substitution_refuses(self):
        mutated = copy.deepcopy(self.request)
        digest = mutated["reviewed_artifacts"].pop("tests/test_blind_unseal_v12_design.py")
        mutated["reviewed_artifacts"]["tests/substitute.py"] = digest
        self.write_request(mutated)
        with self.assertRaisesRegex(ValueError, "REVIEWED_ARTIFACTS"):
            self.validate_with_frozen_blobs()

    def test_required_security_check_cannot_be_removed(self):
        mutated = copy.deepcopy(self.request)
        mutated["required_checks"] = [
            item for item in mutated["required_checks"]
            if "public API exposes no injected orderer" not in item
        ]
        self.write_request(mutated)
        with self.assertRaisesRegex(ValueError, "REQUIRED_CHECK"):
            self.validate_with_frozen_blobs()


if __name__ == "__main__":
    unittest.main()
