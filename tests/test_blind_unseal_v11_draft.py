import copy
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import validate_blind_unseal_v11_draft as validator


class BlindUnsealV11DraftTest(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "contracts" / "blind_runtime_unseal_v11_draft.json"
        self.draft = json.loads(self.path.read_text(encoding="utf-8"))

    def assert_rejected(self, mutate):
        payload = copy.deepcopy(self.draft)
        mutate(payload)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "draft.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(validator.DraftError):
                validator.load_draft(str(ROOT), str(path))

    def test_draft_validates_but_authorizes_nothing(self):
        draft = validator.load_draft(str(ROOT), str(self.path))
        self.assertEqual("DRAFT_NO_EXECUTION", draft["status"])
        self.assertEqual({
            "execution_authorized": False, "blind_read_allowed": False,
            "lsf_registration_allowed": False, "training_allowed": False,
        }, draft["authority"])

    def test_draft_rejects_authority_and_finalization_shortcuts(self):
        self.assert_rejected(lambda d: d["authority"].update(execution_authorized=True))
        self.assert_rejected(lambda d: d["authority"].update(blind_read_allowed=True))
        self.assert_rejected(lambda d: d["draft_bindings"].update(job_spec="v10"))
        self.assert_rejected(lambda d: d["draft_bindings"].update(final_contract_sha256="0" * 64))
        self.assert_rejected(lambda d: d["p0"]["remaining_gates"].update(R07="PASS"))

    def test_v10_reuse_and_receipt_privacy_are_not_optional(self):
        self.assert_rejected(lambda d: d["v10_non_reuse"].update(retry_requeue_rerun_forbidden=False))
        self.assert_rejected(lambda d: d["v10_non_reuse"].update(job_id="388762"))
        self.assert_rejected(lambda d: d["public_failure_receipt"]["exact_fields"].append("exception_text"))
        self.assert_rejected(lambda d: d["public_failure_receipt"]["forbidden_fields"].remove("source_path"))
        self.assert_rejected(lambda d: d["post_consumption_failure_taxonomy"].pop())


if __name__ == "__main__":
    unittest.main()
