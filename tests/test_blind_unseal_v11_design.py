import copy
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import validate_blind_unseal_v11_design as validator


class BlindUnsealV11DesignTest(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "contracts" / "blind_runtime_unseal_v11_design.json"
        self.contract = json.loads(self.path.read_text(encoding="utf-8"))

    def validate_mutation(self, mutate):
        payload = copy.deepcopy(self.contract)
        mutate(payload)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "contract.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(validator.DesignError):
                validator.validate_design(str(ROOT), str(path))

    def test_design_is_valid_but_never_authorizes_execution(self):
        receipt = validator.validate_design(str(ROOT), str(self.path))
        self.assertEqual("PASS_DESIGN_ONLY", receipt["status"])
        self.assertFalse(receipt["execution_authorized"])
        self.assertFalse(receipt["blind_read_allowed"])
        self.assertFalse(receipt["training_allowed"])
        self.assertEqual(7, receipt["failure_stage_count"])

    def test_authority_gate_and_one_shot_semantics_fail_closed(self):
        self.validate_mutation(lambda value: value["authority"].update(execution_authorized=True))
        self.validate_mutation(lambda value: value["required_pre_execution_gates"].remove("INDEPENDENT_REVIEW_PASS"))
        self.validate_mutation(lambda value: value["failure_taxonomy"][0].update(retryable=True))
        self.validate_mutation(lambda value: value["pre_consumption_refusal"].update(creates_public_failure_receipt=True))
        self.validate_mutation(lambda value: value["non_reuse_rules"].update(job_388761_must_not_be_retried_or_requeued=False))
        self.validate_mutation(lambda value: value["p0"]["remaining_gates"].update(R07="PASS"))

    def test_failure_taxonomy_and_public_receipt_privacy_fail_closed(self):
        self.validate_mutation(lambda value: value["failure_taxonomy"][0].update(code="SEALED_AUDIT_FAILED"))
        self.validate_mutation(lambda value: value["failure_taxonomy"].append(copy.deepcopy(value["failure_taxonomy"][0])))
        self.validate_mutation(lambda value: value["public_failure_receipt"]["exact_fields"].append("exception_text"))
        self.validate_mutation(lambda value: value["public_failure_receipt"]["exact_fields"].remove("tool_set_sha256"))
        self.validate_mutation(lambda value: value["public_failure_receipt"]["binding_rules"].update(contract_sha256="CURRENT_FILE_DIGEST"))
        self.validate_mutation(lambda value: value["public_failure_receipt"].update(scope="PRE_AND_POST_CONSUMPTION"))
        self.validate_mutation(lambda value: value["public_failure_receipt"]["forbidden_fields"].remove("wall_time"))
        self.validate_mutation(lambda value: value["public_failure_receipt"].update(required_circuits=[{"circuit": "partial"}]))
        self.validate_mutation(lambda value: value["synthetic_failure_fixture"].update(embedded_receipt_is_public_evidence=True))
        self.validate_mutation(lambda value: value["synthetic_failure_fixture"].update(contract_sha256="0" * 64))

    def test_frozen_input_digests_are_trust_anchors(self):
        self.validate_mutation(lambda value: value["frozen_inputs"]["v10_failure_audit"].update(sha256="0" * 64))
        self.validate_mutation(lambda value: value["frozen_inputs"]["v10_runner_reference"].update(path="src/data/run_blind_unseal_v9.py"))


if __name__ == "__main__":
    unittest.main()
