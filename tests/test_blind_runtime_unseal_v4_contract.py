from __future__ import print_function
import hashlib
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v4.json")
V3 = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v3.json")


def load(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


class BlindRuntimeUnsealV4ContractTest(unittest.TestCase):
    def test_v3_is_preserved_and_pinned(self):
        contract = load(PATH)
        with open(V3, "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        self.assertEqual(digest, contract["supersedes"]["sha256"])

    def test_receipt_digest_is_external_not_self_referential(self):
        receipt = load(PATH)["allowed_receipt"]
        self.assertNotIn("receipt_sha256", receipt["envelope_fields"])
        self.assertIn("external", receipt["receipt_digest_location"])
        self.assertTrue(receipt["forbid_self_referential_digest"])

    def test_reference_definition_and_decision_rule_agree(self):
        contract = load(PATH)
        self.assertIn("path-backed", contract["one_shot_protocol"]["executed_stage_reference_definition"])
        self.assertIn("executed_stage_reference_count",
                      contract["decision_rules"]["R07"]["pass_when"])
        self.assertIn("executed_stage_reference_count",
                      contract["allowed_receipt"]["circuit_row_fields"])

    def test_consumption_marker_precedes_blind_read(self):
        protocol = load(PATH)["one_shot_protocol"]
        self.assertIn("before the first BLIND data read",
                      protocol["consumption_order"])
        self.assertIn("exclusive-create", protocol["consumption_order"])
        self.assertIn("marker already exists", protocol["failure_action"])


if __name__ == "__main__":
    unittest.main()
