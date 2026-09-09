from __future__ import print_function

import hashlib
import json
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "data"))

import validate_blind_unseal_preflight_v5 as preflight


V5 = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v5.json")
V4 = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v4.json")
JOB = os.path.join(ROOT, "contracts", "blind_runtime_unseal_job_v5.json")
SPLIT = os.path.join(ROOT, "contracts", "data_split_v1.json")


def load(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


class BlindRuntimeUnsealV5ContractTest(unittest.TestCase):
    def test_current_static_preflight_passes_without_blind_read(self):
        result = preflight.validate(ROOT)
        self.assertEqual("PASS", result["status"])
        self.assertFalse(result["blind_data_read"])
        self.assertFalse(result["candidate_join_performed"])
        self.assertTrue(result["checks"]["no_blind_read_in_preflight"])

    def test_v4_is_preserved_and_pinned(self):
        contract = load(V5)
        self.assertEqual(digest(V4), contract["supersedes"]["sha256"])
        self.assertEqual("contracts/blind_runtime_unseal_v4.json",
                         contract["supersedes"]["contract"])

    def test_tool_job_and_split_digests_are_pinned(self):
        contract = load(V5)
        self.assertEqual(digest(JOB), contract["inputs"]["job_spec_sha256"])
        self.assertEqual(digest(SPLIT), contract["scope"]["split_contract_sha256"])
        for relative_path, expected in contract["toolchain"]["artifact_sha256"].items():
            self.assertEqual(digest(os.path.join(ROOT, *relative_path.split("/"))), expected,
                             relative_path)

    def test_contract_requires_durable_complete_release(self):
        protocol = load(V5)["one_shot_protocol"]
        self.assertEqual(["CONSUMED", "receipt.json", "receipt.json.sha256", "RELEASED"],
                         protocol["required_release_artifacts"])
        self.assertIn("MISSING_RESULT_PATH", protocol["executed_stage_reference_definition"])


if __name__ == "__main__":
    unittest.main()
