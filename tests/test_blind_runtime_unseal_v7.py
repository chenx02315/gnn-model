import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("blind_unseal_v7", ROOT / "src" / "data" / "run_blind_unseal_v7.py")
V7 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V7)


class BlindUnsealV7Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name
        self.output = os.path.join(self.root, "out")
        os.mkdir(self.output)
        self.contract = {
            "scope": {"blind_circuits": ["x"], "formal_runtime_membership_sha256": "membership", "method_registry_sha256": "registry"},
            "allowed_receipt": {"envelope_fields": ["schema_version", "status", "formal_runtime_membership_sha256", "method_registry_sha256", "tool_set_sha256", "contract_sha256", "circuits", "failure_code"], "circuit_row_fields": ["circuit", "executed_stage_reference_count", "unique_runtime_join_count", "missing_runtime_join_count", "ambiguous_runtime_join_count", "coverage_rate", "frozen_runtime_eligible_action_space_sha256", "source_artifact_set_sha256"]}
        }
        self.contract_sha, self.tool_sha = "contract", "tool"

    def tearDown(self):
        self.temp.cleanup()

    def _consumed(self):
        V7._exclusive_write(os.path.join(self.output, "CONSUMED"), V7._json_bytes({"schema_version": "blind-runtime-unseal-consumed-v7", "status": "CONSUMED", "contract_sha256": self.contract_sha, "tool_set_sha256": self.tool_sha}))

    def _pass_receipt(self):
        return {"schema_version": "blind-runtime-unseal-receipt-v7", "status": "PASS", "formal_runtime_membership_sha256": "membership", "method_registry_sha256": "registry", "tool_set_sha256": self.tool_sha, "contract_sha256": self.contract_sha, "circuits": [{"circuit": "x", "executed_stage_reference_count": 1, "unique_runtime_join_count": 1, "missing_runtime_join_count": 0, "ambiguous_runtime_join_count": 0, "coverage_rate": 1.0, "frozen_runtime_eligible_action_space_sha256": "a", "source_artifact_set_sha256": "b"}]}

    def test_non_lsf_refused(self):
        previous = dict(os.environ)
        try:
            os.environ.pop("LSB_JOBID", None)
            with self.assertRaisesRegex(V7.Refusal, "LSF_ENVIRONMENT_REQUIRED"):
                V7._require_lsf({"registration": {"job_id": "9"}})
        finally:
            os.environ.clear(); os.environ.update(previous)

    def test_wrong_job_id_refused(self):
        previous = dict(os.environ)
        try:
            os.environ["LSB_JOBID"] = "8"; os.environ["LSB_JOBINDEX"] = "0"
            with self.assertRaisesRegex(V7.Refusal, "LSF_JOB_ID_MISMATCH"):
                V7._require_lsf({"registration": {"job_id": "9"}})
        finally:
            os.environ.clear(); os.environ.update(previous)

    def test_missing_review_receipt_refused(self):
        with self.assertRaises(FileNotFoundError):
            V7._verify_review(self.root, {"review_gate": {"receipt": "missing.json"}}, "x", {"registration": {"job_id": "1"}}, {})

    def test_existing_consumed_is_not_replayable(self):
        self._consumed()
        with self.assertRaises(FileExistsError):
            V7._exclusive_write(os.path.join(self.output, "CONSUMED"), b"again")

    def test_release_and_semantic_verification(self):
        self._consumed()
        V7._write_release(self.root, self.contract, self.contract_sha, self.tool_sha, self.output, self._pass_receipt())
        self.assertTrue(V7._verify_release(self.root, self.contract, self.contract_sha, self.tool_sha, self.output))

    def test_release_rejects_bad_sidecar(self):
        self._consumed()
        V7._write_release(self.root, self.contract, self.contract_sha, self.tool_sha, self.output, self._pass_receipt())
        pathlib.Path(self.output, "receipt.json.sha256").write_text("0" * 64 + "  receipt.json\n", encoding="ascii")
        self.assertFalse(V7._verify_release(self.root, self.contract, self.contract_sha, self.tool_sha, self.output))

    def test_fixed_argv_refuses_extra(self):
        self.assertEqual(V7.main(["--bundle-root", self.root, "--extra"]), 2)

    def test_contract_is_explicitly_pending(self):
        contract = json.loads((ROOT / "contracts" / "blind_runtime_unseal_v7.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["status"], "SEALED_PENDING_REGISTRATION_AND_REVIEW")
        self.assertEqual(contract["inputs"]["job_spec_sha256"], "PENDING_REGISTRATION")

    def test_dirty_commit_is_refused_before_blob_checks(self):
        def fake_git(_root, *args):
            if args == ("status", "--porcelain"):
                return " M contract.json"
            return ""
        with mock.patch.object(V7, "_git", side_effect=fake_git):
            with self.assertRaisesRegex(V7.Refusal, "GIT_DIRTY"):
                V7._require_clean_git(self.root, {"reviewed_commit": "a" * 40}, {})

    def test_hash_drift_is_refused(self):
        target = pathlib.Path(self.root, "artifact.py")
        target.write_text("actual", encoding="ascii")
        def fake_git(_root, *args):
            if args == ("status", "--porcelain"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return "b" * 40
            if args == ("rev-parse", "a" * 40):
                return "a" * 40
            if args == ("merge-base", "--is-ancestor", "a" * 40, "b" * 40):
                return ""
            if args == ("show", "a" * 40 + ":artifact.py"):
                return "expected"
            raise AssertionError(args)
        with mock.patch.object(V7, "_git", side_effect=fake_git), mock.patch.object(V7, "_resolve", return_value=str(target)):
            with self.assertRaisesRegex(V7.Refusal, "REVIEWED_BLOB_OR_WORKTREE_DRIFT"):
                V7._require_clean_git(self.root, {"reviewed_commit": "a" * 40}, {"artifact.py": "0" * 64})


if __name__ == "__main__":
    unittest.main()
