from __future__ import print_function

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "src", "data")
sys.path.insert(0, DATA)

import bootstrap_blind_unseal_v6 as bootstrap
import run_blind_unseal_v5 as core
import run_blind_unseal_v6 as runner


def load(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def put(path, payload, binary=False):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8", "newline": "\n"}
    with open(path, mode, **kwargs) as stream:
        stream.write(payload)


class BlindUnsealV6Test(unittest.TestCase):
    def setUp(self):
        self.contract_path = os.path.join(ROOT, "contracts", "blind_runtime_unseal_v6.json")
        self.contract = load(self.contract_path)

    def test_bootstrap_and_runner_have_safe_top_level_imports(self):
        allowed = {"__future__", "argparse", "hashlib", "importlib", "json", "os", "re", "subprocess", "sys"}
        for filename in ("bootstrap_blind_unseal_v6.py", "run_blind_unseal_v6.py"):
            with open(os.path.join(DATA, filename), encoding="utf-8") as stream:
                tree = ast.parse(stream.read())
            imported = set()
            for node in tree.body:
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imported.add((node.module or "").split(".")[0])
            self.assertTrue(imported.issubset(allowed), (filename, imported - allowed))

    def test_pinned_artifacts_and_static_gate_pass_before_review(self):
        bootstrap.verify_artifacts(ROOT, self.contract["bootstrap"]["reviewed_artifact_sha256"])
        job, split = bootstrap.validate_static_gate(ROOT, self.contract)
        self.assertEqual(["s9234", "s38584", "wb_dma"],
                         [row["circuit"] for row in job["circuits"]])
        self.assertTrue(split["sealed_blind_test"])

    def test_external_bootstrap_sidecar_matches(self):
        sidecar_path = os.path.join(ROOT, *self.contract["bootstrap"]["external_checksum_sidecar"].split("/"))
        with open(sidecar_path, encoding="ascii") as stream:
            fields = stream.read().strip().split()
        self.assertEqual("src/data/bootstrap_blind_unseal_v6.py", fields[1])
        self.assertEqual(fields[0], bootstrap.sha256_file(os.path.join(ROOT, *fields[1].split("/"))))
        self.assertEqual(bootstrap.sha256_file(sidecar_path),
                         self.contract["bootstrap"]["external_checksum_sidecar_sha256"])

    def test_helper_mismatch_refuses_before_dynamic_import(self):
        with mock.patch.object(bootstrap, "verify_artifacts",
                               side_effect=bootstrap.BootstrapError("ARTIFACT_DIGEST_MISMATCH")), \
                mock.patch.object(bootstrap.importlib, "import_module") as imported:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "ARTIFACT_DIGEST_MISMATCH"):
                bootstrap.bootstrap(ROOT)
            imported.assert_not_called()

    def test_unresolved_valid_looking_review_commit_is_rejected(self):
        commit = "c" * 40
        with tempfile.TemporaryDirectory() as work:
            contract_path = os.path.join(work, "contract.json")
            put(contract_path, "{}\n")
            contract_sha = bootstrap.sha256_file(contract_path)
            review = {"status": "PASS", "execution_allowed": True,
                      "contract_sha256": contract_sha, "reviewed_artifacts": {},
                      "reviewed_commit": commit}
            put(os.path.join(work, "review.json"), json.dumps(review))
            contract = {"review_gate": {"receipt": "review.json"}}
            answers = [work.encode("utf-8") + b"\n", ("d" * 40).encode("ascii") + b"\n"]
            with mock.patch.object(bootstrap, "git_bytes", side_effect=answers):
                with self.assertRaisesRegex(bootstrap.BootstrapError,
                                            "REVIEW_COMMIT_UNRESOLVED"):
                    bootstrap.verify_review(work, contract_path, contract, {})

    def test_direct_runner_refuses_without_project_import(self):
        result = subprocess.run([sys.executable, os.path.join(DATA, "run_blind_unseal_v6.py")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        self.assertEqual(2, result.returncode)
        self.assertIn("REFUSED_USE_BOOTSTRAP_V6", result.stdout)

    def valid_receipt(self, contract_sha, tool_sha):
        rows = []
        for circuit in self.contract["scope"]["blind_circuits"]:
            rows.append({
                "circuit": circuit, "executed_stage_reference_count": 1,
                "unique_runtime_join_count": 1, "missing_runtime_join_count": 0,
                "ambiguous_runtime_join_count": 0, "coverage_rate": 1.0,
                "frozen_runtime_eligible_action_space_sha256": "a" * 64,
                "source_artifact_set_sha256": "b" * 64
            })
        return {
            "schema_version": "blind-runtime-unseal-receipt-v6", "status": "PASS",
            "formal_runtime_membership_sha256": self.contract["scope"]["formal_runtime_membership_sha256"],
            "method_registry_sha256": self.contract["scope"]["method_registry_sha256"],
            "tool_set_sha256": tool_sha, "contract_sha256": contract_sha,
            "circuits": rows
        }

    def make_release(self, work):
        contract_sha = bootstrap.sha256_file(self.contract_path)
        tool_sha = core.tool_set_sha256(self.contract["bootstrap"]["reviewed_artifact_sha256"])
        consumed = json.dumps({
            "schema_version": "blind-runtime-unseal-consumed-v6", "status": "CONSUMED",
            "contract_sha256": contract_sha, "tool_set_sha256": tool_sha
        }, sort_keys=True).encode("utf-8") + b"\n"
        core.durable_exclusive_write(os.path.join(work, "CONSUMED"), consumed)
        runner.release(core, work, self.valid_receipt(contract_sha, tool_sha))
        return contract_sha, tool_sha

    def test_semantic_release_verifier_accepts_only_complete_bound_state(self):
        with tempfile.TemporaryDirectory() as work:
            contract_sha, tool_sha = self.make_release(work)
            self.assertTrue(runner.verify_release(work, self.contract, contract_sha, tool_sha))
            put(os.path.join(work, "CONSUMED"), b"{}\n", binary=True)
            self.assertFalse(runner.verify_release(work, self.contract, contract_sha, tool_sha))
        with tempfile.TemporaryDirectory() as work:
            contract_sha, tool_sha = self.make_release(work)
            released_path = os.path.join(work, "RELEASED")
            released = load(released_path)
            released["contract_sha256"] = "0" * 64
            put(released_path, json.dumps(released))
            self.assertFalse(runner.verify_release(work, self.contract, contract_sha, tool_sha))

    def test_semantic_release_verifier_rejects_schema_or_field_splice(self):
        with tempfile.TemporaryDirectory() as work:
            contract_sha, tool_sha = self.make_release(work)
            receipt_path = os.path.join(work, "receipt.json")
            receipt = load(receipt_path)
            receipt["elapsed"] = 1.25
            payload = json.dumps(receipt, ensure_ascii=False, indent=2,
                                 sort_keys=True).encode("utf-8") + b"\n"
            put(receipt_path, payload, binary=True)
            digest = hashlib.sha256(payload).hexdigest()
            put(os.path.join(work, "receipt.json.sha256"), digest + "  receipt.json\n")
            put(os.path.join(work, "RELEASED"),
                runner.release_marker_payload(contract_sha, digest), binary=True)
            self.assertFalse(runner.verify_release(work, self.contract, contract_sha, tool_sha))


if __name__ == "__main__":
    unittest.main()
