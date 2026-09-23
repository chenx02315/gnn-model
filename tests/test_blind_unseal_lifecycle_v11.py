import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLE = "/temp/jiangchuanc/blind_runtime_unseal_v11_bundle"
ARGV = ["python3", BUNDLE + "/src/data/run_blind_unseal_v11_final.py", "--bundle-root", BUNDLE]
sys.path.insert(0, str(ROOT / "src" / "data"))
from build_blind_unseal_lifecycle_v11 import (LifecycleError, build_final_job_spec,
    build_independent_review, build_registration_receipt, canonical_bytes,
    finalize_contract, materialize_final_template, sha256_bytes,
    validate_one_way_lifecycle, verify_implementation_freeze)


class BlindUnsealLifecyclev11Test(unittest.TestCase):
    def setUp(self):
        materialized_contract = json.loads((ROOT / "contracts" / "blind_runtime_unseal_v11.json").read_text())
        freeze_commit = materialized_contract.get("lifecycle", {}).get("implementation_freeze_commit")
        if freeze_commit:
            self.draft_template = json.loads(subprocess.check_output(("git", "show", freeze_commit + ":contracts/blind_runtime_unseal_job_v11_template.json"), cwd=str(ROOT)).decode())
            self.draft_contract = json.loads(subprocess.check_output(("git", "show", freeze_commit + ":contracts/blind_runtime_unseal_v11.json"), cwd=str(ROOT)).decode())
        else:
            self.draft_template = json.loads((ROOT / "contracts" / "blind_runtime_unseal_job_v11_template.json").read_text())
            self.draft_contract = materialized_contract
        self.tmp = tempfile.TemporaryDirectory(); self.repo = pathlib.Path(self.tmp.name)
        (self.repo / "src" / "data").mkdir(parents=True); (self.repo / "contracts").mkdir()
        for name in ("build_blind_unseal_lifecycle_v11.py", "run_blind_unseal_v11_final.py",
                     "validate_blind_unseal_registration_v11.py", "validate_blind_unseal_scheduler_audit_v11.py"):
            (self.repo / "src" / "data" / name).write_bytes((ROOT / "src" / "data" / name).read_bytes())
        self.runner = self.repo / "src" / "data" / "run_blind_unseal_v11_final.py"
        self.external_manifest_path = str(self.repo.parent / (self.repo.name + "-control-manifest.json"))
        self.constant_patches = [
            mock.patch("build_blind_unseal_lifecycle_v11.EXPECTED_EXTERNAL_CONTROL_MANIFEST", self.external_manifest_path),
            mock.patch("validate_blind_unseal_registration_v11.EXPECTED_EXTERNAL_CONTROL_MANIFEST", self.external_manifest_path),
            mock.patch("validate_blind_unseal_registration_v11.verify_staged_bundle", return_value="synthetic-staging-verified"),
        ]
        for patcher in self.constant_patches: patcher.start()
        for command in (("git", "init", "-q"), ("git", "config", "user.email", "synthetic@example.invalid"),
                        ("git", "config", "user.name", "Synthetic"),
                        ("git", "config", "core.autocrlf", "false"), ("git", "add", "."),
                        ("git", "commit", "-qm", "implementation freeze")):
            subprocess.check_call(command, cwd=str(self.repo))
        self.commit = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=str(self.repo)).decode().strip()
        self.artifacts = {"src/data/run_blind_unseal_v11_final.py": sha256_bytes(self.runner.read_bytes())}
        self.held = {"job_id": "812345", "git_commit": self.commit,
          "command_argv": ARGV,
          "queue": "normal", "resource_request": "select[type==X]", "cwd": BUNDLE,
          "stdout_path": "/evidence/stdout.log", "stderr_path": "/evidence/stderr.log"}
        self.roots = {name: str(self.repo / "sealed" / name) for name in ("s9234", "s38584", "wb_dma")}
        self.raw = ("812345^PSUSP^owner^normal^" + " ".join(ARGV) + "^host^opaque-time^select[type==X]^/evidence/stdout.log^/evidence/stderr.log^" + BUNDLE + "\n").encode("utf-8")
        self.global_raw = self.raw + b"9^PSUSP^other^normal^other^host^t^-^/x^/y^/z\n"
        self.raw_al = ("Job <812345>, Status <PSUSP>\nSpecified CWD <" + BUNDLE + ">\n").encode("utf-8")
        self.manifest = b""

    def tearDown(self):
        for patcher in reversed(self.constant_patches): patcher.stop()
        if os.path.exists(self.external_manifest_path): os.unlink(self.external_manifest_path)
        self.tmp.cleanup()

    def _bundle(self):
        self.assertTrue(verify_implementation_freeze(str(self.repo), self.commit, self.artifacts))
        template = materialize_final_template(self.draft_template, self.held, self.roots); tb = canonical_bytes(template)
        contract = finalize_contract(self.draft_contract, tb, self.commit, self.artifacts)
        # The runner checks every frozen input itself.  These are synthetic bytes,
        # never measurements, and make the E2E call exercise that real gate.
        frozen = {
          "contracts/blind_runtime_unseal_protocol_v7.json": b"{}\n",
          "data/manifests/blind_gate_snapshot_v1.json": b"{}\n",
          "data/manifests/lsf_probe_v8_20260910.json": b"{}\n",
          "contracts/data_split_v1.json": b"{}\n",
          "data/manifests/blind_input_inventory_freeze_v1.json": canonical_bytes({"circuits": {
              name: {"measurement_file_set_sha256": "1" * 64,
                     "driver_log_file_set_sha256": "2" * 64,
                     "driver_log_count": 0}
              for name in ("s9234", "s38584", "wb_dma")}})}
        for relative, payload in frozen.items():
            path = self.repo / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(payload)
        contract["protocol"]["sha256"] = sha256_bytes(frozen[contract["protocol"]["path"]])
        contract["gate_snapshot"]["sha256"] = sha256_bytes(frozen[contract["gate_snapshot"]["path"]])
        contract["scheduler_fixture"]["sha256"] = sha256_bytes(frozen[contract["scheduler_fixture"]["path"]])
        contract["scope"]["split_contract_sha256"] = sha256_bytes(frozen[contract["scope"]["split_contract"]])
        contract["inputs"]["inventory_freeze_receipt_sha256"] = sha256_bytes(frozen[contract["inputs"]["inventory_freeze_receipt"]])
        manifest_paths = tuple(sorted(list(frozen) + [
            "src/data/build_blind_unseal_lifecycle_v11.py",
            "src/data/run_blind_unseal_v11_final.py",
            "src/data/validate_blind_unseal_registration_v11.py",
            "src/data/validate_blind_unseal_scheduler_audit_v11.py",
        ]))
        manifest = {"schema_version": "blind-runtime-unseal-control-manifest-v11",
                    "bundle_root": str(self.repo), "freeze_commit": self.commit,
                    "files": [{"path": relative, "sha256": sha256_bytes((self.repo / relative).read_bytes())}
                              for relative in manifest_paths]}
        self.manifest = canonical_bytes(manifest)
        pathlib.Path(self.external_manifest_path).write_bytes(self.manifest)
        cb = canonical_bytes(contract)
        (self.repo / "contracts" / "blind_runtime_unseal_job_v11_template.json").write_bytes(tb)
        (self.repo / "contracts" / "blind_runtime_unseal_v11.json").write_bytes(cb)
        receipt = build_registration_receipt(tb, cb, sha256_bytes(self.raw), sha256_bytes(self.global_raw), sha256_bytes(self.raw_al), sha256_bytes(self.manifest), "owner", "host", "opaque-time"); rb = canonical_bytes(receipt)
        (self.repo / "contracts" / "blind_runtime_unseal_registration_v11.json").write_bytes(rb)
        job = build_final_job_spec(rb, tb, cb, str(self.repo / "out")); jb = canonical_bytes(job)
        (self.repo / "contracts" / "blind_runtime_unseal_job_v11.json").write_bytes(jb)
        review = build_independent_review(rb, jb, cb, self.raw, self.global_raw, self.raw_al, self.manifest, "812345",
          str(self.repo / "contracts" / "blind_runtime_unseal_job_v11_template.json"),
          str(self.repo / "contracts" / "blind_runtime_unseal_v11.json"), str(self.runner))
        vb = canonical_bytes(review); (self.repo / "contracts" / "blind_unseal_independent_review_v11.json").write_bytes(vb)
        subprocess.check_call(("git", "add", "."), cwd=str(self.repo))
        subprocess.check_call(("git", "commit", "-qm", "lifecycle bundle"), cwd=str(self.repo))
        return tb, cb, rb, jb, vb

    def test_complete_bundle_and_real_validator_pass(self):
        tb, cb, rb, jb, vb = self._bundle()
        self.assertTrue(validate_one_way_lifecycle(tb, cb, rb, jb, vb))
        review = json.loads(vb); self.assertEqual(len(review), 35)
        self.assertEqual(review["reviewed_artifacts"], self.artifacts)
        self.assertEqual(review["external_control_manifest_path"], self.external_manifest_path)
        self.assertNotIn(b'":null', tb + cb + rb + jb + vb)

    def test_adversarial_argv_is_rejected(self):
        bad = dict(self.held); bad["command_argv"] = ["python3", "-c", "print(123)"]
        with self.assertRaises(LifecycleError):
            materialize_final_template(self.draft_template, bad, self.roots)

    def test_synthetic_e2e_calls_runner_validate_bundle(self):
        self._bundle()
        old_bytecode = sys.dont_write_bytecode; sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location("synthetic_v11_runner", str(self.runner))
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        runner.EXPECTED_EXTERNAL_CONTROL_MANIFEST = self.external_manifest_path
        sys.dont_write_bytecode = old_bytecode
        old = os.environ.get("LSB_JOBID"); old_index = os.environ.get("LSB_JOBINDEX")
        os.environ["LSB_JOBID"] = "812345"; os.environ["LSB_JOBINDEX"] = "0"
        try:
            contract, _, job, _ = runner.validate_bundle(str(self.repo))
        finally:
            if old is None: os.environ.pop("LSB_JOBID", None)
            else: os.environ["LSB_JOBID"] = old
            if old_index is None: os.environ.pop("LSB_JOBINDEX", None)
            else: os.environ["LSB_JOBINDEX"] = old_index
        self.assertEqual(contract["status"], "FINAL_HELD_UNSEAL_REVIEW_REQUIRED")
        self.assertEqual(job["status"], "REGISTERED_HELD")

    def test_lsf_nonarray_jobindex_must_be_exactly_zero(self):
        self._bundle()
        old_bytecode = sys.dont_write_bytecode; sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location("synthetic_v11_runner_index", str(self.runner))
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        runner.EXPECTED_EXTERNAL_CONTROL_MANIFEST = self.external_manifest_path
        sys.dont_write_bytecode = old_bytecode
        saved = {key: os.environ.get(key) for key in ("LSB_JOBID", "LSB_JOBINDEX")}
        try:
            os.environ["LSB_JOBID"] = "812345"; os.environ["LSB_JOBINDEX"] = "0"
            self.assertEqual(runner.validate_bundle(str(self.repo))[0]["status"], "FINAL_HELD_UNSEAL_REVIEW_REQUIRED")
            for value in ("", "1", "2", "not-an-index"):
                os.environ["LSB_JOBINDEX"] = value
                with self.assertRaisesRegex(runner.Refusal, "^LSF_JOB_ID_OR_INDEX$"):
                    runner.validate_bundle(str(self.repo))
            os.environ.pop("LSB_JOBINDEX", None)
            with self.assertRaisesRegex(runner.Refusal, "^LSF_JOB_ID_OR_INDEX$"):
                runner.validate_bundle(str(self.repo))
            os.environ["LSB_JOBINDEX"] = "0"; os.environ["LSB_JOBID"] = "812346"
            with self.assertRaisesRegex(runner.Refusal, "^LSF_JOB_ID_OR_INDEX$"):
                runner.validate_bundle(str(self.repo))
        finally:
            for key, value in saved.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value

    def test_bad_raw_or_fake_review_cannot_pass(self):
        tb, cb, rb, jb, _ = self._bundle()
        with self.assertRaises(LifecycleError):
            build_independent_review(rb, jb, cb, self.raw.replace(b"PSUSP", b"RUN"), self.global_raw, self.raw_al, self.manifest, "812345",
              str(self.repo / "contracts" / "blind_runtime_unseal_job_v11_template.json"), str(self.repo / "contracts" / "blind_runtime_unseal_v11.json"), str(self.runner))
        fake = {"status": "PASS", "registration_validator_pass": True}
        with self.assertRaises(LifecycleError): validate_one_way_lifecycle(tb, cb, rb, jb, canonical_bytes(fake))

    def test_draft_worktree_drift_and_future_keys_fail_closed(self):
        with self.assertRaises(LifecycleError): materialize_final_template({"status": "FINAL_HELD_JOB_TEMPLATE"}, self.held, self.roots)
        self.runner.write_bytes(b"drift")
        with self.assertRaises(LifecycleError): verify_implementation_freeze(str(self.repo), self.commit, self.artifacts)
        # New unknown keys are rejected by exact recursive schemas, not a finite blacklist.
        template = materialize_final_template(self.draft_template, self.held, self.roots); template["future_receipt"] = "x"
        with self.assertRaises(LifecycleError):
            finalize_contract(self.draft_contract, canonical_bytes(template), self.commit, self.artifacts)

    def test_final_job_spec_mutations_fail_before_review_or_release(self):
        tb, cb, rb, jb, vb = self._bundle()
        original = json.loads(jb)
        mutations = []
        changed = json.loads(jb); changed["registration"]["job_id"] = "912345"; mutations.append(changed)
        changed = json.loads(jb); changed["registration"]["command_argv"].append("--mutated"); mutations.append(changed)
        changed = json.loads(jb); changed["measurement_files"] = changed["measurement_files"][:-1]; mutations.append(changed)
        changed = json.loads(jb); changed["circuits"] = list(reversed(changed["circuits"])); mutations.append(changed)
        changed = json.loads(jb); changed["contract_sha256"] = "0" * 64; mutations.append(changed)
        changed = json.loads(jb); changed["job_template_sha256"] = "0" * 64; mutations.append(changed)
        changed = json.loads(jb); changed["extra"] = True; mutations.append(changed)
        changed = json.loads(jb); changed["circuits"][0]["root"] = "relative/root"; mutations.append(changed)
        for changed in mutations:
            mutated = canonical_bytes(changed)
            with self.assertRaises(LifecycleError):
                validate_one_way_lifecycle(tb, cb, rb, mutated, vb)
            with self.assertRaises(LifecycleError):
                build_independent_review(rb, mutated, cb, self.raw, self.global_raw, self.raw_al, self.manifest, "812345",
                  str(self.repo / "contracts" / "blind_runtime_unseal_job_v11_template.json"),
                  str(self.repo / "contracts" / "blind_runtime_unseal_v11.json"), str(self.runner))
        self.assertEqual(json.loads(jb), original)

    def test_final_template_requires_three_absolute_unique_roots(self):
        missing = dict(self.roots); missing.pop("wb_dma")
        with self.assertRaises(LifecycleError): materialize_final_template(self.draft_template, self.held, missing)
        relative = dict(self.roots); relative["s9234"] = "relative"
        with self.assertRaises(LifecycleError): materialize_final_template(self.draft_template, self.held, relative)
        duplicate = dict(self.roots); duplicate["s38584"] = duplicate["s9234"]
        with self.assertRaises(LifecycleError): materialize_final_template(self.draft_template, self.held, duplicate)


if __name__ == "__main__": unittest.main()


