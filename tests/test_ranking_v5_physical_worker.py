import json
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.models import ranking_v5_physical_worker as worker
from src.models.runtime_ranking_v3 import digest


class StoreTests(unittest.TestCase):
    def store(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        return Path(directory.name), worker.PhysicalArtifactStore(Path(directory.name) / "out", allow_test_path=True)

    def test_create_once_existing_output_rejected(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup); path = Path(directory.name) / "out"
        worker.PhysicalArtifactStore(path, allow_test_path=True)
        with self.assertRaises(FileExistsError): worker.PhysicalArtifactStore(path, allow_test_path=True)

    def test_model_ack_and_readback(self):
        root, store = self.store(); raw = b"model"; self.assertEqual(digest({"x": 1})[:0] + worker._sha_bytes(raw), store.persist_model_bytes(raw, worker._sha_bytes(raw)))
        self.assertEqual(raw, (store.output / "model.pt").read_bytes())

    def test_wrong_model_bytes_rejected(self):
        root, store = self.store()
        with self.assertRaisesRegex(ValueError, "MODEL_BYTES"): store.persist_model_bytes(b"x", "0" * 64)

    def test_model_bound_rejected(self):
        root, store = self.store(); raw = b"x" * (worker.MAX_MODEL_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "MODEL_BYTES"): store.persist_model_bytes(raw, worker._sha_bytes(raw))

    def test_logs_count_bound_rejected(self):
        root, store = self.store()
        with self.assertRaisesRegex(ValueError, "LOG_COUNT"): store.persist_logs([])

    def test_logs_record_bound_rejected(self):
        root, store = self.store(); records = [{"x": "x" * worker.MAX_LOG_RECORD_BYTES}] * worker.LOG_RECORDS
        with self.assertRaisesRegex(ValueError, "LOG_RECORD_BOUND"): store.persist_logs(records)

    def test_logs_are_exclusive_and_hashed(self):
        root, store = self.store(); records = [{"epoch": i} for i in range(worker.LOG_RECORDS)]
        sha = store.persist_logs(records); self.assertEqual(worker._sha_bytes((store.output / "fitting.jsonl").read_bytes()), sha)
        with self.assertRaises(FileExistsError): store.persist_logs(records)

    def test_tampered_freeze_rejected(self):
        root, store = self.store(); payload = {"family": "f"}; sha = digest(payload)
        self.assertEqual(sha, store.persist_freeze(payload, sha))
        (store.output / "freeze.json").write_text(json.dumps({"payload": {"bad": 1}, "sha256": sha}))
        with self.assertRaises(ValueError): store.read_freeze(sha)

    def test_freeze_and_receipt_bounds_rejected(self):
        root, store = self.store(); payload = {"x": "x" * worker.MAX_FREEZE_BYTES}
        with self.assertRaisesRegex(ValueError, "FREEZE_BOUND"):
            store.persist_freeze(payload, digest(payload))
        with self.assertRaisesRegex(ValueError, "RECEIPT_BOUND"):
            store.write_receipt({"x": "x" * worker.MAX_RECEIPT_BYTES})

    def test_path_traversal_and_prefix_rejected(self):
        with self.assertRaises(ValueError): worker._safe_path(Path("relative") / ".." / "out", allow_test_path=True)
        with self.assertRaises(ValueError): worker._safe_path(Path(tempfile.gettempdir()) / "out")

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink unsupported")
    def test_symlink_output_rejected(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        root = Path(directory.name); target = root / "target"; target.mkdir(); link = root / "link"
        try: link.symlink_to(target, target_is_directory=True)
        except OSError: self.skipTest("symlink privilege unavailable")
        with self.assertRaisesRegex(ValueError, "SYMLINK"): worker.PhysicalArtifactStore(link / "out", allow_test_path=True)

    def test_source_verifier_rejects_missing_binding(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        with self.assertRaisesRegex(ValueError, "SOURCE_FILE"): worker.verify_source_files(directory.name)


class FixtureTests(unittest.TestCase):
    def test_synthetic_fixture_has_72_rows_and_only_fit_cycles(self):
        request = worker.synthetic_request()
        self.assertEqual(72, len(request["rows"])); self.assertEqual(60, len(request["fit_cycles"]))
        self.assertEqual(set(worker.FAMILIES.values()), {row["family"] for row in request["rows"]})

    def test_test_release_is_explicitly_nonformal_authority(self):
        release = worker._test_release({name: "a" * 64 for name in worker.boundary.REQUIRED_SOURCE_BINDINGS})
        self.assertEqual("TEST_ONLY_AUTHORITY_NOT_FORMAL", release["user_authorization_id"])

    def test_only_exact_generated_fixture_can_provision_or_fit(self):
        source_map = {name: "a" * 64 for name in worker.boundary.REQUIRED_SOURCE_BINDINGS}
        original_request = worker.synthetic_request(); original_release = worker._test_release(source_map)
        cases = []
        changed = copy.deepcopy(original_request); changed["fit_cycles"][next(iter(changed["fit_cycles"]))] += 1; cases.append((changed, original_release))
        changed = copy.deepcopy(original_request); changed["rows"][0]["action_uid"] = "forged"; cases.append((changed, original_release))
        changed_release = copy.deepcopy(original_release); changed_release["user_authorization_id"] = "operator"; cases.append((original_request, changed_release))
        with tempfile.TemporaryDirectory() as directory, patch.object(worker, "verify_source_files", return_value=source_map), \
                patch.object(worker, "fit_prepared") as fit:
            for number, (request, release) in enumerate(cases):
                output = Path(directory) / ("out%d" % number)
                with self.assertRaisesRegex(ValueError, "GENERATED_SYNTHETIC_FIXTURE"):
                    worker.execute_synthetic(request, release, output, None, None, root=directory, allow_test_path=True)
                self.assertFalse(output.exists())
            fit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
