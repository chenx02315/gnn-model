import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.models import ranking_v5_real_artifact_store as store_module
from src.models.runtime_ranking_v3 import digest


class StoreTests(unittest.TestCase):
    def make(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        prefix = (Path(temporary.name) / "gnn_model_ranking_v5_train_").as_posix()
        output = Path(prefix + "unit")
        patcher = patch.object(store_module, "PRODUCTION_PREFIX", prefix); patcher.start(); self.addCleanup(patcher.stop)
        return output, store_module.RealArtifactStore(output.as_posix())

    def test_model_ack_tamper_cap_and_artifact_overwrite(self):
        output, store = self.make(); raw = b"model"; sha = hashlib.sha256(raw).hexdigest()
        self.assertEqual(sha, store.persist_model_bytes(raw, sha))
        output.joinpath("model.pt").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "MODEL_ACK"): store.ack_model(sha)
        with self.assertRaisesRegex(ValueError, "MODEL_BOUND"):
            store.persist_model_bytes(b"x" * (store_module.MODEL_MAX_BYTES + 1), "0" * 64)
        with self.assertRaisesRegex(ValueError, "MODEL_BOUND"):
            store.persist_model_bytes(b"", hashlib.sha256(b"").hexdigest())
        with self.assertRaises(FileExistsError): store.persist_model_bytes(raw, sha)
        output2, second = self.make(); output2.joinpath("model.pt").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "MODEL_ACK"):
            second.ack_model(hashlib.sha256(b"").hexdigest())

    def test_exact_logs_caps_and_readback(self):
        output, store = self.make(); records = [{"epoch": index} for index in range(store_module.LOG_RECORD_COUNT)]
        sha = store.persist_logs(records); self.assertEqual(sha, store.ack_logs(sha))
        with self.assertRaisesRegex(ValueError, "LOG_COUNT"): store.persist_logs(records[:-1])
        output2, second = self.make(); huge = [{"x":"x" * store_module.LOG_RECORD_MAX_BYTES}] * store_module.LOG_RECORD_COUNT
        with self.assertRaisesRegex(ValueError, "LOG_RECORD_BOUND"): second.persist_logs(huge)

    def test_freeze_ack_reread_corruption_and_receipt_bound(self):
        output, store = self.make(); payload = {"family":"f", "scores":{"a":1.0}}; sha = digest(payload)
        self.assertEqual(sha, store.persist_freeze(payload, sha)); self.assertEqual((payload, sha), store.read_freeze(sha))
        output.joinpath("freeze.json").write_text('{"payload":{},"sha256":"' + sha + '"}\n')
        with self.assertRaisesRegex(ValueError, "FREEZE_READ"): store.read_freeze(sha)
        output2, second = self.make()
        with self.assertRaisesRegex(ValueError, "RECEIPT_BOUND"):
            second.persist_receipt({"x":"x" * store_module.RECEIPT_MAX_BYTES})

    def test_json_preflight_rejects_unbounded_inputs_before_any_artifact_write(self):
        cases = [
            ({"x": "\\" * (store_module.JSON_MAX_STRING_CHARS + 1)}, "RECEIPT_BOUND"),
            ({"x": 1 << store_module.JSON_MAX_INT_BITS}, "JSON_INT"),
            (set(), "JSON_TYPE"),
        ]
        deep = value = []
        for _ in range(store_module.JSON_MAX_DEPTH + 1):
            child = []; value.append(child); value = child
        cases.append((deep, "JSON_DEPTH"))
        cyclic = []; cyclic.append(cyclic); cases.append((cyclic, "JSON_CYCLE"))
        for value, error in cases:
            output, store = self.make()
            with patch.object(store_module.json.JSONEncoder, "iterencode", side_effect=AssertionError("encoded")):
                with self.assertRaisesRegex(ValueError, error):
                    store.persist_receipt(value)
            self.assertEqual([], list(output.iterdir()))

    def test_json_maximum_structural_boundaries_are_serialized(self):
        value = "x" * store_module.JSON_MAX_STRING_CHARS
        for _ in range(store_module.JSON_MAX_DEPTH):
            value = [value]
        output, store = self.make()
        self.assertTrue(store.persist_receipt(value))
        self.assertTrue(output.joinpath("worker_receipt.json").is_file())
        output, store = self.make()
        nodes = [[0] * store_module.JSON_MAX_CONTAINER_ITEMS for _ in range(3)]
        nodes.append([0] * (store_module.JSON_MAX_CONTAINER_ITEMS - 6))
        nodes.append(1 << (store_module.JSON_MAX_INT_BITS - 1))
        self.assertTrue(store.persist_receipt(nodes))

    def test_freeze_duplicate_raw_json_keys_are_refused(self):
        output, store = self.make(); payload = {"family": "f"}; sha = digest(payload)
        output.joinpath("freeze.json").write_text(
            '{"payload":' + json.dumps(payload, separators=(",", ":"))
            + ',"sha256":"' + sha + '","sha256":"' + sha + '"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "FREEZE_READ"):
            store.read_freeze(sha)

        # A corrupt sub-cap envelope can exceed the decoder's recursion limit.
        # Convert that decoder exception to the same fail-closed read error.
        deep_raw = ('{"payload":' + '[' * 5000 + '0' + ']' * 5000
                    + ',"sha256":"' + sha + '"}\n').encode('utf-8')
        self.assertLess(len(deep_raw), store_module.FREEZE_MAX_BYTES)
        output.joinpath('freeze.json').write_bytes(deep_raw)
        with self.assertRaisesRegex(ValueError, 'FREEZE_READ'):
            store.read_freeze(sha)

    def test_output_existing_bad_prefix_zero_io_and_symlink(self):
        output, store = self.make()
        with self.assertRaises(FileExistsError): store_module.RealArtifactStore(output.as_posix())
        names = ("open", "stat", "lstat", "is_symlink", "resolve")
        originals = {name:getattr(Path, name) for name in names}; calls = {name:0 for name in names}
        def guard(name):
            def wrapped(path, *args, **kwargs):
                calls[name] += 1
                return originals[name](path, *args, **kwargs)
            return wrapped
        with patch.object(Path, "open", new=guard("open")), patch.object(Path, "stat", new=guard("stat")), \
                patch.object(Path, "lstat", new=guard("lstat")), patch.object(Path, "is_symlink", new=guard("is_symlink")), \
                patch.object(Path, "resolve", new=guard("resolve")):
            with self.assertRaisesRegex(ValueError, "OUTPUT_PATH"):
                store_module.RealArtifactStore("relative/out")
        self.assertEqual({name:0 for name in names}, calls)
        with self.assertRaisesRegex(ValueError, "OUTPUT_PATH"):
            store_module.RealArtifactStore((output / "nested").as_posix())
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        target = root / "target"; target.mkdir(); link = root / "link"
        try: link.symlink_to(target, target_is_directory=True)
        except OSError: self.skipTest("symlink privilege unavailable")
        prefix = (link / "gnn_model_ranking_v5_train_").as_posix()
        patcher = patch.object(store_module, "PRODUCTION_PREFIX", prefix); patcher.start(); self.addCleanup(patcher.stop)
        with self.assertRaisesRegex(ValueError, "SYMLINK"):
            store_module.RealArtifactStore((link / "gnn_model_ranking_v5_train_unit").as_posix())

    def test_replaced_output_directory_is_refused_before_artifact_open(self):
        output, store = self.make(); output.rmdir(); output.write_bytes(b"not-a-directory")
        with self.assertRaisesRegex(ValueError, "OUTPUT_DIR"):
            store.ack_model("0" * 64)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_artifact_rejected(self):
        output, store = self.make(); fifo = output / "model.pt"
        try: os.mkfifo(fifo)
        except OSError as error: self.skipTest(str(error))
        with self.assertRaisesRegex(ValueError, "ORDINARY_FILE"):
            store.ack_model("0" * 64)


if __name__ == "__main__":
    unittest.main()
