import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_real_request_loader as loader
from src.models.runtime_ranking_v3 import FAMILIES, FEATURES, digest


def request():
    rows = []; cycles = {}
    for circuit, family in FAMILIES.items():
        for index in range(2):
            uid = "%s:%d" % (circuit, index)
            rows.append(dict(action_uid=uid, circuit=circuit, family=family, role="TRAIN",
                             **{field: float(index + 1) for field in FEATURES}))
            cycles[uid] = 100 if index == 0 else 200
    held = sorted(FAMILIES.values())[0]
    return {"scope": boundary.SCOPE, "source_sha256": boundary.SOURCE_SHA256, "family": held,
            "seed": boundary.SEEDS[0], "model": boundary.MODEL, "rows": rows,
            "fit_cycles": {uid: value for uid, value in cycles.items()
                           if next(row["family"] for row in rows if row["action_uid"] == uid) != held}}


def envelope(value):
    return {"schema": loader.SCHEMA, "roles": ["TRAIN"], "source_sha256": boundary.SOURCE_SHA256,
            "package_receipt_sha256": boundary.PACKAGE_SHA256, "request_sha256": digest(value), "request": value}


class LoaderTests(unittest.TestCase):
    def sealed(self, value=None, name="request.json"):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name) / name
        raw = json.dumps(envelope(value or request()), sort_keys=True, separators=(",", ":")).encode()
        path.write_bytes(raw)
        return Path(directory.name), name, hashlib.sha256(raw).hexdigest()

    def test_loads_exact_train_only_request(self):
        root, name, sha = self.sealed()
        loaded = loader.load_sealed_train_request(root, name, sha)
        self.assertEqual(request(), loaded); self.assertEqual(12, len(loaded["rows"]))

    def test_bad_outer_digest_and_json_are_rejected(self):
        root, name, sha = self.sealed()
        with self.assertRaisesRegex(ValueError, "REQUEST_SHA"): loader.load_sealed_train_request(root, name, "0" * 64)
        (root / name).write_bytes(b"not-json")
        actual = hashlib.sha256(b"not-json").hexdigest()
        with self.assertRaisesRegex(ValueError, "REQUEST_JSON"): loader.load_sealed_train_request(root, name, actual)

    def test_package_source_and_request_digest_are_bound(self):
        for field, value in (("package_receipt_sha256", "0" * 64), ("source_sha256", "0" * 64),
                             ("request_sha256", "0" * 64)):
            root, name, sha = self.sealed(); data = json.loads((root / name).read_text()); data[field] = value
            raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode(); (root / name).write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "ENVELOPE_BINDING"):
                loader.load_sealed_train_request(root, name, hashlib.sha256(raw).hexdigest())

    def test_roles_uid_family_and_held_cycles_are_rejected(self):
        cases = []
        bad = request(); bad["rows"][0]["role"] = "PILOT"; cases.append(bad)
        bad = request(); bad["rows"][1]["action_uid"] = bad["rows"][0]["action_uid"]; cases.append(bad)
        bad = request(); bad["rows"][0]["family"] = "wrong"; cases.append(bad)
        bad = request(); held_uid = next(row["action_uid"] for row in bad["rows"] if row["family"] == bad["family"]); bad["fit_cycles"][held_uid] = 100; cases.append(bad)
        for item in cases:
            root, name, sha = self.sealed(item)
            with self.assertRaisesRegex(ValueError, "REQUEST_CONTENT"):
                loader.load_sealed_train_request(root, name, sha)

    def test_extra_held_label_field_and_forbidden_roles_are_rejected(self):
        bad = request(); bad["held_labels"] = {}
        root, name, sha = self.sealed(bad)
        with self.assertRaisesRegex(ValueError, "REQUEST_CONTENT"): loader.load_sealed_train_request(root, name, sha)
        root, name, sha = self.sealed(); data = json.loads((root / name).read_text()); data["roles"] = ["TRAIN", "VALIDATION"]
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode(); (root / name).write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "ENVELOPE_BINDING"):
            loader.load_sealed_train_request(root, name, hashlib.sha256(raw).hexdigest())

    def test_relative_escape_and_forbidden_root_name_rejected(self):
        root, name, sha = self.sealed()
        with self.assertRaisesRegex(ValueError, "REQUEST_PATH"): loader.load_sealed_train_request(root, "../request.json", sha)
        with tempfile.TemporaryDirectory(prefix="PILOT_") as directory:
            with self.assertRaisesRegex(ValueError, "FORBIDDEN_PATH"):
                loader.load_sealed_train_request(directory, "missing.json", "0" * 64)

    def test_protected_root_is_rejected_lexically_before_access(self):
        with patch.object(Path, 'lstat', side_effect=AssertionError('protected lstat')) as ls, \
             patch.object(Path, 'is_dir', side_effect=AssertionError('protected is_dir')) as dirs, \
             patch.object(Path, 'is_symlink', side_effect=AssertionError('protected is_symlink')) as links, \
             patch.object(Path, 'resolve', side_effect=AssertionError('protected resolve')) as resolved:
            with self.assertRaisesRegex(ValueError, "REQUEST_PATH"):
                loader.load_sealed_train_request("/ssd/cjc/multimode_ate_gnn_v1/child", "request.json", "0" * 64)
            for call in (ls, dirs, links, resolved):
                call.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            lexical_parent = str(Path(directory) / ".." / Path(directory).name)
            with self.assertRaisesRegex(ValueError, "REQUEST_PATH"):
                loader.load_sealed_train_request(lexical_parent, "request.json", "0" * 64)

    def test_oversize_file_rejected_before_read(self):
        root, name, sha = self.sealed(); (root / name).write_bytes(b"x" * (loader.MAX_REQUEST_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "REQUEST_SIZE"):
            loader.load_sealed_train_request(root, name, "a" * 64)

    def test_bounded_reader_does_not_use_path_read_bytes(self):
        root, name, sha = self.sealed()
        from unittest.mock import patch
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
            self.assertEqual(request(), loader.load_sealed_train_request(root, name, sha))

    def test_directory_request_rejected(self):
        root, _, sha = self.sealed()
        (root / 'directory.json').mkdir()
        with self.assertRaisesRegex(ValueError, 'REQUEST_PATH'):
            loader.load_sealed_train_request(root, 'directory.json', sha)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Linux FIFO test')
    def test_fifo_rejected_without_open(self):
        root, _, sha = self.sealed()
        os.mkfifo(root / 'fifo.json')
        with patch.object(Path, 'open', side_effect=AssertionError('FIFO opened')) as opened:
            with self.assertRaisesRegex(ValueError, 'REQUEST_PATH'):
                loader.load_sealed_train_request(root, 'fifo.json', sha)
            opened.assert_not_called()

    def test_parent_directory_symlink_rejected(self):
        root, name, sha = self.sealed()
        parent = root / 'linked_directory'
        try:
            parent.symlink_to(root, target_is_directory=True)
        except OSError:
            self.skipTest('symlink privilege unavailable')
        with self.assertRaisesRegex(ValueError, 'SYMLINK'):
            loader.load_sealed_train_request(root, 'linked_directory/' + name, sha)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink unavailable")
    def test_symlink_request_or_parent_rejected(self):
        root, name, sha = self.sealed(); target = root / name; link = root / "linked.json"
        try: link.symlink_to(target)
        except OSError: self.skipTest("symlink privilege unavailable")
        with self.assertRaisesRegex(ValueError, "SYMLINK"):
            loader.load_sealed_train_request(root, link.name, sha)


if __name__ == "__main__":
    unittest.main()
