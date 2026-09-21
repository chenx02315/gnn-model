import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))

import validate_blind_unseal_registration_v9 as V9


class BlindUnsealStagingV9Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temp.name) / "bundle"
        self.repo.mkdir()
        for relative in V9.CONTROL_MANIFEST_PATHS:
            path = self.repo / pathlib.PurePosixPath(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode("utf-8"))
        for command in (("git", "init", "-q"),
                        ("git", "config", "user.email", "staging@example.invalid"),
                        ("git", "config", "user.name", "Staging Test"),
                        ("git", "add", "."),
                        ("git", "commit", "-qm", "staged controls")):
            subprocess.check_call(command, cwd=str(self.repo))
        self.freeze = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=str(self.repo)).decode("ascii").strip()

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self, mutate=None):
        files = []
        for relative in V9.CONTROL_MANIFEST_PATHS:
            payload = (self.repo / pathlib.PurePosixPath(relative)).read_bytes()
            files.append({"path": relative, "sha256": hashlib.sha256(payload).hexdigest()})
        value = {"schema_version": "blind-runtime-unseal-control-manifest-v9",
                 "bundle_root": str(self.repo), "freeze_commit": self.freeze,
                 "files": files}
        if mutate:
            mutate(value)
        return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    def verify(self, manifest=None, freeze=None, root=None):
        root = str(self.repo) if root is None else root
        raw = self.manifest() if manifest is None else manifest
        external = pathlib.Path(self.temp.name) / "control-manifest.json"
        external.write_bytes(raw)
        with mock.patch.object(V9, "EXPECTED_BUNDLE_ROOT", root), \
             mock.patch.object(V9, "EXPECTED_EXTERNAL_CONTROL_MANIFEST", str(external)):
            return V9.verify_staged_bundle(root, self.freeze if freeze is None else freeze,
                                           raw)

    def test_clean_git_checkout_and_exact_manifest_pass(self):
        self.assertRegex(self.verify(), r"^[0-9a-f]{64}$")

    def test_dirty_checkout_and_digest_drift_fail(self):
        target = self.repo / pathlib.PurePosixPath(V9.CONTROL_MANIFEST_PATHS[0])
        target.write_bytes(target.read_bytes() + b"drift")
        with self.assertRaises(V9.ValidationError):
            self.verify()
        subprocess.check_call(("git", "checkout", "--", V9.CONTROL_MANIFEST_PATHS[0]), cwd=str(self.repo))
        bad = self.manifest(lambda value: value["files"][0].update({"sha256": "0" * 64}))
        with self.assertRaises(V9.ValidationError):
            self.verify(bad)

    def test_manifest_argument_must_equal_fixed_external_file(self):
        raw = self.manifest()
        external = pathlib.Path(self.temp.name) / "fixed-control-manifest.json"
        external.write_bytes(raw + b"drift")
        with mock.patch.object(V9, "EXPECTED_BUNDLE_ROOT", str(self.repo)), \
             mock.patch.object(V9, "EXPECTED_EXTERNAL_CONTROL_MANIFEST", str(external)):
            with self.assertRaises(V9.ValidationError):
                V9.verify_staged_bundle(str(self.repo), self.freeze, raw)

    def test_empty_non_git_and_nonancestor_fail(self):
        empty = pathlib.Path(self.temp.name) / "empty"
        empty.mkdir()
        with self.assertRaises(V9.ValidationError):
            self.verify(root=str(empty), manifest=b"{}\n")
        with self.assertRaises(V9.ValidationError):
            self.verify(freeze="f" * 40)

    def test_symlink_bundle_is_rejected_when_supported(self):
        link = pathlib.Path(self.temp.name) / "bundle-link"
        try:
            os.symlink(str(self.repo), str(link), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink not available")
        manifest = self.manifest(lambda value: value.update({"bundle_root": str(link)}))
        with self.assertRaises(V9.ValidationError):
            self.verify(root=str(link), manifest=manifest)


if __name__ == "__main__":
    unittest.main()
