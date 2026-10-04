from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from src.models.preflight_runtime_v2 import parse_lock, validate_installed_dependencies
from src.models.runtime_training_v2 import TrainingV2Error


class RuntimeV2PreflightTest(unittest.TestCase):
    def test_distribution_versions_define_exact_lock_match(self):
        with patch("src.models.preflight_runtime_v2.importlib.metadata.version", return_value="2.5.1"):
            self.assertEqual({"torch": "2.5.1"}, validate_installed_dependencies({"torch": "2.5.1"}))

    def test_distribution_version_drift_is_rejected(self):
        with patch("src.models.preflight_runtime_v2.importlib.metadata.version", return_value="2.5.2"):
            with self.assertRaisesRegex(TrainingV2Error, "DEPENDENCY_VERSION:torch"):
                validate_installed_dependencies({"torch": "2.5.1"})

    def test_transitive_dependency_drift_is_rejected(self):
        with patch("src.models.preflight_runtime_v2.importlib.metadata.version", side_effect=lambda name: {"torch": "2.5.1", "filelock": "wrong"}[name]):
            with self.assertRaisesRegex(TrainingV2Error, "DEPENDENCY_VERSION:filelock"):
                validate_installed_dependencies({"torch": "2.5.1", "filelock": "4.0.9"})

    def test_bootstrap_canonicalizes_before_any_read_or_write(self):
        script = (Path(__file__).resolve().parents[1] / "scripts/bootstrap_runtime_v2_b.sh").read_text(encoding="utf-8")
        first_realpath = script.index("fresh_root=$(realpath")
        self.assertLess(first_realpath, script.index("mkdir -p"))
        self.assertLess(first_realpath, script.index("cp -a"))
        self.assertLess(first_realpath, script.index("python3 -m venv"))
        self.assertIn('repo_root=$(realpath -e -- "$2")', script)
        self.assertIn('package_root=$(realpath -e -- "$3")', script)
        self.assertIn('outcome_split_root=$(realpath -e -- "$4")', script)
    def test_lock_requires_exact_core_versions(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "lock.txt"
            path.write_text("numpy==2.1.3\nscikit-learn==1.5.2\nscipy==1.14.1\ntorch==2.5.1\nxgboost==2.1.2\n", encoding="utf-8")
            self.assertEqual("2.5.1", parse_lock(path)["torch"])

    def test_lock_rejects_unpinned_dependency(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "lock.txt"
            path.write_text("numpy>=2\nscikit-learn==1.5.2\nscipy==1.14.1\ntorch==2.5.1\nxgboost==2.1.2\n", encoding="utf-8")
            with self.assertRaisesRegex(TrainingV2Error, "UNPINNED"):
                parse_lock(path)


if __name__ == "__main__":
    unittest.main()
