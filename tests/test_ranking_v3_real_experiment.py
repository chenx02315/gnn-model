import json
import unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_export_ranking_v3_real_inputs as export_fixture
from scripts import run_ranking_v3_real_experiment as driver

class ExperimentTests(unittest.TestCase):
    def test_release_hash_refused_before_package_access(self):
        with patch.object(driver, '_read_json_once', side_effect=ValueError('EXPERIMENT_RELEASE_SHA')) as read:
            with self.assertRaisesRegex(ValueError, 'RELEASE_SHA'):
                driver.run('nonexistent', 'a'*64, 'release', 'b'*64, 'output')
        self.assertEqual(read.call_count, 1)

    def test_source_export_to_subprocess_evaluator_all_models_toy_grid(self):
        try:
            import torch, numpy, xgboost
        except ImportError:
            self.skipTest('ML dependencies absent: fixed subprocess entrypoint not verified locally')
        fixture = export_fixture.ExportRankingRealInputsTests(); fixture.setUp()
        try:
            package = fixture.root/'package'; receipt = fixture.call(package)
            release = dict(status='PASS_TRAIN_ONLY_EXECUTION_RELEASE', independent_review_pass=True,
                data_gate_pass=True, roles=['TRAIN'], source_sha256=receipt['source_sha256'],
                reviewed_sources={name:export_fixture.sha(name) for name in driver.REVIEWED_FILES})
            release_path = fixture.root/'release.json'; release_path.write_text(json.dumps(release))
            output = fixture.root/'experiment'
            # Explicit toy-only patches replace the physical B destination/count
            # guards, not source/release hashing, worker process or evaluator.
            with patch.object(driver, 'validate_destination'), patch.object(driver, 'EXPECTED_ACTIONS', 12):
                result = driver.run(package, export_fixture.sha(package/'receipt.json'), release_path, export_fixture.sha(release_path), output)
            self.assertEqual(set(result), set(driver.MODELS))
            for model in driver.MODELS:
                self.assertEqual(result[model]['receipt_count'], 18)
            for path in output.glob('*_request.json'):
                request = json.loads(path.read_bytes())
                self.assertNotIn('heldout_outcomes', request)
                self.assertNotIn('evaluator_root', request)
            self.assertTrue((output/'summary.json').exists())
        finally:
            fixture.tearDown()

if __name__ == '__main__':
    unittest.main()
