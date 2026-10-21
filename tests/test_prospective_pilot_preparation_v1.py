import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import prepare_prospective_pilot_v1 as builder


class PreparationTests(unittest.TestCase):
    def test_actual_fixed_local_contracts_partial_only(self):
        result = builder.prepare()
        self.assertEqual(result['remaining_missing_count'], 18)
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['assessment']['configuration_complete'])
        self.assertFalse(result['assessment']['artifact_contents_verified'])
        self.assertIsNone(result['plan']['freeze_components']['runner_adapter_sha256'])
        self.assertEqual(result['plan']['comparison']['epsilon'], 0.01)
        self.assertFalse(result['proposals']['actual_execution_allowed'])
        self.assertEqual(result['proposals']['epsilon'], 0.01)
        self.assertEqual(len(result['resolved_pin_sources']), 2)

    def test_no_dataset_or_unknown_source_read(self):
        original = Path.read_bytes
        seen = []
        def read(path):
            name = path.relative_to(builder.ROOT).as_posix()
            self.assertIn(name, builder.SOURCES)
            seen.append(name)
            return original(path)
        with patch.object(Path, 'read_bytes', read):
            builder.prepare()
        self.assertEqual(set(seen), set(builder.SOURCES))

    def test_wrong_train_family_rejected(self):
        evidence, docs = builder.read_sources(builder.ROOT)
        changed = copy.deepcopy(docs)
        changed['contracts/data_split_v1.json']['formal_runtime_membership']['TRAIN'] = []
        with patch.object(builder, 'read_sources', return_value=(evidence, changed)):
            with self.assertRaisesRegex(ValueError, 'TRAIN_MEMBERSHIP_MISMATCH'):
                builder.prepare()

    def test_missing_source_rejected_no_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'FIXED_REGULAR_SOURCE_REQUIRED'):
                builder.prepare(directory)

    def test_legacy_policy_conflicts_not_silently_merged(self):
        result = builder.prepare()
        self.assertEqual(len(result['legacy_policy_conflicts']), 3)
        self.assertIn('PASS', result['historical_roster_not_reused'])
        self.assertIsNone(result['plan']['limits']['memory_limit_bytes'])
        self.assertIsNone(result['plan']['limits']['attempt_wall_timeout_s'])
        self.assertIsNone(result['plan']['freeze_components']['candidate_roster_sha256'])


if __name__ == '__main__':
    unittest.main()
