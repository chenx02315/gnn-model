import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts import prepare_prospective_input_binding_v1 as prep


class PreparationTests(unittest.TestCase):
    def test_only_two_pinned_projection_reads(self):
        read = Path.read_bytes
        seen = []
        def bounded(path):
            seen.append(path.relative_to(prep.ROOT).as_posix())
            return read(path)
        with patch.object(Path, 'read_bytes', bounded):
            result = prep.prepare()
        self.assertEqual(set(seen), set(prep.SOURCES))
        self.assertEqual(len(seen), 2)
        self.assertFalse(result['real_roster_frozen'])
        self.assertFalse(result['execution_ready'])
        self.assertTrue(result['timestamps_are_fabricated_not_measurements'])
        observation = result['synthetic_observation_summary']
        self.assertEqual(observation['raw_observed_interval_ns_sum'], 40)
        self.assertEqual(observation['attempt_count'], 4)
        self.assertEqual(observation['actual_processes_executed'], 0)
        for attempt in observation['attempts']:
            self.assertEqual(attempt['input_binding_sha256'],
                result['synthetic_examples'][attempt['circuit']]['binding_sha256'])
        for example in result['synthetic_examples'].values():
            self.assertIsNone(example['payload']['identities']['fault_universe'])
            self.assertEqual(len(example['missing_identity_names']), 8)
            self.assertFalse(example['legacy_model_compatible'])

    def test_missing_source_no_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'FIXED_SMALL_PROJECTION_REQUIRED'):
                prep.prepare(directory)

    def test_changed_projection_fails_before_parse(self):
        with patch.object(Path, 'read_bytes', return_value=b'{}'):
            with self.assertRaisesRegex(ValueError, 'E70_PROJECTION_PIN_MISMATCH'):
                prep.prepare()


if __name__ == '__main__':
    unittest.main()
