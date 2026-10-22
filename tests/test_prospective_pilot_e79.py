"""Read fixed local code/receipts only; no dataset, process or remote access."""
import unittest
from unittest import mock

from scripts import prepare_prospective_pilot_e79 as preparation


class PreparationTests(unittest.TestCase):
    def test_real_gaps_preserved_and_example_never_releases(self):
        value = preparation.prepare()
        self.assertEqual(len(value['historical_e67_missing_fields_preserved']), 18)
        self.assertEqual(len(value['work_packages']), 4)
        self.assertEqual(len(value['evidence']), 10)
        for row in value['current_budget_assessments'].values():
            self.assertEqual(row['status'], 'INCOMPLETE_DESIGN')
            self.assertIsNone(row['total_physical_calls_upper'])
        example = value['synthetic_arithmetic_example']
        self.assertEqual(example['total_physical_calls_upper'], 192)
        self.assertEqual(example['summed_attempt_envelope_seconds_upper'], 2304)
        self.assertFalse(example['execution_ready'])
        self.assertFalse(value['execution_ready'])
        self.assertFalse(value['training_release'])

    def test_reference_source_drift_rejects(self):
        with mock.patch.object(preparation, 'DRIVER_SHA', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'REFERENCE_DRIVER_PIN'):
                preparation.prepare()

    def test_readiness_flag_cannot_be_promoted(self):
        original = preparation.json.loads
        def injected(raw):
            value = original(raw)
            if value.get('schema') == 'e79-pilot-convergence-v1':
                value['execution_ready'] = True
            return value
        with mock.patch.object(preparation.json, 'loads', side_effect=injected):
            with self.assertRaisesRegex(ValueError, 'NO_RELEASE'):
                preparation.prepare()

    def test_new_checkpoint_evidence_needs_explicit_reassessment(self):
        original = preparation.json.loads
        def injected(raw):
            value = original(raw)
            if 'actual_model_checkpoint_authenticated' in value:
                value['actual_model_checkpoint_authenticated'] = True
            return value
        with mock.patch.object(preparation.json, 'loads', side_effect=injected):
            with self.assertRaisesRegex(ValueError, 'CHECKPOINT_REMAINS_UNVERIFIED'):
                preparation.prepare()


if __name__ == '__main__':
    unittest.main()
