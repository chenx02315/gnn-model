"""Actual local failure-receipt regression; no new collection or remote calls."""
import json
from pathlib import Path
import unittest


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.phase = cls.repo.parent / 'runtime_training_staging_20260928/v6_e135_f_replay_r1'
        cls.raw = json.loads((cls.phase / 'read1/stdout.json').read_bytes())
        cls.saved = json.loads((cls.repo / 'data/manifests/ranking_v6_e135_initial_read_failure_r1.json').read_bytes())

    def test_partial_pattern_identity_preserves_integer_nanoseconds_exactly(self):
        row = self.raw['source_receipt']['files'][0]
        self.assertEqual(self.saved['pattern_observation'], row)
        for key in ('st_mtime_ns', 'st_ctime_ns'):
            value = self.saved['pattern_observation']['identity'][key]
            self.assertIs(type(value), int)
            self.assertEqual(value, 1793069176022511787)

    def test_failure_is_size_predicate_not_known_strictly_oversize_or_login_failure(self):
        self.assertFalse(self.raw['capture_complete'])
        self.assertEqual(self.raw['error'], dict(code='PREOPEN_SIZE_CAP', stage='READ_REFERENCE', type='ValueError'))
        self.assertEqual(self.saved['transport']['exit_code'], 0)
        self.assertIsNone(self.saved['reference_exact_size_bytes'])
        self.assertTrue(self.saved['do_not_infer_exact_or_strictly_oversize_from_error_only'])
        self.assertFalse(self.saved['reference_body_opened'])

    def test_first_failure_closes_unused_roles_without_renewing_clock(self):
        closed = json.loads((self.phase / 'closed.json').read_bytes())
        self.assertEqual(closed['calls_consumed'], 1)
        self.assertEqual(closed['calls_allowed_after_failure'], 0)
        self.assertFalse(closed['retry_or_resume_allowed'])
        self.assertEqual(self.saved['Tessent_launches'], 0)
        self.assertEqual(self.saved['Python_process_selfchecks'], 0)
        self.assertFalse(self.saved['physical_HF_D95_verified'])
        self.assertFalse(self.saved['training_release'])


if __name__ == '__main__':
    unittest.main()
