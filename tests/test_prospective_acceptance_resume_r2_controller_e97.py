"""New local phase names only; no remote or scheduler calls."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts import execute_acceptance_resume_e97_r2 as m


class Tests(unittest.TestCase):
    def test_only_new_phase_names_and_restore_on_failure(self):
        original = m.controller.OBS_PHASE, m.controller.RESUME_PHASE, m.controller.REVIEWS
        def check():
            self.assertTrue(str(m.controller.OBS_PHASE).endswith('_r2'))
            self.assertTrue(str(m.controller.RESUME_PHASE).endswith('_r2'))
            self.assertTrue(all(str(p).endswith('_r2.json') for p in m.controller.REVIEWS.values()))
            raise ValueError('synthetic-only')
        with patch.object(m.controller, 'main', side_effect=check) as call:
            with self.assertRaisesRegex(ValueError, 'synthetic-only'):
                m.main()
            call.assert_called_once()
        self.assertEqual(original, (m.controller.OBS_PHASE,m.controller.RESUME_PHASE,m.controller.REVIEWS))

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(),feature_version=(3,6))


if __name__ == '__main__':
    unittest.main()
