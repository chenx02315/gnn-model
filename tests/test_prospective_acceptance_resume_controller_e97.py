"""Local composition and fake transport tests; no scheduler calls."""
import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from scripts import execute_acceptance_resume_e97 as m


class Tests(unittest.TestCase):
    def test_pinned_prepare_observe(self):
        raw = m.prepare('observe', m.transport_base.sha(m.CORE.read_bytes()))
        self.assertLess(len(raw), 65536)
        ast.parse(raw.decode('ascii'), feature_version=(3, 6))

    def test_wrong_source_and_phase(self):
        for mode, pin in (('observe', '0'*64), ('register', '0'*64)):
            with self.assertRaises(ValueError):
                m.prepare(mode, pin)

    def test_missing_reviews_no_resume_payload(self):
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT_PINS_REQUIRED'):
            m.prepare('resume', m.transport_base.sha(m.CORE.read_bytes()))

    def test_once_observation_phase_no_transport_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Mock()
            helper.verify_cached_host.return_value = 'mock-only'
            helper.decode.side_effect = json.loads
            helper.transport.return_value = dict(
                stdout=b'{"schema":"e97-pre-resume-observation-v1","job_id":394230}',
                stderr=b'', exit_code=0, timeout=False, overflow=False,
                write_failed=False, threads_incomplete=False, remote_termination_verified=False)
            with patch.object(m, 'OBS_PHASE', Path(directory)/'observation'), \
                 patch.object(m, 'prepare', return_value=b'# synthetic'), \
                 patch.object(m.transport_base, 'load_transport', return_value=helper), \
                 patch.object(sys, 'argv', ['controller', 'observe', 'a'*64]):
                m.main()
                with self.assertRaises(FileExistsError):
                    m.main()
            helper.transport.assert_called_once()


if __name__ == '__main__':
    unittest.main()
