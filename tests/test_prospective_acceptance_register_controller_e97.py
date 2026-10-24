"""Fake registration transport only; never calls a scheduler."""
import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from scripts import execute_acceptance_register_e97 as m


class Tests(unittest.TestCase):
    def test_wrong_source_no_transport(self):
        with patch.object(m, 'load_transport') as load:
            with self.assertRaisesRegex(ValueError, 'HELPER_CHANGED'):
                m.prepare('0'*64)
        load.assert_not_called()

    def test_once_known_id_and_unknown_attempt_never_retried(self):
        for job_id in (123, None):
            with self.subTest(job_id=job_id), tempfile.TemporaryDirectory() as root:
                observation = dict(schema='e97-held-registration-result-v1',job_id=job_id,
                    status='REGISTERED_HELD_REVIEW_PENDING',automatic_resume=False)
                helper = Mock()
                helper.verify_cached_host.return_value = 'mock-only'
                helper.decode.side_effect = json.loads
                helper.transport.return_value = dict(stdout=json.dumps(observation).encode(),stderr=b'',
                    exit_code=0,timeout=False,overflow=False,write_failed=False,
                    threads_incomplete=False,remote_termination_verified=False)
                with patch.object(m, 'PHASE', Path(root)/'phase'), \
                     patch.object(m, 'load_transport', return_value=helper), \
                     patch.object(m, 'prepare', return_value=b'# fake payload'), \
                     patch.object(sys, 'argv', ['controller','a'*64]):
                    if job_id is None:
                        with self.assertRaisesRegex(ValueError, 'ATTEMPT_CONSUMED'):
                            m.main()
                    else:
                        m.main()
                    with self.assertRaises(FileExistsError):
                        m.main()
                helper.transport.assert_called_once()

    def test_python36_ast(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3,6))


if __name__ == '__main__':
    unittest.main()
