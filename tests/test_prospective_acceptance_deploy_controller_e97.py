"""Deployment controller uses only fake transport in these tests."""
import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import execute_acceptance_deploy_e97 as m


class Tests(unittest.TestCase):
    def test_changed_helper_rejected_before_transport(self):
        with patch.object(m, 'load_module') as load:
            with self.assertRaisesRegex(ValueError, 'HELPER_CHANGED'):
                m.prepare('0'*64)
        load.assert_not_called()

    def test_fake_deploy_receipt_and_no_second_attempt(self):
        helper = Mock()
        helper.verify_cached_host.return_value = 'mock-local-key'
        receipt = dict(schema='e97-bundle-deployment-v1',status='DEPLOYED_ONLY',
                       manifest_sha256=m.MANIFEST_SHA,jobs_submitted=0,files=24)
        helper.transport.return_value = dict(stdout=json.dumps(receipt).encode(),stderr=b'',
            exit_code=0,timeout=False,overflow=False,write_failed=False,
            threads_incomplete=False,remote_termination_verified=False)
        helper.decode.side_effect = json.loads
        with tempfile.TemporaryDirectory() as root, \
             patch.object(m, 'PHASE', Path(root)/'deployment'), \
             patch.object(m, 'prepare', return_value=b'# fake reviewed payload'), \
             patch.object(m, 'load_module', return_value=helper), \
             patch.object(sys, 'argv', ['controller','a'*64]):
            m.main()
            with self.assertRaises(FileExistsError):
                m.main()
        helper.transport.assert_called_once()

    def test_python36_ast(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3,6))


if __name__ == '__main__':
    unittest.main()
