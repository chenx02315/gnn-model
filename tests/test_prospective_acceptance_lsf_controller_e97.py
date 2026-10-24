"""Controller happy/failure flow with a fake transport; never SSH."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import execute_acceptance_lsf_probe_e97 as m


class Tests(unittest.TestCase):
    def test_fake_transport_happy_flow_and_exclusive_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'reader.py'
            source.write_bytes(b'# fake reviewed payload\n')
            phase = Path(root) / 'evidence'
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            value = dict(schema='acceptance_lsf_setup_e97_v1',hostname='bupt-vncs2',
                         execution_ready=False, jobs_submitted=0, programs_launched=0,
                         status='PASS_BOUNDED_SETUP_METADATA_ONLY')
            helper = Mock()
            helper.verify_cached_host.return_value = 'SHA256:mock-only'
            helper.transport.return_value = dict(stdout=json.dumps(value).encode(),stderr=b'',
                exit_code=0,timeout=False,overflow=False,write_failed=False,
                threads_incomplete=False,remote_termination_verified=False)
            helper.decode.side_effect = json.loads
            with patch.object(m, 'SOURCE', source), patch.object(m, 'PHASE', phase), \
                 patch.object(m, 'load_transport', return_value=helper), \
                 patch.object(sys, 'argv', ['controller', digest]):
                m.main()
                self.assertEqual(len(list(phase.iterdir())), 4)
                with self.assertRaises(FileExistsError):
                    m.main()
                helper.transport.assert_called_once()

    def test_changed_source_rejected_before_transport(self):
        with patch.object(m, 'load_transport') as loader, \
             patch.object(sys, 'argv', ['controller', '0'*64]):
            with self.assertRaisesRegex(ValueError, 'SOURCE_CHANGED'):
                m.main()
        loader.assert_not_called()

    def test_python36_ast(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
