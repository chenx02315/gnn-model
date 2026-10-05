import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import verify_ranking_v4_rss_fix_linux as gate


class RssGateLauncherTests(unittest.TestCase):
    def test_bad_sha_refuses_before_root_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'gate'
            archive = Path(directory) / 'source.tar.gz'
            archive.write_bytes(b'invalid')
            with patch.object(gate, 'ROOT', root), patch.object(gate.sys, 'platform', 'linux'):
                self.assertEqual(1, gate.run_with_failure_receipt(archive, '0' * 64))
            self.assertFalse(root.exists())

    def test_existing_root_is_never_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'marker'
            marker.write_bytes(b'keep')
            with patch.object(gate, 'ROOT', root), patch.object(gate.sys, 'platform', 'linux'):
                self.assertEqual(1, gate.run_with_failure_receipt('unused', 'unused'))
            self.assertEqual([marker], list(root.iterdir()))

    def test_post_creation_failure_has_create_once_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'gate'
            def failing_run(*args):
                root.mkdir()
                raise ValueError('SIMULATED_DISCOVERY_FAILURE')
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'run', side_effect=failing_run):
                self.assertEqual(1, gate.run_with_failure_receipt('archive', 'sha'))
            value = json.loads((root / 'receipt.json').read_text())
            self.assertFalse(value['gate_pass'])
            self.assertEqual(1, value['exit_code'])
            self.assertIn('SIMULATED_DISCOVERY_FAILURE', value['error'])

    def test_build_is_bounded_two_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.tar.gz'
            receipt = gate.build(path)
            self.assertEqual(2, receipt['entries'])
            self.assertLess(receipt['bytes'], 50000)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt['sha256'])


if __name__ == '__main__':
    unittest.main()
