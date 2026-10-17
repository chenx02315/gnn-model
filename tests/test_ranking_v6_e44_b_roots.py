import json
import unittest
from unittest.mock import patch
from scripts import run_ranking_v6_e44_b_roots as transport
from tests.test_ranking_v6_e43_b_roots import payload


class CorrectEndpointTests(unittest.TestCase):
    def test_fixed_verified_endpoint_and_ed25519(self):
        self.assertEqual(transport.COMMAND[-2], 'cjc@gpuserver.buptic.top')
        self.assertIn('HostKeyAlgorithms=ssh-ed25519', transport.COMMAND)
        self.assertIn('StrictHostKeyChecking=yes', transport.COMMAND)
        self.assertIn('BatchMode=yes', transport.COMMAND)
        self.assertNotIn('work.buptic.top', transport.COMMAND)
        self.assertEqual(transport.SOURCE.name, 'probe_ranking_v6_e43_b_metadata_roots.py')

    def test_verified_hostname_required_without_io(self):
        data = payload()
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')):
            self.assertFalse(transport.validate_response(json.dumps(data).encode()))
            data['hostname'] = 'bupt-gpus1'
            self.assertTrue(transport.validate_response(json.dumps(data).encode()))
            data['training_release'] = True
            self.assertFalse(transport.validate_response(json.dumps(data).encode()))

    def test_rejected_hash_before_connection(self):
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError, 'REVIEWED_SOURCE_SHA_MISMATCH'):
                transport.run('0'*64, 'unused')

    def test_previous_receipt_prefix_rejected_before_connection(self):
        import hashlib
        sha = hashlib.sha256(transport.SOURCE.read_bytes()).hexdigest()
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError, 'LOCAL_RECEIPT_PATH_REJECTED'):
                transport.run(sha, '../runtime_training_staging_20260928/v6_e43_b_roots_never_created')


if __name__ == '__main__': unittest.main()
