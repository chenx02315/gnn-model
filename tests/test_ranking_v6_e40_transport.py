"""Synthetic transport checks only; no source measurements or SSH calls."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts import run_ranking_v6_e40_readonly as transport
from scripts import project_ranking_v6_e40_result_paths as producer


def synthetic_payload():
    files = []
    for spec in producer.SPECS:
        entry = {key: spec[key] for key in ('circuit', 'coverage_root', 'stage_alias',
                 'path', 'sha256', 'byte_count', 'header_sha256')}
        entry['row_count'] = spec['expected_rows']
        entry['rows'] = [dict(zip(('source_row', 'candidate', 'h_patterns', 'm_patterns',
                                  'candidate_origin'), row), h_result='prefix/H/result',
                              f_result='run/F/result') for row in spec['targets']]
        files.append(entry)
    return dict(status='PASS_TARGET_RESULT_PATH_METADATA_ONLY', files=files, file_count=4,
                total_bytes=32919, total_rows=73, target_rows=8,
                source_file_bytes_read_for_sha_and_structure=True, quality_evaluated=False,
                result_files_opened=False, source_origin_assigned=False, training_release=False,
                physical_files_written=False,
                resource=dict(address_space_limit_bytes=1073741824, cpu_limit_s=20, workers=1))


class TransportTests(unittest.TestCase):
    def test_positive_response_is_pure_and_bounded(self):
        raw = json.dumps(synthetic_payload()).encode('ascii')
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')), \
             patch('os.open', side_effect=AssertionError('NO_RESULT_OPEN')):
            self.assertTrue(transport.validate_response(raw))
        self.assertLess(len(raw), transport.LIMIT)
        self.assertEqual(transport.LIMIT, 65536)
        self.assertEqual(transport.COMMAND[-1], '/usr/bin/python3 -I -S -B -')

    def test_duplicate_json_quality_or_changed_identity_rejected(self):
        good = synthetic_payload()
        raw = json.dumps(good).encode('ascii')
        self.assertFalse(transport.validate_response(raw.replace(b'"status":', b'"status":0,"status":', 1)))
        self.assertFalse(transport.validate_response(b'{"status":NaN}'))
        self.assertFalse(transport.validate_response(65536))
        self.assertFalse(transport.validate_response(b' ' * (transport.LIMIT + 1)))
        for key, value in (('quality_evaluated', True), ('training_release', True),
                           ('extra_quality', 95), ('target_rows', 9)):
            bad = copy.deepcopy(good)
            bad[key] = value
            self.assertFalse(transport.validate_response(json.dumps(bad).encode('ascii')))
        bad = copy.deepcopy(good)
        bad['files'][0]['rows'][0]['candidate'] = 'changed'
        self.assertFalse(transport.validate_response(json.dumps(bad).encode('ascii')))

    def test_source_sha_mismatch_cannot_start_process(self):
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError, 'REVIEWED_SOURCE_SHA_MISMATCH'):
                transport.run('0' * 64, 'unused')

    def test_wrong_receipt_location_cannot_start_process(self):
        import hashlib
        sha = hashlib.sha256(transport.SOURCE.read_bytes()).hexdigest()
        with patch('subprocess.Popen', side_effect=AssertionError('NO_SSH')):
            with self.assertRaisesRegex(ValueError, 'LOCAL_RECEIPT_PATH_REJECTED'):
                transport.run(sha, Path(__file__).resolve().parent / 'no_receipt')


if __name__ == '__main__': unittest.main()
