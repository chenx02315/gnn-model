import copy
import unittest
from unittest.mock import patch
from scripts.summarize_ranking_v6_e40_result_paths import summarize
from test_ranking_v6_e40_transport import synthetic_payload


class SummaryTests(unittest.TestCase):
    def test_pure_equal_and_different_paths(self):
        data = synthetic_payload()
        data['files'][1]['rows'][0]['f_result'] = 'other/F/result'
        with patch('os.open', side_effect=AssertionError('NO_FILE')), \
             patch('subprocess.Popen', side_effect=AssertionError('NO_PROCESS')):
            result = summarize(data)
        first = result['targets'][0]['declared_path_comparison']
        self.assertEqual(first['h_result']['classification'], 'same_declared_string')
        self.assertEqual(first['f_result']['classification'], 'different_declared_strings')
        self.assertFalse(result['training_release'])
        self.assertNotIn('prefix/H/result', str(result))

    def test_two_empty_paths_are_missing_not_proof_of_reuse(self):
        data = synthetic_payload()
        for item in data['files']:
            for row in item['rows']: row['h_result'] = ''
        result = summarize(data)
        self.assertTrue(all(t['declared_path_comparison']['h_result']['classification'] == 'missing_declaration'
                            for t in result['targets']))

    def test_changed_scope_or_quality_fields_refused(self):
        for field, value in (('quality_evaluated', True), ('extra_quality', 95), ('total_rows', 74)):
            data = copy.deepcopy(synthetic_payload())
            data[field] = value
            with self.assertRaises(ValueError): summarize(data)


if __name__ == '__main__': unittest.main()
