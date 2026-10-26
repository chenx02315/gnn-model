import ast
import hashlib
from pathlib import Path
import unittest
from src.data import prospective_report_dialect_e115 as m


STATS = b"""Statistics Report
Fault Classes #faults
 FU (full) 10
 DS (det_simulation) 6 (60.00%)
 DI (det_implication) 2 (20.00%)
 AU (atpg_untestable) 2 (20.00%)
Fault Sub-classes
 DI (det_implication)
 SCAN (scan_path) 2 (20.00%)
Coverage
 test_coverage 80.00%
#test_patterns 4
CPU_time (secs) 123.4
"""


class Reports(unittest.TestCase):
    def scan(self, raw, chunk=7, **overrides):
        kwargs = dict(expected_bytes=len(raw), expected_sha256=hashlib.sha256(raw).hexdigest())
        kwargs.update(overrides)
        return m.scan_stil((raw[p:p+chunk] for p in range(0, len(raw), chunk)), **kwargs)

    def test_actual_table_shape_and_subclass_heading(self):
        result = m.parse_statistics(STATS, 10)
        self.assertEqual(result['detected_common_faults'], 8)
        self.assertEqual(result['generated_patterns'], 4)
        self.assertIsNone(result['actual_atpg_runtime_ns'])
        self.assertFalse(result['d95_verified'])

    def test_pre_atpg_statistics_need_not_have_generated_patterns(self):
        raw = STATS.replace(b'#test_patterns 4\n', b'')
        result = m.parse_statistics(raw, 10, patterns_required=False)
        self.assertIsNone(result['generated_patterns'])
        self.assertEqual(result['detected_common_faults'], 8)
        with self.assertRaises(ValueError):
            m.parse_statistics(raw, 10)

    def test_statistics_rejects_truncated_missing_duplicate_unknown_or_mismatch(self):
        for raw in (STATS.split(b'Coverage')[0], STATS.replace(b'FU (full) 10', b'FU (full) 11'),
                    STATS.replace(b'DS (det_simulation)', b'DS (unknown)'),
                    STATS.replace(b'DS (det_simulation) 6', b'DS (det_simulation) 7'),
                    STATS + b'#test_patterns 5\n', STATS.replace(b'#test_patterns 4', b''),
                    STATS.replace(b'Fault Sub-classes', b'DS (det_simulation) 0\nFault Sub-classes')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.parse_statistics(raw, 10)

    def test_duplicate_comment_ann_not_cycle_sum(self):
        raw = b'STIL 1.0;\n// TesterCycle:0\nAnn {* TesterCycle:0 *}\n// TesterCycle:40\nAnn {* TesterCycle:40 *}\n'
        result = self.scan(raw)
        self.assertEqual(result['annotation_records'], 4)
        self.assertEqual(result['maximum_reported_tester_cycle'], 40)
        self.assertFalse(result['stil_semantics_qualified'])
        self.assertNotIn('ate_cycles', result)

    def test_chunk_boundaries_every_position_and_eof(self):
        raw = b'STIL 1.0;\n// TesterCycle:12345\nAnn {* TesterCycle:12345 *}'
        for chunk in range(1, len(raw) + 1):
            self.assertEqual(self.scan(raw, chunk)['maximum_reported_tester_cycle'], 12345)

    def test_no_prefix_as_full_file_or_wrong_hash(self):
        raw = b'// TesterCycle:9\n'
        with self.assertRaisesRegex(ValueError, 'COMPLETE_BYTES'):
            self.scan(raw, expected_bytes=len(raw)+1)
        with self.assertRaisesRegex(ValueError, 'COMPLETE_BYTES'):
            self.scan(raw, expected_sha256='0'*64)
        with self.assertRaises(ValueError):
            self.scan(raw, expected_bytes=len(raw)-1)

    def test_malformed_and_overflow_annotations(self):
        for value in (b'', b'-1', b'12x', b'9223372036854775808', b'9'*50):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.scan(b'Ann {* TesterCycle:'+value+b' *}\n')
        with self.assertRaises(ValueError):
            self.scan(b'STIL 1.0;\n')

    def test_budget_failure_propagates_without_partial_summary(self):
        def stop():
            raise ValueError('STOP_BUDGET')
        with self.assertRaisesRegex(ValueError, 'STOP_BUDGET'):
            self.scan(b'// TesterCycle:9\n', tick=stop)

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
