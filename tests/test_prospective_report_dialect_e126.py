"""Local immutable E125 evidence and synthetic byte negatives; no new reads on A."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import prospective_report_dialect_e115 as old
from src.data import prospective_report_dialect_e126 as m

RESPONSE_SHA = 'b5765db14b6f9ae3ab0a0d19791723badc693e113d6c1af4ed0817c72a2fdbac'
STATS_SHA = '6a2c43dda14dc5c383ef50312b1af4682908db9649b1a5a13a29016e0094903d'


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        raw = (cls.root.parent / 'runtime_training_staging_20260928/v6_e125_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == RESPONSE_SHA
        value = json.loads(raw)
        row = next(row for row in value['files'] if row['path'].endswith('/statistics.rpt'))
        cls.stats = base64.b64decode(row['body_base64'], validate=True)
        assert len(cls.stats) == row['bytes'] == 2681
        assert hashlib.sha256(cls.stats).hexdigest() == row['sha256'] == STATS_SHA

    def test_actual_e125_old_fails_new_passes_without_raw_normalization(self):
        before = self.stats
        with self.assertRaisesRegex(ValueError, 'CLASS_LABEL_OR_DUPLICATE'):
            old.parse_statistics(self.stats, 71216)
        result = m.parse_statistics(self.stats, 71216)
        self.assertEqual(result['schema'], m.SCHEMA)
        self.assertEqual(result['bytes'], 2681)
        self.assertEqual(result['sha256'], STATS_SHA)
        self.assertEqual(self.stats, before)
        self.assertEqual(result['generated_patterns'], 1)
        self.assertEqual(result['classes'], dict(FU=71216, UC=29001, UO=23805,
            DS=14610, DI=3713, PT=64, UU=2, AU=21))
        self.assertEqual(result['detected_common_faults'], 18323)
        self.assertNotEqual(result['detected_common_faults'], 18323 + 64)
        self.assertFalse(result['complete_stage_acceptance_verified'])
        self.assertFalse(result['d95_verified'])
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['training_release'])
        self.assertIsNone(result['actual_atpg_runtime_ns'])

    def test_only_exact_observed_pt_label_is_supported(self):
        for label in (b'possibly_testable', b'possible_testable', b'posdet', b'unknown', b'POSDET_TESTABLE'):
            with self.subTest(label=label), self.assertRaises(ValueError):
                m.parse_statistics(self.stats.replace(b'posdet_testable', label), 71216)

    def test_unknown_duplicate_and_malformed_top_rows_rejected(self):
        cases = (
            self.stats.replace(b'PT (posdet_testable)', b'ZZ (unknown)'),
            self.stats.replace(b'Fault Sub-classes', b'PT (posdet_testable) 0\nFault Sub-classes', 1),
            self.stats.replace(b'PT (posdet_testable)', b'PT posdet_testable'),
            self.stats.replace(b'Fault Sub-classes', b'Fault Classes\nFault Sub-classes', 1))
        for raw in cases:
            with self.assertRaises(ValueError):
                m.parse_statistics(raw, 71216)

    def test_partition_denominator_or_truncated_fields_rejected(self):
        for raw, count in ((self.stats, 71215), (self.stats.replace(b'29001', b'29000'), 71216),
                           (self.stats.split(b'Coverage')[0], 71216),
                           (self.stats.split(b'#test_patterns')[0], 71216),
                           (self.stats.replace(b'Fault Classes', b'No classes'), 71216)):
            with self.assertRaises(ValueError):
                m.parse_statistics(raw, count)

    def test_subclass_rows_are_not_double_counted_and_bad_section_rejected(self):
        raw = self.stats.replace(b'Fault Sub-classes', b'Fault Sub-classes\nPT (arbitrary_subclass_label) 999999\n', 1)
        self.assertEqual(m.parse_statistics(raw, 71216)['detected_common_faults'], 18323)
        self.assertEqual(m.parse_statistics(raw, 71216)['classes']['PT'], 64)
        for bad in (self.stats.replace(b'Fault Sub-classes', b'Fault Sub-classes\nFault Sub-classes', 1),
                    b'Fault Sub-classes\n' + self.stats):
            with self.assertRaisesRegex(ValueError, 'SUBCLASS_SECTION'):
                m.parse_statistics(bad, 71216)

    def test_pattern_duplicate_and_pre_atpg_pattern_requirement_preserved(self):
        with self.assertRaisesRegex(ValueError, 'PATTERN_ROW'):
            m.parse_statistics(self.stats + b'#test_patterns 2\n', 71216)
        raw = b'\n'.join(line for line in self.stats.splitlines() if not line.strip().startswith(b'#test_patterns'))
        with self.assertRaises(ValueError):
            m.parse_statistics(raw, 71216)
        result = m.parse_statistics(raw, 71216, patterns_required=False)
        self.assertIsNone(result['generated_patterns'])
        self.assertEqual(result['detected_common_faults'], 18323)

    def test_full_byte_bounds_nul_types_and_count_bound_preserved(self):
        for raw in (b'', b'x' * 65537, self.stats + b'\x00', self.stats.decode('ascii')):
            with self.assertRaises(ValueError):
                m.parse_statistics(raw, 71216)
        for count in (0, True, m.MAX_COUNT + 1):
            with self.assertRaises(ValueError):
                m.parse_statistics(self.stats, count)
        with self.assertRaisesRegex(ValueError, 'PATTERN_REQUIREMENT_TYPE'):
            m.parse_statistics(self.stats, 71216, patterns_required=1)

    def test_old_source_globals_and_stil_function_are_unchanged(self):
        path = self.root / 'src/data/prospective_report_dialect_e115.py'
        original_source = path.read_bytes()
        labels = copy.deepcopy(old.LABELS)
        original = old.parse_statistics
        with mock.patch('subprocess.Popen') as spawn:
            m.parse_statistics(self.stats, 71216)
            spawn.assert_not_called()
        self.assertEqual(path.read_bytes(), original_source)
        self.assertEqual(old.LABELS, labels)
        self.assertEqual(old.LABELS['PT'], 'possibly_testable')
        self.assertEqual(m.LABELS['PT'], 'posdet_testable')
        self.assertIsNot(m.LABELS, old.LABELS)
        self.assertIs(old.parse_statistics, original)
        self.assertIs(m.scan_stil, old.scan_stil)
        self.assertIs(m.ROW, old.ROW)
        self.assertIs(m.PATTERNS, old.PATTERNS)

    def test_python36_ast(self):
        for path in ('src/data/prospective_report_dialect_e126.py', 'tests/test_prospective_report_dialect_e126.py'):
            ast.parse((self.root / path).read_text(), feature_version=(3, 6))
