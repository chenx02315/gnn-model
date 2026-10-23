"""Tiny synthetic in-memory identity fixtures; no Tessent or filesystem I/O."""
import json
import unittest
from unittest import mock

from src.data import prospective_fault_translation_v2 as m


ROWS = [
    ('0', '/U2/a', '/U1/a', '/U2/a', '/U2/a'),
    ('1', '/U3/b', '/U2/b', '/U3/b', '/U3/b'),
    ('0', '/U4/c', '/U3/c', '/U4/c', '/U4/c'),
]


def mapping(rows=ROWS):
    columns = ('stuck_value', 'canonical_core_path', 'F_native_path',
               'M_native_path', 'H_native_path')
    return ('\t'.join(columns) + '\n' +
            ''.join('\t'.join(row) + '\n' for row in rows)).encode('ascii')


def mtfi(mode='H', classes=('DS', 'DI_1', 'FU'), order=(0, 1, 2)):
    col = {'F': 2, 'M': 3, 'H': 4}[mode]
    lines = list(m.HEADER)
    lines.extend('   %s, %s, "%s";\n' %
                 (ROWS[i][0], classes[i], ROWS[i][col]) for i in order)
    lines.extend(m.FOOTER)
    return ''.join(lines).encode('ascii')


def basic(mode='M', classes=('PT', 'DS', 'FU')):
    col = {'F': 2, 'M': 3, 'H': 4}[mode]
    return ''.join('%s %s "%s"\n' % (row[0], cls, row[col])
                   for row, cls in zip(ROWS, classes)).encode('ascii')


def run(source='H', target='M', source_raw=None, target_raw=None, map_raw=None,
        pins=None, count=3, offset=1):
    inputs = (mapping() if map_raw is None else map_raw,
              mtfi(source) if source_raw is None else source_raw,
              basic(target) if target_raw is None else target_raw)
    expected = {'mapping': m.sha(inputs[0]), 'source_mtfi': m.sha(inputs[1]),
                'target_basic': m.sha(inputs[2])} if pins is None else pins
    return m.translate(*inputs, source, target, count, offset, expected)


class FaultTranslationTests(unittest.TestCase):
    def test_internal_backslash_is_preserved_without_interpretation(self):
        suffix = '/\\escaped[0] /a'
        rows = [tuple(part.replace('/a', suffix) for part in row) for row in ROWS]
        for target in ('M','F'):
            value = run('H', target, map_raw=mapping(rows),
                        source_raw=mtfi().replace(b'/a', suffix.encode('ascii')),
                        target_raw=basic(target).replace(b'/a', suffix.encode('ascii')))
            self.assertIn(suffix.encode('ascii'), value['output_mtfi_bytes'])
            self.assertEqual(json.loads(value['manifest_bytes'])['path_policy'],
                             'OPAQUE_INTERNAL_BACKSLASH_NO_UNESCAPE_V2')
            self.assertFalse(value['tessent_acceptance_verified'])

    def test_trailing_backslash_and_control_quote_paths_remain_rejected(self):
        for path in ('/a\\', '/a"b', '/a\x00b', '/a\nb', '/a\rb', '/a\tb', ' /a'):
            with self.assertRaises(ValueError):
                m.valid_path(path, 'PATH')
        with self.assertRaisesRegex(ValueError, 'MTFI_PATH'):
            run(source_raw=mtfi().replace(b'/U2/a', b'/U2/a\\'))
        with self.assertRaisesRegex(ValueError, 'BASIC_PATH'):
            run(target_raw=basic().replace(b'/U2/a', b'/U2/a\\'))
        rows = list(ROWS)
        rows[0] = tuple(part + '\\' if index else part for index,part in enumerate(rows[0]))
        with self.assertRaisesRegex(ValueError, 'MAPPING_CORE_PATH'):
            run(map_raw=mapping(rows))

    def test_observed_dotted_classes_and_no_wildcard(self):
        for label in ('DI.CLK', 'DI.SCAN', 'DI.SEN', 'DI.SR'):
            value = run(source_raw=mtfi(classes=(label, 'EQ', 'RE')))
            self.assertEqual(value['translated_detected_entries'], 1)
            self.assertIn(label.encode('ascii'), value['output_mtfi_bytes'])
        for label in ('DI.UNKNOWN', 'DI.SCAN.EXTRA', 'DIRTY', 'AU.UNKNOWN'):
            with self.assertRaises(ValueError):
                run(source_raw=mtfi(classes=(label, 'UU', 'UU')))

    def test_eq_after_detected_is_not_inherited_and_au_not_carried(self):
        value = run(source_raw=mtfi(classes=('DS', 'EQ', 'AU.PC')),
                    target_raw=basic(classes=('AU.TC', 'EQ', 'RE')))
        self.assertEqual(value['translated_detected_entries'], 1)
        self.assertEqual(value['expected_minimum_pre_detected'], 1)
        manifest=json.loads(value['manifest_bytes'])
        self.assertFalse(manifest['eq_adjacency_detection_inferred'])
        self.assertFalse(manifest['excluded_faults_proven_undetected'])

    def test_provisional_di_suffix_is_unambiguous_positive_integer(self):
        for label in ('DI_0', 'DI_00', 'DI_01', 'DI_100', 'DIRTY'):
            self.assertFalse(m.detected(label))
        for label in ('DI', 'DI_1', 'DI_99'):
            self.assertTrue(m.detected(label))

    def test_h_to_m_h_to_f_m_to_f_namespace_and_union(self):
        for source, target in (('H', 'M'), ('H', 'F'), ('M', 'F')):
            value = run(source, target)
            manifest = json.loads(value['manifest_bytes'])
            self.assertEqual(value['translated_detected_entries'], 2)
            self.assertEqual(value['expected_minimum_pre_detected'], 2)
            self.assertIn(b'/U1/a' if target == 'F' else b'/U2/a',
                          value['output_mtfi_bytes'])
            self.assertEqual(manifest['source_mode'], source)
            self.assertEqual(manifest['target_mode'], target)
            self.assertEqual(manifest['f_flat_instance_offset'], 1)
            self.assertEqual(manifest['parent_input_sha256'],
                             manifest['input_sha256']['source_mtfi'])
            self.assertFalse(manifest['tessent_acceptance_verified'])
            self.assertFalse(manifest['d95_verified'])

    def test_deterministic_output_order_independent_of_source_order(self):
        first = run(source_raw=mtfi(order=(0, 1, 2)))
        second = run(source_raw=mtfi(order=(2, 1, 0)))
        self.assertEqual(first['output_mtfi_bytes'], second['output_mtfi_bytes'])
        self.assertEqual(first['output_mtfi_sha256'], second['output_mtfi_sha256'])
        self.assertNotEqual(first['manifest_sha256'], second['manifest_sha256'])

    def test_empty_detection_is_header_only_not_zero_cycles(self):
        value = run(source_raw=mtfi(classes=('FU', 'PT', 'UU')),
                    target_raw=basic(classes=('PT', 'FU', 'UU')))
        self.assertEqual(value['output_mtfi_bytes'],
                         ''.join(m.HEADER + m.FOOTER).encode('ascii'))
        self.assertEqual(value['translated_detected_entries'], 0)
        self.assertEqual(value['expected_minimum_pre_detected'], 0)
        self.assertNotIn('cycles', json.loads(value['manifest_bytes']))

    def test_disjoint_baseline_adds_union_without_d95_claim(self):
        value = run(target_raw=basic(classes=('FU', 'PT', 'DS')))
        manifest = json.loads(value['manifest_bytes'])
        self.assertEqual(value['translated_detected_entries'], 2)
        self.assertEqual(value['expected_minimum_pre_detected'], 3)
        self.assertEqual(manifest['target_baseline_detected_entries'], 1)
        self.assertFalse(manifest['d95_verified'])

    def test_duplicate_missing_extra_and_wrong_mode_source_rejected(self):
        duplicate = mtfi(order=(0, 0, 2))
        with self.assertRaisesRegex(ValueError, 'SOURCE_DUPLICATE'):
            run(source_raw=duplicate)
        missing = (''.join(m.HEADER) +
                   '   0, DS, "/U2/a";\n' + ''.join(m.FOOTER)).encode('ascii')
        with self.assertRaisesRegex(ValueError, 'SOURCE_COUNT'):
            run(source_raw=missing)
        extra = mtfi().replace(b'/U4/c', b'/U99/c')
        with self.assertRaisesRegex(ValueError, 'SOURCE_EXTRA_OR_WRONG_MODE'):
            run(source_raw=extra)
        with self.assertRaisesRegex(ValueError, 'SOURCE_EXTRA_OR_WRONG_MODE'):
            run(source_raw=mtfi('F'))

    def test_target_duplicate_extra_and_missing_rejected(self):
        with self.assertRaisesRegex(ValueError, 'BASIC_DUPLICATE'):
            run(target_raw=basic().replace(b'/U4/c', b'/U2/a'))
        with self.assertRaisesRegex(ValueError, 'BASIC_EXTRA_OR_WRONG_MODE'):
            run(target_raw=basic().replace(b'/U4/c', b'/U99/c'))
        with self.assertRaisesRegex(ValueError, 'BASIC_MISSING'):
            run(target_raw=basic().splitlines(keepends=True)[0] +
                           basic().splitlines(keepends=True)[1])

    def test_malformed_fault_looking_line_dirty_and_escaped_quote_rejected(self):
        with self.assertRaisesRegex(ValueError, 'MTFI_FAULT_LINE'):
            run(source_raw=mtfi().replace(b'0, DS,', b'0 DS,'))
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_SOURCE_CLASS'):
            run(source_raw=mtfi(classes=('DIRTY', 'DI_1', 'FU')))
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_SOURCE_CLASS'):
            run(source_raw=mtfi(classes=('DI_SOMETHING', 'DI_1', 'FU')))
        with self.assertRaisesRegex(ValueError, 'MTFI_FAULT_LINE'):
            run(source_raw=mtfi().replace(b'/U2/a', b'/U2/\\"a'))

    def test_pins_caps_transition_and_mapping_row_rules(self):
        pins = {'mapping': '0' * 64, 'source_mtfi': m.sha(mtfi()),
                'target_basic': m.sha(basic())}
        with self.assertRaisesRegex(ValueError, 'INPUT_SHA_MISMATCH_mapping'):
            run(pins=pins)
        with self.assertRaisesRegex(ValueError, 'MODE_TRANSITION'):
            run('F', 'H')
        with self.assertRaisesRegex(ValueError, 'MODE_TRANSITION'):
            run('H', 'H')
        with self.assertRaisesRegex(ValueError, 'COMMON_COUNT'):
            run(count=100001)
        bad = list(ROWS)
        bad[0] = ('0', '/U2/a', '/U2/a', '/U2/a', '/U2/a')
        with self.assertRaisesRegex(ValueError, 'MAPPING_ROW_NAMESPACE_F'):
            run(map_raw=mapping(bad))
        with self.assertRaisesRegex(ValueError, 'INPUT_BYTES_BOUND_mapping'):
            with mock.patch.object(m, 'MAX_FILE', 5):
                run()

    def test_mapping_duplicate_missing_extra_and_all_input_pins(self):
        with self.assertRaisesRegex(ValueError, 'MAPPING_DUPLICATE_CANONICAL'):
            run(map_raw=mapping([ROWS[0], ROWS[0], ROWS[2]]))
        with self.assertRaisesRegex(ValueError, 'MAPPING_COUNT'):
            run(map_raw=mapping(ROWS[:2]))
        with self.assertRaisesRegex(ValueError, 'MAPPING_ROW'):
            run(map_raw=mapping(ROWS + [ROWS[0]]))
        for key in ('source_mtfi', 'target_basic'):
            pins = {'mapping': m.sha(mapping()), 'source_mtfi': m.sha(mtfi()),
                    'target_basic': m.sha(basic())}
            pins[key] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'INPUT_SHA_MISMATCH_' + key):
                run(pins=pins)


if __name__ == '__main__':
    unittest.main()
