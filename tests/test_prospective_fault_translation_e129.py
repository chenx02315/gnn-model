"""E128 inventory/samples plus synthetic full flows, not real-MTFI replay."""
import ast
import base64
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import prospective_fault_translation_v2 as old
from src.data import prospective_fault_translation_e129 as m
from src.data import prospective_report_dialect_e126 as statistics
from tests import test_prospective_fault_translation_v2 as fixtures


def run(module, source='H', target='M', source_raw=None, target_raw=None,
        map_raw=None, count=3, offset=1, pins=None):
    inputs = dict(mapping=fixtures.mapping() if map_raw is None else map_raw,
        source_mtfi=fixtures.mtfi(source) if source_raw is None else source_raw,
        target_basic=fixtures.basic(target) if target_raw is None else target_raw)
    hashes = {key: m.sha(value) for key, value in inputs.items()} if pins is None else pins
    return module.translate(inputs['mapping'], inputs['source_mtfi'], inputs['target_basic'],
        source, target, count, offset, hashes)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        raw = (cls.repo.parent / 'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert m.sha(raw) == 'd70818980f52ad17e9a1d7eb917d9618d1bf203d4ec29b7e780430529528189e'
        response = json.loads(raw)
        cls.inventory = next(row for row in response['files'] if row['path'].endswith('/faults.mtfi'))
        cls.stats_receipt = next(row for row in response['files'] if row['path'].endswith('/statistics.rpt'))

    def test_actual_inventory_and_sample_provenance_not_complete_real_mtfi_replay(self):
        inventory = self.inventory
        self.assertEqual(inventory['status'], 'MTFI_INVENTORY')
        self.assertEqual(inventory['bytes'], 2520140)
        self.assertEqual(inventory['sha256'], '55f6850eee753e3aff90b7b2199a366cb635a7b6a00adae84b1f20fc049ded5f')
        self.assertEqual(inventory['row_count'], 71216)
        self.assertEqual(inventory['unknown_labels'], ['AU.SEQ'])
        self.assertNotIn('body_base64', inventory)
        self.assertFalse(inventory['namespace_or_unique_fault_set_verified'])
        example = inventory['unknown_examples'][0]
        raw = base64.b64decode(example['line_base64'], validate=True)
        self.assertEqual(len(raw), example['line_bytes'])
        self.assertEqual(example['line_number'], 1042)
        match = m.FAULT_RE.fullmatch(raw.decode('ascii').rstrip('\n'))
        self.assertEqual(match.groups(), ('0', 'AU.SEQ', '/ijtag_tck'))
        source = (''.join(m.HEADER).encode('ascii') + raw + ''.join(m.FOOTER).encode('ascii'))
        keys = {('0', '/ijtag_tck')}
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_SOURCE_CLASS'):
            old.parse_source_mtfi(source, 1, keys)
        self.assertEqual(m.parse_source_mtfi(source, 1, keys), [])
        basic = b'0 AU.SEQ "/ijtag_tck"\n'
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_BASIC_CLASS'):
            old.parse_target_basic(basic, 1, keys)
        self.assertEqual(m.parse_target_basic(basic, 1, keys), set())

    def test_all_actual_bounded_class_samples_accept_with_explicit_detection_only(self):
        rows, keys, expected = [], set(), []
        for example in self.inventory['class_examples']:
            line = base64.b64decode(example['line_base64'], validate=True).decode('utf-8')
            stuck, label, path = m.FAULT_RE.fullmatch(line.rstrip('\n')).groups()
            key = (stuck, path)
            self.assertNotIn(key, keys)
            keys.add(key)
            rows.append(line)
            if label in ('DS', 'DI.CLK', 'DI.SCAN', 'DI.SEN'):
                expected.append((key, label))
        synthetic_sample_envelope = ''.join(list(m.HEADER) + rows + list(m.FOOTER)).encode('utf-8')
        self.assertEqual(len(rows), 10)
        self.assertEqual(m.parse_source_mtfi(synthetic_sample_envelope, 10, keys), expected)
        self.assertEqual(len(expected), 4)

    def test_fstats_and_mtfi_inventory_difference_does_not_promote_eq_or_d95(self):
        receipt = self.stats_receipt
        raw = base64.b64decode(receipt['body_base64'], validate=True)
        self.assertEqual(len(raw), receipt['bytes'])
        self.assertEqual(m.sha(raw), '629b433cd87ad7e471834decf9cce0f47735268da7028215b0eed68f8c60fff4')
        parsed = statistics.parse_statistics(raw, 71216)
        counts = self.inventory['class_counts']
        self.assertEqual(sum(counts.values()), 71216)
        self.assertEqual(counts['AU.SEQ'] + counts['AU.TC'], parsed['classes']['AU'])
        self.assertEqual(parsed['classes']['AU'], 15)
        explicit = sum(value for key, value in counts.items() if m.detected(key))
        self.assertEqual(explicit, 44131)
        self.assertEqual(parsed['detected_common_faults'], 69062)
        self.assertFalse(m.detected('EQ'))
        self.assertFalse(parsed['d95_verified'])
        self.assertFalse(self.inventory['detected_count_inferred'])

    def test_translate_actually_uses_new_classifier_for_source_and_target(self):
        source = fixtures.mtfi(classes=('DS', 'EQ', 'AU.SEQ'))
        target = fixtures.basic(classes=('AU.SEQ', 'EQ', 'AU.TC'))
        with mock.patch.object(m, 'valid_class', wraps=m.valid_class) as classifier:
            result = run(m, source_raw=source, target_raw=target)
        self.assertGreaterEqual([call.args[0] for call in classifier.call_args_list].count('AU.SEQ'), 2)
        self.assertEqual(result['translated_detected_entries'], 1)
        self.assertEqual(result['expected_minimum_pre_detected'], 1)
        self.assertIn(b'DS', result['output_mtfi_bytes'])
        self.assertNotIn(b'AU.SEQ', result['output_mtfi_bytes'])
        self.assertNotIn(b'EQ', result['output_mtfi_bytes'])
        manifest = json.loads(result['manifest_bytes'])
        self.assertEqual(manifest['schema'], m.SCHEMA)
        self.assertIn('AU.SEQ', manifest['noncarried_classes'])
        self.assertFalse(manifest['eq_adjacency_detection_inferred'])
        self.assertFalse(manifest['excluded_faults_proven_undetected'])
        self.assertFalse(manifest['full_real_e128_mtfi_replay_verified'])
        self.assertEqual(manifest['parent_input_sha256'], m.sha(source))

    def test_exact_only_no_new_au_or_di_wildcard(self):
        self.assertEqual(m.NONCARRIED - old.NONCARRIED, {'AU.SEQ'})
        for label in ('AU.SEQ', 'EQ'):
            self.assertTrue(m.valid_class(label))
            self.assertFalse(m.detected(label))
        for label in ('AU.NEW', 'AU.SEQ.EXTRA', 'AU.SEQ_1', 'DI.UNKNOWN', 'DI.SCAN.EXTRA', 'DI_0', 'DI_100'):
            self.assertFalse(m.valid_class(label))
            for keyword, raw in (('source_raw', fixtures.mtfi(classes=(label, 'UU', 'UU'))),
                                 ('target_raw', fixtures.basic(classes=(label, 'UU', 'UU')))):
                with self.assertRaises(ValueError):
                    run(m, **{keyword: raw})

    def test_existing_accepted_cases_keep_output_and_semantic_manifest_fields(self):
        ignore = {'schema', 'policy', 'noncarried_classes', 'full_real_e128_mtfi_replay_verified'}
        for source, target in sorted(m.TRANSITIONS):
            for labels in (('DS', 'DI_1', 'FU'), ('DI.CLK', 'EQ', 'AU.TC'), ('UU', 'PT', 'RE')):
                source_raw = fixtures.mtfi(source, classes=labels)
                old_result = run(old, source, target, source_raw=source_raw)
                result = run(m, source, target, source_raw=source_raw)
                self.assertEqual(result['output_mtfi_bytes'], old_result['output_mtfi_bytes'])
                self.assertEqual(result['output_mtfi_sha256'], old_result['output_mtfi_sha256'])
                before, after = json.loads(old_result['manifest_bytes']), json.loads(result['manifest_bytes'])
                self.assertEqual({k: v for k, v in before.items() if k not in ignore},
                                 {k: v for k, v in after.items() if k not in ignore})

    def test_sha_mapping_path_denominator_and_serialization_guards_preserved(self):
        for kwargs in (dict(pins={}), dict(count=True), dict(count=4), dict(offset=2049),
                       dict(source_raw=fixtures.mtfi()[:-1]),
                       dict(source_raw=fixtures.mtfi().replace(b'\n', b'\r\n')),
                       dict(source_raw=fixtures.mtfi().replace(b'/U2/a', b'/U2/a\\')),
                       dict(target_raw=fixtures.basic().replace(b'/U2/a', b'/wrong')),
                       dict(map_raw=fixtures.mapping().replace(b'/U2/a', b'/mismatch', 1))):
            with self.assertRaises(ValueError):
                run(m, **kwargs)
        for key in ('MAX_FILE', 'MAX_TOTAL', 'MAX_COMMON', 'MAX_PATH', 'HEADER', 'FOOTER', 'DOTTED_DETECTED'):
            self.assertEqual(getattr(m, key), getattr(old, key))

    def test_local_function_globals_not_imported_old_classifier_functions(self):
        for name in ('detected', 'valid_class', 'parse_source_mtfi', 'parse_target_basic', 'translate'):
            self.assertIs(getattr(m, name).__globals__, m.__dict__)
            self.assertIsNot(getattr(m, name), getattr(old, name))
        self.assertIs(m.mapping_lookup, old.mapping_lookup)
        self.assertIs(m.valid_path, old.valid_path)

    def test_old_source_globals_unchanged_and_no_io_or_tool_launch(self):
        path = self.repo / 'src/data/prospective_fault_translation_v2.py'
        raw, classes, detector = path.read_bytes(), copy.deepcopy(old.NONCARRIED), old.valid_class
        with mock.patch('subprocess.Popen') as spawn, mock.patch('builtins.open') as opening:
            run(m, source_raw=fixtures.mtfi(classes=('AU.SEQ', 'DI_1', 'EQ')))
            opening.assert_not_called()
            spawn.assert_not_called()
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(old.NONCARRIED, classes)
        self.assertIs(old.valid_class, detector)
        self.assertFalse(old.valid_class('AU.SEQ'))

    def test_python36_ast(self):
        for path in ('src/data/prospective_fault_translation_e129.py', 'tests/test_prospective_fault_translation_e129.py'):
            ast.parse((self.repo / path).read_text(), feature_version=(3, 6))
