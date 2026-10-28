"""Synthetic groups plus required local E128 provenance fixture, not portable CI.

Requires the approved staging/v6_e128_failure_readback_20261027_r1/stdout.json
outside Git. No complete real E133 bodies, new remote reads or tool execution.
"""
import ast
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import eq_group_coverage_e133_r2 as m


KEYS = [('0', '/a'), ('1', '/b'), ('0', '/c'), ('1', '/d'), ('0', '/e'), ('1', '/f')]


def stats(counts, patterns=True):
    labels = m.statistics.LABELS
    text = 'Fault Classes #faults\n FU (full) 6\n'
    text += ''.join(' %s (%s) %d\n' % (label, labels[label], value) for label, value in counts.items())
    text += 'Fault Sub-classes\nCoverage\n'
    text += '#test_patterns 1\n' if patterns else ''
    return text.encode('ascii')


def fixture(labels=('DS', 'EQ', 'UC', 'EQ', 'AU.SEQ', 'EQ')):
    mapping = ('stuck_value\tcanonical_core_path\tH_native_path\tM_native_path\tF_native_path\n' +
        ''.join('\t'.join((stuck, path, path, path, path)) + '\n' for stuck, path in KEYS)).encode('ascii')
    manifest = dict(schema='multimode_common_fault_universe_v1', fault_model='stuck-at',
        common_fault_count=6, f_flat_instance_offset=0, mapping=dict(sha256=m.sha(mapping)))
    mtfi = ''.join(m.faults.HEADER) + ''.join(' %s, %s, "%s";\n' % (key[0], label, key[1])
        for key, label in zip(KEYS, labels)) + ''.join(m.faults.FOOTER)
    report = '\n type code pin_pathname\n ---- ------ ------------------------------------\n'
    report += ''.join(' %s %s %s\n' % (key[0], label, key[1]) for key, label in zip(KEYS, labels))
    counts = {'DS': 0, 'DI': 0}
    current = None
    for label in labels:
        if label != 'EQ':
            current = 'DI' if label != 'DS' and m.faults.detected(label) else label.split('.')[0]
        counts[current] = counts.get(current, 0) + 1
    return dict(manifest=m.canonical(manifest), mapping=mapping,
        F_basic=''.join('%s FU "%s"\n' % key for key in KEYS).encode('ascii'),
        F_mtfi=mtfi.encode('ascii'), F_faults_report=report.encode('ascii'),
        F_statistics=stats(counts), F_pre_statistics=stats(dict(DS=1, DI=0, UC=5), False))


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.provenance_bytes = (cls.repo.parent / 'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert m.sha(cls.provenance_bytes) == m.E128_SHA

    def setUp(self):
        self.bodies = fixture()

    def analyze(self, bodies=None, provenance=None, **kwargs):
        bodies = self.bodies if bodies is None else bodies
        return m.analyze_bodies(bodies, expected_count=6, expected_mapping_sha=m.sha(bodies['mapping']),
            provenance={'e128_response_bytes': self.provenance_bytes} if provenance is None else provenance, **kwargs)

    def test_complete_report_groups_credit_only_detected_representatives_cross_polarity_allowed(self):
        result = self.analyze()
        self.assertEqual(result['detected_count'], 2)
        self.assertEqual(result['report_group_count'], 3)
        self.assertEqual(result['report_EQ_members'], 3)
        self.assertEqual(result['expanded_top_class_counts'], dict(DS=2, UC=2, AU=2))
        expected = m.sha(m.canonical([['0', '/a'], ['1', '/b']]))
        self.assertEqual(result['detected_set_sha256'], expected)
        self.assertFalse(result['group_polarity_matching_assumed'])
        self.assertTrue(result['observed_report_uncollapsed_enumeration_verified'])
        self.assertFalse(result['actual_fault_mode_setting_observed'])
        self.assertTrue(result['synthetic_only'])
        self.assertEqual(result['scope'], 'SYNTHETIC_TEST_ONLY_NOT_ACTUAL_AES')
        self.assertFalse(result['frozen_contract_d95_pass'])

    def test_mathematical_d95_in_synthetic_fixture_never_seals_certificate(self):
        result = self.analyze(fixture(('DS', 'EQ', 'DS', 'EQ', 'DI.SCAN', 'EQ')))
        self.assertEqual(result['detected_count'], 6)
        self.assertTrue(result['candidate_meets_d95_math'])
        self.assertTrue(result['synthetic_only'])
        self.assertFalse(result['separate_coverage_only_certificate_sealed'])
        self.assertFalse(result['independent_final_reviewed'])
        self.assertFalse(result['complete_stage_or_action_acceptance'])
        self.assertFalse(result['training_release'])

    def test_native_order_is_not_group_order_and_hashes_are_deterministic(self):
        first = self.analyze()
        lines = self.bodies['F_mtfi'].decode('ascii').splitlines(keepends=True)
        n, f = len(m.faults.HEADER), len(m.faults.FOOTER)
        self.bodies['F_mtfi'] = ''.join(lines[:n] + list(reversed(lines[n:-f])) + lines[-f:]).encode('ascii')
        second = self.analyze()
        self.assertEqual(first['detected_set_sha256'], second['detected_set_sha256'])
        self.assertEqual(first['complete_group_mapping_sha256'], second['complete_group_mapping_sha256'])
        self.assertEqual(second, self.analyze())

    def test_pt_group_has_zero_credit_and_strict_di_whitelist_is_preserved(self):
        for label in ('PT', 'AU.SEQ', 'UC', 'UO'):
            result = self.analyze(fixture(('DS', 'EQ', 'UC', 'EQ', label, 'EQ')))
            self.assertEqual(result['detected_count'], 2)
            self.assertEqual(result['possible_detection_credit'], 0)
        for label in ('DI', 'DI.CLK', 'DI.SCAN', 'DI.SEN', 'DI.SR', 'DI_1', 'DI_99'):
            self.assertEqual(self.analyze(fixture((label, 'EQ', 'UC', 'EQ', 'AU.SEQ', 'EQ')))['detected_count'], 2)
        for label in ('DI.UNKNOWN', 'AU.NEW', 'PD'):
            bodies = fixture()
            bodies['F_faults_report'] = bodies['F_faults_report'].replace(b' DS ', (' ' + label + ' ').encode('ascii'))
            with self.assertRaisesRegex(ValueError, 'UNKNOWN_REPORT_CLASS'):
                self.analyze(bodies)

    def test_orphan_eq_duplicate_missing_outside_or_wrong_native_class_rejected(self):
        report = self.bodies['F_faults_report']
        lines = report.splitlines(keepends=True)
        variants = [b''.join(lines[:3] + [lines[4], lines[3]] + lines[5:]),
                    report.replace(b'1 EQ /b', b'0 EQ /a'), report.replace(b'1 EQ /b\n', b''),
                    report.replace(b'/b', b'/outside'), report.replace(b'0 DS /a', b'0 UC /a')]
        for raw in variants:
            bodies = dict(self.bodies, F_faults_report=raw)
            with self.assertRaises(ValueError):
                self.analyze(bodies)

    def test_per_class_statistics_must_match_even_when_total_and_ds_di_match(self):
        bodies = dict(self.bodies, F_statistics=stats(dict(DS=2, DI=0, UC=1, AU=3)))
        with self.assertRaisesRegex(ValueError, 'PER_CLASS_GROUP_EXPANSION_MISMATCH'):
            self.analyze(bodies)

    def test_native_false_stuck_single_instance_envelope_and_full_keysets_required(self):
        variants = [('F_mtfi', self.bodies['F_mtfi'].replace(b'FALSE', b'TRUE')),
                    ('F_mtfi', self.bodies['F_mtfi'].replace(b'FaultType (Stuck)', b'FaultType (Transition)')),
                    ('F_mtfi', self.bodies['F_mtfi'].replace(b'Instance ("")', b'Instance ("/other")')),
                    ('F_basic', self.bodies['F_basic'].replace(b'1 FU "/b"', b'0 FU "/a"')),
                    ('mapping', self.bodies['mapping'].replace(b'/b', b'/wrong', 1))]
        for role, raw in variants:
            with self.assertRaises(ValueError):
                self.analyze(dict(self.bodies, **{role: raw}))

    def test_report_header_blank_interruption_or_extra_fields_fail_closed(self):
        for raw in (self.bodies['F_faults_report'].replace(b'pin_pathname', b'unknown'),
                    self.bodies['F_faults_report'].replace(b'1 EQ /b\n', b'\n1 EQ /b\n'),
                    self.bodies['F_faults_report'].replace(b'/b', b'/b extra'),
                    self.bodies['F_faults_report'] + b'garbage\n'):
            with self.assertRaises(ValueError):
                self.analyze(dict(self.bodies, F_faults_report=raw))

    def test_same_state_provenance_requires_exact_response_not_caller_bool_or_forged_mode(self):
        for value in ({}, {'actual_fault_mode_setting_observed': True},
                      {'e128_response_bytes': self.provenance_bytes + b' '},
                      {'e128_response_bytes': b'{}'}):
            with self.assertRaises(ValueError):
                self.analyze(provenance=value)
        result = self.analyze()
        self.assertTrue(result['provenance']['same_fault_state_command_sequence_verified'])
        self.assertFalse(result['provenance']['actual_fault_mode_setting_observed'])

    def test_real_n_requires_all_seven_actual_pins_before_content_use(self):
        with mock.patch.object(m, '_provenance') as provenance:
            with self.assertRaisesRegex(ValueError, 'FROZEN_SEVEN_INPUT_PIN'):
                m.analyze_bodies(self.bodies, provenance={'e128_response_bytes': self.provenance_bytes})
            provenance.assert_not_called()
        with self.assertRaises(ValueError):
            self.analyze(dict(self.bodies, extra=b'data'))
        with self.assertRaises(ValueError):
            self.analyze(dict(self.bodies, manifest=b'x' * 65537))

    def test_new_policy_contract_and_old_false_flags_unchanged_no_io_tool_or_training(self):
        policy_bytes = (self.repo / 'contracts/eq_group_coverage_certificate_spec_e133_v1.json').read_bytes()
        self.assertEqual(m.sha(policy_bytes), m.SPEC_SHA)
        policy = json.loads(policy_bytes)
        with mock.patch('builtins.open') as opening, mock.patch('subprocess.Popen') as spawn:
            value = self.analyze()
            opening.assert_not_called()
            spawn.assert_not_called()
        self.assertEqual(value['policy_id'], policy['policy_id'])
        self.assertEqual(value['certificate_spec_sha256'], m.SPEC_SHA)
        self.assertEqual(value['percent_floor'], 95)
        self.assertEqual(m.THRESHOLD, 67656)
        self.assertEqual(m.COMMON_COUNT, 71216)
        self.assertFalse(value['frozen_contract_d95_pass'])
        self.assertFalse(value['training_release'])
        self.assertIsNone(value['actual_atpg_runtime_ns'])


    def test_balanced_outer_quotes_accept_opaque_path_without_unescaping(self):
        opaque = b'/' + bytes([92]) + b'text_in_r_reg[0] /Q'
        bodies = {role: raw.replace(b'/a', opaque) for role, raw in self.bodies.items()}
        manifest = json.loads(bodies['manifest'])
        manifest['mapping']['sha256'] = m.sha(bodies['mapping'])
        bodies['manifest'] = m.canonical(manifest)
        bodies['F_faults_report'] = bodies['F_faults_report'].replace(
            b'0 DS ' + opaque, b'0 DS "' + opaque + b'"')
        with mock.patch.object(m.faults, 'valid_path', wraps=m.faults.valid_path) as validator:
            result = self.analyze(bodies)
        self.assertEqual(result['detected_count'], 2)
        self.assertTrue(any(call.args[0] == opaque.decode('ascii') and
            call.args[1] == 'REPORT_NATIVE_PATH' for call in validator.call_args_list))
        self.assertEqual(result['parse_version'], m.PARSE_VERSION)
        self.assertEqual(result['origin_r1_source_sha256'], m.ORIGIN_R1_SHA256)
        self.assertEqual(result['certificate_spec_sha256'], m.SPEC_SHA)

    def test_balanced_plain_quotes_preserve_detected_and_group_hashes(self):
        first = self.analyze()
        bodies = dict(self.bodies, F_faults_report=self.bodies['F_faults_report'].replace(
            b'0 DS /a', b'0 DS "/a"').replace(b'1 EQ /b', b'1 EQ "/b"'))
        second = self.analyze(bodies)
        self.assertEqual(first['detected_set_sha256'], second['detected_set_sha256'])
        self.assertEqual(first['complete_group_mapping_sha256'], second['complete_group_mapping_sha256'])

    def test_unmatched_empty_nested_or_unknown_quoted_paths_still_rejected(self):
        for path in (b'"/a', b'/a"', b'""', b'"/a""', b'" /a "', b'"/outside"'):
            bodies = dict(self.bodies, F_faults_report=self.bodies['F_faults_report'].replace(b'0 DS /a', b'0 DS ' + path))
            with self.assertRaises(ValueError):
                self.analyze(bodies)

    def test_duplicate_keys_after_quote_normalization_are_rejected(self):
        bodies = dict(self.bodies, F_faults_report=self.bodies['F_faults_report'].replace(
            b'1 EQ /b', b'0 EQ "/a"'))
        with self.assertRaisesRegex(ValueError, 'REPORT_KEY_DUPLICATE_OR_OUTSIDE'):
            self.analyze(bodies)

    def test_frozen_r1_source_and_failed_quoted_dialect_remain_unchanged(self):
        from src.data import eq_group_coverage_e133 as r1
        original = (self.repo / 'src/data/eq_group_coverage_e133.py').read_bytes()
        self.assertEqual(m.sha(original), m.ORIGIN_R1_SHA256)
        bodies = dict(self.bodies, F_faults_report=self.bodies['F_faults_report'].replace(
            b'0 DS /a', b'0 DS "/a"'))
        with self.assertRaisesRegex(ValueError, 'REPORT_NATIVE_PATH'):
            r1.analyze_bodies(bodies, expected_count=6, expected_mapping_sha=m.sha(bodies['mapping']),
                provenance={'e128_response_bytes': self.provenance_bytes})
        self.assertEqual(m.sha((self.repo / 'src/data/eq_group_coverage_e133.py').read_bytes()), m.ORIGIN_R1_SHA256)

    def test_owned_sources_python36(self):
        for path in ('src/data/eq_group_coverage_e133_r2.py', 'tests/test_eq_group_coverage_e133_r2.py'):
            ast.parse((self.repo / path).read_text(), feature_version=(3, 6))
