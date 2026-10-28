"""Synthetic audit with required approved local E128 provenance (not portable CI).

No remote access or complete actual H body fixture is used here.
"""
import ast
from pathlib import Path
import unittest
from unittest import mock

from src.data import hf_detection_credit_e134 as m
from tests.test_eq_group_coverage_e133 import fixture, stats, KEYS


def pair(h_labels=('DS', 'EQ', 'UC', 'EQ', 'AU.TC', 'EQ'), f_labels=None):
    f = fixture() if f_labels is None else fixture(f_labels)
    original = fixture(h_labels)
    h = {role.replace('F_', 'H_'): original[role] for role in
         ('F_basic', 'F_mtfi', 'F_faults_report', 'F_statistics')}
    replay = m.frozen.translate(f['mapping'], h['H_mtfi'], f['F_basic'], 'H', 'F', 6, 0,
        dict(mapping=m.sha(f['mapping']), source_mtfi=m.sha(h['H_mtfi']), target_basic=m.sha(f['F_basic'])))
    h.update(translation_status=replay['output_mtfi_bytes'], translation_manifest=replay['manifest_bytes'])
    return h, f


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.raw = (cls.repo.parent / 'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert m.sha(cls.raw) == m.groups.E128_SHA

    def analyze(self, h=None, f=None, **kwargs):
        h0, f0 = pair()
        h, f = h0 if h is None else h, f0 if f is None else f
        return m.analyze_bodies(h, f, {'e128_response_bytes': self.raw}, 6, m.sha(f['mapping']), **kwargs)

    def test_preserved_import_does_not_establish_new_F_origins(self):
        r = self.analyze()
        self.assertEqual(r['H_physical_DT_count'], 2)
        self.assertEqual(r['imported_explicit_key_count'], 1)
        self.assertTrue(r['imported_expansion_credit_preserved'])
        self.assertEqual(r['status'], 'UNPROVEN')
        self.assertTrue(r['provenance']['F_reset_AU_reclassify_observed_between_merge_and_pre_statistics'])
        self.assertFalse(r['F_pre_post_partition_stability_proven'])
        self.assertFalse(r['physical_HF_D95_verified'])
        self.assertFalse(r['training_release'])
        self.assertEqual(r, self.analyze())

    def test_H_A_detected_does_not_credit_F_EQ_B_cross_polarity(self):
        h, f = pair(('DS', 'UC', 'UC', 'EQ', 'AU.TC', 'EQ'))
        r = self.analyze(h, f)
        self.assertEqual(r['H_physical_DT_count'], 1)
        self.assertEqual(r['imported_expansion_unproven_count'], 1)
        self.assertEqual(r['imported_expansion_counterexamples'][0]['unproven_members'], [['1', '/b']])
        self.assertEqual(r['conservative_physical_union_count'], 1)

    def test_new_F_DT_groups_not_automatically_credited(self):
        h, f = pair(f_labels=('DS', 'EQ', 'DS', 'EQ', 'AU.SEQ', 'EQ'))
        r = self.analyze(h, f)
        self.assertEqual(r['F_state_DT_count'], 4)
        self.assertEqual(r['F_state_DT_not_H_proven_count'], 2)
        self.assertEqual(r['independent_new_F_physical_DT_count'], 0)
        self.assertEqual(r['conservative_physical_union_count'], 2)

    def test_count_alignment_or_mismatch_never_proves_partition(self):
        h, f = pair()
        for count in (1, 2):
            f['F_pre_statistics'] = stats(dict(DS=count, DI=0, UC=6-count), False)
            r = self.analyze(h, f)
            self.assertFalse(r['pre_DT_count_alignment_proves_partition_or_physical_origins'])
            self.assertEqual(r['conservative_physical_union_count'], 2)
        f['F_pre_statistics'] = stats(dict(DS=5, DI=0, UC=1), False)
        with self.assertRaisesRegex(ValueError, 'PRE_POST_DETECTION_COUNT_ORDER'):
            self.analyze(h, f)
        with self.assertRaises(TypeError):
            self.analyze(partition_stability_proven=True)

    def test_unjustified_H_baseline_DS_removes_all_H_physical_credit(self):
        h, f = pair()
        h['H_basic'] = h['H_basic'].replace(b'0 FU "/a"', b'0 DS "/a"')
        r = self.analyze(h, f)
        self.assertEqual(r['H_observed_DT_count'], 2)
        self.assertEqual(r['H_physical_DT_count'], 0)
        self.assertFalse(r['imported_explicit_all_H_physically_proven'])
        self.assertFalse(r['all_F_state_credit_already_justified_by_H'])
        self.assertEqual(r['conservative_physical_union_count'], 0)

    def test_exact_v2_manifest_not_e129_manifest_or_hash_only(self):
        h, f = pair()
        alt = m.extension.translate(f['mapping'], h['H_mtfi'], f['F_basic'], 'H', 'F', 6, 0,
            dict(mapping=m.sha(f['mapping']), source_mtfi=m.sha(h['H_mtfi']), target_basic=m.sha(f['F_basic'])))
        self.assertEqual(alt['output_mtfi_bytes'], h['translation_status'])
        for role, raw in [('translation_manifest', alt['manifest_bytes']),
                          ('translation_status', h['translation_status'] + b'\n')]:
            with self.assertRaisesRegex(ValueError, 'EXACT_FROZEN_V2_TRANSLATION_REPLAY'):
                self.analyze(dict(h, **{role: raw}), f)

    def test_H_only_lower_bound_meeting_math_never_seals_synthetic(self):
        labels = ('DS', 'EQ', 'DS', 'EQ', 'DI.SCAN', 'EQ')
        h, f = pair(labels, labels)
        r = self.analyze(h, f)
        self.assertEqual(r['conservative_physical_union_count'], 6)
        self.assertTrue(r['conservative_lower_bound_meets_d95_math'])
        self.assertTrue(r['synthetic_only'])
        self.assertFalse(r['certificate_sealed'])
        self.assertFalse(r['physical_HF_D95_verified'])

    def test_full_partition_unknown_class_or_per_class_delta_rejected(self):
        a, b = KEYS[:2]
        good = dict(representative=a, members={a,b}, fault_class='DS')
        for rows in ([good, good], [dict(good, members={a})]):
            with self.assertRaises(ValueError):
                m.audit_credit_sets({a}, rows, {a}, set(), {a,b})
        with self.assertRaises(ValueError):
            m.audit_credit_sets({a}, [dict(good, fault_class='DI.UNKNOWN')], {a}, set(), {a,b})
        h, f = pair()
        h['H_statistics'] = stats(dict(DS=2, DI=0, UC=1, AU=3))
        with self.assertRaisesRegex(ValueError, 'GROUP_CLASS_STATISTICS_MISMATCH'):
            self.analyze(h, f)

    def test_all_actual_pins_precede_provenance_and_no_caller_boolean(self):
        h, f = pair()
        with mock.patch.object(m, '_h_provenance') as p:
            with self.assertRaisesRegex(ValueError, 'FROZEN_BODY_PIN'):
                m.analyze_bodies(h, f, {'e128_response_bytes': self.raw})
            p.assert_not_called()
        with self.assertRaises(ValueError):
            m.analyze_bodies(h, f, {'H_same_state_exports_verified': True}, 6, m.sha(f['mapping']))

    def test_three_six_ast_and_pure_source_has_no_execution_or_io(self):
        raw = Path(m.__file__).read_text(encoding='utf-8')
        ast.parse(raw, feature_version=(3,6))
        self.assertNotIn('subprocess', raw)
        self.assertNotIn('open(', raw)


if __name__ == '__main__':
    unittest.main()
