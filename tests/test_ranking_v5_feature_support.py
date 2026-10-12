"""Synthetic-only feature package tests; no real TRAIN root is examined."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.models import ranking_v5_feature_support as support


def fixture_rows():
    rows = []
    for index, (circuit, family) in enumerate(sorted(support.FAMILIES.items())):
        for flag in (0, 1):
            rows.append({'action_uid': '%s:%s' % (circuit, flag), 'circuit': circuit,
                         'family': family, 'role': 'TRAIN', 'scheme_hf': flag,
                         'scheme_hmf': 1 - flag, 'log1p_h_limit': float(index),
                         'log1p_m_limit': 0., 'h_limit_fraction_of_circuit_max': .5,
                         'm_limit_fraction_of_circuit_max': 0., 'log1p_common_fault_count': 2.})
    return sorted(rows, key=lambda r: r['action_uid'])


def folds_for(rows):
    return {family: {'fit': [r.copy() for r in rows if r['family'] != family],
                     'heldout': [r.copy() for r in rows if r['family'] == family]}
            for family in support.FAMILY_NAMES}


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def make_package(root, rows=None, mutate=None):
    rows = rows or fixture_rows()
    source_inputs = {name: 'a' * 64 for name in ('features.tsv', 'train_outcomes.tsv', 'graph_manifest.tsv')}
    graphs = {name: 'b' * 64 for name in support.FAMILIES}
    source = support.digest({'source_input_sha256': source_inputs, 'graph_sha256': graphs})
    receipt = {'schema_version': 'ranking-v3-real-input-export-receipt-v1', 'scope': support.SCOPE,
               'release_sha256': 'c' * 64, 'source_sha256': source, 'source_input_sha256': source_inputs,
               'graph_sha256': graphs, 'family_metadata_sha256': 'd' * 64,
               'train_action_count': len(rows), 'train_outcome_count': len(rows), 'graph_count': 6,
               'fold_manifest_sha256': {}}
    for family, fold in folds_for(rows).items():
        directory = root / ('fold_' + family)
        directory.mkdir()
        hashes = {name: 'e' * 64 for name in support.SHARDS}
        hashes['fit_features.json'] = write_json(directory / 'fit_features.json', fold['fit'])
        hashes['heldout_features.json'] = write_json(directory / 'heldout_features.json', fold['heldout'])
        manifest = {'schema_version': 'ranking-v3-real-train-fold-v1', 'scope': support.SCOPE,
                    'source_sha256': source, 'family': family, 'release': {
                        'status': 'PASS_TRAIN_ONLY_DATA_RELEASE', 'source_sha256': source,
                        'independent_review_pass': True, 'roles': ['TRAIN']},
                    'fitting': [r['action_uid'] for r in fold['fit']],
                    'heldout': [r['action_uid'] for r in fold['heldout']], 'sha256': hashes}
        if mutate:
            mutate(manifest)
        receipt['fold_manifest_sha256'][family] = write_json(directory / 'manifest.json', manifest)
    sha = write_json(root / 'receipt.json', receipt)
    return support.FixturePin(str(root), sha, source, len(rows))


class FeatureSupportTests(unittest.TestCase):
    def test_fixed_root_gate_zero_io(self):
        with patch.object(support.os, 'lstat', side_effect=AssertionError('I/O')), \
                patch.object(support.os, 'open', side_effect=AssertionError('I/O')):
            for root in ('/tmp/anything', support.FIXED_ROOT + '/', support.FIXED_ROOT + '/..',
                         support.FIXED_ROOT.replace('/train_folds', '/BLIND'), Path(support.FIXED_ROOT), None):
                with self.assertRaisesRegex(ValueError, 'FIXED_ROOT'):
                    support.analyze_package(root)

    def test_pure_metrics_and_no_identifiers(self):
        rows = fixture_rows()
        result = support.analyze_rows(folds_for(rows), expected_count=12)
        first = support.FAMILY_NAMES[0]
        feature = result['folds'][first]['features']['log1p_m_limit']
        self.assertTrue(feature['std_floor_triggered'])
        self.assertEqual(feature['normalizer_std'], 1e-12)
        self.assertEqual(feature['heldout_max_abs_z'], 0.)
        index = next(r['log1p_h_limit'] for r in rows if r['family'] == first)
        fit_values = [r['log1p_h_limit'] for r in rows if r['family'] != first]
        mean = sum(fit_values) / len(fit_values)
        std = math.sqrt(sum((v - mean) ** 2 for v in fit_values) / len(fit_values))
        expected = min(abs(index - v) / std for v in fit_values)
        for scheme in ('HF', 'HMF'):
            distance = result['folds'][first]['nearest_fit_distance'][scheme]
            self.assertAlmostEqual(distance['min'], expected)
            self.assertAlmostEqual(distance['p90'], expected)
            self.assertEqual(result['folds'][first]['by_scheme'][scheme]['log1p_h_limit']['fit_mean'], mean)
        encoded = json.dumps(result)
        self.assertNotIn('action_uid', encoded)
        for row in rows:
            self.assertNotIn(row['action_uid'], encoded)

    def test_collisions_exact_vector_and_pairs(self):
        rows = fixture_rows()
        for row in rows:
            row['log1p_h_limit'] = 0.
        result = support.analyze_rows(folds_for(rows), expected_count=12)
        self.assertEqual(result['cross_family_exact_vector_collisions'], {
            'vector_count': 2, 'action_count': 12, 'cross_family_pair_count': 30})
        self.assertEqual(result['folds'][support.FAMILY_NAMES[0]]['nearest_fit_distance']['HF']['max'], 0.)

    def test_missing_fit_scheme(self):
        rows = fixture_rows()
        for row in rows:
            if row['family'] != support.FAMILY_NAMES[0]:
                row['scheme_hf'], row['scheme_hmf'] = 0, 1
        result = support.analyze_rows(folds_for(rows), expected_count=12)
        metric = result['folds'][support.FAMILY_NAMES[0]]['nearest_fit_distance']['HF']
        self.assertEqual(metric['unsupported_scheme_count'], 1)
        self.assertIsNone(metric['min'])

    def test_row_rejections(self):
        mutations = [lambda r: r.pop('role'), lambda r: r.update(role='BLIND'),
                     lambda r: r.update(scheme_hf=True), lambda r: r.update(scheme_hf=.5),
                     lambda r: r.update(log1p_h_limit=float('nan')),
                     lambda r: r.update(log1p_h_limit=float('inf')),
                     lambda r: r.update(log1p_h_limit='1'), lambda r: r.update(total_cycles=3),
                     lambda r: r.update(action_scheme='HMF' if r['scheme_hf'] else 'HF')]
        for mutation in mutations:
            rows = fixture_rows()
            mutation(rows[0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                support.analyze_rows(folds_for(rows), expected_count=12)

    def test_uid_and_cross_fold_drift(self):
        folds = folds_for(fixture_rows())
        for kind in ('duplicate', 'reverse', 'drift', 'missing'):
            altered = copy.deepcopy(folds)
            fit = altered[support.FAMILY_NAMES[0]]['fit']
            if kind == 'duplicate':
                fit[1]['action_uid'] = fit[0]['action_uid']
            elif kind == 'reverse':
                fit.reverse()
            elif kind == 'drift':
                fit[0]['log1p_h_limit'] += .25
            else:
                fit.pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                support.analyze_rows(altered, expected_count=12)

    def test_reader_positive_only_19_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = make_package(root)
            opened = []
            original = support.os.open
            def recording(path, flags, *args):
                opened.append(Path(path).name)
                return original(path, flags, *args)
            with patch.object(support.os, 'open', side_effect=recording):
                result = support._analyze_fixture_package(str(root), fixture_pin=pin)
            self.assertEqual(result['receipt_sha256'], pin.receipt_sha256)
            self.assertEqual(len(opened), 19)
            self.assertEqual(set(opened), {'receipt.json', 'manifest.json', 'fit_features.json', 'heldout_features.json'})

    def test_reader_hash_and_manifest_drift(self):
        for kind in ('bytes', 'release', 'join', 'source'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def mutate(manifest):
                    if kind == 'release':
                        manifest['release']['roles'] = []
                    if kind == 'join':
                        manifest['heldout'] = manifest['fitting'][:1]
                    if kind == 'source':
                        manifest['source_sha256'] = 'f' * 64
                pin = make_package(root, mutate=mutate)
                if kind == 'bytes':
                    (root / ('fold_' + support.FAMILY_NAMES[0]) / 'fit_features.json').write_bytes(b'[]')
                reason = {'bytes': 'HASH', 'release': 'MANIFEST_RELEASE',
                          'join': 'MANIFEST_JOIN', 'source': 'MANIFEST_RELEASE'}[kind]
                with self.assertRaisesRegex(ValueError, 'FEATURE_SUPPORT_' + reason + '$'):
                    support._analyze_fixture_package(str(root), fixture_pin=pin)

    def test_strict_json_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            for raw in (b'{"a":1,"a":2}', b'[NaN]', b'[Infinity]'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    support._read_json(path, hashlib.sha256(raw).hexdigest())
            path.write_bytes(b'[]')
            os.link(path, Path(directory) / 'link.json')
            with self.assertRaisesRegex(ValueError, 'LINK_OR_SIZE'):
                support._read_json(path, hashlib.sha256(b'[]').hexdigest())

    def test_quantile_interpolation(self):
        self.assertEqual(support._quantile([0., 2., 10.], .5), 2.)
        self.assertAlmostEqual(support._quantile([0., 2., 10.], .9), 8.4)

    def test_bounded_reader_and_fixture_pin_zero_io(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(support.os, 'lstat', side_effect=AssertionError('I/O')):
                bad = support.FixturePin(str(root), 'a' * 64, 'b' * 64, 1707)
                with self.assertRaisesRegex(ValueError, 'FIXTURE_BOUNDS'):
                    support._analyze_fixture_package(str(root), fixture_pin=bad)
            path = root / 'large.json'
            path.write_bytes(b' ' * 65)
            with patch.object(support, 'MAX_BYTES', 64), \
                    patch.object(support.os, 'open', side_effect=AssertionError('open')):
                with self.assertRaisesRegex(ValueError, 'LINK_OR_SIZE'):
                    support._read_json(path, 'a' * 64)

    def test_file_identity_change_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.json'
            path.write_bytes(b'[]')
            original = support.os.fstat
            count = 0
            def changed(descriptor):
                nonlocal count
                info = original(descriptor)
                count += 1
                if count < 2:
                    return info
                fields = {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_size',
                          'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_mode')}
                fields['st_size'] += 1
                return SimpleNamespace(**fields)
            with patch.object(support.os, 'fstat', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'MUTATED'):
                    support._read_json(path, hashlib.sha256(b'[]').hexdigest())

    def test_symlink_file_and_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / 'real'
            real.mkdir()
            path = real / 'data.json'
            path.write_bytes(b'[]')
            try:
                (root / 'file.json').symlink_to(path)
                (root / 'alias').symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest('local symlink privilege unavailable: ' + str(exc))
            for target in (root / 'file.json', root / 'alias' / 'data.json'):
                with self.assertRaisesRegex(ValueError, 'SYMLINK_OR_REPARSE'):
                    support._read_json(target, hashlib.sha256(b'[]').hexdigest())

    def test_v3_feature_order_and_normalizer_equivalence(self):
        from src.models import runtime_ranking_v3 as v3
        self.assertEqual(support.FEATURES, v3.FEATURES)
        self.assertEqual(support.FAMILIES, v3.FAMILIES)
        folds = folds_for(fixture_rows())
        result = support.analyze_rows(folds, expected_count=12)
        for family, fold in folds.items():
            mean, std = v3.fit_normalizer(v3.feature_matrix(fold['fit']))
            for index, name in enumerate(v3.FEATURES):
                reported = result['folds'][family]['features'][name]
                self.assertEqual(reported['fit_mean'], mean[index])
                self.assertEqual(reported['normalizer_std'], std[index])

    def test_asymmetric_schemes_keep_global_normalizer(self):
        rows = fixture_rows()
        for row in rows:
            row['log1p_h_limit'] += 100. * row['scheme_hf']
        result = support.analyze_rows(folds_for(rows), expected_count=12)
        for fold in result['folds'].values():
            global_feature = fold['features']['log1p_h_limit']
            for scheme in ('HF', 'HMF'):
                feature = fold['by_scheme'][scheme]['log1p_h_limit']
                self.assertEqual(feature['normalizer_std'], global_feature['normalizer_std'])
                self.assertEqual(feature['fit_mean'], global_feature['fit_mean'])
                self.assertEqual(feature['fit_population_std'], global_feature['fit_population_std'])

    def test_mock_symlink_ancestor_gate(self):
        info = SimpleNamespace(st_mode=0o120777, st_file_attributes=0)
        with patch.object(support.os, 'lstat', return_value=info), \
                patch.object(support.os, 'open', side_effect=AssertionError('open')):
            with self.assertRaisesRegex(ValueError, 'SYMLINK_OR_REPARSE'):
                support._read_json(Path('fixture.json'), 'a' * 64)


if __name__ == '__main__':
    unittest.main()
