"""Fabricated metadata/ordinary temp files only; no actual local TRAIN table."""
import ast
import contextlib
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import diagnose_ranking_v6_e34_local_groups as diagnostic


def fixture():
    manifests, lineage = [], []
    for i, mode in enumerate(('H', 'F')):
        attempt = 'RAW_SECRET_PARENT_'+mode
        row = {name:'' for name in diagnostic.reader.MANIFEST_FIELDS}
        row.update(attempt_id=attempt, circuit='s38417', family='iscas89_s38417', role='TRAIN',
                   stage='RAW_SECRET_STAGE', mode=mode, environment_cohort='RAW_SECRET_COHORT',
                   retry_group_id='RAW_SECRET_GROUP', retry_order=str(i+1), retry_order_status='KNOWN_ORDER',
                   wall_s=('10' if i == 0 else '2'), attempt_outcome_class='SUCCESS', timeout_status='NOT_TIMEOUT',
                   source_log_sha256=hashlib.sha256(mode.encode()).hexdigest(), source_artifact_sha256='a'*64,
                   source_log_path='/never/read/source_log')
        manifests.append(row)
        lineage.append(dict(circuit='s38417', parent_attempt_id=attempt, attempt_id=attempt,
                            retry_group_id=row['retry_group_id'], retry_order=str(i+1),
                            order_evidence='EMBEDDED_SIEMENS_START_ORDER', session_index='1', session_count='1',
                            attempt_outcome_class='SUCCESS', timeout_status='NOT_TIMEOUT'))
    return manifests, lineage


class LocalGroupTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.lineage = fixture()

    def diagnose(self):
        return diagnostic.diagnose(self.manifest, self.lineage)

    def test_mode_conflict_same_stage_cohort_retained_parents_no_repair(self):
        result = self.diagnose()
        self.assertEqual(result['problem_group_count'], 1)
        group = result['problem_groups'][0]
        self.assertEqual(group['field_specific_mismatches'], ['mode'])
        self.assertEqual(group['mode_counts'], dict(H=1, M=0, F=1, OTHER=0))
        self.assertEqual(group['environment_cohort_distinct_count'], 1)
        self.assertEqual(group['parent_count'], 2)
        self.assertEqual(group['multi_session_parent_count'], 0)
        self.assertEqual(group['source_log_sha256_distinct_count'], 2)
        self.assertTrue(group['retry_order_complete_one_based'])
        self.assertEqual(group['declared_wall_sum_s'], '12')
        self.assertFalse(result['groups_repaired_or_split'])
        self.assertFalse(result['original_reader_PARTIAL_reclassified'])
        self.assertNotIn('RAW_SECRET', json.dumps(result))
        self.assertNotIn('/never/read', json.dumps(result))

    def test_stage_and_cohort_specific_digests_not_raw_values(self):
        self.manifest[1].update(stage='otherStage', environment_cohort='otherCohort')
        group = self.diagnose()['problem_groups'][0]
        self.assertEqual(group['field_specific_mismatches'], ['environment_cohort', 'mode', 'stage'])
        self.assertEqual(group['stage_distinct_count'], 2)
        self.assertTrue(all(len(value) == 64 for value in group['stage_value_sha256']))

    def test_failures_wall_aggregate_and_parent_session_gap(self):
        self.manifest[0]['attempt_outcome_class'] = self.lineage[0]['attempt_outcome_class'] = 'FAILURE'
        self.lineage[0]['session_count'] = '2'
        result = self.diagnose()
        group = result['problem_groups'][0]
        self.assertEqual(group['declared_wall_by_outcome_class_s']['FAILURE'], '10')
        self.assertEqual(group['parent_session_completeness_issue_count'], 1)
        self.assertEqual(result['parent_session_issue_count'], 1)

    def test_missing_lineage_order_fact_and_orphan_preserved(self):
        self.lineage[0]['attempt_id'] = 'orphan'
        self.manifest[1]['retry_order'] = '7'
        result = self.diagnose()
        self.assertEqual(result['orphan_lineage_count'], 1)
        group = result['problem_groups'][0]
        self.assertEqual(group['lineage_missing_count'], 1)
        self.assertFalse(group['retry_order_complete_one_based'])

    def test_homogeneous_groups_only_counted_explicit_detail_truncation(self):
        self.manifest[1]['mode'] = 'H'
        result = self.diagnose()
        self.assertEqual(result['homogeneous_group_count'], 1)
        self.assertEqual(result['problem_groups'], [])
        self.manifest[1]['mode'] = 'F'
        with patch.object(diagnostic, 'MAX_DETAILS', 0):
            result = self.diagnose()
        self.assertEqual(result['omitted_problem_group_count'], 1)
        self.assertTrue(result['status'].startswith('PARTIAL'))

    def test_no_io_or_mutation_order_deterministic_and_candidate_quality_rejected(self):
        before = copy.deepcopy((self.manifest, self.lineage))
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('os.open', side_effect=AssertionError('FD_IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('SAMPLING')):
            result = self.diagnose()
        self.assertEqual(before, (self.manifest, self.lineage))
        self.manifest.reverse()
        self.lineage.reverse()
        self.assertEqual(result, self.diagnose())
        self.manifest[0]['total_cycles'] = 'quality_forbidden'
        with self.assertRaisesRegex(diagnostic.DiagnosticError, 'EXACT_SCHEMA'):
            self.diagnose()

    def test_bad_role_wall_and_schema_types(self):
        for changes in (dict(role='BLIND_TEST'), dict(family='other'), dict(wall_s='-1'),
                        dict(wall_s=''), dict(wall_s='NaN'), dict(wall_s=3.), dict(mode=True)):
            old = dict(self.manifest[0])
            self.manifest[0].update(changes)
            with self.assertRaises(diagnostic.DiagnosticError):
                self.diagnose()
            self.manifest[0] = old

    def test_source_compatibility_pins_and_no_dynamic_cli_paths(self):
        source = Path(diagnostic.__file__).read_text()
        ast.parse(source, feature_version=(3, 6))
        self.assertEqual(len(diagnostic.LOCAL_SPECS), 2)
        self.assertEqual({spec['kind'] for spec in diagnostic.LOCAL_SPECS}, {'manifest', 'lineage'})
        self.assertTrue(all('s38417_' in spec['path'] for spec in diagnostic.LOCAL_SPECS))
        with patch.object(diagnostic.sys, 'argv', ['diagnostic', '/arbitrary']), \
                patch.object(diagnostic, '_stable_bytes', side_effect=AssertionError('IO')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.main(), 2)
        self.assertIn('CLI_ARGUMENTS_FORBIDDEN', output.getvalue())


class StableLocalFileTests(unittest.TestCase):
    def test_windows_cross_api_ctime_only_exception_preserves_same_api_checks(self):
        with tempfile.TemporaryDirectory(prefix='e34_group_fixture_') as directory:
            path = Path(directory)/'fabricated.tsv'
            path.write_bytes(b'fabricated_metadata')
            expected = hashlib.sha256(b'fabricated_metadata').hexdigest()
            original_lstat, original_fstat = os.lstat, os.fstat
            target = str(path)
            def changed_ctime(info, amount):
                names = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
                         'st_mtime', 'st_ctime', 'st_mtime_ns', 'st_ctime_ns')
                values = {name:getattr(info, name) for name in names}
                values['st_file_attributes'] = getattr(info, 'st_file_attributes', 0)
                values['st_ctime_ns'] += amount
                return types.SimpleNamespace(**values)
            # Synthetic convention difference, not a claim about real table
            # contents or a generic license to ignore changing ctime.
            with patch.object(diagnostic, '_cross_api_identity', side_effect=lambda info:diagnostic._identity(info)[:-1]), \
                    patch.object(diagnostic.os, 'fstat', side_effect=lambda fd:changed_ctime(original_fstat(fd), 111)):
                self.assertEqual(diagnostic._stable_bytes(target, expected, 100), b'fabricated_metadata')
            for changed_api in ('path', 'fd'):
                calls = {'path': 0, 'fd': 0}
                def lstat(name):
                    info = original_lstat(name)
                    if name == target:
                        calls['path'] += 1
                        return changed_ctime(info, 1 if changed_api == 'path' and calls['path'] > 1 else 0)
                    return info
                def fstat(fd):
                    calls['fd'] += 1
                    return changed_ctime(original_fstat(fd), 111 +
                                         (1 if changed_api == 'fd' and calls['fd'] > 1 else 0))
                with patch.object(diagnostic, '_cross_api_identity', side_effect=lambda info:diagnostic._identity(info)[:-1]), \
                        patch.object(diagnostic.os, 'lstat', side_effect=lstat), \
                        patch.object(diagnostic.os, 'fstat', side_effect=fstat):
                    with self.subTest(api=changed_api), self.assertRaisesRegex(
                            diagnostic.DiagnosticError, 'READ_IDENTITY_OR_SIZE_CHANGED'):
                        diagnostic._stable_bytes(target, expected, 100)

    def test_posix_cross_api_ctime_still_required(self):
        info = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=3, st_nlink=1, st_size=4,
                                     st_mtime=5, st_ctime=6, st_mtime_ns=50, st_ctime_ns=60)
        changed = types.SimpleNamespace(**dict(vars(info), st_ctime_ns=61))
        with patch.object(diagnostic.os, 'name', 'posix'):
            self.assertNotEqual(diagnostic._cross_api_identity(info), diagnostic._cross_api_identity(changed))
        with patch.object(diagnostic.os, 'name', 'nt'):
            self.assertEqual(diagnostic._cross_api_identity(info), diagnostic._cross_api_identity(changed))

    def test_regular_sha_cap_hardlink_no_writes_by_reader(self):
        with tempfile.TemporaryDirectory(prefix='e34_group_fixture_') as directory:
            path = Path(directory)/'fabricated.tsv'
            path.write_bytes(b'fabricated_metadata')
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            before = path.read_bytes()
            self.assertEqual(diagnostic._stable_bytes(str(path), expected, 100), before)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaisesRegex(diagnostic.DiagnosticError, 'SHA256_MISMATCH'):
                diagnostic._stable_bytes(str(path), '0'*64, 100)
            with self.assertRaisesRegex(diagnostic.DiagnosticError, 'BYTE_CAP'):
                diagnostic._stable_bytes(str(path), expected, 1)
            alias = Path(directory)/'hardlink.tsv'
            try:
                os.link(str(path), str(alias))
            except (OSError, NotImplementedError) as exc:
                self.skipTest('actual hardlink unavailable: '+str(exc))
            with self.assertRaisesRegex(diagnostic.DiagnosticError, 'SINGLE_LINK'):
                diagnostic._stable_bytes(str(path), expected, 100)

    def test_actual_symlink_if_available(self):
        with tempfile.TemporaryDirectory(prefix='e34_group_fixture_') as directory:
            path, alias = Path(directory)/'fabricated.tsv', Path(directory)/'symlink.tsv'
            path.write_bytes(b'fabricated')
            try:
                alias.symlink_to(path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('actual symlink unavailable: '+str(exc))
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic._stable_bytes(str(alias), hashlib.sha256(b'fabricated').hexdigest(), 100)


if __name__ == '__main__':
    unittest.main()
