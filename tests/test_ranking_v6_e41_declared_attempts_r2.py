"""Fabricated metadata only; no actual input, source logs or network opened."""
import copy
import csv
import io
import json
import sys
import unittest
from unittest.mock import patch
from scripts import diagnose_ranking_v6_e41_declared_attempts_r2 as helper
from scripts import run_ranking_v6_e41_local_join_r2 as runner
from test_ranking_v6_e40_transport import synthetic_payload


def fixture():
    payload = synthetic_payload()
    attempts = []
    for item in payload['files']:
        version = item['coverage_root'].rsplit('/', 1)[-1]
        for row in item['rows']:
            for mode in ('H', 'F'):
                name = '{}_v{}_{}_{}'.format(item['circuit'], 1 if version == '10_coverage95_v1' else 2, row['candidate'], mode)
                row[mode.lower() + '_result'] = item['coverage_root'] + '/04_integer_refine/' + name
                attempts.append(dict(circuit=item['circuit'], mode=mode, attempt_id=name,
                    stage='04_integer_refine', source_log_path=version + '/04_integer_refine/' + name + '.driver.log'))
    return payload, attempts


class DiagnosticTests(unittest.TestCase):
    def test_unrelated_safe_shallow_rows_retained_without_stage_invention(self):
        payload, attempts = fixture()
        attempts += [dict(circuit='s35932', mode='H', attempt_id='shallow1', stage='endpoint', source_log_path='driver.log'),
                     dict(circuit='s35932', mode='H', attempt_id='shallow2', stage='endpoint', source_log_path='endpoint/driver.log')]
        result = helper.diagnose(payload, attempts)
        self.assertEqual(result['provided_attempt_rows'], 18)
        self.assertEqual(result['provided_path_depth_counts'], dict(one_component=1, two_components=1, three_or_more_components=16))
        self.assertEqual(result['strict_match_classifications']['ONE_STRICT_MATCH'], 16)

    def test_shallow_same_marker_never_strict(self):
        payload, attempts = fixture()
        name = attempts[0]['source_log_path'].rsplit('/', 1)[-1]
        scope = attempts[0]['source_log_path'].split('/')[0]
        attempts += [dict(circuit='s35932', mode='H', attempt_id='shallow1', stage='04_integer_refine', source_log_path=name),
                     dict(circuit='s35932', mode='H', attempt_id='shallow2', stage='04_integer_refine', source_log_path=scope+'/'+name)]
        result = helper.diagnose(payload, attempts)
        counts = result['declarations'][0]['provided_marker_match_counts']
        self.assertEqual(counts, dict(strict_namespace_stage=1, same_namespace_stage_conflict=1, other_namespace=1, other_circuit_or_mode=0))

    def test_one_each_pure_and_no_ownership(self):
        payload, attempts = fixture()
        with patch('builtins.open', side_effect=AssertionError('NO_OPEN')), \
             patch('os.open', side_effect=AssertionError('NO_FD')):
            result = helper.diagnose(payload, attempts)
        self.assertEqual(result['strict_match_classifications'], dict(ZERO_STRICT_MATCH=0, ONE_STRICT_MATCH=16, MULTIPLE_STRICT_MATCHES=0))
        self.assertEqual(result['unique_strict_attempt_id_sha256_count'], 16)
        self.assertFalse(result['invocation_identity_certified'])
        self.assertFalse(result['training_release'])
        self.assertNotIn('.driver.log', str(result))

    def test_zero_multiple_and_shared_ids_retained(self):
        payload, attempts = fixture()
        attempts.pop()
        duplicate = dict(attempts[0], attempt_id='second_distinct_reference')
        attempts.append(duplicate)
        result = helper.diagnose(payload, attempts)
        self.assertEqual(result['strict_match_classifications'], dict(ZERO_STRICT_MATCH=1, ONE_STRICT_MATCH=14, MULTIPLE_STRICT_MATCHES=1))
        # Two declarations may share a referenced session; references remain two.
        payload, attempts = fixture()
        payload['files'][2]['rows'][1]['h_result'] = payload['files'][2]['rows'][0]['h_result']
        result = helper.diagnose(payload, attempts)
        self.assertEqual(result['declaration_count'], 16)
        self.assertEqual(result['total_strict_declaration_attempt_references'], 16)
        self.assertEqual(result['unique_strict_attempt_id_sha256_count'], 15)
        self.assertFalse(result['source_origin_assigned'])

    def test_namespace_circuit_mode_stage_collisions_not_selected(self):
        for change, bucket in (({'stage': '02_hf_coarse'}, 'same_namespace_stage_conflict'),
                               ({'mode': 'F'}, 'other_circuit_or_mode'),
                               ({'circuit': 's38417'}, 'other_circuit_or_mode'),
                               ({'source_log_path': 'other/04_integer_refine/PLACEHOLDER'}, 'other_namespace'),
                               ({'source_log_path': 'SCOPE/02_hf_coarse/PLACEHOLDER'}, 'same_namespace_stage_conflict')):
            payload, attempts = fixture()
            first = attempts[0]
            changed = dict(first, **change)
            changed['source_log_path'] = changed['source_log_path'].replace('PLACEHOLDER', first['source_log_path'].rsplit('/', 1)[-1]).replace('SCOPE', first['source_log_path'].split('/')[0])
            attempts[0] = changed
            result = helper.diagnose(payload, attempts)
            row = result['declarations'][0]
            self.assertEqual(row['classification'], 'ZERO_STRICT_MATCH')
            self.assertEqual(row['provided_marker_match_counts'][bucket], 1)

    def test_missing_or_outside_declaration_not_rebased(self):
        payload, attempts = fixture()
        payload['files'][0]['rows'][0]['h_result'] = ''
        payload['files'][1]['rows'][0]['h_result'] = '/elsewhere/' + helper.marker(payload['files'][1]['rows'][0]['h_result'])
        result = helper.diagnose(payload, attempts)
        self.assertEqual(result['strict_match_classifications']['ZERO_STRICT_MATCH'], 2)
        self.assertTrue(result['declarations'][0]['declaration_missing'])

    def test_forbidden_fields_duplicate_and_bad_paths_fail_closed(self):
        for kind in ('quality', 'duplicate', 'absolute', 'traversal', 'windows', 'blank', 'unexpected_circuit'):
            payload, attempts = fixture()
            if kind == 'quality': attempts[0]['wall_time'] = '123'
            elif kind == 'duplicate': attempts.append(copy.deepcopy(attempts[0]))
            elif kind == 'absolute': attempts[0]['source_log_path'] = '/some/log'
            elif kind == 'traversal': attempts[0]['source_log_path'] = 'root/../log'
            elif kind == 'windows': attempts[0]['source_log_path'] = 'root\\stage\\log'
            elif kind == 'blank': attempts[0]['stage'] = ''
            else: attempts[0]['circuit'] = 'wb_dma'
            with self.subTest(kind=kind), self.assertRaises(ValueError): helper.diagnose(payload, attempts)

    def test_transform_is_exactly_one_suffix_not_fuzzy(self):
        self.assertEqual(helper.marker('/a/X.driver.log'), 'X')
        self.assertEqual(helper.marker('/a/X.log.log'), 'X.log')
        self.assertEqual(helper.marker('/a/X.log.extra'), 'X.log.extra')
        self.assertEqual(helper.marker('/a/X.csv'), 'X')
        self.assertEqual(helper.marker('/a/X/'), 'X')


class RunnerTests(unittest.TestCase):
    def test_safe_phase_and_known_read_guard_without_actual_input(self):
        with patch.object(sys, 'argv', ['fixed']), patch.object(runner.stable, '_stable_bytes', side_effect=ValueError('FILE_SHA256_MISMATCH')), \
             patch('sys.stdout', io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result['phase'], 'READ_E40')
        self.assertEqual(result['code'], 'FILE_SHA256_MISMATCH')

    def test_arbitrary_exception_text_not_echoed(self):
        with patch.object(sys, 'argv', ['fixed']), patch.object(runner.stable, '_stable_bytes', side_effect=ValueError('PRIVATE_PATH_OR_ROW')), \
             patch('sys.stdout', io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['code'], 'UNCLASSIFIED_FAILURE')

    def test_fixed_three_reads_train_selection_and_small_output(self):
        payload, attempts = fixture()
        raw = json.dumps(payload, separators=(',', ':')).encode('ascii')
        self.assertLessEqual(len(raw), 5858)
        raw += b' ' * (5858 - len(raw))
        data = [raw]
        for circuit in ('s35932', 's38417'):
            output = io.StringIO(newline='')
            writer = csv.DictWriter(output, fieldnames=runner.stable.reader.MANIFEST_FIELDS, delimiter='\t')
            writer.writeheader()
            selected = [a for a in attempts if a['circuit'] == circuit]
            if circuit == 's35932':
                selected += [dict(circuit=circuit, mode='H', attempt_id='filler_'+str(n), stage='endpoint',
                                  source_log_path='other/endpoint/filler_'+str(n)+'.driver.log') for n in range(6985-16)]
            for attempt in selected:
                row = {key: '' for key in runner.stable.reader.MANIFEST_FIELDS}
                row.update(attempt, role='TRAIN', family=runner.stable.reader.FAMILIES[circuit])
                writer.writerow(row)
            data.append(output.getvalue().encode('utf-8'))
        stdout = io.StringIO()
        with patch.object(sys, 'argv', ['fixed']), patch.object(runner.stable, '_stable_bytes', side_effect=data) as read, \
             patch('sys.stdout', stdout), patch('subprocess.Popen', side_effect=AssertionError('NO_NETWORK')):
            self.assertEqual(runner.main(), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(read.call_count, 3)
        self.assertEqual(result['provided_attempt_rows'], 6985)
        self.assertEqual(result['fixed_local_input_audit']['file_count'], 3)
        self.assertLess(len(stdout.getvalue()), 65536)
        self.assertEqual([call.args[1] for call in read.call_args_list], [s[2] for s in runner.SPECS])

    def test_dynamic_paths_refused_before_input_read(self):
        with patch.object(sys, 'argv', ['fixed', 'other']), patch.object(runner.stable, '_stable_bytes', side_effect=AssertionError('NO_READ')), \
             patch('sys.stdout', io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
        self.assertEqual(json.loads(output.getvalue())['code'], 'NO_DYNAMIC_PATHS')


if __name__ == '__main__': unittest.main()
