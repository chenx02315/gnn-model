"""Pure E94 compiler tests using local pinned observation bytes only."""
import ast
import copy
import json
from pathlib import Path
import unittest

from src.data import prospective_tessent_acceptance_v1 as m

ROOT = Path(__file__).resolve().parents[1]
E85_RAW = (ROOT / 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes()
E93_RAW = (ROOT / 'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes()


def compile_raw():
    return m.compile_acceptance(E85_RAW, E93_RAW, m.E85_SHA256, m.E93_SHA256)


class TessentAcceptanceRecipeTests(unittest.TestCase):
    def test_exact_four_fixed_recipes_and_known_identities(self):
        value = compile_raw()
        self.assertEqual(value['schema'], m.SCHEMA)
        self.assertEqual([(row['circuit'], row['transition'], row['target_mode'])
                          for row in value['items']], list(m.ROSTER))
        self.assertEqual(len(value['items']), 4)
        self.assertEqual(value['items'][0]['library_sha256'], m.LIBRARY_SHA256)
        self.assertEqual(value['items'][0]['translated_status_sha256'],
                         '42181b22d419162caca0a97e78124bc139f627269568a40c5197fec5747a71c1')
        spi_m = value['items'][2]
        self.assertEqual(spi_m['tsdb_source_tree_sha256'],
                         '112ab605cbf56af8f7d7ab544174b61b5b9550cb7e4ecf08d7284e95cdfa4d8e')
        self.assertEqual(spi_m['common_basic_sha256'],
                         'a8741335b50611f0b4e6a6cec6712862d1c829a97d98b3ab347009a21172f305')
        self.assertEqual(spi_m['expected_common_count'], 10418)

    def test_tcl_is_literal_fixed_acceptance_not_atpg(self):
        for row in compile_raw()['items']:
            text = row['tcl_bytes'].decode('ascii')
            self.assertEqual(m.sha(row['tcl_bytes']), row['tcl_sha256'])
            self.assertIn('read_cell_library {' + m.LIBRARY + '}', text)
            self.assertEqual(text.count('read_faults '), 2)
            self.assertIn('read_faults {' + row['translated_status_path'] +
                          '} -merge -show_warnings', text)
            self.assertIn('reset_au_faults -reclassify', text)
            self.assertIn('report_statistics -detailed_analysis > /dev/null', text)
            self.assertIn('add_processors localhost:1', text)
            self.assertIn('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS', text)
            self.assertNotIn('$::env', text)
            lowered = text.lower()
            for forbidden in ('create_patterns', 'write_faults', 'write_patterns',
                              '\nsource ', '\neval ', '\nexec '):
                self.assertNotIn(forbidden, lowered)

    def test_target_modes_have_exact_scan_setup(self):
        for row in compile_raw()['items']:
            text = row['tcl_bytes'].decode('ascii')
            scan = text.index('import_scan_mode ')
            clock = text.index('set_clock_off_simulation ON')
            split = text.index('set_split_capture_cycle ON')
            analysis = text.index('set_system_mode analysis')
            processors = text.index('add_processors localhost:1')
            random_atpg = text.index('set_random_atpg OFF')
            fault_type = text.index('set_fault_type Stuck')
            self.assertLess(scan, clock)
            self.assertLess(clock, split)
            self.assertLess(split, analysis)
            self.assertLess(analysis, processors)
            self.assertLess(processors, random_atpg)
            self.assertLess(random_atpg, fault_type)
            self.assertEqual(text.count('set_clock_off_simulation ON'), 1)
            self.assertEqual(text.count('set_split_capture_cycle ON'), 1)
            self.assertEqual(text.count('set_random_atpg OFF'), 1)
            if row['target_mode'] == 'F':
                self.assertIn('import_scan_mode F_fullscan_4ch', text)
                self.assertNotIn('import_scan_mode edt_mode', text)
                fill = text.index('set_atpg_fill X')
                self.assertLess(random_atpg, fill)
                self.assertLess(fill, fault_type)
                self.assertEqual(text.count('set_atpg_fill X'), 1)
            else:
                self.assertIn('import_scan_mode edt_mode', text)
                self.assertIn('async_set_reset_static_disable 1', text)
                self.assertNotIn('F_fullscan_4ch', text)
                self.assertNotIn('set_atpg_fill', text)

    def test_future_scratch_and_source_tree_are_separate(self):
        for row in compile_raw()['items']:
            self.assertTrue(row['future_scratch'].startswith(m.ROOT + '/scratch/'))
            self.assertTrue(row['future_scratch_must_not_preexist'])
            self.assertTrue(row['tsdb_source_root'].startswith(m.PHASE4 + '/'))
            self.assertTrue(row['isolated_tsdb_copy'].startswith(row['future_scratch']))
            self.assertNotEqual(row['tsdb_source_root'], row['isolated_tsdb_copy'])
            self.assertEqual(row['argv'], [m.LAUNCHER, '-shell', '-license_wait',
                                           '5', '-dofile', row['tcl_path']])

    def test_metadata_keeps_all_release_and_measurement_claims_false(self):
        value = compile_raw()
        for key in ('engine_version_verified', 'resource_limits_verified',
                    'scratch_created', 'scratch_publication_verified',
                    'tsdb_isolated_copy_verified', 'os_guard_verified',
                    'tessent_acceptance_verified', 'semantic_acceptance_verified',
                    'd95_verified',
                    'counts_exported', 'execution_ready', 'training_release'):
            self.assertFalse(value[key])
        self.assertEqual(value['actual_tessent_calls'], 0)
        self.assertEqual(value['actual_atpg_calls'], 0)
        self.assertEqual(value['create_patterns_calls'], 0)
        self.assertTrue(value['tessent_may_write_implicit_scratch'])
        self.assertTrue(value['real_run_requires_isolated_tsdb_copy_and_output'])
        self.assertTrue(value['library_body_identity_verified_by_e85'])
        self.assertTrue(value['tsdb_tree_identities_verified_by_e85'])
        self.assertTrue(value['requires_fresh_prelaunch_identity_recheck'])
        self.assertIn('STOP_ON_FIRST_FAILURE_ZERO_RETRIES',
                      value['future_execution_policy'])
        policy = value['future_executor_log_policy']
        self.assertEqual(policy['exit_code_must_equal'], 0)
        self.assertTrue(policy['pass_marker_must_appear_exactly_once'])
        self.assertEqual(policy['reject_case_insensitive_tokens'],
                         ['ERROR', 'FATAL', 'invalid pin_pathname'])
        self.assertEqual(policy['reviewed_warning_allowlist'], [])
        self.assertIn('FAIL_ON_ANY_WARNING', policy['warning_policy'])
        self.assertFalse(policy['pass_marker_alone_is_semantic_acceptance'])

    def test_only_raw_pinned_bytes_are_an_authenticated_compile_input(self):
        first = compile_raw()
        self.assertEqual(first['observations'],
                         {'e85': m.E85_SHA256, 'e93': m.E93_SHA256})
        with self.assertRaisesRegex(ValueError, 'E85_RAW_BYTES_REQUIRED'):
            m.compile_acceptance(json.loads(E85_RAW), E93_RAW,
                                 m.E85_SHA256, m.E93_SHA256)
        with self.assertRaisesRegex(ValueError, 'E93_RAW_BYTES_REQUIRED'):
            m.compile_acceptance(E85_RAW, json.loads(E93_RAW),
                                 m.E85_SHA256, m.E93_SHA256)
        with self.assertRaisesRegex(ValueError, 'E85_PIN'):
            m.compile_acceptance(E85_RAW, E93_RAW, '0' * 64, m.E93_SHA256)
        with self.assertRaisesRegex(ValueError, 'E93_RAW_SHA'):
            m.compile_acceptance(E85_RAW, E93_RAW + b'\n',
                                 m.E85_SHA256, m.E93_SHA256)

    def test_validators_reject_extra_outcome_and_unknown_result(self):
        e85 = json.loads(E85_RAW)
        e93 = json.loads(E93_RAW)
        bad = copy.deepcopy(e93)
        bad['outcome'] = 'PASS'
        with self.assertRaisesRegex(ValueError, 'E93_KEYS'):
            m.validate_e93(bad)
        bad = copy.deepcopy(e93)
        bad['results'][0]['outcome'] = 'PASS'
        with self.assertRaisesRegex(ValueError, 'E93_RESULT_KEYS'):
            m.validate_e93(bad)
        bad = copy.deepcopy(e93)
        bad['results'][0]['transition'] = 'H_TO_X'
        with self.assertRaisesRegex(ValueError, 'E93_RESULT_IDENTITY'):
            m.validate_e93(bad)
        bad = copy.deepcopy(e93)
        bad['input_files'][0]['role'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'E93_INPUT_FILE_SET'):
            m.validate_e93(bad)

    def test_rejects_path_injection_and_unqualified_observation_status(self):
        e85 = json.loads(E85_RAW)
        e93 = json.loads(E93_RAW)
        bad = copy.deepcopy(e85)
        bad['library']['resolved_path'] = m.LIBRARY + ';exec bad'
        with self.assertRaisesRegex(ValueError, 'E85_LIBRARY_IDENTITY'):
            m.validate_e85(bad)
        bad = copy.deepcopy(e85)
        bad['tsdb_trees'][0]['root'] = '/tmp/injected'
        with self.assertRaisesRegex(ValueError, 'E85_TREE_ROOT'):
            m.validate_e85(bad)
        bad = copy.deepcopy(e93)
        bad['results'][0]['status'] = 'PARTIAL'
        with self.assertRaisesRegex(ValueError, 'E93_RESULT_IDENTITY'):
            m.validate_e93(bad)

    def test_library_binary_and_tree_versions_are_pinned(self):
        e85 = json.loads(E85_RAW)
        e93 = json.loads(E93_RAW)
        for mutate, code in (
            (lambda row: row['binary'].__setitem__('body_sha256', '0' * 64),
             'E85_BINARY_IDENTITY'),
            (lambda row: row['library'].__setitem__('body_sha256', '0' * 64),
             'E85_LIBRARY_IDENTITY'),
            (lambda row: row['tsdb_trees'][0].__setitem__('tree_sha256', '0' * 64),
             'E85_TREE_IDENTITY')):
            bad = copy.deepcopy(e85)
            mutate(bad)
            with self.assertRaisesRegex(ValueError, code):
                m.validate_e85(bad)

    def test_mutated_raw_observations_fail_even_with_old_expected_pins(self):
        e85 = json.loads(E85_RAW)
        e85['library']['body_sha256'] = '0' * 64
        changed_e85 = json.dumps(e85, sort_keys=True).encode('ascii')
        with self.assertRaisesRegex(ValueError, 'E85_RAW_SHA'):
            m.compile_acceptance(changed_e85, E93_RAW,
                                 m.E85_SHA256, m.E93_SHA256)
        e93 = json.loads(E93_RAW)
        e93['results'][0]['output_mtfi_sha256'] = 'f' * 64
        changed_e93 = json.dumps(e93, sort_keys=True).encode('ascii')
        with self.assertRaisesRegex(ValueError, 'E93_RAW_SHA'):
            m.compile_acceptance(E85_RAW, changed_e93,
                                 m.E85_SHA256, m.E93_SHA256)

    def test_core_ast_has_no_io_process_or_network_imports(self):
        source = (ROOT / 'src/data/prospective_tessent_acceptance_v1.py').read_text()
        tree = ast.parse(source)
        imports = {alias.name.split('.')[0] for node in ast.walk(tree)
                   if isinstance(node, (ast.Import, ast.ImportFrom))
                   for alias in node.names}
        self.assertEqual(imports, {'hashlib', 'json', 're'})
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertNotIn('open', calls)


if __name__ == '__main__':
    unittest.main()
