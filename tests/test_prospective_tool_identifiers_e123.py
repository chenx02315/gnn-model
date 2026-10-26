"""Pure byte edits and optional no-window Tcl interpreter; no EDA or server."""
import ast
import copy
import difflib
from pathlib import Path
import re
import unittest
from unittest import mock

from src.data import prospective_tool_identifiers_e123 as m


class Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        templates = self.root / 'src/data/templates'
        self.sources = m.recipe.freeze_sources((templates / 'e108_common_base.tcl').read_bytes(),
            (templates / 'e108_incremental_base.tcl').read_bytes())

    def test_exact_ascii_byte_hex_roundtrip_and_fixed_78_unique_ids(self):
        uids = [task['task_uid'] for phase in m.recipe.pilot.build_plan()['phases'] for task in phase['tasks']]
        tokens = [m.encode(uid) for uid in uids]
        self.assertEqual(len(set(tokens)), 78)
        for uid, token in zip(uids, tokens):
            self.assertEqual(token, 'r' + uid.encode('ascii').hex())
            self.assertEqual(bytes.fromhex(token[1:]).decode('ascii'), uid)
            self.assertIsNotNone(re.fullmatch('[A-Za-z0-9]+', token))
        result = m.validate_roster()
        self.assertEqual(result['semantic_task_uids'], 78)
        self.assertEqual(result['actual_tessent_task_count'], 48)
        self.assertFalse(result['vendor_length_limit_verified'])

    def test_collision_prone_punctuation_is_not_removed_or_mapped_to_underscore(self):
        values = ('a:b', 'a_b', 'a-b', 'a.b', 'ab')
        self.assertEqual(len({m.encode(uid) for uid in values}), len(values))
        self.assertNotIn(':', m.encode('aes_core:HF:h1:H'))

    def test_non_ascii_whitespace_paths_or_non_uid_types_rejected(self):
        for uid in ('é', '', '.', '..', '../x', 'a/b', 'a b', 'a\n', True, None, b'abc'):
            with self.assertRaises(ValueError):
                m.encode(uid)

    def test_only_three_tool_lines_and_one_helper_block_change(self):
        before = copy.deepcopy(self.sources)
        result = m.transform_sources(self.sources)
        self.assertEqual(self.sources, before)
        for name, updated in result['derived_sources'].items():
            original = self.sources[name]['tcl_bytes']
            self.assertEqual(updated.count(m.HELPER), 1)
            self.assertIn(m.ANCHOR + m.HELPER, updated)
            self.assertEqual(updated.count(b'${tool_id}'), 3)
            self.assertEqual(original.count(b'${run_id}') - updated.count(b'${run_id}'), 3)
            diff = list(difflib.ndiff(original.decode('ascii').splitlines(), updated.decode('ascii').splitlines()))
            removed = [line[2:] for line in diff if line.startswith('- ')]
            added = [line[2:] for line in diff if line.startswith('+ ')]
            self.assertEqual(len(removed), 3)
            self.assertEqual(len(added), 6)
            self.assertTrue(all('set_context ' in line or 'set_current_mode ' in line for line in removed))
            self.assertNotIn(b'add_processors', updated)

    def test_paths_markers_controls_and_fault_import_policy_remain_byte_identical(self):
        result = m.transform_sources(self.sources)
        categories = (b'set out ', b'if {$phase ', b'puts "MAPPED_', b'puts "ATPG_',
            b'set_random_atpg', b'compaction', b'set_atpg_limits', b'read_faults', b'write_faults',
            b'set source ', b'set status ', b'set translation_manifest ')
        for name, updated in result['derived_sources'].items():
            original = self.sources[name]['tcl_bytes']
            for prefix in categories:
                old_lines = [line for line in original.splitlines() if prefix in line]
                new_lines = [line for line in updated.splitlines() if prefix in line]
                self.assertEqual(old_lines, new_lines)
            self.assertIn(b'_RUN_ID=$run_id"', updated)
            self.assertIn(b'${mode}_${run_id}', updated)

    def test_manifest_names_new_bytes_without_claiming_old_source_pin_or_tool_pass(self):
        result = m.transform_sources(self.sources)
        manifest = result['manifest']
        for name, raw in result['derived_sources'].items():
            row = manifest['sources'][name]
            self.assertEqual(row['pre_repair_effective_sha256'], self.sources[name]['tcl_sha256'])
            self.assertEqual(row['post_repair_effective_sha256'], m.sha(raw))
            self.assertNotEqual(row['pre_repair_effective_sha256'], row['post_repair_effective_sha256'])
            self.assertEqual(row['exact_diff_counts']['current_mode_suffix_replacements'], 2)
        for key in ('tessent_verified', 'execution_authorized', 'execution_ready', 'training_release'):
            self.assertIs(manifest[key], False)
        self.assertTrue(manifest['new_package_authorization_required'])
        self.assertEqual(manifest['manifest_sha256'], m.sha(m.canonical(
            {k: v for k, v in manifest.items() if k != 'manifest_sha256'})))

    def test_changed_or_already_repaired_source_rejected(self):
        changed = copy.deepcopy(self.sources)
        changed['common']['tcl_bytes'] += b'\n'
        changed['common']['tcl_sha256'] = m.sha(changed['common']['tcl_bytes'])
        with self.assertRaises(ValueError):
            m.transform_sources(changed)
        derived = m.transform_sources(self.sources)['derived_sources']
        repaired = copy.deepcopy(self.sources)
        repaired['common']['tcl_bytes'] = derived['common']
        repaired['common']['tcl_sha256'] = m.sha(derived['common'])
        with self.assertRaises(ValueError):
            m.transform_sources(repaired)

    def test_never_changes_semantic_plan_bindings_controls_or_environment(self):
        plan = m.recipe.pilot.build_plan()
        before = copy.deepcopy(plan)
        with mock.patch('subprocess.Popen') as spawn:
            m.transform_sources(self.sources)
            spawn.assert_not_called()
        self.assertEqual(plan, before)

    def test_source_python36(self):
        for path in ('src/data/prospective_tool_identifiers_e123.py',
                     'tests/test_prospective_tool_identifiers_e123.py'):
            ast.parse((self.root / path).read_text(), feature_version=(3, 6))


class LocalTclEquivalenceTests(unittest.TestCase):
    def test_exact_helper_matches_python_on_all_78_uids_without_tk_window(self):
        try:
            import tkinter
            interpreter = tkinter.Tcl()
        except (ImportError, RuntimeError) as exc:
            self.skipTest('Local Tcl interpreter unavailable: ' + type(exc).__name__)
        except Exception as exc:
            self.skipTest('Local Tcl initialization unavailable: ' + type(exc).__name__)
        # Suppress only this fixed diagnostic puts in the no-window interpreter.
        interpreter.eval('rename puts original_puts; proc puts {args} {}')
        for phase in m.recipe.pilot.build_plan()['phases']:
            for task in phase['tasks']:
                uid = task['task_uid']
                interpreter.setvar('run_id', uid)
                interpreter.eval(m.HELPER.decode('ascii'))
                self.assertEqual(interpreter.getvar('tool_id'), m.encode(uid))
