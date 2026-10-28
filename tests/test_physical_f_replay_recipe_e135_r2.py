"""Pure local recipe assertions, not Tessent or remote execution tests."""
import ast
import base64
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_f_replay_recipe_e135_r2 as recipe


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = Path(__file__).resolve().parents[1]
        raw = (repo.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        assert recipe.legacy.sha(raw) == recipe.legacy.evidence.E128_SHA
        rows = json.loads(raw)['files']
        cls.tcl = base64.b64decode(next(row for row in rows
            if row['sha256'] == recipe.legacy.BASE_TCL_SHA256)['body_base64'])
        cls.expected = recipe.legacy.EXPECTED_INIT.encode('ascii')

    def candidate(self):
        return recipe.build_candidate(self.tcl, self.expected)

    def test_explicit_external_reports_on_both_sides_of_simulation(self):
        text = self.candidate()['body'].decode('ascii')
        self.assertEqual(text.count('report_patterns -external > '), 2)
        self.assertNotIn('report_patterns > ', text)
        self.assertLess(text.index('/snapshots/loaded.patterns.rpt'), text.index('simulate_patterns '))
        self.assertLess(text.index('simulate_patterns '), text.index('/snapshots/simulated.patterns.rpt'))
        self.assertIn('simulate_patterns -source external -store_patterns none\n', text)

    def test_keeps_baseline_before_load_and_before_simulation(self):
        text = self.candidate()['body'].decode('ascii')
        self.assertLess(text.index('baseline.faults.rpt baseline'), text.index('read_patterns '))
        self.assertLess(text.index('imported.faults.rpt imported'), text.index('simulate_patterns '))
        self.assertIn('read_faults $common_source -show_warnings\n', text)
        for forbidden in ('create_patterns', 'add_processors', 'write_patterns', 'read_faults $status'):
            self.assertNotIn(forbidden, text)

    def test_new_paths_and_deterministic_bytes(self):
        first = self.candidate()
        self.assertEqual(first, self.candidate())
        self.assertNotIn(recipe.legacy.ROOT.encode('ascii'), first['body'])
        self.assertIn(recipe.ROOT.encode('ascii'), first['body'])
        self.assertEqual(first['sha256'], recipe.legacy.sha(first['body']))

    def test_does_not_mutate_legacy_gates_or_root(self):
        before = (recipe.legacy.COMMANDS_VERIFIED, recipe.legacy.REVIEWED_SPEC_SHA256,
                  recipe.legacy.INITIAL_CLOCK_SHA256, recipe.legacy.ROOT, recipe.legacy._USED)
        result = self.candidate()
        self.assertEqual(before, (recipe.legacy.COMMANDS_VERIFIED,
            recipe.legacy.REVIEWED_SPEC_SHA256, recipe.legacy.INITIAL_CLOCK_SHA256,
            recipe.legacy.ROOT, recipe.legacy._USED))
        for key in ('independent_review_pass', 'execution_authorized', 'physical_d95_verified'):
            self.assertIs(result[key], False)
        self.assertIsNone(recipe.INDEPENDENT_SEMANTIC_REVIEW)
        self.assertIsNone(recipe.EXECUTION_AUTHORIZATION)
        self.assertFalse(hasattr(recipe, 'worker'))

    def test_helper_bytes_and_digest_bind_new_root_not_parent(self):
        result = self.candidate()
        helper = result['baseline_expectations_body']
        self.assertIn(('[open '+recipe.ROOT+'/inputs/F.basic r]').encode('ascii'), helper)
        self.assertNotIn(recipe.legacy.ROOT.encode('ascii'), helper)
        self.assertEqual(result['baseline_expectations_sha256'], recipe.legacy.sha(helper))
        self.assertEqual(result['parent_baseline_expectations_sha256'],
                         recipe.legacy.sha(self.expected))
        self.assertNotEqual(result['baseline_expectations_sha256'],
                            result['parent_baseline_expectations_sha256'])
        self.assertIn(('source '+recipe.ROOT+'/code/expected_baseline.tcl\n').encode('ascii'),
                      result['body'])
        for content in (helper, result['body']):
            self.assertNotIn(recipe.legacy.ROOT.encode('ascii'), content)

    def test_helper_drift_fails_closed(self):
        changed = recipe.legacy.EXPECTED_INIT.replace('[open ', '[changed ')
        with mock.patch.object(recipe.legacy, 'EXPECTED_INIT', changed):
            with self.assertRaisesRegex(ValueError, 'LEGACY_HELPER_ANCHOR_DRIFT'):
                recipe.build_candidate(self.tcl, changed.encode('ascii'))

    def test_rejects_wrong_inputs(self):
        with self.assertRaisesRegex(ValueError, 'PINNED_F4_TCL'):
            recipe.build_candidate(self.tcl+b' ', self.expected)
        for bad in (b'', self.expected+b' ', self.expected.decode('ascii')):
            with self.assertRaisesRegex(ValueError, 'EXACT_BASELINE_EXPECTATIONS_REQUIRED'):
                recipe.build_candidate(self.tcl, bad)

    def test_legacy_recipe_anchor_drift_fails(self):
        parent = recipe.legacy.build_recipe(self.tcl, self.expected)
        for old in (b'read_patterns ', b'simulate_patterns ', b'report_patterns > '):
            altered = dict(parent, body=parent['body'].replace(old, b'changed '))
            with mock.patch.object(recipe.legacy, 'build_recipe', return_value=altered):
                with self.assertRaisesRegex(ValueError, 'LEGACY_RECIPE_ANCHOR_DRIFT'):
                    self.candidate()

    def test_python36_syntax(self):
        ast.parse(Path(recipe.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
