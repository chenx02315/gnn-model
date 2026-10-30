"""Exact pure rebase of existing locally pinned Tcl, no remote execution."""
import ast
import hashlib
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_f_replay_recipe_e138 as m


class RecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_physical_f_replay_recipe_e135_r2 import Tests
        Tests.setUpClass();cls.tcl,cls.helper=Tests.tcl,Tests.expected

    def candidate(self):return m.build_candidate(self.tcl,self.helper)

    def test_only_root_changes_in_both_main_and_helper(self):
        old=m.parent.build_candidate(self.tcl,self.helper);new=self.candidate()
        for key,pin in (('body','sha256'),('baseline_expectations_body','baseline_expectations_sha256')):
            self.assertEqual(new[key].replace(m.ROOT.encode(),m.parent.ROOT.encode()),old[key])
            self.assertEqual(hashlib.sha256(new[key]).hexdigest(),new[pin])
            self.assertNotIn(m.parent.ROOT.encode(),new[key])
            self.assertNotIn(m.parent.legacy.ROOT.encode(),new[key])
        for flag in ('parent_source_identity_observed','independent_review_pass',
                'execution_authorized','execution_ready','physical_d95_verified'):
            self.assertIs(new[flag],False)

    def test_no_io_process_or_historical_global_mutation(self):
        old=(m.parent.ROOT,m.parent.legacy.ROOT,m.parent.legacy._USED,
            m.parent.legacy.REVIEWED_SPEC_SHA256,m.parent.legacy.COMMANDS_VERIFIED)
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            self.candidate()
        opened.assert_not_called();spawn.assert_not_called()
        self.assertEqual(old,(m.parent.ROOT,m.parent.legacy.ROOT,m.parent.legacy._USED,
            m.parent.legacy.REVIEWED_SPEC_SHA256,m.parent.legacy.COMMANDS_VERIFIED))

    def test_deterministic_and_scientific_commands_preserved(self):
        self.assertEqual(self.candidate(),self.candidate())
        raw=self.candidate()['body']
        self.assertEqual(raw.count(b'report_patterns -external > '),2)
        self.assertIn(b'simulate_patterns -source external -store_patterns none\n',raw)
        for token in (b'create_patterns',b'add_processors',b'write_patterns',b'read_faults $status'):
            self.assertNotIn(token,raw)
        self.assertIn(('source '+m.ROOT+'/code/expected_baseline.tcl\n').encode(),raw)

    def test_unknown_root_and_parent_output_drift_rejected(self):
        with mock.patch.object(m,'ROOT',m.parent.ROOT):
            with self.assertRaisesRegex(ValueError,'E138_RECIPE_FIXED_NEW_ROOT'):self.candidate()
        bad=m.parent.build_candidate(self.tcl,self.helper);bad['body']+=b'SENTINEL'
        with mock.patch.object(m.parent,'build_candidate',return_value=bad):
            with self.assertRaisesRegex(ValueError,'E138_RECIPE_PARENT_ARTIFACT_PIN'):self.candidate()

    def test_frozen_parent_source_and_python36_syntax(self):
        raw=Path(m.parent.__file__).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),m.EXPECTED_PARENT_SOURCE_SHA256)
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
