"""Only existing approved local files; no remote or tool launch."""
import ast
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_pattern_replay_plan_e135 as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = Path(__file__).resolve().parents[1]
        cls.prior = (repo.parent / 'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        cls.audit = (repo / 'data/manifests/ranking_v6_e134_actual_audit_r1.json').read_bytes()

    def test_export_observed_is_not_file_existence_or_replay_proof(self):
        r = m.build_plan(self.prior, self.audit)
        p = r['candidate_pattern']
        self.assertTrue(p['export_command_observed'])
        self.assertFalse(p['file_exists_verified'])
        self.assertIsNone(p['sha256'])
        self.assertIsNone(p['bytes'])
        self.assertFalse(p['imported_pattern_count_verified'])
        self.assertEqual(p['original_generated_report_count'], 256)
        self.assertEqual(r, m.build_plan(self.prior, self.audit))

    def test_precise_pattern_path_not_stale_recipe_root(self):
        p = m.build_plan(self.prior, self.audit)['candidate_pattern']['path']
        self.assertEqual(p, m.ROOT + '/aes_core/runs/e116-aes_core/attempts/F_aes_core:HF:h1:F/tester.stil')
        self.assertNotIn('prospective_e81', p)

    def test_existing_authority_does_not_become_new_run_authority(self):
        r = m.build_plan(self.prior, self.audit)
        for key in ('user_authorization_received', 'execution_ready', 'training_release',
                    'physical_HF_D95_verified', 'old_artifacts_may_be_modified', 'LSF_allowed'):
            self.assertIs(r[key], False)
        self.assertEqual(r['remote_calls_authorized'], 0)
        self.assertEqual(r['Tessent_launches_authorized'], 0)
        self.assertEqual(r['proposed_ATPG_generations'], 0)

    def test_original_unproven_diagnostic_is_required(self):
        for body in (self.audit + b' ', self.audit.replace(b'UNPROVEN', b'PASS')):
            with self.assertRaisesRegex(ValueError, 'EXACT_SEALED_E134'):
                m.build_plan(self.prior, body)
        with self.assertRaisesRegex(ValueError, 'EXACT_EXISTING_E128'):
            m.build_plan(self.prior + b' ', self.audit)

    def test_no_io_or_process_in_pure_planner(self):
        with mock.patch('subprocess.Popen') as spawn, mock.patch('builtins.open') as opened:
            r = m.build_plan(self.prior, self.audit)
        spawn.assert_not_called()
        opened.assert_not_called()
        self.assertEqual(r['H_proven_DT_count'], 18323)
        self.assertFalse(r['exact_Stuck_STIL_command_options_verified'])

    def test_canonical_plan_sha_and_python36(self):
        r = m.build_plan(self.prior, self.audit)
        saved = r.pop('plan_sha256')
        self.assertEqual(saved, m.sha(m.canonical(r)))
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_proposal_is_pending_whole_bounded_no_generation_package(self):
        path = Path(__file__).resolve().parents[1] / 'contracts/physical_f_pattern_replay_proposal_e135_v1.json'
        proposal = json.loads(path.read_bytes())
        self.assertFalse(proposal['user_authorization_received'])
        self.assertFalse(proposal['execution_ready'])
        scope = proposal['scope_if_granted']
        self.assertEqual(scope['Tessent_launches_max'], 1)
        self.assertEqual(scope['A_connections_max'], 3)
        self.assertEqual(scope['automatic_retries'], 0)
        self.assertEqual(scope['sampled_worker_and_descendants_rss_swap_bytes_max'], 512*1048576)
        self.assertEqual(scope['ATPG_generations'], 0)
        self.assertEqual(scope['create_patterns_commands'], 0)
        for field in ('foreign_status_merge', 'new_pattern_generation', 'B_access', 'BLIND_access', 'training', 'history_or_source_tree_writes'):
            self.assertFalse(scope[field])
        self.assertTrue(proposal['result_boundary']['no_fallback_new_ATPG_if_pattern_missing_or_import_fails'])


if __name__ == '__main__':
    unittest.main()
