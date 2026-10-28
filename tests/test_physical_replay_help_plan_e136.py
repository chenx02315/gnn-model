import ast
import json
from pathlib import Path
import unittest
from unittest import mock

from src.data import physical_replay_help_plan_e136 as m


class Tests(unittest.TestCase):
    def test_fixed_help_only_commands_no_design_pattern_generation_or_simulation(self):
        lines = m.render_help_tcl().decode('ascii').splitlines()
        commands = [line for line in lines if not line.startswith('puts ')]
        self.assertEqual(commands, ['set_context patterns -scan -design_identifier e136help'] +
                         ['help '+name for name in m.COMMANDS] + ['exit'])
        self.assertNotIn('-manual', '\n'.join(lines))
        for forbidden in ('read_design ', 'read_cell_library ', 'read_patterns ',
                          'create_patterns', 'simulate_patterns -', 'read_faults ', 'exec '):
            self.assertFalse(any(line.startswith(forbidden) for line in lines))

    def test_each_help_section_has_exact_boundaries_and_deterministic_bytes(self):
        text = m.render_help_tcl().decode('ascii')
        for name in m.COMMANDS:
            self.assertEqual(text.count('puts "E136_HELP_BEGIN='+name+'"'), 1)
            self.assertEqual(text.count('puts "E136_HELP_END='+name+'"'), 1)
        self.assertEqual(m.render_help_tcl(), m.render_help_tcl())
        self.assertLess(len(m.render_help_tcl()), 4096)

    def test_pure_render_does_not_grant_or_launch(self):
        with mock.patch('subprocess.Popen') as spawn, mock.patch('builtins.open') as opened:
            self.assertTrue(m.render_help_tcl())
        spawn.assert_not_called()
        opened.assert_not_called()
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_new_proposal_is_pending_and_explicitly_counts_help_start(self):
        root = Path(__file__).resolve().parents[1]
        p = json.loads((root / 'contracts/physical_f_replay_help_recovery_proposal_e136_v1.json').read_bytes())
        s = p['scope_if_granted']
        self.assertFalse(p['user_authorization_received'])
        self.assertFalse(p['execution_ready'])
        self.assertEqual(s['Tessent_launches_max'], 2)
        self.assertEqual(s['help_only_Tessent_launches_max'], 1)
        self.assertEqual(s['F_fault_simulation_Tessent_launches_max'], 1)
        self.assertEqual(s['ATPG_generations'], 0)
        self.assertEqual(s['sampled_worker_and_descendants_rss_swap_bytes_max'], 512*1048576)
        self.assertFalse(s['E135_budget_or_clock_reuse'])
        self.assertFalse(s['reference_PDF_body_read_or_export'])
        self.assertEqual(tuple(s['fixed_help_commands']), m.COMMANDS)


if __name__ == '__main__':
    unittest.main()
