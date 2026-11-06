"""Proposal scope checks only; no E139 runtime or authority is supplied."""
import copy
from pathlib import Path
import unittest
from src.data import physical_e138_contract as old

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def test_only_identity_and_directories_change_not_budgets(self):
        value=old.decode((REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes())
        self.assertEqual(set(value),{'schema','package','status','scope_if_granted'})
        self.assertEqual(value['schema'],'e139-fixed-f-replay-proposal-v1')
        self.assertEqual(value['package'],'E139')
        self.assertEqual(value['status'],'PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION')
        expected=copy.deepcopy(old.POLICY)
        expected.update(schema='e139-fixed-f-replay-policy-v1',package='E139',
            new_remote_root='/temp/jiangchuanc/multimode_ate_physical_f_replay_e139_r1',
            new_local_phase='v6_e139_clean_F_replay_r1')
        self.assertEqual(old.canonical(value['scope_if_granted']),old.canonical(expected))

    def test_old_contract_cannot_release_new_proposal(self):
        proposal=(REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()
        authority=(REPO/'contracts/physical_f_clean_replay_authorization_e138.json').read_bytes()
        with self.assertRaises(ValueError):old.check_authority(authority,proposal,old.sha(authority),old.sha(proposal))

    def test_executed_authority_and_bootstrap_bytes_preserved(self):
        for name,pin in (
            ('contracts/physical_f_clean_replay_authorization_e138.json','bcaa8da7adc2e61daa35ccd50ce42dfd4131de180c7f3ca3adbbc86e8403dd74'),
            ('src/data/physical_runtime_bootstrap_e138.py','8a8d95802d4a5b52958511bfaf8f3e7c2a34b82460c335b701e69f3b7a3de238')):
            self.assertEqual(old.sha((REPO/name).read_bytes()),pin)


if __name__=='__main__':unittest.main()
