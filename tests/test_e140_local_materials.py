"""Real fixed local caches, no phase/grant/process/remote operations."""
import copy
import json
from pathlib import Path
import pickle
import unittest
from unittest import mock
from scripts import e140_local_materials as m

REPO = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (REPO/'scripts/e139_local_materials.py').read_bytes()
        cls.adapter = m.load_adapter(cls.raw)
        old = m.origin.prepare()
        assert old.public_summary()['status'] == m.READY
        cls.old, cls.summary = old.private_bytes(), old.public_summary()
        cls.material = m.rebind(cls.summary, cls.old, cls.raw)

    def test_actual_fixed_cache_ready_counts_effective_pins_and_all_input_crossjoins(self):
        self.assertEqual(m.prepare().public_summary()['package'], 'E140')
        private = self.material.private_bytes()
        effective = {r['name']:r['effective_sha256'] for r in m.native.specification()['origins']}
        self.assertEqual(self.material.public_summary()['role_source_counts'], dict(capture=35,execution=53,readback=36))
        for role,bundle in private['roles'].items():
            self.assertEqual(bundle['source_order'], self.old['roles'][role]['source_order'])
            self.assertIsNone(bundle['dependency_checks'])
            for name,raw in bundle['sources'].items():
                self.assertEqual(m.origin.sha(raw), effective[name])
                self.assertEqual(bundle['source_sha256'][name], effective[name])
        for key,name in self.adapter.INPUT_SOURCES.items():
            self.assertEqual(private['execution_inputs'][key], private['roles']['execution']['sources'][name])

    def test_policy_identity_only_budgets_static_inputs_and_origin_audit(self):
        private = self.material.private_bytes()
        policy = json.loads(private['execution_inputs']['policy'])
        prior = json.loads(self.old['execution_inputs']['policy'])
        for key in set(policy)-{'schema','package','new_remote_root','new_local_phase'}:
            self.assertEqual(policy[key], prior[key])
        self.assertEqual(policy['package'], 'E140')
        self.assertEqual(policy['new_remote_root'], m.native.ROOT)
        self.assertEqual(policy['new_local_phase'], m.native.PHASE)
        for key in set(self.adapter.STATIC_INPUT_PINS)-{'policy'}:
            self.assertEqual(private['execution_inputs'][key], self.old['execution_inputs'][key])
        rows = self.material.public_summary()['artifacts']
        row = next(r for r in rows if r['path']=='src/data/physical_e138_contract.py')
        self.assertNotEqual(row['origin_sha256'], row['sha256'])
        self.assertEqual(row['sha256'], m.native.CONTRACT_EFFECTIVE_SHA256)
        self.assertIsNone(self.material.public_summary()['effective_dependency_checks'])
        self.assertFalse(self.material.public_summary()['execution_ready'])

    def test_zero_io_rebind_no_oldglobals_mutation_and_failclosed(self):
        before = m.native.previous.specification()
        with mock.patch('pathlib.Path.open') as opened, mock.patch('builtins.open') as builtin, mock.patch('subprocess.Popen') as spawn:
            result = m.rebind(self.summary, self.old, self.raw)
        for op in (opened,builtin,spawn): op.assert_not_called()
        self.assertEqual(before,m.native.previous.specification())
        bad=copy.deepcopy(self.old); bad['roles']['capture']['sources']['physical_e138_contract']+=b' '
        for summary,private,raw in (({'status':'NOT_READY'},self.old,self.raw),(self.summary,bad,self.raw),(self.summary,self.old,self.raw+b' ')):
            with self.assertRaises(ValueError): m.rebind(summary,private,raw)
        self.assertEqual(result.public_summary()['status'],m.READY)

    def test_private_snapshots_public_allowlist_and_nonserializable(self):
        private=self.material.private_bytes(); private['roles'].clear()
        self.assertEqual(len(self.material.private_bytes()['roles']),3)
        self.assertIn('E140',repr(self.material))
        with self.assertRaises(TypeError): pickle.dumps(self.material)
        for row in self.material.public_summary()['artifacts']:
            self.assertLessEqual(set(row),{'role','path','bytes','sha256','origin_sha256','check'})


if __name__=='__main__': unittest.main()
