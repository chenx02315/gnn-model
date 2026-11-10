"""Finite local native graph checks only; NO E140 grant/entry/remote run."""
import ast
from contextlib import contextmanager
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from scripts import e138_deployment_materials as materials
from scripts import e138_source_session as loader
from scripts import e140_native_graph_candidate as m

REPO = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = materials.prepare().private_bytes()
        cls.origins = {n: raw for b in cls.material['roles'].values() for n, raw in b['sources'].items()}
        cls.result = m.build(cls.origins)
        cls.effective = cls.result.private_sources()
        cls.prior = m.previous.build(cls.origins).private_sources()
        cls.intermediate = dict(cls.prior)
        cls.intermediate[m.BOOTSTRAP] = m.repair.build(cls.prior[m.BOOTSTRAP]).private_sources()[m.BOOTSTRAP]
        cls.proposal_raw = (REPO/'contracts/physical_f_clean_replay_proposal_e140_v1.json').read_bytes()
        cls.proposal = json.loads(cls.proposal_raw)

    @contextmanager
    def session(self):
        rows = [dict(name=n, sha256=sha(self.effective[n]),
                     body_base64=base64.b64encode(self.effective[n]).decode('ascii')) for n in m.SOURCE_ORDER]
        before = {k: v for k, v in sys.modules.items() if k == 'src' or k.startswith('src.')}
        try:
            with mock.patch.object(loader,'FROZEN_SOURCE_SHA256',{n:sha(v) for n,v in self.effective.items()}), \
                 mock.patch.object(loader,'FROZEN_SOURCE_ORDER',m.SOURCE_ORDER):
                with loader.source_session(rows) as loaded:
                    yield loaded
        finally:
            self.assertEqual(before,{k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')})

    def test_all56_pins_exact_rule_counts_reverse_and_history_untouched(self):
        spec = m.specification()
        self.assertEqual(len(spec['origins']),56)
        self.assertEqual(len(m.EFFECTIVE_OVERRIDES),14)
        for row in spec['origins']:
            n = row['name']
            self.assertEqual(sha(self.intermediate[n]),row['sha256'])
            self.assertEqual(sha(self.effective[n]),row['effective_sha256'])
            ast.parse(self.effective[n],feature_version=(3,6))
        for n,rules in m.REPLACEMENTS.items():
            reverse = self.effective[n]
            for old,new,count in rules:
                self.assertEqual(self.intermediate[n].count(old.encode()),count)
                reverse = reverse.replace(new.encode(),old.encode())
            self.assertEqual(reverse,self.intermediate[n])
        for n in m.previous.UNCHANGED_PINS:
            self.assertEqual(self.effective[n],self.origins[n])
        for n,raw in self.origins.items():
            self.assertEqual((REPO/'src/data'/(n+'.py')).read_bytes(),raw)

    def test_proposal_exact_same_budget_science_only_four_policy_identity_changes(self):
        prior = json.loads((REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes())
        expected = copy.deepcopy(prior)
        expected.update(schema='e140-fixed-f-replay-proposal-v1',package='E140')
        expected['scope_if_granted'].update(schema='e140-fixed-f-replay-policy-v1',package='E140',
            new_remote_root=m.ROOT,new_local_phase=m.PHASE)
        self.assertEqual(self.proposal,expected)
        changed = {k for k,v in prior['scope_if_granted'].items() if self.proposal['scope_if_granted'][k]!=v}
        self.assertEqual(changed,{'schema','package','new_remote_root','new_local_phase'})

    def test_actual_private_graph_components_capture_pin_and_coordinated_schemas(self):
        with self.session() as loaded, mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            c = loaded[m.CONTRACT]; a = loaded['physical_e138_batch_assembler']
            self.assertEqual(c.ROOT,m.ROOT);self.assertEqual(c.PHASE,m.PHASE)
            self.assertEqual(c.POLICY,self.proposal['scope_if_granted'])
            self.assertIsNone(c.FROZEN)
            self.assertIsNone(a.FROZEN_SOURCE_SHA256)
            with mock.patch.object(a,'FROZEN_SOURCE_SHA256',{n:sha(raw) for n,raw in self.effective.items()}):
                components = a._components(self.effective)
            for key,node in components.items():
                if key!='bootstrap':self.assertIs(node.contract,c)
            self.assertEqual(components['capture'].DEPENDENCY_SHA256[m.CONTRACT],m.CONTRACT_EFFECTIVE_SHA256)
            components['capture']._source_bindings()
            self.assertEqual(components['runtime'].SCHEMA,'physical-f-clean-replay-execution-e140-v1')
            self.assertEqual(loaded['physical_e138_role2_join'].runtime.SCHEMA,components['runtime'].SCHEMA)
            for name in ('physical_e138_role2_join','physical_e138_role3_export','physical_e138_readback_runtime'):
                self.assertIs(loaded[name].contract,c)
            evidence={}
            with self.assertRaisesRegex(ValueError,'E138_BOOTSTRAP_ADMISSION_FAILED'):
                components['bootstrap'].bootstrap({},None,None,{},evidence)
            self.assertEqual(evidence['schema'],'e140-private-runtime-bootstrap-v1')
            self.assertEqual(a._bootstrap_failure(evidence),evidence)
            self.assertIsNone(components['runtime'].FACTORY_FREEZE)
            self.assertIsNone(loaded['physical_e138_batch_candidate'].AUTH_SHA256)
            for n,node in loaded.items():self.assertEqual(node.__source_sha256__,sha(self.effective[n]))
        opened.assert_not_called();spawn.assert_not_called()

    def test_all_consumed_grants_explicitly_rejected_before_decode_and_actual_e139_not_reused(self):
        actual = (REPO/'contracts/physical_f_clean_replay_authorization_e139.json').read_bytes()
        self.assertEqual(sha(actual),m.E139_AUTH)
        with self.session() as loaded:
            c = loaded[m.CONTRACT]; b=loaded[m.BOOTSTRAP]
            for pin in (m.E137_AUTH,m.E138_AUTH,m.E139_AUTH):
                with mock.patch.object(c,'decode') as decoded:
                    with self.assertRaisesRegex(ValueError,'E138_AUTHORITY_PINS_NOT_CONFIGURED'):
                        c.check_authority(actual,self.proposal_raw,pin,sha(self.proposal_raw))
                    decoded.assert_not_called()
                with mock.patch.object(b,'AUTH_SHA256',pin),mock.patch.object(b,'PROPOSAL_SHA256','2'*64), \
                     mock.patch.object(b,'CONTEXT_SHA256','3'*64), \
                     mock.patch.object(b,'EXPECTED_BOOT_ID','3ebeb9bb-410c-476c-a000-5c625f590473'), \
                     mock.patch.object(b,'decode') as decoded:
                    with self.assertRaisesRegex(ValueError,'E138_BOOTSTRAP_ADMISSION_FAILED'):
                        b.bootstrap({},None,None,{})
                    decoded.assert_not_called()
            self.assertEqual(c.OLD_AUTH_SHA256,m.E139_AUTH)

    def test_fixed_parent_recipe_main_helper_newroot_only(self):
        with self.session() as loaded:
            recipe = loaded['physical_f_replay_recipe_e138']; inputs=self.material['execution_inputs']
            result = recipe.build_candidate(inputs['incremental'],inputs['parent_helper'])
            parent = recipe.parent.build_candidate(inputs['incremental'],inputs['parent_helper'])
            self.assertEqual(result['schema'],'physical-f-clean-replay-recipe-e140-candidate-v1')
            for body,pin in (('body','sha256'),('baseline_expectations_body','baseline_expectations_sha256')):
                self.assertIn(m.ROOT.encode(),result[body])
                self.assertNotIn(m.previous.pair.ROOT_NEW.encode(),result[body])
                self.assertEqual(result[body].replace(m.ROOT.encode(),recipe.parent.ROOT.encode()),parent[body])
                self.assertEqual(sha(result[body]),result[pin])
            self.assertFalse(result['execution_ready'])

    def test_nine_builtins_repair_and_default_gate_no_io(self):
        tree = ast.parse(self.effective[m.BOOTSTRAP])
        assignment = next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and
            isinstance(n.value,ast.Call) and
            any(isinstance(t,ast.Name) and t.id=='namespace' for t in n.targets))
        binding = next(k.value for k in assignment.value.keywords if k.arg=='__builtins__')
        self.assertEqual(ast.literal_eval(binding.args[0].generators[0].iter),m.repair.BUILTIN_NAMES)
        with mock.patch('builtins.open') as opened,mock.patch('builtins.compile') as compiled:
            m.build(self.origins)
        opened.assert_not_called();compiled.assert_not_called()
        with self.assertRaises(ValueError):m.build(dict(self.origins,unknown=b''))
        tampered=dict(self.origins);tampered[m.CONTRACT]+=b' '
        with self.assertRaises(ValueError):m.build(tampered)
        manifest=self.result.public_manifest()
        self.assertFalse(manifest['native_graph']['execution_ready'])
        self.assertFalse(manifest['native_graph']['authority_supplied'])
        self.assertEqual(manifest['derivation_chain']['bootstrap_repair']['sources'][0]['effective_sha256'],m.repair.EFFECTIVE_SHA256)


if __name__=='__main__':
    unittest.main()
