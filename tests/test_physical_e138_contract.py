"""Synthetic frozen inputs, not a real E138 user grant or trusted loader."""
import ast
import copy
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from src.data import physical_e138_contract as m


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.proposal=dict(schema='e138-fixed-f-replay-proposal-v1',package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',scope_if_granted=copy.deepcopy(m.POLICY))
        self.authority=dict(schema='e138-explicit-whole-package-authorization-v1',approved_package='E138',
            approval_source='explicit_user_reply',user_reply='SYNTHETIC TEST ONLY',
            user_authorization_received=True,proposal_sha256=m.sha(m.canonical(self.proposal)),
            approved_scope=copy.deepcopy(m.POLICY),execution_ready=False)
        self.package={key:b'SYNTHETIC NOT A RUNTIME INPUT' for key in m.INPUT_KEYS}
        self.package.update(authority=m.canonical(self.authority),proposal=m.canonical(self.proposal),policy=m.canonical(m.POLICY))
        order=tuple(sorted(m.REQUIRED_SOURCES))
        self.frozen=dict(authorization_sha256=m.sha(self.package['authority']),proposal_sha256=m.sha(self.package['proposal']),
            payload_sha256='a'*64,policy_sha256=m.sha(self.package['policy']),
            input_sha256={key:m.sha(raw) for key,raw in self.package.items()},
            source_sha256={name:str(i+1)*64 for i,name in enumerate(order)},source_order=order)
        for key,value in (('FROZEN',self.frozen),('LOADED_SOURCE_ORDER',order)):
            patch=mock.patch.object(m,key,value);patch.start();self.addCleanup(patch.stop)
        for name,pin in self.frozen['source_sha256'].items():
            module=sys.modules.get('src.data.'+name)
            if module is None:
                module=types.ModuleType('src.data.'+name)
                patch=mock.patch.dict(sys.modules,{'src.data.'+name:module})
                patch.start();self.addCleanup(patch.stop)
            patch=mock.patch.object(module,'__source_sha256__',pin,create=True)
            patch.start();self.addCleanup(patch.stop)

    def refreeze_test_bytes(self):
        # Test-only independent expectation fixture. Never a production entrypoint.
        self.frozen.update(authorization_sha256=m.sha(self.package['authority']),
            proposal_sha256=m.sha(self.package['proposal']),policy_sha256=m.sha(self.package['policy']),
            input_sha256={key:m.sha(raw) for key,raw in self.package.items()})

    def test_pure_synthetic_consistency_is_not_execution_or_authorization_proof(self):
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn, \
                mock.patch('time.monotonic') as clock,mock.patch('os.open') as fd:
            value=m.admit(self.package)
        for call in (opened,spawn,clock,fd):call.assert_not_called()
        self.assertEqual(value['root'],m.ROOT);self.assertEqual(value['phase'],m.PHASE)
        for key in ('loaded_tags_are_authentication','independent_review_verified',
                'remote_authorization_proven','components_rebound','ledger_consumed','execution_ready'):
            self.assertIs(value[key],False)

    def test_missing_freeze_or_old_grant_rejects_before_inputs_and_io(self):
        for frozen in (None,{},dict(self.frozen,authorization_sha256=m.OLD_AUTH_SHA256)):
            with mock.patch.object(m,'FROZEN',frozen),mock.patch('builtins.open') as opened:
                with self.assertRaisesRegex(ValueError,'E138_FREEZE_NOT_CONFIGURED'):m.admit(None)
            opened.assert_not_called()

    def test_actual_old_grant_cannot_be_reused(self):
        raw=(Path(__file__).resolve().parents[1]/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
        self.assertEqual(m.sha(raw),m.OLD_AUTH_SHA256)
        self.package['authority']=raw;self.refreeze_test_bytes()
        with self.assertRaisesRegex(ValueError,'E138_FREEZE_NOT_CONFIGURED'):m.admit(self.package)

    def test_old_or_aliased_root_phase_and_scope_are_not_accepted(self):
        for change in (dict(new_remote_root='/temp/jiangchuanc/multimode_ate_physical_f_replay_e135_recipe_r2'),
                dict(new_remote_root=m.ROOT+'/../'+m.ROOT.rsplit('/',1)[1]),
                dict(new_local_phase='v6_e137_clean_F_replay_r1'),dict(BLIND_access=True)):
            bad=dict(m.POLICY,**change)
            self.package['policy']=m.canonical(bad);self.refreeze_test_bytes()
            with self.assertRaisesRegex(ValueError,'E138_EXACT_FROZEN_POLICY'):m.admit(self.package)

    def test_strict_budget_types_and_extra_policy_keys(self):
        for change in (dict(worker_count=True),dict(automatic_retries=False),dict(connections_max=3.0),dict(extra=True)):
            self.package['policy']=m.canonical(dict(m.POLICY,**change));self.refreeze_test_bytes()
            with self.assertRaisesRegex(ValueError,'E138_EXACT_FROZEN_POLICY'):m.admit(self.package)

    def test_explicit_grant_shape_and_proposal_hash_mismatch(self):
        for change in (dict(approved_package='E137'),dict(user_authorization_received=1),
                dict(proposal_sha256='f'*64),dict(execution_ready=0),dict(user_reply=''),dict(extra=True)):
            self.package['authority']=m.canonical(dict(self.authority,**change));self.refreeze_test_bytes()
            with self.assertRaisesRegex(ValueError,'E138_NEW_EXPLICIT_GRANT_REQUIRED'):m.admit(self.package)

    def test_grant_scope_and_proposal_scope_must_match_frozen_policy(self):
        for target in ('authority','proposal'):
            value=copy.deepcopy(self.authority if target=='authority' else self.proposal)
            value['approved_scope' if target=='authority' else 'scope_if_granted']['tessent_launches_max']=2
            self.package[target]=m.canonical(value);self.refreeze_test_bytes()
            with self.assertRaisesRegex(ValueError,'E138_EXACT_FROZEN_POLICY'):m.admit(self.package)
            self.package[target]=m.canonical(self.authority if target=='authority' else self.proposal)

    def test_duplicate_json_nonfinite_and_bad_utf8_are_rejected(self):
        for raw in (b'{"schema":1,"schema":2}',b'{"x":NaN}',b'{"x":Infinity}',
                b'{"x":1e999}',b'{"x":-1e999}',b'{"nested":[1e999]}',b'\xff'):
            self.package['policy']=raw;self.refreeze_test_bytes()
            with self.assertRaisesRegex(ValueError,'E138_CONTRACT_JSON_REJECTED'):m.admit(self.package)

    def test_input_missing_extra_drift_and_size_cap(self):
        for package in (dict(self.package,extra=b''),{k:v for k,v in self.package.items() if k!='shell'},
                dict(self.package,shell='not-bytes'),dict(self.package,shell=b'CHANGED')):
            with self.assertRaises(ValueError):m.admit(package)
        with mock.patch.object(m,'sha') as sha:
            with self.assertRaisesRegex(ValueError,'E138_EXACT_PACKAGE_BYTES'):
                m.admit(dict(self.package,shell=b'x'*10485761))
            sha.assert_not_called()

    def test_source_set_order_tags_and_self_pin_are_consistency_checked(self):
        with mock.patch.object(m,'LOADED_SOURCE_ORDER',tuple(reversed(self.frozen['source_order']))):
            with self.assertRaisesRegex(ValueError,'E138_LOADER_ORDER_CONSISTENCY'):m.admit(self.package)
        for sources in ({},dict(self.frozen['source_sha256'],extra='a'*64)):
            with mock.patch.object(m,'FROZEN',dict(self.frozen,source_sha256=sources)):
                with self.assertRaisesRegex(ValueError,'E138_SOURCE_FREEZE_ROSTER_AND_ORDER'):m.admit(self.package)
        name=self.frozen['source_order'][0]
        with mock.patch.object(sys.modules['src.data.'+name],'__source_sha256__','0'*64):
            with self.assertRaisesRegex(ValueError,'E138_LOADED_SOURCE_TAG_CONSISTENCY'):m.admit(self.package)

    def test_forged_loaded_tags_do_not_cross_default_freeze_gate(self):
        # setUp populated synthetic tags. They do not provide the missing trust origin.
        with mock.patch.object(m,'FROZEN',None):
            with self.assertRaisesRegex(ValueError,'E138_FREEZE_NOT_CONFIGURED'):m.admit(self.package)

    def test_no_unknown_freeze_keys_and_source_order_duplicates(self):
        for bad in (dict(self.frozen,extra=True),dict(self.frozen,source_order=('x','x','x'))):
            with mock.patch.object(m,'FROZEN',bad):
                with self.assertRaises(ValueError):m.admit(self.package)

    def test_python36_inert_import_and_numeric_timestamp_policy_unchanged(self):
        source=Path(m.__file__).read_text(encoding='utf-8');ast.parse(source,feature_version=(3,6))
        namespace={'__name__':'inert_e138_contract'}
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            exec(compile(source,'<inert-e138-contract>','exec'),namespace)
        opened.assert_not_called();spawn.assert_not_called()
        self.assertIsNone(namespace['FROZEN']);self.assertEqual(namespace['POLICY']['whole_package_seconds_max'],3600)
