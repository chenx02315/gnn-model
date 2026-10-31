"""Synthetic grant and virtual installed files; no remote or tool calls."""
import ast
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_engine_evidence_e138 as m

REPO=Path(__file__).resolve().parents[1]
SAMPLER=(REPO/'src/data/physical_engine_evidence_e137.py').read_bytes()
SELECTOR=(REPO/'src/data/physical_engine_selector_e137.py').read_bytes()
BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_physical_e138_contract import ContractTests
        self.case=ContractTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.context=dict(role='execution',authorization_sha256=self.case.frozen['authorization_sha256'],boot_id=BOOT,
            root=m.contract.ROOT,phase=m.contract.PHASE,package_start=1000.,package_end=4600.,connection_start=2000.,utc_end=9000.)
        self.package=dict(authority=self.case.package['authority'],proposal=self.case.package['proposal'],context=m.canonical(self.context))
        self.frozen=dict(authorization_sha256=self.case.frozen['authorization_sha256'],proposal_sha256=self.case.frozen['proposal_sha256'],
            context_sha256=m.sha(self.package['context']),adapter_source_sha256='c'*64)
        for patch in (mock.patch.object(m,'FREEZE',self.frozen),mock.patch.object(m,'__source_sha256__','c'*64,create=True),mock.patch.object(m,'_USED',False)):
            patch.start();self.addCleanup(patch.stop)
        self.tick=mock.Mock();self.mono=mock.Mock(return_value=2001.);self.utc=mock.Mock(return_value=5000.)

    def collect(self,raw=SAMPLER):return m.collect(self.package,raw,SELECTOR,BOOT,{},self.tick,self.mono,self.utc)

    def test_default_old_grant_and_source_drift_zero_callbacks_compile(self):
        with mock.patch('builtins.compile') as compile:
            with mock.patch.object(m,'FREEZE',None):
                with self.assertRaises(ValueError):self.collect()
            with mock.patch.object(m,'FREEZE',dict(self.frozen,authorization_sha256=m.contract.OLD_AUTH_SHA256)):
                with self.assertRaises(ValueError):self.collect()
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_SOURCE_PIN'):self.collect(SAMPLER+b' ')
        compile.assert_not_called();self.tick.assert_not_called();self.mono.assert_not_called()

    def test_context_scope_bool_deadline_and_overflow_rejected_before_callbacks(self):
        for change in (dict(root='/old'),dict(package_start=True),dict(package_end=4601),dict(connection_start=5000)):
            self.package['context']=m.canonical(dict(self.context,**change));self.frozen['context_sha256']=m.sha(self.package['context'])
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_ORIGINAL_CONTEXT'):self.collect()
        self.package['context']=m.canonical(self.context).replace(b'9000.0',b'1e999');self.frozen['context_sha256']=m.sha(self.package['context'])
        with self.assertRaises(ValueError):self.collect()
        self.tick.assert_not_called();self.mono.assert_not_called()

    def test_deadline_failure_consumes_attempt_and_does_not_compile(self):
        self.mono.return_value=4400.
        with mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_DEADLINE'):self.collect()
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_ONE_COLLECTION_NO_RETRY'):self.collect()
        compile.assert_not_called()

    def test_invalid_plan_rejected_before_sampling(self):
        with self.assertRaises(ValueError):self.collect()
        self.assertTrue(m._USED)

    def test_selector_drift_and_expired_utc_reject_without_sampler_loading(self):
        with mock.patch.object(m,'_load') as load:
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_SOURCE_PIN'):
                m.collect(self.package,SAMPLER,SELECTOR+b' ',BOOT,{},self.tick,self.mono,self.utc)
            self.utc.return_value=9000.
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_DEADLINE'):self.collect()
        load.assert_not_called()

    def test_origin_pins_and_python36_syntax(self):
        self.assertEqual(m.sha(SAMPLER),m.SAMPLER_SHA)
        self.assertEqual(m.sha(SELECTOR),m.binding.SELECTOR_SHA)
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))

    def test_tick_crossing_deadline_is_caught_by_post_guard(self):
        self.tick.side_effect=lambda:setattr(self.mono,'return_value',4400.)
        with mock.patch.object(m,'_load') as load:
            with self.assertRaisesRegex(ValueError,'E138_ENGINE_DEADLINE'):self.collect()
        load.assert_not_called()

    def test_real_selector_plan_classification_redaction_over_virtual_samples(self):
        from tests.test_physical_engine_evidence_e137 import Tests as OldTests
        from tests.test_physical_engine_selector_e137 import synthetic_sources
        old=OldTests();self.addCleanup(old.doCleanups);old.setUp()
        functions,shell=synthetic_sources()
        original=m._load
        def load(raw,name):
            module=original(raw,name)
            if name=='selector':
                # Synthetic source fixtures only; all actual selector algorithms run.
                module.FUNCTIONS_SHA=m.sha(functions);module.SHELL_SHA=m.sha(shell)
                module.FUNCTIONS_BYTES=len(functions);module.SHELL_BYTES=len(shell)
                module.RUN_ROOT=m.contract.ROOT
            else:module.PINS=old.pins
            return module
        selector=load(SELECTOR,'selector')
        env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL',LANG='C',LC_ALL='C')
        argv=[selector.LAUNCHER,'-shell','-log',m.contract.ROOT+'/tool.log','-dofile',m.contract.ROOT+'/code/replay.tcl']
        plan=selector.build_plan(functions,shell,env,argv)
        with mock.patch.object(m,'_load',side_effect=load):
            result=m.collect(self.package,SAMPLER,SELECTOR,BOOT,plan,self.tick,self.mono,self.utc)
        self.assertEqual(result['classification']['status'],'CONDITIONALLY_SELECTED')
        self.assertNotIn(b'SENTINEL',m.canonical(result))
        self.assertFalse(result['engine_identity_authenticated'])

    def test_actual_sample_path_chain_with_virtual_files_and_redacted_plan(self):
        from tests.test_physical_engine_evidence_e137 import Tests as OldTests
        old=OldTests();self.addCleanup(old.doCleanups);old.setUp()
        original=m._load
        def load(raw,name):
            module=original(raw,name)
            if name=='selector':
                module._validate_plan=mock.Mock()
                module.classify=mock.Mock(return_value=dict(status='CONDITIONALLY_SELECTED'))
                module.redact_plan=mock.Mock(return_value={'synthetic_redacted':True})
            else:
                module.PINS=old.pins # Only synthetic file content pins, not paths or read guards.
                self.assertIs(module.sample_path.__globals__,vars(module))
            return module
        with mock.patch.object(m,'_load',side_effect=load),mock.patch('subprocess.Popen') as spawn:
            result=self.collect()
        spawn.assert_not_called()
        from src.data import physical_engine_evidence_e137 as origin
        self.assertEqual(set(result['files']),set(origin.PATHS))
        self.assertFalse(result['execution_ready']);self.assertFalse(result['memory_enforcement_verified'])
        self.assertNotIn('body_base64',m.canonical(result).decode())
