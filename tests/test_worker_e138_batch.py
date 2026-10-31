"""Native loader/contract with synthetic runtime components, no remote IO."""
import ast
import base64
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from scripts import worker_e138_batch as m
from src.data import physical_e138_contract as contract

REPO=Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def setUp(self):
        self.loader=(REPO/'scripts/e138_source_session.py').read_bytes()
        proposal=dict(schema='e138-fixed-f-replay-proposal-v1',package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',scope_if_granted=copy.deepcopy(contract.POLICY))
        self.package={'proposal':m.canonical(proposal)}
        self.package['authority']=m.canonical(dict(schema='e138-explicit-whole-package-authorization-v1',
            approved_package='E138',approval_source='explicit_user_reply',user_reply='synthetic-only',
            user_authorization_received=True,proposal_sha256=m.sha(self.package['proposal']),
            approved_scope=copy.deepcopy(contract.POLICY),execution_ready=False))
        self.bodies=[('physical_e138_contract',(REPO/'src/data/physical_e138_contract.py').read_bytes()),
            ('physical_replay_capture_e138',b'from . import physical_e138_contract as contract\nAUTH_SHA=PROPOSAL_SHA=None\ndef check_authority(a,p): return contract.check_authority(a,p,AUTH_SHA,PROPOSAL_SHA)\ndef capture(a,p,end,tick,monotonic):\n tick()\n return {"synthetic":True}\n'),
            ('physical_e138_runtime_primitives',b'import types\nclass Domain:\n peak=100\n def sample(self):return {}\nlegacy=types.SimpleNamespace(process=types.SimpleNamespace(_boot_id=lambda:"synthetic-boot"),direct=types.SimpleNamespace(Descendants=Domain))\n')]
        self.patch(m,'_USED',False)
        self.patch(m,'_STAGE','ADMISSION')
        self.patch(m.platform,'node',return_value='bupt-vncs2');self.patch(m.platform,'system',return_value='Linux')
        self.patch(m.os,'getuid',return_value=1047,create=True);self.patch(m.time,'monotonic',return_value=1000.)
        self.configure()

    def patch(self,*args,**kwargs):
        patch=mock.patch.object(*args,**kwargs);value=patch.start();self.addCleanup(patch.stop);return value

    def configure(self,role='capture'):
        self.rows=[dict(name=name,sha256=m.sha(raw),body_base64=base64.b64encode(raw).decode('ascii')) for name,raw in self.bodies]
        self.intent=dict(role=role,attempt_consumed=True,role_index=1 if role=='capture' else 2,
            connections_max=3,automatic_retries=0,payload_sha256='c'*64)
        self.freeze=dict(role=role,payload_sha256='c'*64,loader_sha256=m.sha(self.loader),
            source_sha256={name:m.sha(raw) for name,raw in self.bodies},source_order=tuple(name for name,raw in self.bodies),
            input_sha256={key:m.sha(raw) for key,raw in self.package.items()},
            authorization_sha256=m.sha(self.package['authority']),proposal_sha256=m.sha(self.package['proposal']),assembly=None)
        self.patch(m,'FROZEN',self.freeze)

    def run_dispatch(self):return m.dispatch(self.package,self.rows,self.loader,self.intent,'c'*64,1000.)

    def test_default_denies_before_compile_clock_host_or_open(self):
        with mock.patch.object(m,'FROZEN',None),mock.patch('builtins.compile') as compile,\
                mock.patch.object(m.time,'monotonic') as now,mock.patch('builtins.open') as opened:
            with self.assertRaisesRegex(m.WorkerFailure,'EXTERNAL_FREEZE_REQUIRED'):self.run_dispatch()
        compile.assert_not_called();now.assert_not_called();opened.assert_not_called()

    def test_native_loader_contract_capture_dispatch_and_registry_restoration(self):
        before={k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')}
        with mock.patch('subprocess.Popen') as spawn:
            value=json.loads(self.run_dispatch())
        spawn.assert_not_called();self.assertEqual(value['capture'],{'synthetic':True})
        self.assertEqual(value['remote_start_monotonic'],1000.);self.assertTrue(value['remote_utc_sample'].endswith('+0000'))
        self.assertFalse(value['execution_ready'])
        self.assertEqual(before,{k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')})
        with self.assertRaisesRegex(m.WorkerFailure,'EXTERNAL_FREEZE_REQUIRED'):self.run_dispatch()

    def test_source_and_loader_drift_before_compile(self):
        for kind in ('loader','source','input'):
            with self.subTest(kind=kind),mock.patch('builtins.compile') as compile:
                if kind=='loader':
                    with self.assertRaises(m.WorkerFailure):m.dispatch(self.package,self.rows,b'bad',self.intent,'c'*64,1000.)
                elif kind=='source':
                    rows=copy.deepcopy(self.rows);rows[-1]['body_base64']='eA=='
                    with self.assertRaises(m.WorkerFailure):m.dispatch(self.package,rows,self.loader,self.intent,'c'*64,1000.)
                else:
                    with self.assertRaises(m.WorkerFailure):m.dispatch(dict(self.package,authority=b'bad'),self.rows,self.loader,self.intent,'c'*64,1000.)
                compile.assert_not_called()

    def test_readback_not_implemented_and_intent_exact_types(self):
        self.freeze['role']='readback'
        with self.assertRaisesRegex(m.WorkerFailure,'EXTERNAL_FREEZE_REQUIRED'):self.run_dispatch()
        self.freeze['role']='capture';self.intent['role_index']=True
        with self.assertRaisesRegex(m.WorkerFailure,'EXACT_INTENT'):self.run_dispatch()

    def test_fixed_host_failure_still_consumes_worker_instance(self):
        self.patch(m.platform,'node',return_value='not-A')
        with self.assertRaisesRegex(m.WorkerFailure,'FIXED_A_LINUX'):self.run_dispatch()
        self.assertTrue(m._USED)
        with self.assertRaises(m.WorkerFailure):self.run_dispatch()

    def execution(self):
        self.bodies.append(('physical_e138_batch_assembler',b'from . import physical_e138_contract as contract\nAUTH_SHA256=PROPOSAL_SHA256=POLICY_SHA256=PAYLOAD_SHA256=FROZEN_INPUT_SHA256=FROZEN_SOURCE_SHA256=None\ndef execute(package,sources,started):\n assert contract.FROZEN["source_sha256"]==FROZEN_SOURCE_SHA256\n assert contract.LOADED_SOURCE_ORDER==tuple(sources)\n assert package["role2_intent"]==package["expected_intent"]\n return {"role":"execution","synthetic":True,"execution_ready":False}\n'))
        self.package['role2_intent']=m.canonical(dict(self.intent,role='execution',role_index=2))
        self.package['expected_intent']=self.package['role2_intent']
        self.configure('execution')
        self.freeze['assembly']={key:copy.deepcopy(self.freeze[key]) for key in contract.FREEZE_KEYS if key in self.freeze}
        self.freeze['assembly']['policy_sha256']='d'*64

    def test_execution_freeze_installed_only_inside_fresh_source_session(self):
        self.execution()
        self.assertTrue(json.loads(self.run_dispatch())['synthetic'])
        self.assertIsNone(contract.FROZEN)

    def test_execution_input_intent_and_freeze_join_cannot_be_forged(self):
        self.execution();self.freeze['assembly']['payload_sha256']='d'*64
        with self.assertRaisesRegex(m.WorkerFailure,'ASSEMBLY_FREEZE_JOIN'):self.run_dispatch()

    def test_python36_syntax(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))

    def test_safe_default_denial_is_single_bounded_public_frame(self):
        self.patch(m,'FROZEN',None)
        with mock.patch('builtins.compile') as compile:
            raw=m.safe_dispatch(self.package,self.rows,self.loader,self.intent,'c'*64,1000.)
        compile.assert_not_called();value=json.loads(raw)
        self.assertEqual(value['error_code'],'E138_WORKER_EXTERNAL_FREEZE_REQUIRED')
        self.assertEqual(value['stage'],'ADMISSION');self.assertFalse(value['attempt_consumed'])
        self.assertLess(len(raw),1024)

    def test_safe_boundary_redacts_unknown_and_subclass_exception_text(self):
        class Private(m.WorkerFailure):pass
        for exc in (ValueError('SENTINEL_PRIVATE'),KeyboardInterrupt('SENTINEL_PRIVATE'),
                Private('E138_WORKER_SOURCE_PIN'),m.WorkerFailure('E138_WORKER_SOURCE_PIN SENTINEL_PRIVATE')):
            with self.subTest(kind=type(exc).__name__),mock.patch.object(m,'dispatch',side_effect=exc):
                raw=m.safe_dispatch({},[],b'',{},'c'*64,1000.)
            self.assertNotIn(b'SENTINEL_PRIVATE',raw)
            self.assertEqual(json.loads(raw)['error_code'],'E138_WORKER_REDACTED_FAILURE')

    def test_safe_success_and_stage_on_source_load_failure(self):
        with mock.patch.object(m,'dispatch',return_value=b'{"synthetic":true}'):
            self.assertEqual(m.safe_dispatch({},[],b'',{},'c'*64,1000.),b'{"synthetic":true}')
        self.bodies[-1]=(self.bodies[-1][0],b'raise RuntimeError("SENTINEL_PRIVATE")')
        self.configure()
        raw=m.safe_dispatch(self.package,self.rows,self.loader,self.intent,'c'*64,1000.)
        self.assertNotIn(b'SENTINEL_PRIVATE',raw);value=json.loads(raw)
        self.assertEqual(value['stage'],'SOURCE_LOAD');self.assertTrue(value['attempt_consumed'])
        self.assertEqual(value['error_code'],'E138_WORKER_REDACTED_FAILURE')

    def native_fixture_session(self,session,rows,role,configure=None):
        """Only physical test backends/content pins are substituted, in RAM.

        Worker receives actual loader/component bytes; fixture installation
        occurs when the real source_session yields, not via production hooks.
        """
        from tests import test_physical_e138_batch_assembler as fixture
        from tests import test_physical_replay_capture_e138 as capture_fixture
        from tests import test_physical_replay_source_inventory_e135 as inventory_fixture
        @contextmanager
        def enter():
            with session(rows) as loaded:
                assembler=loaded.get('physical_e138_batch_assembler')
                with mock.patch.object(fixture,'m',assembler if assembler else fixture.m), \
                        mock.patch.object(capture_fixture,'m',loaded['physical_replay_capture_e138']), \
                        mock.patch.object(inventory_fixture,'inv',loaded['physical_replay_source_inventory_e135']), \
                        mock.patch.object(inventory_fixture,'core',loaded['physical_replay_source_reader_e135']):
                    case=fixture.NativeFlowTests() if role=='execution' else capture_fixture.CaptureTests()
                    try:
                        case.setUp()
                        if configure:configure(case,loaded)
                        yield case,loaded
                    finally:case.doCleanups()
        return enter()

    def native_dispatch(self,role):
        from scripts import e138_source_session as loader
        from tests.test_e138_source_session import Tests as LoaderTests
        from tests import test_physical_e138_batch_assembler as fixture
        roots={'physical_e138_contract','physical_replay_capture_e138','physical_e138_runtime_primitives'}
        if role=='execution':
            roots|=set(fixture.m.COMPONENTS.values())|set(fixture.m.ORIGINS.values())|set(fixture.m.INPUT_SOURCES.values())|set(fixture.m.contract.REQUIRED_SOURCES)|{'physical_e138_batch_assembler'}
        self.bodies=LoaderTests().native_bodies(roots)
        rows=[dict(name=name,sha256=m.sha(raw),body_base64=base64.b64encode(raw).decode('ascii')) for name,raw in self.bodies]
        pins={name:m.sha(raw) for name,raw in self.bodies};order=tuple(name for name,raw in self.bodies)
        with mock.patch.object(loader,'FROZEN_SOURCE_SHA256',pins),mock.patch.object(loader,'FROZEN_SOURCE_ORDER',order):
            with self.native_fixture_session(loader.source_session,rows,role) as pair:
                case,loaded=pair
                if role=='execution':
                    self.package=copy.deepcopy(case.package);assembly=copy.deepcopy(case.frozen)
                    assembly['source_sha256']=pins;assembly['source_order']=order
                else:
                    self.package=dict(authority=case.authority,proposal=case.proposal);assembly=None
        self.configure(role);self.freeze['assembly']=assembly
        if role=='execution':
            self.freeze['payload_sha256']=assembly['payload_sha256']
            self.intent=json.loads(self.package['role2_intent'])
        from scripts import e138_reviewed_envelope as envelope
        template=copy.deepcopy(self.freeze);static_package=dict(self.package)
        template.pop('payload_sha256')
        if role=='execution':
            template['assembly'].pop('payload_sha256')
            template['input_sha256'].pop('role2_intent')
            template['assembly']['input_sha256'].pop('role2_intent',None)
            static_package.pop('role2_intent')
        derived,reconstructed=envelope.derive(template,static_package,self.intent,self.freeze['payload_sha256'])
        self.assertEqual(derived,self.freeze);self.assertEqual(reconstructed,self.package)
        self.freeze.clear();self.freeze.update(derived);self.package=reconstructed
        # Do not patch the shared types module: native source tag checks depend
        # on genuine ModuleType identity. Only the worker's constructor is wrapped.
        original=types.ModuleType;owner=self
        class InstrumentedLoader(original):
            def __getattribute__(self,name):
                value=original.__getattribute__(self,name)
                if name!='source_session':return value
                @contextmanager
                def instrumented(actual_rows):
                    def configure_case(case,loaded):
                        if role=='execution':
                            owner.assertEqual(case.package,owner.package)
                            assembler=loaded['physical_e138_batch_assembler'];original_private=assembler._private
                            def private(raw,name):
                                result=original_private(raw,name)
                                if name=='finite_sampler':result.sample_path=case.sample_path
                                return result
                            case.patch(assembler,'_private',side_effect=private)
                        else:
                            runtime=loaded['physical_e138_runtime_primitives']
                            owner.patch(runtime.legacy.direct,'Descendants',fixture.Domain)
                            owner.patch(runtime.legacy.process,'_boot_id',return_value='synthetic-boot')
                    with owner.native_fixture_session(value,actual_rows,role,configure_case) as pair:
                        yield pair[1]
                return instrumented
        def construct(name):return InstrumentedLoader(name) if name=='_e138_reviewed_source_session' else original(name)
        with mock.patch.object(m,'types',types.SimpleNamespace(ModuleType=construct)),mock.patch('subprocess.Popen') as spawn:
            result=m.safe_dispatch(self.package,self.rows,self.loader,self.intent,self.freeze['payload_sha256'],
                2000. if role=='execution' else 1000.)
        spawn.assert_not_called()
        return json.loads(result)

    def test_actual_worker_native_capture_with_virtual_physical_files(self):
        result=self.native_dispatch('capture')
        self.assertTrue(result['capture']['complete'])
        self.assertFalse(result['execution_ready'])

    def test_actual_worker_native_assembler_with_virtual_physical_backends(self):
        result=self.native_dispatch('execution')
        self.assertIsNotNone(result['owned_root'],result)
        self.assertEqual(result['worker_response']['launch_debit'],1)
        self.assertFalse(result['execution_ready'])


if __name__=='__main__':unittest.main()
