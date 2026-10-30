"""Mock physical composition; no shell, Tessent, SSH or real deployment."""
import ast
import base64
import copy
from contextlib import ExitStack
from pathlib import Path
import sys
from types import SimpleNamespace
import types
import unittest
from unittest import mock
from src.data import physical_e137_batch_execution as m

REPO=Path(__file__).resolve().parents[1]


class ActualPublicationTests(unittest.TestCase):
    """Real private Files / TrackedFiles dispatch over virtual anchored IO."""
    def setUp(self):
        from tests.test_physical_e137_root_receipt import ReceiptTests,UTC
        self.fixture=ReceiptTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.now=4395.
        self.fixture.utc=UTC+3395.
        self.session,self.files=self.fixture.create()
        m.os.close(self.files.directory(m.ROOT+'/journal',True))
        self.writes=[]
        self.backend=mock.patch.object(self.session.services.io,'_publish',side_effect=self.write)
        self.backend.start();self.addCleanup(self.backend.stop)

    def write(self,fd,name,raw):
        self.writes.append((name,raw))

    def tick(self):
        if self.fixture.now>=4400.:
            raise ValueError('ROLE2_HARD_DEADLINE')

    def test_actual_tracked_dispatch_preserves_reserve_before_hard_end(self):
        m._publish_evidence(self.files,self.tick,'stdout.log',b'synthetic')
        self.assertEqual(self.writes,[('stdout.log',b'synthetic')])

    def test_actual_dispatch_blocks_before_write_even_while_package_clock_valid(self):
        self.fixture.now=4400.;self.fixture.utc+=5.
        with self.assertRaisesRegex(ValueError,'ROLE2_HARD_DEADLINE'):
            m._publish_evidence(self.files,self.tick,'stdout.log',b'synthetic')
        self.assertEqual(self.writes,[])

    def test_actual_dispatch_detects_deadline_crossed_during_backend_write(self):
        def crossing(fd,name,raw):
            self.write(fd,name,raw)
            self.fixture.now=4400.;self.fixture.utc+=5.
        self.session.services.io._publish.side_effect=crossing
        with self.assertRaisesRegex(ValueError,'ROLE2_HARD_DEADLINE'):
            m._publish_evidence(self.files,self.tick,'stdout.log',b'synthetic')
        self.assertEqual(len(self.writes),1)
        with self.assertRaisesRegex(ValueError,'ROLE2_HARD_DEADLINE'):
            m._publish_evidence(self.files,self.tick,'stdout_ack.json',b'{}')
        self.assertEqual(len(self.writes),1)


class PureTests(unittest.TestCase):
    def test_default_all_admission_pins_deny_before_clock_proc_io(self):
        with mock.patch.object(m.time,'monotonic') as now,mock.patch.object(m.execution.process,'_boot_id') as boot,\
                mock.patch.object(m.execution.io,'_directory') as directory:
            with self.assertRaisesRegex(ValueError,'BATCH_PACKET_NOT_FROZEN'):m.execute({},1000.)
        now.assert_not_called();boot.assert_not_called();directory.assert_not_called()

    def test_actual_source_policy_admission_and_role1_join_pure(self):
        from tests.test_physical_replay_capture_e137 import CaptureTests
        from tests.test_physical_f_replay_execution_e137 import clock_value
        authority=(REPO/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
        proposal=(REPO/'contracts/physical_f_clean_replay_proposal_e137_v1.json').read_bytes()
        prior=m.decode((REPO.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes())
        tcl=base64.b64decode(next(r for r in prior['files'] if r['sha256']==m.execution.legacy.BASE_TCL_SHA256)['body_base64'])
        package={k:b'not-used-by-pure-admission' for k in m.INPUT_KEYS}
        for name,key in (('physical_f_replay_execution_e135','runtime_source'),('physical_f_replay_execution_e137','worker_source'),
                ('physical_runtime_bootstrap_e137','bootstrap_source'),('physical_engine_evidence_e137','collector_source'),
                ('physical_e137_root_receipt','root_receipt_source')):
            package[key]=(REPO/'src/data'/(name+'.py')).read_bytes()
        package.update(authority=authority,proposal=proposal,policy=m.canonical(m.POLICY),incremental=tcl,
            parent_helper=m.execution.legacy.EXPECTED_INIT.encode('ascii'))
        required={'physical_e137_batch_execution','physical_f_replay_execution_e137','physical_replay_capture_e137',
            'physical_runtime_bootstrap_e137','physical_engine_evidence_e137','physical_engine_selector_e137',
            'physical_stil_dependencies_e137','physical_e137_root_receipt'}|set(m.execution.SOURCE_PINS)|set(m.bootstrap.SOURCE_PINS)|set(m.capture.DEPENDENCY_SHA256)
        source_map={n:m.sha((REPO/'src/data'/(n+'.py')).read_bytes()) for n in required}
        case=CaptureTests();case.setUp()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(m.capture,'AUTH_SHA',m.roots.APPROVED_AUTH_SHA))
                captured=case.capture()
                fixture_validator=types.FunctionType(m.capture.validate_receipt.__code__,dict(vars(m.capture)))
                case.doCleanups() # Real grant validation below uses real proposal pins.
                def delegate(raw):return _fixture_validator(raw)
                stack.enter_context(mock.patch.object(m.capture,'_fixture_validator',fixture_validator,create=True))
                stack.enter_context(mock.patch.object(m.capture,'validate_receipt',delegate))
                clock=clock_value();clock.update(authorization_sha256=m.roots.APPROVED_AUTH_SHA,initial_response_sha256=m.sha(m.canonical(captured)))
                package.update(original_clock=m.canonical(clock),role1_response=m.canonical(dict(role='capture',capture=captured,
                    boot_id=clock['boot_id'],remote_start_monotonic=clock['remote_start_monotonic'],execution_ready=False)),
                    role2_intent=m.canonical(dict(role='execution',attempt_consumed=True,role_index=2,connections_max=3,automatic_retries=0,payload_sha256='a'*64)))
                for name,pin in source_map.items():stack.enter_context(mock.patch.object(sys.modules['src.data.'+name],'__source_sha256__',pin,create=True))
                for name,value in dict(AUTH_SHA256=m.roots.APPROVED_AUTH_SHA,POLICY_SHA256=m.sha(package['policy']),PAYLOAD_SHA256='a'*64,
                        FROZEN_INPUT_SHA256={k:m.sha(v) for k,v in package.items()},FROZEN_SOURCE_SHA256=source_map).items():
                    stack.enter_context(mock.patch.object(m,name,value))
                result=m.admission(package)
                self.assertEqual(result[0]['monotonic_end'],4600.)
                self.assertEqual(result[1],captured)
                self.assertIn(m.ROOT.encode('ascii'),result[2]['body'])
                wrong=dict(package,role1_response=package['role1_response']+b' ')
                with self.assertRaisesRegex(ValueError,'BATCH_EXACT_INPUT_BYTES'):m.admission(wrong)
                with mock.patch.object(m,'FROZEN_SOURCE_SHA256',{}):
                    with self.assertRaisesRegex(ValueError,'BATCH_COMPLETE_SOURCE_BINDINGS'):m.admission(package)
        finally:case.doCleanups()

    def test_vendor_ldd_policy_records_two_source_outcomes_not_final_proof(self):
        env={'LD_LIBRARY_PATH':'/trusted/original/lib'}
        pre=m.selector.ROOT+'/lnx-x86/lib64:'+m.selector.ROOT+'/lnx-x86/lib32:'+env['LD_LIBRARY_PATH']
        measured=dict(classification=dict(selected={'mgls':{'width':'32'},'engine':{'width':'64'}},
            pre_ldd_library_path_sha256=m.sha(pre.encode('utf-8'))))
        result=m._ldd_policy({},measured,env)
        self.assertFalse(result['ldd_behavior_verified']);self.assertFalse(result['final_environment_observed'])
        self.assertNotEqual(result['pre_ldd_sha256'],result['replacement_sha256'])
        measured['classification']['pre_ldd_library_path_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'BATCH_VENDOR_LD_ORDER'):m._ldd_policy({},measured,env)

    def test_ast36_and_inert_no_io(self):
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            namespace={'__package__':'src.data'};exec(compile(raw,'<inert-batch>','exec'),namespace)
        opened.assert_not_called();self.assertIsNone(namespace['FROZEN_SOURCE_SHA256'])

    def test_validator_self_source_binding_is_private(self):
        original=m.dependencies.verify
        def fake(pattern,allowed,tick):return verify.__source_sha256__
        with mock.patch.object(m.dependencies,'verify',fake),mock.patch.object(m,'FROZEN_SOURCE_SHA256',
                {'physical_stil_dependencies_e137':'a'*64}):
            self.assertEqual(m._verify_dependencies('p',[],lambda:None),'a'*64)
            self.assertFalse(hasattr(fake,'__source_sha256__'))
        self.assertIs(m.dependencies.verify,original)


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.package={k:k.encode('ascii') for k in m.INPUT_KEYS}
        self.clock=dict(remote_start_monotonic=1000.,monotonic_end=4600.,utc_end=9000.,boot_id='3ebeb9bb-410c-476c-a000-5c625f590473')
        rows=[dict(role=r,path='/synthetic/'+r,bytes=3,sha256='1'*64,identity={}) for r in ('pattern','library','F_basic')]
        self.captured=dict(pattern=rows[0],inputs=rows[1:],tree=dict(rows=[]))
        self.recipe=dict(body=b'SYNTHETIC_MAIN',baseline_expectations_body=b'SYNTHETIC_HELPER',sha256=m.sha(b'SYNTHETIC_MAIN'),baseline_expectations_sha256=m.sha(b'SYNTHETIC_HELPER'))
        self.domain=mock.Mock(peak=123,pid=12345,identity=(12345,99));self.domain.snapshot.return_value={}
        self.files=mock.Mock();self.files.directory.return_value=333
        self.services=mock.Mock();self.services.Files.return_value=self.files
        self.monitor=mock.Mock();self.monitor.sample.return_value={'sampled_named_bytes':123}
        self.services._storage.return_value=(mock.Mock(),self.monitor)
        self.services.run_selftests.return_value=[dict(case=n,passed=True,cleaned=True) for n in m.execution.legacy.SELFTEST_CASES]
        self.services._observer.return_value=dict(output=b'SYNTHETIC_TOOL_OUTPUT',failure=None,returncode=0,cleaned=True,launch_attempted=True)
        self.boot=SimpleNamespace(bootstrap=mock.Mock())
        def bootstrap(package,domain,tick,meta):
            meta.update({'values_disclosed':False,'cleaned':True})
            return SimpleNamespace(environment=lambda:dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL',LM_LICENSE_FILE='123@SENTINEL_LICENSE'))
        self.boot.bootstrap.side_effect=bootstrap
        self.sampler=SimpleNamespace(SELECTOR_SHA256='a'*64,collect=mock.Mock(),sample_path=mock.Mock())
        present=dict(state='PRESENT',identity={'st_size':3},sha256='b'*64,whole_file_hashed=True)
        self.measured=dict(files={p:copy.deepcopy(present) for p in m.evidence.PATHS},classification={'selected':{}})
        self.sampler.collect.return_value=self.measured
        self.sampler.sample_path.side_effect=lambda path,*args:copy.deepcopy(self.measured['files'][path])
        self.root=SimpleNamespace(tracked_services=mock.Mock())
        self.root_session=SimpleNamespace(services=self.services,emit=mock.Mock())
        self.root.tracked_services.return_value=self.root_session
        self.publication_count=None
        def emit(files,response_raw,cleanup_raw):
            self.assertIs(files,self.files)
            self.assertEqual(m.decode(cleanup_raw),{k:v for k,v in self.services._observer.return_value.items() if k!='output'})
            cfg=self.root.tracked_services.call_args.args[0]
            self.assertIn(b'SENTINEL',cfg['worker_spec']) # Private RAM only.
            binding=dict(clock_sha256=m.sha(self.package['original_clock']),role2_intent_sha256=m.sha(self.package['role2_intent']))
            proof=self.root.CLEANUP_OBSERVER(files,cleanup_raw,response_raw,binding)
            self.assertEqual(proof['active_descendant_pids'],[])
            self.publication_count=self.files.publish.call_count
            return {'input_bindings':{'worker_spec_sha256':m.sha(cfg['worker_spec'])},'root':m.ROOT}
        self.root_session.emit.side_effect=emit
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for patch in (mock.patch.object(m,'_USED',False),mock.patch.object(m,'__source_sha256__','a'*64,create=True),
            mock.patch.object(m,'admission',return_value=(self.clock,self.captured,self.recipe)),
            mock.patch.object(m,'_private',side_effect=[self.boot,self.sampler,self.root]),
            mock.patch.object(m,'_ldd_policy',return_value={'final_environment_observed':False}),
            mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),mock.patch.object(m.platform,'machine',return_value='x86_64'),
            mock.patch.object(m.platform,'system',return_value='Linux'),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
            mock.patch.object(m.os.sys,'platform','linux'),mock.patch.object(m.os,'close'),
            mock.patch.object(m.time,'monotonic',return_value=2001.),mock.patch.object(m.time,'time',return_value=5000.),
            mock.patch.object(m.execution.process,'_boot_id',return_value=self.clock['boot_id']),
            mock.patch.object(m.execution.process,'_check_worker'),mock.patch.object(m.execution.direct,'Descendants',return_value=self.domain),
            mock.patch.object(m.selector,'build_plan',return_value={}),mock.patch.object(m.execution,'_source_recheck'),
            mock.patch.object(m.execution,'_closure_recheck'),mock.patch.object(m.execution.io,'_publish'),
            mock.patch.object(m,'_verify_dependencies',return_value={'status':'PASS'})):
            self.stack.enter_context(patch)

    def test_actual_pipeline_order_uses_registered_files_and_one_observer(self):
        def observe(*args):
            self.assertEqual(self.services.run_selftests.call_count,1)
            self.assertEqual(m._verify_dependencies.call_count,1)
            self.assertIn('launch_intent.json',[c.args[0] for c in self.files.publish.call_args_list])
            return self.services._observer.return_value
        self.services._observer.side_effect=observe
        result=m.execute(self.package,2000.)
        self.assertEqual(set(result),{'role','worker_response','owned_root','cleanup_observation','execution_ready'})
        self.assertEqual(self.services._observer.call_count,1);self.assertEqual(self.boot.bootstrap.call_count,1)
        self.assertEqual(self.files.copy.call_count,3);self.assertEqual(m.execution.io._publish.call_count,2)
        self.assertEqual(self.sampler.sample_path.call_count,len(m.evidence.PATHS))
        self.services._storage.assert_called_once_with(4400.)
        self.assertEqual(self.publication_count,self.files.publish.call_count)
        self.assertNotIn(b'SENTINEL',m.canonical(result))
        for call in self.files.publish.call_args_list:self.assertNotIn(b'SENTINEL',call.args[1])
        self.assertEqual(result['worker_response']['instance_sha256'],result['owned_root']['input_bindings']['worker_spec_sha256'])
        self.assertFalse(result['worker_response']['ldd_policy']['final_environment_observed'])
        with self.assertRaisesRegex(ValueError,'BATCH_ONE_ATTEMPT_NO_RETRY'):m.execute(self.package,2000.)

    def test_clean_failed_tool_can_emit_ownership_but_unknown_cleanup_cannot(self):
        self.services._observer.return_value.update(failure='CASE_TIMEOUT',returncode=1)
        result=m.execute(self.package,2000.)
        self.assertEqual(result['worker_response']['status'],'STOPPED_FIRST_FAILURE')
        self.assertIsNotNone(result['owned_root'])

    def test_expired_active_window_cannot_publish_initial_sidecar(self):
        now=[2001.]
        m.time.monotonic.side_effect=lambda:now[0]
        def collect(*args):
            now[0]=4391.
            return self.measured
        self.sampler.collect.side_effect=collect
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root'])
        self.services._storage.return_value[0].assert_not_called()
        self.services.Files.assert_not_called()

    def test_clean_observer_return_in_reserve_preserves_evidence_and_receipt(self):
        now=[2001.]
        m.time.monotonic.side_effect=lambda:now[0]
        def observe(*args):
            self.assertLessEqual(args[1],4390.)
            now[0]=4395.
            return self.services._observer.return_value
        self.services._observer.side_effect=observe
        result=m.execute(self.package,2000.)
        self.assertIsNotNone(result['owned_root'])
        self.assertIn('stdout.log',[c.args[0] for c in self.files.publish.call_args_list])

    def test_hard_deadline_and_evidence_write_failure_do_not_invent_receipt(self):
        now=[2001.]
        m.time.monotonic.side_effect=lambda:now[0]
        def observe(*args):
            now[0]=4400.
            return self.services._observer.return_value
        self.services._observer.side_effect=observe
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root'])
        self.root_session.emit.assert_not_called()

    def test_evidence_publication_failure_has_no_durability_claim(self):
        def publish(name,*args,**kwargs):
            if name=='stdout.log':raise OSError('DISK_FAILURE_PRIVATE')
        self.files.publish.side_effect=publish
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root'])
        self.assertNotIn(b'DISK_FAILURE_PRIVATE',m.canonical(result))
        self.root_session.emit.assert_not_called()

    def test_failed_selfchecks_or_dependency_never_launch(self):
        self.services.run_selftests.return_value[0]['passed']=False
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root']);self.assertEqual(result['launch_debit'],0)
        self.services._observer.assert_not_called();self.root_session.emit.assert_not_called()

    def test_dependency_failure_or_installed_drift_prevents_tool(self):
        m._verify_dependencies.side_effect=ValueError('dependency mismatch')
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root']);self.services._observer.assert_not_called()
        self.services.run_selftests.assert_not_called()

    def test_installed_fallback_drift_prevents_tool(self):
        self.sampler.sample_path.side_effect=lambda *args:{'state':'MISSING'}
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root']);self.services._observer.assert_not_called()
        self.assertEqual(result['launch_debit'],0)

    def test_live_descendant_blocks_qualified_root_receipt(self):
        self.domain.snapshot.return_value={999:object()}
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root']);self.assertEqual(result['launch_debit'],1)

    def test_unconfirmed_cleanup_cannot_qualify_root_receipt(self):
        self.services._observer.return_value['cleaned']=False
        result=m.execute(self.package,2000.)
        self.assertIsNone(result['owned_root']);self.assertEqual(result['launch_debit'],1)

    def test_unknown_observer_cleanup_never_invents_rootproof(self):
        self.services._observer.side_effect=OSError('SENTINEL_MUST_NOT_EXPORT')
        result=m.execute(self.package,2000.)
        self.assertEqual(result['schema'],'e137-batch-execution-failure-v1');self.assertIsNone(result['owned_root'])
        self.assertEqual(result['launch_debit'],1);self.assertNotIn(b'SENTINEL',m.canonical(result))
        self.root_session.emit.assert_not_called()

    def test_bootstrap_failure_precreation_is_versioned_and_no_tool(self):
        self.boot.bootstrap.side_effect=ValueError('PRIVATE_SENTINEL')
        result=m.execute(self.package,2000.)
        self.assertEqual(result['schema'],'e137-batch-execution-failure-v1');self.assertIsNone(result['owned_root'])
        self.assertEqual(result['launch_debit'],0);self.assertNotIn(b'SENTINEL',m.canonical(result))
        self.services.Files.assert_not_called();self.services._observer.assert_not_called()
