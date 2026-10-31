"""Synthetic exact-source admission and native composition; no physical runs.

Private synthetic content pins and virtual copy/sampling backends are test
substitutions, not evidence about the real E127 sources or installed engine.
"""
import ast
import base64
import copy
import datetime
import importlib
from pathlib import Path
import stat
import sys
import unittest
from unittest import mock
from src.data import physical_e138_batch_assembler as m

REPO=Path(__file__).resolve().parents[1]
BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'
UTC=datetime.datetime(2026,10,30,tzinfo=datetime.timezone.utc).timestamp()


class Domain(object):
    peak=123
    pid=12345
    identity=(12345,99)
    def sample(self):return {}
    def snapshot(self):return {}


class AdmissionTests(unittest.TestCase):
    def test_default_closed_without_clock_compile_or_io(self):
        with mock.patch.object(m.time,'monotonic') as now,mock.patch.object(m,'_components') as load,mock.patch('builtins.open') as opened:
            result=m.execute({}, {},1000.)
        for call in (now,load,opened):call.assert_not_called()
        self.assertIsNone(result['owned_root'])
        self.assertFalse(result['worker_response']['attempt_consumed'])
        self.assertFalse(result['execution_ready'])

    def test_inert_and_python36(self):
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))


class NativeFlowTests(unittest.TestCase):
    def patch(self,*args,**kwargs):
        patch=mock.patch.object(*args,**kwargs);value=patch.start();self.addCleanup(patch.stop);return value

    def setUp(self):
        # Load dormant compatibility modules before synthetic fixture patches,
        # so their import-time constants do not capture test inventory pins.
        for name in m.contract.REQUIRED_SOURCES:importlib.import_module('src.data.'+name)
        from tests.test_physical_replay_capture_e138 import CaptureTests
        from tests.test_physical_e138_runtime_primitives import clock_value
        from tests.test_physical_engine_selector_e137 import synthetic_sources,present
        from src.data import physical_e138_runtime_primitives as runtime
        from src.data import physical_runtime_bootstrap_e138 as bootstrap
        from src.data import physical_replay_capture_e138 as capture
        self.capture_case=CaptureTests();self.addCleanup(self.capture_case.doCleanups);self.capture_case.setUp()
        self.fs=self.capture_case.fs
        # Grammar-safe tiny pattern; update only synthetic fixture pins.
        pattern_path=capture.PATTERN['path'];self.fs.body[pattern_path]=b'STIL 1.0; Signals { "a" In; } Pattern p {}'
        self.fs.info[pattern_path].st_size=len(self.fs.body[pattern_path])
        self.pattern=dict(capture.PATTERN,bytes=len(self.fs.body[pattern_path]),sha256=m.sha(self.fs.body[pattern_path]))
        self.patch(capture,'PATTERN',self.pattern)
        self.captured=self.capture_case.capture()
        self.package={key:b'SYNTHETIC_UNUSED' for key in m.contract.INPUT_KEYS}
        self.package.update(authority=self.capture_case.authority,proposal=self.capture_case.proposal,
            policy=m.canonical(m.contract.POLICY),role2_intent=m.canonical(dict(role='execution',attempt_consumed=True,
                role_index=2,connections_max=3,automatic_retries=0,payload_sha256='a'*64)))
        clock=clock_value();clock.update(authorization_sha256=m.sha(self.package['authority']),proposal_sha256=m.sha(self.package['proposal']),
            initial_response_sha256=m.sha(m.canonical(self.captured)))
        self.package.update(original_clock=m.canonical(clock),role1_response=m.canonical(dict(role='capture',capture=self.captured,
            boot_id=BOOT,remote_start_monotonic=1000.,execution_ready=False)))
        self.env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL',LM_LICENSE_FILE='123@SENTINEL_LICENSE',
            MGLS_LICENSE_FILE='123@SENTINEL_LICENSE')
        self.profile=bootstrap.profile.snapshot(self.env,False)
        self.package.update(e112=m.canonical(dict(runtime_profile=self.profile)),
            parent_worker_source=(REPO/'scripts/worker_pt_label_generation_e127.py').read_bytes(),
            profile_source=(REPO/'src/data/prospective_runtime_profile_e112.py').read_bytes())
        self.package['functions'],self.package['shell']=synthetic_sources()
        # Frozen local E128 recipe input only; not an E137/E138 attempt phase.
        prior=m.decode((REPO.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes())
        self.package['incremental']=base64.b64decode(next(row for row in prior['files'] if row['sha256']==runtime.legacy.BASE_TCL_SHA256)['body_base64'])
        self.package['parent_helper']=runtime.legacy.EXPECTED_INIT.encode('ascii')
        names=set(m.COMPONENTS.values())|set(m.ORIGINS.values())|set(m.INPUT_SOURCES.values())|set(m.contract.REQUIRED_SOURCES)|{
            'physical_e138_batch_assembler','physical_f_replay_recipe_e135_r2'}|set(bootstrap.SOURCE_PINS)|set(capture.DEPENDENCY_SHA256)|{
            getattr(runtime.legacy,name).__name__.rsplit('.',1)[1] for name in runtime.HELPER_PINS}
        self.sources={name:(REPO/'src/data'/(name+'.py')).read_bytes() for name in names}
        for key,name in m.INPUT_SOURCES.items():self.package[key]=self.sources[name]
        manifest={name:m.sha(raw) for name,raw in self.sources.items()}
        order=tuple(sorted(names))
        self.frozen=dict(authorization_sha256=m.sha(self.package['authority']),proposal_sha256=m.sha(self.package['proposal']),
            payload_sha256='a'*64,policy_sha256=m.sha(self.package['policy']),
            input_sha256={key:m.sha(raw) for key,raw in self.package.items()},source_sha256=manifest,source_order=order)
        self.patch(m.contract,'FROZEN',self.frozen);self.patch(m.contract,'LOADED_SOURCE_ORDER',order)
        for name,pin in manifest.items():self.patch(importlib.import_module('src.data.'+name),'__source_sha256__',pin,create=True)
        for key,value in dict(AUTH_SHA256=self.frozen['authorization_sha256'],PROPOSAL_SHA256=self.frozen['proposal_sha256'],
                POLICY_SHA256=self.frozen['policy_sha256'],PAYLOAD_SHA256='a'*64,FROZEN_INPUT_SHA256=self.frozen['input_sha256'],
                FROZEN_SOURCE_SHA256=manifest,_USED=False).items():self.patch(m,key,value)
        self.now=2001.;self.utc=UTC+1001
        self.patch(m.time,'monotonic',side_effect=lambda:self.now);self.patch(m.time,'time',side_effect=lambda:self.utc)
        self.patch(m.platform,'node',return_value='bupt-vncs2');self.patch(m.platform,'system',return_value='Linux')
        self.patch(m.platform,'machine',return_value='x86_64');self.patch(m.os.sys,'platform','linux')
        self.patch(m.os,'getuid',return_value=1047,create=True);self.patch(m.direct,'Descendants',Domain)
        self.patch(m.process,'_boot_id',return_value=BOOT);self.patch(m.process,'_check_worker')
        self.calls=[];self.writes=[];self.modules=None;self.service=None
        self.patch(capture.anchored,'_mkdir',side_effect=self.mkdir)
        self.patch(capture.anchored,'_publish',side_effect=self.publish)
        self.patch(capture.anchored,'_read_at',side_effect=self.read_at)
        self.fs.add(m.ROOT.rsplit('/',1)[0],directory=True)
        self.patch(m.direct.base,'supervise',side_effect=self.supervise)
        self.actual_components=m._components
        self.patch(m,'_components',side_effect=self.components)
        self.engine_rows={path:dict(state='MISSING') for path in importlib.import_module('src.data.physical_engine_evidence_e137').PATHS}
        selector=importlib.import_module('src.data.physical_engine_selector_e137')
        for path in (selector.ENGINE['64'],selector.MGLS['64'],selector.TCL['64']):
            row=present(directory=path==selector.TCL['64'])
            self.engine_rows[path]=dict(row,sha256=None if path==selector.TCL['64'] else 'b'*64,whole_file_hashed=path!=selector.TCL['64'])
        for path in importlib.import_module('src.data.physical_engine_evidence_e137').CHAIN:
            self.engine_rows[path]=dict(present(),sha256='c'*64,whole_file_hashed=True)

    def mkdir(self,parent,name):
        path=self.fs.handles[parent][0]+'/'+name
        if path in self.fs.info:raise FileExistsError()
        self.fs.add(path,directory=True);return self.fs.directory(path)

    def publish(self,fd,name,raw):
        path=self.fs.handles[fd][0]+'/'+name
        if path in self.fs.info:raise FileExistsError()
        self.fs.add(path,raw=raw);self.writes.append(path)

    def read_at(self,fd,name,budget,**kwargs):
        raw=self.fs.body[self.fs.handles[fd][0]+'/'+name]
        return None,len(raw),m.sha(raw)

    def supervise(self,argv,*args,**kwargs):
        self.calls.append(argv)
        if argv[0]=='/bin/bash':
            return dict(output=m.canonical(dict(nonce='E127_PRIVATE_RUNTIME_V1',values=self.env,profile=self.profile)),
                cleaned=True,returncode=0,launch_attempted=True,failure=None)
        case=len(self.calls)-2
        return dict(output=b'DIRECT_SYNTHETIC_OK' if case==0 else b'SYNTHETIC_TIMEOUT',
            cleaned=True,returncode=0 if case==0 else -9,launch_attempted=True,
            failure=None if case==0 else 'CASE_TIMEOUT',readiness={} if case==2 else None)

    def selector_fixture(self,selector):
        selector.FUNCTIONS_SHA=m.sha(self.package['functions']);selector.FUNCTIONS_BYTES=len(self.package['functions'])
        selector.SHELL_SHA=m.sha(self.package['shell']);selector.SHELL_BYTES=len(self.package['shell'])

    def components(self,sources):
        modules=self.actual_components(sources);self.modules=modules
        c=modules['capture'];original=importlib.import_module('src.data.physical_replay_capture_e138')
        c.PATTERN=copy.deepcopy(self.pattern);c.INPUT_PINS=copy.deepcopy(original.INPUT_PINS);c.TREE_PIN=copy.deepcopy(original.TREE_PIN)
        modules['bootstrap'].E112_SHA256=m.sha(self.package['e112'])
        old_bind=modules['binding'].bind
        def bind(*args):
            result=old_bind(*args);self.selector_fixture(result['selector'])
            stil=result['stil'];stil.TREE_FILES=c.TREE_PIN['files'];stil.TREE_BYTES=c.TREE_PIN['bytes']
            names=dict(pattern='tester.stil',library='cells.lib',F_basic='F.basic')
            stil.FIXED=tuple(dict(path=m.ROOT+'/inputs/'+names[row['role']],bytes=row['bytes'],sha256=row['sha256'])
                for row in [self.captured['pattern']]+self.captured['inputs'])
            return result
        modules['binding'].bind=bind
        old_load=modules['collector']._load
        def load(raw,name):
            result=old_load(raw,name)
            if name=='selector':self.selector_fixture(result)
            else:result.sample_path=lambda path,tick,budget:self.sample_path(path,tick,budget)
            return result
        modules['collector']._load=load
        old_tracked=modules['roots'].tracked_services
        def tracked(package):
            session=old_tracked(package);services=session.services;self.service=services
            old_storage=services._storage
            def storage(end):
                persist,monitor=old_storage(end);monitor.sample=lambda:dict(sampled_named_bytes=123)
                return persist,monitor
            services._storage=storage
            def copy_file(files,source,target,size,digest,expected_identity):
                files.tick();self.assertEqual(m.sha(self.fs.body[source]),digest)
                self.assertEqual(modules['roots'].identity(self.fs.info[source]),expected_identity)
                fd=files.directory(target.rsplit('/',1)[0]);m.os.close(fd)
                self.fs.add(target,raw=self.fs.body[source])
            services.Files.copy=copy_file
            def tree_copy(files,source,pin):
                for row in pin['rows']:
                    path=m.ROOT+'/tsdb'+('/'+row['relative'] if row['relative'] else '')
                    if row['kind']=='directory':m.os.close(files.directory(path,True))
                    else:self.fs.add(path,raw=self.fs.body[source+'/'+row['relative']])
            services._tree_copy=tree_copy
            services._observer=self.observe
            return session
        modules['roots'].tracked_services=tracked
        return modules

    def sample_path(self,path,tick,budget):
        tick();return copy.deepcopy(self.engine_rows[path])

    def observe(self,launch,end,domain,budget,on_spawn,scratch):
        self.calls.append(launch['argv']);self.assertLessEqual(end,min(4390.,self.now+1800))
        on_spawn(dict(pid=54321,startticks=10,uid=1047));scratch.sample()
        return dict(output=b'SYNTHETIC_TOOL_OUTPUT',failure=None,cleaned=True,cleanup_error=None,
            returncode=0,launch_attempted=True)

    def run_flow(self):
        old_private=m._private
        def private(raw,name):
            result=old_private(raw,name)
            if name=='finite_sampler':result.sample_path=self.sample_path
            return result
        with mock.patch.object(m,'_private',side_effect=private):
            return m.execute(self.package,self.sources,2000.)

    def test_native_admitted_full_flow_actual_component_apis(self):
        result=self.run_flow()
        self.assertIsNotNone(result['owned_root'],result)
        self.assertEqual(result['owned_root']['schema'],'e138-final-registered-root-receipt-v1')
        self.assertEqual(result['worker_response']['status'],'OBSERVED_PENDING_SCIENTIFIC_AUDIT')
        self.assertEqual(len(self.calls),5) # bootstrap + three real selfcheck calls + tool mock
        self.assertEqual(result['worker_response']['instance_sha256'],result['owned_root']['input_bindings']['worker_spec_sha256'])
        self.assertNotIn(b'SENTINEL',m.canonical(result))
        self.assertTrue(any(path.endswith('stdout.log') for path in self.writes))
        self.assertEqual(self.service.storage.__origin_source_sha256__,self.modules['runtime'].ORIGIN_STORAGE_SHA256)

    def test_all_default_freezes_and_old_grant_deny_before_compile_or_callbacks(self):
        for key in ('AUTH_SHA256','PROPOSAL_SHA256','POLICY_SHA256','PAYLOAD_SHA256','FROZEN_INPUT_SHA256','FROZEN_SOURCE_SHA256'):
            with mock.patch.object(m,key,None),mock.patch.object(m,'_components') as compile_sources,mock.patch.object(m.time,'monotonic') as now:
                result=m.execute(self.package,self.sources,2000.)
            compile_sources.assert_not_called();now.assert_not_called()
            self.assertIsNone(result['owned_root'])
        with mock.patch.object(m,'AUTH_SHA256',m.contract.OLD_AUTH_SHA256),mock.patch.object(m,'_components') as load:
            result=m.execute(self.package,self.sources,2000.)
        load.assert_not_called();self.assertFalse(result['worker_response']['attempt_consumed'])
        self.assertEqual(self.calls,[]);self.assertEqual(self.writes,[])

    def test_source_body_drift_and_input_pin_drift_before_compile_or_clock(self):
        bad=dict(self.sources);bad[m.ORIGINS['storage']]+=b' '
        with mock.patch.object(m,'_components') as load,mock.patch.object(m.time,'monotonic') as now:
            result=m.execute(self.package,bad,2000.)
            package=dict(self.package);package['role1_response']+=b' '
            result2=m.execute(package,self.sources,2000.)
        load.assert_not_called();now.assert_not_called()
        for value in (result,result2):self.assertIsNone(value['owned_root'])
        self.assertEqual(self.calls,[]);self.assertEqual(self.writes,[])

    def test_inactive_candidate_never_substitutes_active_assembler_self_pin(self):
        sources=dict(self.sources);sources.pop('physical_e138_batch_assembler')
        manifest={name:m.sha(raw) for name,raw in sources.items()};order=tuple(sorted(manifest))
        frozen=dict(self.frozen,source_sha256=manifest,source_order=order)
        with mock.patch.object(m,'FROZEN_SOURCE_SHA256',manifest),mock.patch.object(m.contract,'FROZEN',frozen),mock.patch.object(m.contract,'LOADED_SOURCE_ORDER',order),mock.patch.object(m,'_components') as load:
            result=m.execute(self.package,sources,2000.)
        load.assert_not_called();self.assertIsNone(result['owned_root'])
        self.assertEqual(self.calls,[]);self.assertEqual(self.writes,[])

    def test_fresh_source_drift_before_first_write(self):
        path=self.pattern['path'];self.fs.body[path]=b'x'*len(self.fs.body[path])
        result=self.run_flow()
        self.assertIsNone(result['owned_root']);self.assertEqual(self.writes,[])
        self.assertEqual(result['worker_response']['launch_debit'],0)

    def test_existing_root_cannot_create_sidecar_or_resume(self):
        self.fs.add(m.ROOT,directory=True)
        result=self.run_flow()
        self.assertIsNone(result['owned_root']);self.assertEqual(self.writes,[])
        self.assertEqual(result['worker_response']['diagnostic']['stage_attempted'],'INITIAL_INTENT')

    def test_memory_and_boot_bounds_stop_before_bootstrap(self):
        with mock.patch.object(Domain,'peak',536870913):result=self.run_flow()
        self.assertIsNone(result['owned_root']);self.assertEqual(self.calls,[])
        with mock.patch.object(m,'_USED',False),mock.patch.object(m.process,'_boot_id',return_value='wrong'):
            result=self.run_flow()
        self.assertIsNone(result['owned_root']);self.assertEqual(self.calls,[])

    def test_original_role2_deadline_and_clock_skew_stop_before_bootstrap(self):
        self.now=4390.;self.utc=UTC+3390
        result=self.run_flow();self.assertIsNone(result['owned_root']);self.assertEqual(self.calls,[])
        self.now=2001.;self.utc=UTC+2000
        with mock.patch.object(m,'_USED',False):result=self.run_flow()
        self.assertIsNone(result['owned_root']);self.assertEqual(self.calls,[])

    def test_after_observer_cleanup_reserve_can_publish_but_not_hard_end(self):
        original=self.observe
        def observe(*args):
            result=original(*args);self.now=4395.;self.utc=UTC+3395;return result
        self.observe=observe
        result=self.run_flow();self.assertIsNotNone(result['owned_root'],result)
        self.assertEqual(result['owned_root']['final_snapshot_monotonic'],4395.)

    def test_after_observer_hard_deadline_never_emits_receipt(self):
        original=self.observe
        def observe(*args):
            result=original(*args);self.now=4400.;self.utc=UTC+3400;return result
        self.observe=observe
        result=self.run_flow();self.assertIsNone(result['owned_root'])
        self.assertEqual(result['worker_response']['launch_debit'],1)
        self.assertIsNotNone(result['worker_response']['instance_sha256'])
        self.assertFalse(any(path.endswith('/stdout.log') for path in self.writes))

    def test_installed_selection_drift_before_debit(self):
        original=self.sample_path;counts=[0]
        def sample(path,tick,budget):
            counts[0]+=1
            if counts[0]>len(self.engine_rows):return dict(state='MISSING')
            return original(path,tick,budget)
        self.sample_path=sample
        result=self.run_flow();self.assertIsNone(result['owned_root'])
        self.assertEqual(result['worker_response']['launch_debit'],0)
        self.assertEqual(len(self.calls),4)

    def test_failed_launch_intent_keeps_debit_and_instance_without_observer(self):
        original=self.publish
        def publish(fd,name,raw):
            if name=='launch_intent.json':raise OSError('SENTINEL_PRIVATE')
            return original(fd,name,raw)
        self.publish=publish
        # Existing bound backend uses an explicit new side effect for this fault.
        from src.data import prospective_acceptance_materializer_v1 as anchored
        with mock.patch.object(anchored,'_publish',side_effect=publish):result=self.run_flow()
        self.assertEqual(result['worker_response']['launch_debit'],1)
        self.assertIsNotNone(result['worker_response']['instance_sha256'])
        self.assertEqual(len(self.calls),4)
        self.assertNotIn(b'SENTINEL',m.canonical(result))

    def test_imported_authority_and_factory_globals_unchanged(self):
        modules=[importlib.import_module('src.data.'+name) for name in m.COMPONENTS.values()]
        keys=('ROOT','AUTH_SHA','AUTH_SHA256','PROPOSAL_SHA','PROPOSAL_SHA256','FREEZE','FACTORY_FREEZE','_USED','_FACTORY_USED')
        before=[{key:copy.deepcopy(vars(module)[key]) for key in keys if key in vars(module)} for module in modules]
        old=REPO/'src/data/physical_e137_batch_execution.py';digest=m.sha(old.read_bytes())
        result=self.run_flow();self.assertIsNotNone(result['owned_root'])
        after=[{key:copy.deepcopy(vars(module)[key]) for key in keys if key in vars(module)} for module in modules]
        self.assertEqual(before,after);self.assertEqual(digest,m.sha(old.read_bytes()))

    def test_hostile_observer_exception_keeps_consumed_attempt_without_leak(self):
        class Hostile(ValueError):
            def __str__(self):raise AssertionError('must not format')
            def __repr__(self):raise AssertionError('must not represent')
        def observe(*args):raise Hostile('SENTINEL_PRIVATE')
        self.observe=observe
        result=self.run_flow();response=result['worker_response']
        self.assertTrue(response['attempt_consumed'])
        self.assertEqual(response['launch_debit'],1);self.assertIsNotNone(response['instance_sha256'])
        self.assertIsNone(result['owned_root']);self.assertNotIn(b'SENTINEL',m.canonical(result))

    def test_single_use_refuses_second_flow_without_new_supervision_or_writes(self):
        self.run_flow();counts=(len(self.calls),len(self.writes))
        result=self.run_flow()
        self.assertEqual(counts,(len(self.calls),len(self.writes)))
        self.assertIsNone(result['owned_root'])

    def test_unknown_cleanup_never_qualifies_root(self):
        original=self.observe
        def observe(*args):
            result=original(*args);result['cleaned']=False;return result
        self.observe=observe
        result=self.run_flow();self.assertIsNone(result['owned_root'])
        self.assertEqual(result['worker_response']['launch_debit'],1)
        self.assertTrue(any(path.endswith('stdout.log') for path in self.writes))

    def test_role2_source_recheck_does_not_invent_a_new60second_clock(self):
        actual=self.components;delayed=[False]
        def components(sources):
            modules=actual(sources);reader=modules['capture'].source
            original=reader.read_file
            def read_file(*args):
                if not delayed[0]:
                    delayed[0]=True;self.now+=61;self.utc+=61
                return original(*args)
            self.patch(reader,'read_file',side_effect=read_file)
            return modules
        with mock.patch.object(m,'_components',side_effect=components):result=self.run_flow()
        self.assertIsNotNone(result['owned_root'],result)

    def test_real_bootstrap_internal_failure_survives_outer_frame_without_secrets(self):
        original=self.supervise
        def supervise(*args,**kwargs):
            result=original(*args,**kwargs);result['failure']='CASE_TIMEOUT';return result
        with mock.patch.object(m.direct.base,'supervise',side_effect=supervise):result=self.run_flow()
        self.assertEqual(set(result),{'role','worker_response','owned_root','cleanup_observation','execution_ready'})
        response=result['worker_response'];failure=response['bootstrap_failure']
        self.assertEqual(failure['schema'],'e138-private-runtime-bootstrap-v1')
        self.assertEqual(failure['status'],'FAILED')
        self.assertEqual(failure['stage_attempted'],'OBSERVATION_CHECK')
        self.assertEqual(failure['error_code'],'E138_BOOTSTRAP_OBSERVATION_CHECK_FAILED')
        self.assertEqual(failure['reviewed_literal_code'],'CASE_TIMEOUT')
        self.assertTrue(failure['output_metadata_measured']);self.assertGreater(failure['output_bytes'],0)
        self.assertEqual(failure['bootstrap_children'],1)
        self.assertEqual(response['diagnostic']['stage_attempted'],'BOOTSTRAP')
        self.assertEqual(response['launch_debit'],0);self.assertIsNone(response['instance_sha256'])
        self.assertEqual(len(self.calls),1);self.assertEqual(self.writes,[])
        self.assertNotIn(b'SENTINEL',m.canonical(result));self.assertIsNone(result['owned_root'])
        calls=len(self.calls);self.run_flow();self.assertEqual(len(self.calls),calls)

    def test_forged_bootstrap_metadata_never_escapes_projection(self):
        valid=dict(schema='e138-private-runtime-bootstrap-v1',status='FAILED',stage_attempted='ADMISSION',
            error_code='E138_BOOTSTRAP_ADMISSION_FAILED',reviewed_literal_code=None,values_disclosed=False,
            bootstrap_children=0,output_bytes=0,output_sha256=m.sha(b''),output_metadata_measured=False,execution_ready=False)
        changes=(dict(stage_attempted='SENTINEL_PRIVATE'),dict(error_code='SENTINEL_PRIVATE'),
            dict(reviewed_literal_code='SENTINEL_PRIVATE'),dict(env='SENTINEL_PRIVATE'),dict(output_bytes=True),
            dict(bootstrap_children=2),dict(output_sha256='SENTINEL_PRIVATE'),dict(values_disclosed=True),
            dict(output_bytes=1),dict(execution_ready=True))
        original=self.components
        for change in changes:
            metadata=dict(valid,**change)
            def components(sources):
                modules=original(sources)
                def bootstrap(package,domain,tick,frozen,evidence):
                    evidence.update(metadata)
                    raise ValueError('SENTINEL_PRIVATE')
                modules['bootstrap'].bootstrap=bootstrap
                return modules
            with mock.patch.object(m,'_USED',False),mock.patch.object(m,'_components',side_effect=components):result=self.run_flow()
            self.assertIsNone(result['worker_response']['bootstrap_failure'])
            self.assertEqual(result['worker_response']['diagnostic']['stage_attempted'],'BOOTSTRAP')
            self.assertNotIn(b'SENTINEL',m.canonical(result))
        self.assertEqual(self.calls,[]);self.assertEqual(self.writes,[])

    def test_bootstrap_projection_closed_for_all_reviewed_stages(self):
        for stage in m._BOOTSTRAP_STAGES:
            evidence=dict(schema='e138-private-runtime-bootstrap-v1',status='FAILED',stage_attempted=stage,
                error_code='E138_BOOTSTRAP_'+stage+'_FAILED',reviewed_literal_code=None,values_disclosed=False,
                bootstrap_children=0,output_bytes=0,output_sha256=m.sha(b''),output_metadata_measured=False,execution_ready=False)
            self.assertEqual(m._bootstrap_failure(evidence),evidence)
            evidence['error_code']='E138_BOOTSTRAP_UNKNOWN_FAILED'
            self.assertIsNone(m._bootstrap_failure(evidence))

    def test_collector_known_failure_code_kept_unknown_secret_redacted(self):
        original=self.components
        for code in ('E138_ENGINE_DEADLINE','E138_ENGINE_DEADLINE:SENTINEL_PRIVATE'):
            def components(sources):
                modules=original(sources)
                def fail(*args,**kwargs):raise ValueError(code)
                modules['collector'].collect=fail
                return modules
            with mock.patch.object(m,'_USED',False),mock.patch.object(m,'_components',side_effect=components):
                result=self.run_flow()
            projected=result['worker_response']['component_failure']
            self.assertEqual(projected,dict(component='ENGINE_COLLECTION',code=code) if code=='E138_ENGINE_DEADLINE' else None)
            self.assertNotIn(b'SENTINEL',m.canonical(result))

    def test_root_exact_public_failure_type_keeps_only_known_code(self):
        original=self.components
        def components(sources):
            modules=original(sources);roots=modules['roots'];factory=roots.tracked_services
            def tracked(package):
                session=factory(package)
                def emit(*args,**kwargs):raise roots.RootReceiptFailure('ROOT_RECEIPT_BIRTH_IDENTITY_CHANGED')
                session.emit=emit;return session
            roots.tracked_services=tracked;return modules
        with mock.patch.object(m,'_components',side_effect=components):result=self.run_flow()
        self.assertEqual(result['worker_response']['component_failure'],dict(component='ROOT_RECEIPT',code='ROOT_RECEIPT_BIRTH_IDENTITY_CHANGED'))
        self.assertIsNone(result['owned_root'])


def stage_failure_test(stage):
    def test(self):
        seen=[];original=m.diagnostics.DiagnosticState.checkpoint
        def checkpoint(state,name):
            original(state,name);seen.append(name)
            if name==stage:raise ValueError('SENTINEL_PRIVATE_UNKNOWN_ERROR')
        with mock.patch.object(m.diagnostics.DiagnosticState,'checkpoint',checkpoint):result=self.run_flow()
        self.assertEqual(seen[-1],stage)
        response=result['worker_response'];diagnostic=response['diagnostic']
        self.assertEqual(diagnostic['stage_attempted'],stage)
        self.assertEqual(response['launch_debit'],int(m.diagnostics.STAGES.index(stage)>m.diagnostics.STAGES.index('LAUNCH_DEBIT')))
        self.assertEqual(response['instance_sha256'] is not None,m.diagnostics.STAGES.index(stage)>=m.diagnostics.STAGES.index('ROOT_SERVICES'))
        self.assertNotIn(b'SENTINEL',m.canonical(result));self.assertIsNone(result['owned_root'])
        self.assertFalse(diagnostic['retry_allowed']);self.assertFalse(diagnostic['evidence_durability_verified'])
    return test


for _stage in m.diagnostics.STAGES[1:]:
    setattr(NativeFlowTests,'test_stop_at_'+_stage.lower(),stage_failure_test(_stage))


if __name__=='__main__':unittest.main()
