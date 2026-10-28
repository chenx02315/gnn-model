"""Mocked integration and inert bytecode only, never launch or deploy anything."""
import ast
import base64
import datetime
import copy
import stat
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import physical_f_replay_execution_e137 as m

REPO = Path(__file__).resolve().parents[1]
LEGACY_BYTES = (REPO/'src/data/physical_f_replay_execution_e135.py').read_bytes()
BOOT = '3ebeb9bb-410c-476c-a000-5c625f590473'


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def clock_value():
    start = datetime.datetime(2026,10,28,tzinfo=datetime.timezone.utc)
    return dict(schema=m.CLOCK_SCHEMA,authorization_sha256='1'*64,proposal_sha256=m.capture.PROPOSAL_SHA,
        reader_payload_sha256='2'*64,initial_response_sha256='3'*64,start_file_sha256='4'*64,boot_id=BOOT,
        remote_start_monotonic=1000.,remote_deadline_monotonic=4600.,remote_clock_sample_monotonic=1001.,
        remote_utc_sample=(start+datetime.timedelta(seconds=1)).isoformat(timespec='microseconds'),
        local_utc_start=start.isoformat(timespec='microseconds'),
        local_utc_deadline=(start+datetime.timedelta(seconds=3600)).isoformat(timespec='microseconds'),
        local_monotonic_start=2000.,local_monotonic_deadline=5600.,local_clock_domain=dict(host='local',clock='system-wide'))


class PureTests(unittest.TestCase):
    def test_default_rejects_before_all_io_time_proc_and_does_not_debit(self):
        with mock.patch.object(m.time,'monotonic') as clock,mock.patch.object(m.process,'_boot_id') as boot,\
                mock.patch.object(m.io,'_directory') as directory,mock.patch.object(m.direct,'Descendants') as domain:
            with self.assertRaisesRegex(ValueError,'E137_UNFROZEN_AUTH_SPEC_CLOCK_CLOSURE'):
                m.worker({})
        clock.assert_not_called()
        boot.assert_not_called()
        directory.assert_not_called()
        domain.assert_not_called()
        self.assertFalse(m._USED)
        self.assertIsNone(m.AUTH_SHA)
        self.assertIsNone(m.REVIEWED_SPEC_SHA256)
        self.assertIsNone(m.INITIAL_CLOCK_SHA256)
        self.assertIsNone(m.EXECUTION_CLOSURE_SHA256)
        self.assertIsNone(m.DEPENDENCY_VALIDATOR_SHA256)
        self.assertIsNone(m.DEPENDENCY_VALIDATOR)
        with mock.patch.object(m,'AUTH_SHA','0'*64),mock.patch.object(m,'REVIEWED_SPEC_SHA256','0'*64),\
                mock.patch.object(m,'INITIAL_CLOCK_SHA256','0'*64),mock.patch.object(m,'EXECUTION_CLOSURE_SHA256','0'*64),\
                mock.patch.object(m.time,'monotonic') as clock:
            with self.assertRaisesRegex(ValueError,'E137_UNFROZEN_AUTH_SPEC_CLOCK_CLOSURE_DEPENDENCIES'):
                m.worker({})
        clock.assert_not_called()

    def test_private_namespace_class_methods_and_storage_original_end(self):
        before = (m.legacy.ROOT,m.legacy.AUTH_SHA256,m.legacy._USED,m.legacy.storage.ROOT,m.legacy.storage.END)
        with mock.patch.object(m.io,'_directory') as directory:
            services = m.private_services(LEGACY_BYTES)
            persist,monitor = services._storage(4600.)
        directory.assert_not_called()
        self.assertIsNone(services.worker)
        self.assertIsNone(services.package_clock)
        self.assertEqual(services.ROOT,m.ROOT)
        self.assertNotEqual(services.ROOT,m.legacy.ROOT)
        for name in ('__init__','directory','publish','copy'):
            self.assertIs(getattr(services.Files,name).__globals__,services.__dict__)
            self.assertEqual(getattr(services.Files,name).__globals__['ROOT'],m.ROOT)
        self.assertEqual(persist.__globals__['END'],4600.)
        self.assertEqual(persist.__globals__['SIDECAR'],m.ROOT+'.initial_intent.json')
        self.assertEqual(type(monitor).sample.__globals__['END'],4600.)
        self.assertEqual(type(monitor).sample.__globals__['ROOT'],m.ROOT)
        self.assertEqual(type(monitor).__init__.__globals__['ROOT'],m.ROOT)
        self.assertEqual(before,(m.legacy.ROOT,m.legacy.AUTH_SHA256,m.legacy._USED,m.legacy.storage.ROOT,m.legacy.storage.END))
        with self.assertRaisesRegex(ValueError,'E137_PRIVATE_SOURCE_PIN'):
            m.private_services(LEGACY_BYTES+b' ')

    def test_new_first_call_clock_no_old_schema_no_reset_no_io(self):
        value = clock_value()
        raw = m.canonical(value)
        with mock.patch.object(m,'AUTH_SHA','1'*64),mock.patch.object(m,'INITIAL_CLOCK_SHA256',m.sha(raw)),\
                mock.patch.object(m.process,'_boot_id') as boot,mock.patch.object(m.time,'time') as now:
            parsed = m.package_clock(raw)
        boot.assert_not_called()
        now.assert_not_called()
        self.assertEqual(parsed['monotonic_end'],4600.)
        for key,bad in [('schema','physical-f-replay-package-clock-e135-v1'),('remote_deadline_monotonic',4700.),
                ('local_monotonic_deadline',5700.),('authorization_sha256','5'*64),('proposal_sha256','5'*64),
                ('remote_clock_sample_monotonic',1060.),('local_clock_domain',{})]:
            changed = m.canonical(dict(value,**{key:bad}))
            with mock.patch.object(m,'AUTH_SHA','1'*64),mock.patch.object(m,'INITIAL_CLOCK_SHA256',m.sha(changed)):
                with self.assertRaises(ValueError):
                    m.package_clock(changed)

    def test_actual_r2_recipe_two_artifacts_pure_and_helper_new_root(self):
        # Already-local frozen E128 snapshot, never an A read or tool launch.
        raw = (REPO.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes()
        self.assertEqual(m.sha(raw),m.legacy.evidence.E128_SHA)
        rows = m.decode(raw)['files']
        tcl = base64.b64decode(next(r for r in rows if r['sha256'] == m.legacy.BASE_TCL_SHA256)['body_base64'])
        result = m.recipe.build_candidate(tcl,m.legacy.EXPECTED_INIT.encode('ascii'))
        self.assertEqual(m.sha(result['body']),result['sha256'])
        self.assertEqual(m.sha(result['baseline_expectations_body']),result['baseline_expectations_sha256'])
        self.assertNotIn(m.legacy.ROOT.encode('ascii'),result['body'])
        self.assertNotIn(m.legacy.ROOT.encode('ascii'),result['baseline_expectations_body'])
        self.assertIn(('source '+m.ROOT+'/code/expected_baseline.tcl').encode('ascii'),result['body'])
        self.assertIn(b'simulate_patterns -source external -store_patterns none',result['body'])
        self.assertEqual(result['body'].count(b'report_patterns -external'),2)

    def test_launch_new_root_hash_and_not_caller_authority(self):
        launch = dict(schema=m.legacy.launch_base.SCHEMA,argv=[m.legacy.launch_base.recipe.identities.LAUNCHER,
            '-shell','-license_wait','5','-log',m.ROOT+'/tool.log','-dofile',m.ROOT+'/code/replay.tcl'],
            cwd=m.ROOT+'/work',env=dict(PATH='/usr/bin',HOME=m.ROOT+'/work',TMPDIR=m.ROOT+'/work',LANG='C',LC_ALL='C'),
            effective_envelope_sha256='0'*64,environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
        launch['environment_sha256'] = m.sha(m.canonical(launch['env']))
        launch['launch_spec_sha256'] = m.sha(m.canonical(launch))
        m.validate_launch(launch)
        with self.assertRaisesRegex(ValueError,'E137_LAUNCH_NOT_AUTHORITY'):
            m.validate_launch(dict(launch,execution_authorized=True))
        changed = dict(launch,cwd=m.legacy.ROOT+'/work')
        with self.assertRaisesRegex(ValueError,'E137_FIXED_LAUNCH'):
            m.validate_launch(changed)

    def test_ast36_inert_import_source_hash_handoff(self):
        raw = Path(m.__file__).read_bytes()
        ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch.object(m.time,'monotonic') as clock:
            namespace = dict(__package__='src.data')
            exec(compile(raw,'<inert-e137-worker>','exec'),namespace)
        opened.assert_not_called()
        clock.assert_not_called()
        self.assertIsNone(namespace['AUTH_SHA'])
        for name,pin in m.SOURCE_PINS.items():
            self.assertEqual(m.sha((REPO/'src/data'/(name+'.py')).read_bytes()),pin)

    def test_execution_closure_hash_uses_devnull_stream_not_resident_body(self):
        info = SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_nlink=1,st_uid=0,
            st_size=134217728,st_mtime_ns=1,st_ctime_ns=1)
        item = dict(path='/cad/mentor/tessent2021_2/bin/SYNTHETIC_ENGINE',bytes=info.st_size,sha256='0'*64,
            identity=m.capture.source.identity(info))
        def reader(fd,name,budget,sink,**bounds):
            self.assertEqual(sink,2002)
            self.assertEqual(bounds['expected_bytes'],134217728)
            return None,item['bytes'],item['sha256']
        read = mock.Mock(side_effect=reader)
        services = SimpleNamespace(_stream_io=mock.Mock(return_value={'_read_at':read}))
        parent = SimpleNamespace(**dict(m.capture.source.identity(info),st_mode=stat.S_IFDIR|0o755,st_nlink=2,st_ino=1))
        with mock.patch.object(m.io,'_directory',side_effect=[2001,2003]),mock.patch.object(m.os,'stat',return_value=info),\
                mock.patch.object(m.os,'fstat',return_value=parent),\
                mock.patch.object(m.os,'open',return_value=2002) as opened,mock.patch.object(m.os,'close') as closed:
            m._closure_recheck([item],services,mock.Mock())
        opened.assert_called_once_with('/dev/null',m.os.O_WRONLY)
        self.assertEqual(read.call_count,1)
        self.assertEqual([c.args[0] for c in closed.call_args_list],[2002,2003,2001])

    def test_engine_parent_path_swapped_during_hash_rejected_and_fds_closed(self):
        info = SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_nlink=1,st_uid=0,
            st_size=3,st_mtime_ns=1,st_ctime_ns=1)
        parent_info = dict(m.capture.source.identity(info),st_mode=stat.S_IFDIR|0o755,st_nlink=2,st_ino=10)
        item = dict(path='/cad/mentor/tessent2021_2/bin/SYNTHETIC_ENGINE',bytes=3,sha256='0'*64,
            identity=m.capture.source.identity(info))
        for swapped_path in (True,False):
            changed = [False]
            def read(fd,name,budget,sink,**bounds):
                self.assertEqual(sink,2002)
                changed[0] = True  # Path now resolves to another directory, held fd remains old.
                return None,3,item['sha256']
            def fstat(fd):
                current = dict(parent_info)
                if changed[0] and (fd == 2003 if swapped_path else fd == 2001):
                    current['st_ino' if swapped_path else 'st_ctime_ns'] = 999
                return SimpleNamespace(**current)
            services = SimpleNamespace(_stream_io=mock.Mock(return_value={'_read_at':read}))
            with mock.patch.object(m.io,'_directory',side_effect=[2001,2003]) as directory,\
                    mock.patch.object(m.os,'stat',return_value=info),mock.patch.object(m.os,'fstat',side_effect=fstat),\
                    mock.patch.object(m.os,'open',return_value=2002),mock.patch.object(m.os,'close') as close:
                code = 'E137_ENGINE_PARENT_REPLACED' if swapped_path else 'E137_ENGINE_HELD_PARENT_CHANGED'
                with self.assertRaisesRegex(ValueError,code):
                    m._closure_recheck([item],services,mock.Mock())
            self.assertEqual(directory.call_count,2 if swapped_path else 1)
            self.assertEqual([c.args[0] for c in close.call_args_list],
                [2002,2003,2001] if swapped_path else [2002,2001])

    def test_dependency_capability_is_missing_not_a_capture_bool(self):
        observed = dict(pattern=dict(role='pattern',bytes=3,sha256='1'*64),inputs=[dict(role=role,bytes=2,sha256='2'*64)
            for role in ('library','F_basic')],tree=dict(rows=[dict(kind='directory',relative=''),
                dict(kind='file',relative='only/member',bytes=1,sha256='3'*64)]))
        with self.assertRaisesRegex(ValueError,'E137_REVIEWED_DEPENDENCY_VERIFIER_MISSING'):
            m._dependencies(observed,mock.Mock())
        pin = '4'*64
        def synthetic_validator(pattern,allowed,tick):
            self.assertEqual(pattern,m.ROOT+'/inputs/tester.stil')
            self.assertEqual(len(allowed),4)
            self.assertTrue(all(r['path'].startswith(m.ROOT+'/') for r in allowed))
            self.assertEqual([r['path'] for r in allowed if '/tsdb/' in r['path']], [m.ROOT+'/tsdb/only/member'])
            return dict(status='PASS',validator_source_sha256=pin,pattern_sha256='1'*64,
                exact_allowlist_sha256=m.sha(m.canonical(allowed)))
        synthetic_validator.__source_sha256__ = pin
        with mock.patch.object(m,'DEPENDENCY_VALIDATOR',synthetic_validator),mock.patch.object(m,'DEPENDENCY_VALIDATOR_SHA256',pin):
            self.assertEqual(m._dependencies(observed,mock.Mock())['status'],'PASS')


class SpecTests(unittest.TestCase):
    def setUp(self):
        proposal = (REPO/'contracts/physical_f_clean_replay_proposal_e137_v1.json').read_bytes()
        auth = m.canonical(dict(schema='physical-f-clean-replay-authorization-e137-v1',approval_source='explicit_user_reply',
            user_reply='\u6279\u51c6 E137 \u6574\u5305',user_authorization_received=True,
            proposal_sha256=m.capture.PROPOSAL_SHA,approved_scope=m.decode(proposal)['scope_if_granted']))
        self.authority_sha = m.sha(auth)
        prior = m.decode((REPO.parent/'runtime_training_staging_20260928/v6_e128_failure_readback_20261027_r1/stdout.json').read_bytes())
        tcl = base64.b64decode(next(r for r in prior['files'] if r['sha256'] == m.legacy.BASE_TCL_SHA256)['body_base64'])
        helper = m.legacy.EXPECTED_INIT.encode('ascii')
        candidate = m.recipe.build_candidate(tcl,helper)
        clock = clock_value()
        clock.update(authorization_sha256=self.authority_sha,initial_response_sha256=m.sha(b'{}'))
        launch = dict(schema=m.legacy.launch_base.SCHEMA,argv=[m.legacy.launch_base.recipe.identities.LAUNCHER,
            '-shell','-license_wait','5','-log',m.ROOT+'/tool.log','-dofile',m.ROOT+'/code/replay.tcl'],cwd=m.ROOT+'/work',
            env=dict(PATH='/usr/bin',HOME=m.ROOT+'/work',TMPDIR=m.ROOT+'/work',LANG='C',LC_ALL='C'),
            effective_envelope_sha256='0'*64,environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
        launch['environment_sha256'] = m.sha(m.canonical(launch['env']))
        launch['launch_spec_sha256'] = m.sha(m.canonical(launch))
        closure = [dict(path=path,bytes=1,sha256='f'*64,identity=dict(st_dev=1,st_ino=i+1,st_mode=stat.S_IFREG|0o755,
            st_nlink=1,st_uid=0,st_size=1,st_mtime_ns=1,st_ctime_ns=1)) for i,path in enumerate(
            [launch['argv'][0],'/cad/mentor/tessent2021_2/bin/SYNTHETIC_ENGINE_NOT_AUTHENTICATED'])]
        self.spec = dict(schema=m.SCHEMA,authority_base64=encoded(auth),proposal_base64=encoded(proposal),
            package_clock_base64=encoded(m.canonical(clock)),capture_base64=encoded(b'{}'),
            legacy_runtime_source_base64=encoded(LEGACY_BYTES),incremental_base64=encoded(tcl),parent_helper_base64=encoded(helper),
            code_base64={'replay.tcl':encoded(candidate['body']),'expected_baseline.tcl':encoded(candidate['baseline_expectations_body'])},
            launch=launch,execution_closure=closure)

    def validate(self,spec,missing_source=False):
        with ExitStack() as stack:
            for patch in (mock.patch.object(m,'AUTH_SHA',self.authority_sha),mock.patch.object(m.capture,'AUTH_SHA',self.authority_sha),
                    mock.patch.object(m,'REVIEWED_SPEC_SHA256',m.sha(m.canonical(spec))),
                    mock.patch.object(m,'INITIAL_CLOCK_SHA256',m.sha(base64.b64decode(spec['package_clock_base64']))),
                    mock.patch.object(m,'EXECUTION_CLOSURE_SHA256',m.sha(m.canonical(spec['execution_closure']))),
                    mock.patch.object(m,'DEPENDENCY_VALIDATOR_SHA256','9'*64),
                    mock.patch.object(m.capture,'validate_receipt',return_value={'synthetic_validation_only':True})):
                stack.enter_context(patch)
            validator = mock.Mock()
            validator.__source_sha256__ = '9'*64
            stack.enter_context(mock.patch.object(m,'DEPENDENCY_VALIDATOR',validator))
            if not missing_source:
                for module in (m.legacy,m.recipe,m.capture,m.legacy.storage,m.process,m.io,m.direct):
                    stack.enter_context(mock.patch.object(module,'__source_sha256__',m.SOURCE_PINS[module.__name__.rsplit('.',1)[1]],create=True))
            return m.check_spec(spec)

    def test_pure_exact_spec_recipe_and_source_loader_join(self):
        with mock.patch.object(m.time,'monotonic') as clock,mock.patch.object(m.io,'_directory') as directory:
            result = self.validate(self.spec)
        clock.assert_not_called()
        directory.assert_not_called()
        self.assertEqual(result['runtime_source'],LEGACY_BYTES)
        self.assertEqual(result['capture'],{'synthetic_validation_only':True})
        self.assertIn(m.ROOT.encode('ascii'),result['code']['expected_baseline.tcl'])
        with self.assertRaisesRegex(ValueError,'E137_VERIFIED_SOURCE_LOADER_REQUIRED'):
            self.validate(self.spec,missing_source=True)

    def test_helper_runtime_capture_engine_scope_and_bool_drift(self):
        changes = [lambda s:s['code_base64'].update({'expected_baseline.tcl':encoded(b'changed helper')}),
            lambda s:s.update(legacy_runtime_source_base64=encoded(LEGACY_BYTES+b' ')),
            lambda s:s.update(capture_base64=encoded(b'{"changed":1}')),
            lambda s:s['execution_closure'][0].update(path='/unapproved/engine'),
            lambda s:s['execution_closure'][0]['identity'].update(st_nlink=2),
            lambda s:s.update(execution_authorized=True)]
        for change in changes:
            changed = copy.deepcopy(self.spec)
            change(changed)
            with self.assertRaises(ValueError):
                self.validate(changed)


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.services = mock.Mock()
        self.files,self.monitor = mock.Mock(),mock.Mock()
        self.files.directory.return_value = 1234  # Mock fd; os.close is mocked.
        self.monitor.sample.return_value = dict(sampled_named_bytes=1024)
        self.services.Files.return_value = self.files
        self.services._storage.return_value = (mock.Mock(),self.monitor)
        self.services.run_selftests.return_value = [dict(case=name,passed=True,cleaned=True,authenticated_claim=True)
            for name in m.legacy.SELFTEST_CASES]
        self.services._observer.return_value = dict(output=b'synthetic supervision output',failure=None,cleaned=True,returncode=0)
        self.domain = mock.Mock(peak=123)
        rows = [dict(role=role,path='/synthetic/'+role,bytes=3,sha256='0'*64,identity={}) for role in ('pattern','library','F_basic')]
        self.prepared = dict(clock=dict(boot_id=BOOT,remote_start_monotonic=1000.,monotonic_end=4600.,utc_end=99999999999.),
            capture=dict(pattern=rows[0],inputs=rows[1:],tree={}),runtime_source=LEGACY_BYTES,
            code={'replay.tcl':b'actual synthetic main','expected_baseline.tcl':b'actual synthetic helper'},
            closure=[],launch=dict(launch_spec_sha256='0'*64))
        for patch in (mock.patch.object(m,'_USED',False),mock.patch.object(m,'check_spec',return_value=self.prepared),
                mock.patch.object(m,'private_services',return_value=self.services),mock.patch.object(m,'_source_recheck'),
                mock.patch.object(m,'_closure_recheck'),mock.patch.object(m,'validate_launch'),
                mock.patch.object(m,'_dependencies',return_value={'status':'SYNTHETIC_INTERFACE_ONLY'}),
                mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
                mock.patch.object(m.os.sys,'platform','linux'),mock.patch.object(m.process,'_boot_id',return_value=BOOT),
                mock.patch.object(m.time,'monotonic',return_value=2000.),mock.patch.object(m.time,'time',return_value=1.),
                mock.patch.object(m.direct,'Descendants',return_value=self.domain),mock.patch.object(m.os,'close'),
                mock.patch.object(m.io,'_publish')):
            patch.start()
            self.addCleanup(patch.stop)

    def test_mocked_three_selfchecks_then_one_tool_original_deadlines(self):
        def observed(*args):
            names = [c.args[0] for c in self.files.publish.call_args_list]
            self.assertIn('launch_intent.json',names)
            self.assertEqual(self.services.run_selftests.call_count,1)
            return dict(output=b'mocked only',failure=None,cleaned=True,returncode=0)
        self.services._observer.side_effect = observed
        value = m.worker({})
        self.assertEqual(value['selfchecks'],3)
        self.assertEqual(value['original_package_deadline'],4600.)
        self.assertEqual(value['connection_deadline'],4400.)
        self.assertEqual(value['session_deadline'],3800.)
        self.services._storage.assert_called_once_with(4600.)
        self.assertEqual(self.services._observer.call_count,1)
        self.assertEqual(m.io._publish.call_count,2)
        self.assertFalse(value['internal_pattern_count_required_positive'])
        self.assertFalse(value['external_pattern_application_verified'])
        self.assertFalse(value['environment_profile_authenticated'])
        self.assertFalse(value['physical_d95_verified'])
        with self.assertRaisesRegex(ValueError,'E137_ONE_WORKER_ZERO_RETRY'):
            m.worker({})

    def test_failed_selfcheck_never_tool_and_memory_storage_stop(self):
        self.services.run_selftests.return_value[0]['passed'] = False
        with self.assertRaisesRegex(ValueError,'E137_THREE_PROCESS_SELFCHECKS'):
            m.worker({})
        self.services._observer.assert_not_called()
        with mock.patch.object(m,'_USED',False):
            self.domain.peak = 536870913
            with self.assertRaisesRegex(ValueError,'E137_SAMPLED_MEMORY_STOP'):
                m.worker({})
        self.services._observer.assert_not_called()
        self.domain.peak = 123
        self.monitor.sample.return_value['sampled_named_bytes'] = 8589934593
        with mock.patch.object(m,'_USED',False):
            with self.assertRaisesRegex(ValueError,'E137_SAMPLED_STORAGE_STOP'):
                m.worker({})

    def test_failed_tool_records_output_before_reject_and_no_retry(self):
        self.services._observer.return_value['failure'] = 'CASE_TIMEOUT'
        with self.assertRaisesRegex(ValueError,'E137_TOOL_OBSERVATION_REJECTED'):
            m.worker({})
        names = [c.args[0] for c in self.files.publish.call_args_list]
        self.assertIn('observation.json',names)
        self.assertIn('stdout.log',names)
        self.assertIn('stdout_ack.json',names)
        self.assertEqual(self.services._observer.call_count,1)
        with self.assertRaisesRegex(ValueError,'E137_ONE_WORKER_ZERO_RETRY'):
            m.worker({})

    def test_changed_boot_or_expired_package_stops_before_filesystem(self):
        with mock.patch.object(m.process,'_boot_id',return_value='different'):
            with self.assertRaisesRegex(ValueError,'E137_ORIGINAL_BOOT'):
                m.worker({})
        self.services.Files.assert_not_called()
        with mock.patch.object(m,'_USED',False),mock.patch.object(m.time,'monotonic',return_value=4600.):
            with self.assertRaisesRegex(ValueError,'E137_ORIGINAL_PACKAGE_EXPIRED'):
                m.worker({})
        self.services.Files.assert_not_called()

    def test_dependency_failure_before_any_selfcheck_or_tool(self):
        with mock.patch.object(m,'_dependencies',side_effect=ValueError('DEPENDENCY_NOT_QUALIFIED')):
            with self.assertRaisesRegex(ValueError,'DEPENDENCY_NOT_QUALIFIED'):
                m.worker({})
        self.services.run_selftests.assert_not_called()
        self.services._observer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
