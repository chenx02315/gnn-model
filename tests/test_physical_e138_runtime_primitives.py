"""Native clock checks and actual private class/function dispatch; no real IO."""
import ast
import copy
import datetime
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_e138_runtime_primitives as m

RAW=(Path(__file__).resolve().parents[1]/'src/data/physical_f_replay_execution_e135.py').read_bytes()
STORAGE_RAW=(Path(__file__).resolve().parents[1]/'src/data/prospective_generation_storage_e118.py').read_bytes()


def clock_value():
    start=datetime.datetime(2026,10,30,tzinfo=datetime.timezone.utc)
    fmt=lambda value:value.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    return dict(schema=m.CLOCK_SCHEMA,authorization_sha256='1'*64,proposal_sha256='2'*64,
        reader_payload_sha256='3'*64,initial_response_sha256='4'*64,start_file_sha256='5'*64,
        boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',root=m.ROOT,phase=m.PHASE,
        remote_start_monotonic=1000.,remote_deadline_monotonic=4600.,remote_clock_sample_monotonic=1001.,
        remote_utc_sample=fmt(start+datetime.timedelta(seconds=1)),local_utc_start=fmt(start),
        local_utc_deadline=fmt(start+datetime.timedelta(seconds=3600)),
        local_monotonic_start=800000.,local_monotonic_deadline=803600.,
        local_clock_domain=dict(host='LOCAL_NOT_A',clock='different-clock'))


class ClockTests(unittest.TestCase):
    def parse(self,value):
        raw=m.canonical(value)
        return m.package_clock(raw,'1'*64,'2'*64,m.sha(raw))

    def test_pure_original_clock_not_compared_to_local_monotonic_domain(self):
        with mock.patch('time.monotonic') as now,mock.patch('time.time') as utc:
            result=self.parse(clock_value())
        now.assert_not_called();utc.assert_not_called()
        self.assertEqual(result['monotonic_end'],4600.)
        self.assertEqual(result['utc_end'],1793322000.)

    def test_default_old_grant_and_hash_drift_deny_before_decode(self):
        with mock.patch.object(m,'decode') as decode:
            for args in ((None,None,None),(m.contract.OLD_AUTH_SHA256,'2'*64,'3'*64)):
                with self.assertRaisesRegex(ValueError,'E138_CLOCK_FREEZE_REQUIRED'):m.package_clock(None,*args)
            with self.assertRaisesRegex(ValueError,'E138_EXACT_CLOCK_BYTES'):
                m.package_clock(b'{}','1'*64,'2'*64,'3'*64)
        decode.assert_not_called()

    def test_old_schema_root_phase_and_extra_clock_fields_rejected(self):
        for change in (dict(schema='physical-f-clean-replay-package-clock-e137-v1'),
                dict(root=m.legacy.ROOT),dict(phase='v6_e137_clean_F_replay_r1'),dict(extra=True)):
            with self.assertRaisesRegex(ValueError,'E138_CLOCK_IDENTITY'):self.parse(dict(clock_value(),**change))

    def test_deadline_reset_bool_nonfinite_and_wrong_utc_format_rejected(self):
        for change in (dict(remote_deadline_monotonic=4601),dict(local_monotonic_deadline=803601),
                dict(remote_start_monotonic=True),dict(remote_clock_sample_monotonic=1060)):
            with self.assertRaises(ValueError):self.parse(dict(clock_value(),**change))
        value=clock_value();value['remote_utc_sample']=value['remote_utc_sample'][:-5]+'+00:00'
        with self.assertRaisesRegex(ValueError,'E138_CLOCK_PY36_UTC_FORMAT'):self.parse(value)
        value=clock_value();value['local_utc_deadline']=value['local_utc_start']
        with self.assertRaisesRegex(ValueError,'E138_ORIGINAL_UNRESET_CLOCK'):self.parse(value)


def launch():
    env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL',LM_LICENSE_FILE='1@SENTINEL',
        HOME=m.ROOT+'/work',TMPDIR=m.ROOT+'/work',LANG='C',LC_ALL='C')
    base=m.legacy.launch_base
    value=dict(schema=base.SCHEMA,argv=[base.recipe.identities.LAUNCHER,'-shell','-license_wait','5',
        '-log',m.ROOT+'/tool.log','-dofile',m.ROOT+'/code/replay.tcl'],cwd=m.ROOT+'/work',env=env,
        effective_envelope_sha256='a'*64,environment_sha256=m.sha(m.canonical(env)),
        environment_profile_authenticated=False,execution_authorized=False,execution_ready=False)
    return dict(value,launch_spec_sha256=m.sha(m.canonical(value)))


class FactoryTests(unittest.TestCase):
    def setUp(self):
        from tests.test_physical_e138_contract import ContractTests
        self.case=ContractTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.frozen=dict(authorization_sha256=self.case.frozen['authorization_sha256'],
            proposal_sha256=self.case.frozen['proposal_sha256'],origin_source_sha256=m.ORIGIN_RUNTIME_SHA256,
            adapter_source_sha256='c'*64,effective_root=m.ROOT)
        for patch in (mock.patch.object(m,'FACTORY_FREEZE',self.frozen),
                mock.patch.object(m,'__source_sha256__','c'*64,create=True)):
            patch.start();self.addCleanup(patch.stop)
        for name,pin in m.HELPER_PINS.items():
            patch=mock.patch.object(getattr(m.legacy,name),'__source_sha256__',pin,create=True)
            patch.start();self.addCleanup(patch.stop)

    def factory(self):
        return m.private_services(RAW,self.case.package['authority'],self.case.package['proposal'],STORAGE_RAW)

    def test_missing_freeze_old_grant_and_origin_drift_cannot_compile(self):
        with mock.patch('builtins.compile') as compile,mock.patch('builtins.open') as opened:
            with mock.patch.object(m,'FACTORY_FREEZE',None):
                with self.assertRaisesRegex(ValueError,'E138_FACTORY_FROZEN_BINDING_REQUIRED'):self.factory()
            with mock.patch.object(m,'FACTORY_FREEZE',dict(self.frozen,authorization_sha256=m.contract.OLD_AUTH_SHA256)):
                with self.assertRaisesRegex(ValueError,'E138_AUTHORITY_PINS_NOT_CONFIGURED'):self.factory()
            with self.assertRaisesRegex(ValueError,'E138_FACTORY_ORIGIN_PIN'):
                m.private_services(RAW+b' ',self.case.package['authority'],self.case.package['proposal'],STORAGE_RAW)
        compile.assert_not_called();opened.assert_not_called()

    def test_storage_requires_exact_raw_and_ignores_mutated_imported_functions(self):
        with mock.patch('builtins.compile') as compile:
            for raw in (None,STORAGE_RAW+b' '):
                with self.assertRaisesRegex(ValueError,'E138_FACTORY_STORAGE_ORIGIN_PIN'):
                    m.private_services(RAW,self.case.package['authority'],self.case.package['proposal'],raw)
            compile.assert_not_called()
        def substituted(raw):raise AssertionError('must never use mutated imported storage')
        substituted.__module__=m.legacy.storage.__name__
        with mock.patch.object(m.legacy.storage,'persist_initial_intent',substituted):
            services=self.factory();persist,monitor=services._storage(4600.)
            self.assertIsNot(persist.__code__,substituted.__code__)
            self.assertIsNot(services.storage,m.legacy.storage)
            self.assertEqual(persist.__globals__['__origin_source_sha256__'],m.ORIGIN_STORAGE_SHA256)

    def test_missing_helper_tag_rejects_before_any_compilation(self):
        with mock.patch.object(m.legacy.io,'__source_sha256__',None),mock.patch('builtins.compile') as compile:
            with self.assertRaisesRegex(ValueError,'E138_FACTORY_HELPER_TAG_CONSISTENCY'):self.factory()
            compile.assert_not_called()

    def test_actual_private_classes_and_storage_globals_are_isolated(self):
        old=(m.legacy.ROOT,m.legacy.AUTH_SHA256,m.legacy._USED,m.legacy.storage.ROOT,m.legacy.storage.END)
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            first,second=self.factory(),self.factory()
            persist,monitor=first._storage(4600.)
        opened.assert_not_called();spawn.assert_not_called()
        self.assertIsNot(first.Files,second.Files)
        for name in ('__init__','directory','publish','copy'):
            self.assertIs(getattr(first.Files,name).__globals__,vars(first))
        self.assertIsNone(first.worker);self.assertIsNone(first.package_clock)
        namespace=persist.__globals__
        self.assertEqual((namespace['ROOT'],namespace['SIDECAR'],namespace['END']),
            (m.ROOT,m.ROOT+'.initial_intent.json',4600.))
        self.assertIs(monitor.sample.__globals__,namespace)
        self.assertIsNone(namespace['__source_sha256__'])
        self.assertEqual(namespace['__origin_source_sha256__'],m.ORIGIN_STORAGE_SHA256)
        first.ROOT='/synthetic/private-change'
        self.assertEqual(second.Files.directory.__globals__['ROOT'],m.ROOT)
        self.assertEqual(old,(m.legacy.ROOT,m.legacy.AUTH_SHA256,m.legacy._USED,m.legacy.storage.ROOT,m.legacy.storage.END))
        with self.assertRaisesRegex(ValueError,'E138_STORAGE_DEADLINE_REQUIRED'):first._storage(4600.)

    def test_nested_observer_validator_uses_new_root_and_no_real_process(self):
        def observe(value,end,domain,budget,on_spawn,scratch):
            _validate_launch(value)
            return {'synthetic_only':True}
        services=self.factory()
        with mock.patch.object(m.legacy.process,'observe_tessent',observe),mock.patch('subprocess.Popen') as spawn:
            result=services._observer(launch(),3000.,object(),[100],None,None)
            self.assertTrue(result['synthetic_only'])
            bad=launch();bad['cwd']=m.legacy.ROOT+'/work'
            with self.assertRaisesRegex(ValueError,'FIXED_REPLAY_ARGV_CWD'):
                services._observer(bad,3000.,object(),[100],None,None)
        spawn.assert_not_called()

    def test_native_launch_validator_binds_all_paths_environment_and_hashes(self):
        value=launch();m.validate_launch(value)
        for change in (dict(cwd=m.legacy.ROOT+'/work'),dict(execution_authorized=True),
                dict(environment_sha256='0'*64),dict(launch_spec_sha256='0'*64)):
            with self.assertRaises(ValueError):m.validate_launch(dict(value,**change))
        bad=copy.deepcopy(value);bad['env']['HOME']=m.legacy.ROOT+'/work'
        with self.assertRaisesRegex(ValueError,'FIXED_HOME_TMP_LOCALE'):m.validate_launch(bad)

    def test_binding_receipt_distinguishes_origin_from_effective_config(self):
        services=self.factory();binding=services.__e138_binding__
        self.assertIsNone(services.__source_sha256__)
        self.assertEqual(binding['origin_source_sha256'],m.ORIGIN_RUNTIME_SHA256)
        self.assertEqual(binding['adapter_source_sha256'],'c'*64)
        self.assertFalse(binding['raw_module_identity_claimed']);self.assertFalse(binding['execution_ready'])

    def test_frozen_origin_and_python36_inert_import(self):
        self.assertEqual(m.sha(RAW),m.ORIGIN_RUNTIME_SHA256)
        self.assertEqual(m.sha(Path(m.legacy.storage.__file__).read_bytes()),m.ORIGIN_STORAGE_SHA256)
        source=Path(m.__file__).read_text(encoding='utf-8');ast.parse(source,feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            namespace=dict(__package__='src.data');exec(compile(source,'<inert-e138-runtime>','exec'),namespace)
        opened.assert_not_called();spawn.assert_not_called()
        self.assertIsNone(namespace['FACTORY_FREEZE'])
