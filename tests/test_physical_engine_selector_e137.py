"""Synthetic source/metadata only: no probing, subprocess or actual identities."""
import ast
import copy
from pathlib import Path
import stat
import unittest
from unittest import mock

from src.data import physical_engine_selector_e137 as m


def synthetic_sources():
    # Minimal branch fixtures, NOT vendor script bodies or executable scripts.
    return tuple(b'\n'.join(fragment for fragment,count in markers for _ in range(count))
        for markers in (m.FUNCTION_BRANCHES,m.SHELL_BRANCHES))


def present(directory=False,executable=True,**changes):
    fields = dict(st_dev=43,st_ino=123,st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|
        (0o755 if executable else 0o644),st_nlink=1,st_uid=0,st_size=100,st_mtime_ns=1,st_ctime_ns=2)
    fields.update(changes)
    return dict(state='PRESENT',identity=fields)


class SelectorTests(unittest.TestCase):
    def setUp(self):
        self.functions,self.shell = synthetic_sources()
        for patch in (mock.patch.object(m,'FUNCTIONS_SHA',m.sha(self.functions)),
                      mock.patch.object(m,'SHELL_SHA',m.sha(self.shell)),
                      mock.patch.object(m,'FUNCTIONS_BYTES',len(self.functions)),
                      mock.patch.object(m,'SHELL_BYTES',len(self.shell))):
            patch.start();self.addCleanup(patch.stop)
        self.env = dict(PATH='/usr/bin:/bin',TESSENT_PATH=m.ROOT,LANG='C',LC_ALL='C',
            LM_LICENSE_FILE='1717@synthetic-license',MGLS_LICENSE_FILE='1717@synthetic-license')
        self.argv = [m.LAUNCHER,'-shell','-license_wait','5','-log',m.RUN_ROOT+'/tool.log',
            '-dofile',m.RUN_ROOT+'/code/replay.tcl']

    def plan(self,argv=None,environment=None):
        return m.build_plan(self.functions,self.shell,self.env if environment is None else environment,
            self.argv if argv is None else argv)

    def metadata(self):
        result = {p:dict(state='MISSING') for p in m.CANDIDATES}
        result[m.MGLS['64']] = present(executable=False)
        result[m.TCL['64']] = present(directory=True)
        result[m.ENGINE['64']] = present()
        return result

    def test_finite_pure_plan_and_default64_source_order(self):
        env,argv = copy.deepcopy(self.env),list(self.argv)
        with mock.patch('builtins.open',side_effect=AssertionError('IO')) as opened, \
                mock.patch('os.stat',side_effect=AssertionError('probe')) as probed, \
                mock.patch('subprocess.Popen',side_effect=AssertionError('spawn')) as spawned:
            plan = self.plan()
            result = m.classify(plan,self.metadata())
        opened.assert_not_called();probed.assert_not_called();spawned.assert_not_called()
        self.assertEqual(len(plan['candidate_paths']),7)
        self.assertEqual(result['status'],'CONDITIONALLY_SELECTED')
        self.assertEqual(result['selected']['engine'],dict(path=m.ENGINE['64'],width='64'))
        self.assertEqual(result['selected']['tcl_library'],m.TCL['64'])
        self.assertEqual([r['purpose'] for r in result['lookup_trace']],['mgls','tcl_before_engine','engine'])
        self.assertEqual(self.env,env);self.assertEqual(self.argv,argv)
        for key in ('candidate_existence_authenticated','selected_engine_identity_authenticated',
                    'actual_engine_selected_observed','complete_dynamic_library_closure_verified',
                    'execution_authorized','execution_ready','training_release'):
            self.assertIs(result[key],False)
        self.assertNotIn('synthetic-license',m.canonical(result).decode('ascii'))
        self.assertNotIn('synthetic-license',m.canonical(plan).decode('ascii'))

    def test_mgls32_then_tcl32_then_engine64_without_artificial_width_rejection(self):
        rows = self.metadata()
        rows[m.MGLS['64']] = dict(state='MISSING')
        rows[m.MGLS['32']] = present(executable=False)
        rows[m.TCL['32']] = present(directory=True)
        result = m.classify(self.plan(),rows)
        self.assertEqual(result['status'],'CONDITIONALLY_SELECTED')
        self.assertEqual(result['selected']['tcl_search_width'],'32')
        self.assertEqual(result['selected']['engine']['width'],'64')
        self.assertEqual(result['selected']['mgls_home'],m.ROOT+'/lnx-x86/bin32/mgls/')
        self.assertEqual(result['pre_ldd_library_path_sha256'],
            m.sha((m.ROOT+'/lnx-x86/lib64:'+m.ROOT+'/lnx-x86/lib32').encode('ascii')))

    def test_no_mgls_uses_empty_width_tcl_before_engine(self):
        rows = self.metadata()
        rows[m.MGLS['64']] = dict(state='MISSING')
        rows[m.TCL['']] = present(directory=True)
        result = m.classify(self.plan(),rows)
        self.assertEqual(result['status'],'CONDITIONALLY_SELECTED')
        self.assertEqual(result['selected']['tcl_library'],m.ROOT+'/lnx-x86/lib/tcl8.6')
        self.assertIsNone(result['selected']['mgls_home'])
        rows[m.TCL['']] = dict(state='MISSING')
        result = m.classify(self.plan(),rows)
        self.assertEqual(result['code'],'TCL_DIRECTORY_MISSING_BEFORE_ENGINE_SEARCH')
        self.assertNotIn('engine',[r['purpose'] for r in result['lookup_trace']])

    def test_explicit_width_falls_back_both_directions_on_real_missing_claims(self):
        for requested,chosen in (('32','64'),('64','32')):
            rows = self.metadata()
            rows[m.ENGINE[requested]] = dict(state='MISSING')
            rows[m.ENGINE[chosen]] = present()
            result = m.classify(self.plan(argv=self.argv+['-'+requested]),rows)
            self.assertEqual(result['status'],'CONDITIONALLY_SELECTED')
            self.assertEqual(result['selected']['engine']['width'],chosen)
        rows = self.metadata()
        rows[m.ENGINE['32']] = present()
        result = m.classify(self.plan(argv=self.argv+['-32']),rows)
        self.assertEqual(result['selected']['engine']['width'],'32')
        self.assertEqual(result['lookup_trace'][-1]['purpose'],'engine_width32_warning_probe')

    def test_present_unsafe_first_is_not_missing_and_never_falls_back(self):
        for change in (dict(st_mode=stat.S_IFLNK|0o777),dict(st_uid=1047),
                       dict(st_mode=stat.S_IFREG|0o666),dict(st_mode=stat.S_IFREG|0o644)):
            rows = self.metadata()
            rows[m.ENGINE['64']] = present(**change)
            rows[m.ENGINE['32']] = present()
            result = m.classify(self.plan(),rows)
            self.assertEqual(result['status'],'BLOCKED')
            self.assertEqual(result['code'],'SOURCE_SELECTED_OBJECT_UNSAFE')
            self.assertNotIn('engine',result['selected'])
            self.assertNotIn(m.ENGINE['32'],[r['path'] for r in result['lookup_trace']])

    def test_unobserved_is_not_missing_even_if_later_candidate_present(self):
        rows = self.metadata()
        del rows[m.ENGINE['64']]
        rows[m.ENGINE['32']] = present()
        result = m.classify(self.plan(),rows)
        self.assertEqual(result['status'],'UNOBSERVED')
        self.assertNotIn('engine',result['selected'])
        self.assertEqual(m.classify(self.plan(),{})['status'],'UNOBSERVED')

    def test_width32_warning_probe_unknown_does_not_fake_complete_branch(self):
        rows = self.metadata()
        rows[m.ENGINE['32']] = present()
        del rows[m.ENGINE['64']]
        result = m.classify(self.plan(argv=self.argv+['-32']),rows)
        self.assertEqual(result['status'],'UNOBSERVED')
        self.assertEqual(result['selected']['engine']['width'],'32')
        # An unsafe64 object only used for warning must not invalidate safe32.
        rows[m.ENGINE['64']] = present(st_mode=stat.S_IFLNK|0o777)
        self.assertEqual(m.classify(self.plan(argv=self.argv+['-32']),rows)['status'],'CONDITIONALLY_SELECTED')

    def test_unknown_dynamic_environment_multiroot_and_relative_paths_rejected(self):
        for key,value in (('MGC_DFT_EXTRA_ARG','-dbg=exec'),('DEBUG',''),('BASH_ENV','/tmp/x'),
                          ('ENV','/tmp/x'),('TCL_LIBRARY','/tmp/tcl'),('TESSENT_WIDTH','32'),
                          ('TESSENT_PATH',m.ROOT+':/tmp/other'),('TESSENT_PATH','.'),
                          ('PATH','.:/usr/bin'),('LD_LIBRARY_PATH','/usr/lib64:'),
                          ('TESSENT_HOME','/other'),('LANG','en_US')):
            env = dict(self.env);env[key] = value
            with self.assertRaises(ValueError,msg=key):self.plan(environment=env)

    def test_dynamic_argument_unknown_duplicate_conflicting_or_other_path_rejected(self):
        for args in (['-dbg=script:launch'],['-systest'],['-help'],['-libcomp','foo'],
                     ['-unknown'],['-32','-64'],['-32','-32'],['-log','/tmp/log'],
                     ['-dofile'],['-license_wait','none']):
            with self.assertRaises(ValueError,msg=str(args)):self.plan(argv=self.argv+args)
        with self.assertRaisesRegex(ValueError,'FIXED_PLATFORM'):
            m.build_plan(self.functions,self.shell,self.env,self.argv,machine='aarch64')

    def test_source_digest_markers_and_order_not_merely_caller_pins(self):
        with self.assertRaisesRegex(ValueError,'EXACT_HELPER_SOURCE'):
            m.build_plan(self.functions+b'changed',self.shell,self.env,self.argv)
        bad = self.functions.replace(m.FUNCTION_BRANCHES[0][0],b'changed')
        with mock.patch.object(m,'FUNCTIONS_SHA',m.sha(bad)),mock.patch.object(m,'FUNCTIONS_BYTES',len(bad)):
            with self.assertRaisesRegex(ValueError,'EXPECTED_HELPER_SOURCE_BRANCHES'):
                m.build_plan(bad,self.shell,self.env,self.argv)
        bad = self.shell.replace(b'\ntcl_setup\n',b'')+b'\ntcl_setup\n'
        with mock.patch.object(m,'SHELL_SHA',m.sha(bad)):
            with self.assertRaisesRegex(ValueError,'TCL_BEFORE_ENGINE'):
                m.build_plan(self.functions,bad,self.env,self.argv)

    def test_metadata_closed_paths_fields_integer_types_and_plan_tamper(self):
        for rows in ({'/outside':dict(state='MISSING')},
                     {m.ENGINE['64']:dict(state='MISSING',identity={})},
                     {m.ENGINE['64']:dict(state='PRESENT',identity={})},
                     {m.ENGINE['64']:present(st_uid=False)},
                     {m.ENGINE['64']:dict(state='GUESS')}):
            with self.assertRaises(ValueError):m.classify(self.plan(),rows)
        plan = self.plan();plan['requested_width']='32'
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_DERIVED_PLAN'):m.classify(plan,self.metadata())

    def test_library_substring_semantics_and_source_fingerprint_constants(self):
        self.env['LD_LIBRARY_PATH']=m.ROOT+'/lnx-x86/lib64suffix:/usr/lib64'
        result=m.classify(self.plan(),self.metadata())
        self.assertEqual(result['pre_ldd_library_path_sha256'],m.sha(self.env['LD_LIBRARY_PATH'].encode()))
        self.assertTrue(result['validate_executable_may_replace_library_path'])
        for path in (Path(m.__file__),Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))

    def test_private_plan_and_public_redactor_never_leak_env_sentinels(self):
        self.env.update(PATH='/sentinel_private_PATH_719/bin',
            LD_LIBRARY_PATH='/sentinel_private_LD_563/lib',
            LM_LICENSE_FILE='1717@sentinel_private_LM_428',
            MGLS_LICENSE_FILE='1717@sentinel_private_MGLS_936')
        plan = self.plan()
        original = copy.deepcopy(plan)
        self.assertEqual(plan['data_handling'],'SENSITIVE_RAM_ONLY')
        self.assertEqual(plan['initial_ld_library_path'],self.env['LD_LIBRARY_PATH'])
        public = m.redact_plan(plan)
        result = m.classify(plan,self.metadata())
        for value in (public,result):
            raw = m.canonical(value).decode('ascii')
            for sentinel in self.env.values():
                if 'sentinel_private_' in sentinel:
                    self.assertNotIn(sentinel,raw)
            for fragment in ('sentinel_private_PATH','sentinel_private_LD',
                             'sentinel_private_LM','sentinel_private_MGLS'):
                self.assertNotIn(fragment,raw)
        self.assertEqual(public['initial_ld_library_path_sha256'],
            m.sha(self.env['LD_LIBRARY_PATH'].encode('utf-8')))
        self.assertEqual(public['plan_sha256'],plan['plan_sha256'])
        self.assertEqual(public['data_handling'],'PUBLIC_REDACTED')
        self.assertIs(public['contains_environment_values'],False)
        self.assertIs(public['private_plan_authenticated'],False)
        self.assertEqual(set(public),{'schema','data_handling','source_sha256','platform','whoami',
            'environment_sha256','argv_sha256','requested_width','candidate_paths','plan_sha256',
            'actual_platform_observed','execution_ready','contains_environment_values',
            'initial_ld_library_path_sha256','private_plan_authenticated','redaction_sha256'})
        self.assertEqual(public['redaction_sha256'],m.sha(m.canonical(
            {k:v for k,v in public.items() if k != 'redaction_sha256'})))
        public['candidate_paths'].clear()
        self.assertEqual(plan,original)

    def test_redaction_requires_exact_private_input_and_is_not_classify_input(self):
        plan = self.plan()
        public = m.redact_plan(plan)
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_DERIVED_PLAN'):
            m.classify(public,self.metadata())
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_DERIVED_PLAN'):
            m.redact_plan(public)
        plan['initial_ld_library_path']='/sentinel_changed/lib'
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_DERIVED_PLAN'):
            m.redact_plan(plan)
        plan=self.plan();plan['unexpected_secret']='sentinel_not_allowed'
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_DERIVED_PLAN'):
            m.redact_plan(plan)


if __name__ == '__main__':
    unittest.main()
