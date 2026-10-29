"""Mocked supervisor only; no shell, Python child, network or Tessent is run."""
import ast
import copy
import json
from pathlib import Path
import unittest
from unittest import mock
from src.data import physical_runtime_bootstrap_e137 as m

REPO=Path(__file__).resolve().parents[1]
AUTH=(REPO/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
WORKER=(REPO/'scripts/worker_pt_label_generation_e127.py').read_bytes()
PROFILE=(REPO/'src/data/prospective_runtime_profile_e112.py').read_bytes()
BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'


class Domain(object):
    peak=123
    def sample(self):return {}


class Tests(unittest.TestCase):
    def setUp(self):
        self.env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL_SECRET',
            LM_LICENSE_FILE='1234@SENTINEL_LICENSE',MGLS_LICENSE_FILE='1234@SENTINEL_LICENSE')
        self.profile=m.profile.snapshot(self.env,False)
        e112=m.canonical(dict(runtime_profile=self.profile)) # Synthetic profile fixture, NOT actual E112 proof.
        self.context=m.canonical(dict(role='execution',authorization_sha256=m.ACTUAL_AUTH_SHA256,boot_id=BOOT,
            package_start=1000.,package_end=4600.,connection_start=2000.,utc_end=9000.))
        self.package=dict(authority=AUTH,context=self.context,e112=e112,worker_source=WORKER,profile_source=PROFILE)
        self.output=m.canonical(dict(nonce='E127_PRIVATE_RUNTIME_V1',values=self.env,profile=self.profile))
        self.domain=Domain();self.tick=mock.Mock()

    def configure(self,stack):
        for patch in (mock.patch.object(m,'AUTH_SHA256',m.ACTUAL_AUTH_SHA256),mock.patch.object(m,'CONTEXT_SHA256',m.sha(self.context)),
                mock.patch.object(m,'EXPECTED_BOOT_ID',BOOT),mock.patch.object(m,'E112_SHA256',m.sha(self.package['e112'])),
                mock.patch.object(m,'_USED',False),mock.patch.object(m.direct,'Descendants',Domain),
                mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),mock.patch.object(m.os,'getuid',return_value=1047,create=True),
                mock.patch.object(m.os.sys,'platform','linux'),mock.patch.object(m.process,'_boot_id',return_value=BOOT),
                mock.patch.object(m.process,'_check_worker'),mock.patch.object(m.time,'monotonic',return_value=2001.),
                mock.patch.object(m.time,'time',return_value=5000.)):
            stack.enter_context(patch)
        for module in (m.direct,m.direct.base,m.process,m.profile,m.adapter,m.pins):
            stack.enter_context(mock.patch.object(module,'__source_sha256__',m.SOURCE_PINS[module.__name__.rsplit('.',1)[1]],create=True))

    def run_bootstrap(self,observed=None,evidence=None):
        from contextlib import ExitStack
        if observed is None:observed=dict(output=self.output,cleaned=True,returncode=0,launch_attempted=True,failure=None)
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',return_value=copy.deepcopy(observed)))
            value=m.bootstrap(self.package,self.domain,self.tick,evidence)
            return value,supervise.call_args

    def test_default_denial_before_clock_proc_io_or_callback(self):
        with mock.patch.object(m.time,'monotonic') as now,mock.patch.object(m.process,'_boot_id') as boot,\
                mock.patch.object(m.direct.base,'supervise') as supervise:
            with self.assertRaisesRegex(ValueError,'E137_BOOTSTRAP_AUTH_CONTEXT_BOOT_NOT_FROZEN'):
                m.bootstrap(self.package,self.domain,self.tick)
        now.assert_not_called();boot.assert_not_called();supervise.assert_not_called();self.tick.assert_not_called()

    def test_private_normalized_values_exact_command_and_no_secret_receipt(self):
        evidence={};result,call=self.run_bootstrap(evidence=evidence)
        raw=m.canonical(result.redacted_receipt())
        self.assertNotIn(b'SENTINEL',raw);self.assertNotIn('SENTINEL',repr(result))
        self.assertEqual(result.environment(),self.env)
        self.assertEqual(set(result.environment()),set(m.adapter.ROOTLESS_KEYS))
        with self.assertRaises(TypeError):json.dumps(result)
        argv,cwd,end,domain,budget=call.args
        self.assertEqual(argv[:2],['/bin/bash','-lc']);self.assertEqual(cwd,'/');self.assertEqual(budget,[65536])
        self.assertLessEqual(end,2031.);self.assertIs(domain,self.domain)
        self.assertTrue(argv[2].startswith('module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '))
        self.assertIn('scratch',call.kwargs)
        self.assertFalse(evidence['environment_authenticated']);self.assertEqual(evidence['bootstrap_children'],1)
        self.assertFalse(evidence['bootstrap_counts_as_selftest']);self.assertEqual(evidence['tessent_launches'],0)

    def test_cleanup_failure_false_exit_output_cap_and_secret_errors_redacted(self):
        for change in (dict(cleaned=False),dict(returncode=False),dict(failure='SECRET_FAILURE'),dict(launch_attempted=False),
                dict(output=b'SENTINEL_SECRET'*6000),dict(output=b'not-json SENTINEL_SECRET')):
            observed=dict(output=self.output,cleaned=True,returncode=0,launch_attempted=True,failure=None);observed.update(change)
            evidence={}
            with self.assertRaisesRegex(ValueError,'^E137_BOOTSTRAP_FAILED_NO_RETRY$') as error:
                self.run_bootstrap(observed,evidence)
            self.assertNotIn('SECRET',str(error.exception));self.assertNotIn(b'SENTINEL',m.canonical(evidence))
            self.assertEqual(evidence['status'],'FAILED')

    def test_one_attempt_and_boot_deadline_source_failures(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',side_effect=lambda *a,**k:
                dict(output=self.output,cleaned=True,returncode=0,launch_attempted=True,failure=None)))
            m.bootstrap(self.package,self.domain,self.tick)
            with self.assertRaisesRegex(ValueError,'E137_ONE_BOOTSTRAP_NO_RETRY'):m.bootstrap(self.package,self.domain,self.tick)
            self.assertEqual(supervise.call_count,1)
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise'))
            stack.enter_context(mock.patch.object(m.process,'_boot_id',return_value='wrong'))
            with self.assertRaises(ValueError):m.bootstrap(self.package,self.domain,self.tick)
            supervise.assert_not_called()
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise'))
            stack.enter_context(mock.patch.object(m.time,'monotonic',return_value=4600.))
            with self.assertRaises(ValueError):m.bootstrap(self.package,self.domain,self.tick)
            supervise.assert_not_called()

    def test_drift_and_injected_tool_keys_rejected(self):
        value=m.decode(self.output);value['values']['MGC_ROOT']='/unapproved'
        for changed in (value,dict(value,profile=dict(self.profile,normalized_sha256='0'*64))):
            with self.assertRaisesRegex(ValueError,'E137_BOOTSTRAP_FAILED_NO_RETRY'):
                self.run_bootstrap(dict(output=m.canonical(changed),cleaned=True,returncode=0,launch_attempted=True,failure=None))
        for key in ('DEBUG','MGC_DFT_EXTRA_ARG','TESSENT_PATH'):
            changed=m.decode(self.output);changed['values'][key]='SENTINEL_INJECTED'
            with self.assertRaisesRegex(ValueError,'E137_BOOTSTRAP_FAILED_NO_RETRY'):
                self.run_bootstrap(dict(output=m.canonical(changed),cleaned=True,returncode=0,launch_attempted=True,failure=None))

    def test_inert_source_pins_and_exact_original_function_bytecode(self):
        for name,pin in m.SOURCE_PINS.items():self.assertEqual(m.sha((REPO/'src/data'/(name+'.py')).read_bytes()),pin)
        self.assertEqual(m.sha(WORKER),m.WORKER_SHA256);self.assertEqual(m.sha(PROFILE),m.PROFILE_SHA256)
        from scripts import worker_pt_label_generation_e127 as original
        compiled=compile(WORKER,'<same-pinned-worker-not-executed>','exec')
        code=next(value for value in compiled.co_consts if isinstance(value,m.CodeType) and value.co_name == 'capture_runtime')
        self.assertEqual(code.co_code,original.capture_runtime.__code__.co_code)
        self.assertEqual(code.co_names,original.capture_runtime.__code__.co_names)
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened:
            namespace=dict(__package__='src.data');exec(compile(raw,'<inert-bootstrap>','exec'),namespace)
        opened.assert_not_called();self.assertIsNone(namespace['EXPECTED_BOOT_ID'])

    def test_source_drift_before_current_clock_or_process(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.configure(stack)
            now=stack.enter_context(mock.patch.object(m.time,'monotonic'))
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise'))
            bad=dict(self.package,profile_source=PROFILE+b' ')
            with self.assertRaisesRegex(ValueError,'E137_BOOTSTRAP_FROZEN_BYTES'):m.bootstrap(bad,self.domain,self.tick)
            now.assert_not_called();supervise.assert_not_called()

    def test_supervisor_exception_has_no_secret_exception_context_and_memory_stops(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',side_effect=OSError('SENTINEL_SECRET')))
            with self.assertRaisesRegex(ValueError,'^E137_BOOTSTRAP_FAILED_NO_RETRY$') as caught:
                m.bootstrap(self.package,self.domain,self.tick)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn('SENTINEL',repr(caught.exception))
            self.assertEqual(supervise.call_count,1)
        with ExitStack() as stack:
            self.configure(stack);self.domain.peak=536870913
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise'))
            with self.assertRaises(ValueError):m.bootstrap(self.package,self.domain,self.tick)
            supervise.assert_not_called()
