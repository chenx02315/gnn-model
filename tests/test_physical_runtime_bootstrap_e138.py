"""Synthetic new-grant/profile and mocked supervisor; no real bootstrap/main."""
import ast
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import pickle
import shlex
import traceback
import unittest
from unittest import mock

from src.data import physical_runtime_bootstrap_e138 as m

REPO=Path(__file__).resolve().parents[1]
WORKER=(REPO/'scripts/worker_pt_label_generation_e127.py').read_bytes()
PROFILE=(REPO/'src/data/prospective_runtime_profile_e112.py').read_bytes()
BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'


class Domain(object):
    peak=123
    def sample(self):return {}


class Tests(unittest.TestCase):
    def setUp(self):
        self.env=dict(PATH='/usr/bin',LD_LIBRARY_PATH='/private/SENTINEL_LD',
            LM_LICENSE_FILE='1234@SENTINEL_LICENSE',MGLS_LICENSE_FILE='1234@SENTINEL_LICENSE')
        self.profile=m.profile.snapshot(self.env,False)
        self.proposal=m.canonical(dict(schema='e138-fixed-f-replay-proposal-v1',package='E138',
            status='PENDING_EXPLICIT_WHOLE_PACKAGE_AUTHORIZATION',scope_if_granted=dict(new_remote_root=m.ROOT,
                new_local_phase=m.PHASE,bootstrap_children_max=1,bootstrap_seconds_max=30,bootstrap_output_bytes_max=65536,
                sampled_worker_and_descendant_rss_swap_bytes_max=536870912,automatic_retries=0)))
        self.auth=m.canonical(dict(schema='e138-explicit-whole-package-authorization-v1',approved_package='E138',
            approval_source='explicit_user_reply',user_reply='SYNTHETIC_TEST_NOT_REAL_GRANT',user_authorization_received=True,
            proposal_sha256=m.sha(self.proposal),approved_scope=m.decode(self.proposal)['scope_if_granted'],execution_ready=False))
        self.context=m.canonical(dict(role='execution',authorization_sha256=m.sha(self.auth),boot_id=BOOT,
            package_start=1000.,package_end=4600.,connection_start=2000.,utc_end=9000.,root=m.ROOT,phase=m.PHASE))
        self.package=dict(authority=self.auth,proposal=self.proposal,context=self.context,
            e112=m.canonical(dict(runtime_profile=self.profile)),worker_source=WORKER,profile_source=PROFILE)
        self.frozen=dict(authorization_sha256=m.sha(self.auth),proposal_sha256=m.sha(self.proposal),context_sha256=m.sha(self.context),
            expected_boot_id=BOOT,root=m.ROOT,phase=m.PHASE)
        self.output=m.canonical(dict(nonce='E127_PRIVATE_RUNTIME_V1',values=self.env,profile=self.profile))
        self.domain=Domain();self.tick=mock.Mock()

    def configure(self,stack):
        for patch in (mock.patch.object(m,'AUTH_SHA256',m.sha(self.package['authority'])),
            mock.patch.object(m,'PROPOSAL_SHA256',m.sha(self.package['proposal'])),
            mock.patch.object(m,'CONTEXT_SHA256',m.sha(self.package['context'])),mock.patch.object(m,'EXPECTED_BOOT_ID',BOOT),
            mock.patch.object(m,'E112_SHA256',m.sha(self.package['e112'])),mock.patch.object(m,'_USED',False),
            mock.patch.object(m.direct,'Descendants',Domain),mock.patch.object(m.platform,'node',return_value='bupt-vncs2'),
            mock.patch.object(m.os,'getuid',return_value=1047,create=True),mock.patch.object(m.os.sys,'platform','linux'),
            mock.patch.object(m.process,'_boot_id',return_value=BOOT),mock.patch.object(m.process,'_check_worker'),
            mock.patch.object(m.time,'monotonic',return_value=2001.),mock.patch.object(m.time,'time',return_value=5000.)):
            stack.enter_context(patch)
        for module in (m.direct,m.direct.base,m.process,m.profile,m.adapter,m.pins):
            stack.enter_context(mock.patch.object(module,'__source_sha256__',m.SOURCE_PINS[module.__name__.rsplit('.',1)[1]],create=True))

    def observed(self,**changes):
        value=dict(output=self.output,cleaned=True,returncode=0,launch_attempted=True,failure=None)
        value.update(changes);return value

    def run_ok(self,observed=None,patcher=None):
        evidence={}
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',return_value=copy.deepcopy(observed or self.observed())))
            if patcher:patcher(stack)
            result=m.bootstrap(self.package,self.domain,self.tick,self.frozen,evidence)
            return result,evidence,supervise.call_args

    def failed(self,expected_stage,observed=None,patcher=None):
        evidence={}
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',return_value=copy.deepcopy(observed or self.observed())))
            if patcher:patcher(stack)
            with self.assertRaisesRegex(ValueError,'^E138_BOOTSTRAP_'+expected_stage+'_FAILED$') as caught:
                m.bootstrap(self.package,self.domain,self.tick,self.frozen,evidence)
            trace=''.join(traceback.format_exception(type(caught.exception),caught.exception,caught.exception.__traceback__))
            self.assertNotIn('SENTINEL',trace)
            self.assertNotIn(b'SENTINEL',m.canonical(evidence))
            self.assertEqual(evidence['stage_attempted'],expected_stage)
            self.assertIn(evidence['error_code'],m.ERROR_CODES)
            self.assertIn(evidence['reviewed_literal_code'],m.LITERAL_CODES|{None})
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            return evidence,supervise.call_count

    def test_default_and_old_grant_zero_io_clock_tick_and_supervision(self):
        for pin in (None,m.OLD_E137_AUTH_SHA256):
            with mock.patch.object(m,'AUTH_SHA256',pin),mock.patch.object(m.time,'monotonic') as now, \
                    mock.patch.object(m.process,'_boot_id') as boot,mock.patch.object(m.direct.base,'supervise') as supervise:
                with self.assertRaisesRegex(ValueError,'^E138_BOOTSTRAP_ADMISSION_FAILED$'):
                    m.bootstrap(self.package,self.domain,self.tick,self.frozen)
            now.assert_not_called();boot.assert_not_called();supervise.assert_not_called()
        self.tick.assert_not_called()

    def test_synthetic_new_grant_fixed_original_child_budgets_and_private_object(self):
        value,receipt,call=self.run_ok()
        self.assertEqual(value.environment(),self.env)
        self.assertNotIn('SENTINEL',repr(value));self.assertNotIn(b'SENTINEL',m.canonical(receipt))
        with self.assertRaises(TypeError):json.dumps(value)
        with self.assertRaises(TypeError):pickle.dumps(value)
        self.assertEqual(receipt['bootstrap_children'],1);self.assertFalse(receipt['bootstrap_counts_as_selftest'])
        self.assertEqual(receipt['tessent_launches'],0);self.assertFalse(receipt['environment_authenticated'])
        argv,cwd,end,domain,budget=call.args
        self.assertEqual(argv[:2],['/bin/bash','-lc']);self.assertEqual(cwd,'/');self.assertEqual(budget,[65536])
        self.assertIs(domain,self.domain);self.assertLessEqual(end,2031.)
        prefix='module load mentor/tessent2021 >/dev/null && /usr/bin/python3 -I -S -B -c '
        self.assertTrue(argv[2].startswith(prefix))
        child=shlex.split(argv[2][len(prefix):]);self.assertEqual(len(child),1)
        ast.parse(child[0],feature_version=(3,6))

    def test_authority_context_and_package_stages_are_precise_and_pre_io(self):
        original=self.package
        self.package=dict(original,extra=b'SENTINEL');self.failed('PACKAGE_SHAPE')
        self.package=dict(original,profile_source=PROFILE+b' ');self.failed('PINNED_BYTES')
        self.package=original
        self.failed('SOURCE_BINDING',patcher=lambda s:s.enter_context(mock.patch.object(m.profile,'__source_sha256__','0'*64)))
        self.failed('ARGUMENTS',patcher=lambda s:s.enter_context(mock.patch.object(m.direct,'Descendants',dict)))

    def test_duplicate_grant_json_and_boolean_clock_are_rejected_without_private_text(self):
        self.package['authority']=b'{"schema":"SENTINEL","schema":"duplicate"}'
        self.frozen['authorization_sha256']=m.sha(self.package['authority'])
        evidence,count=self.failed('AUTHORITY_JSON');self.assertEqual(evidence['reviewed_literal_code'],'DUPLICATE_JSON_KEY');self.assertEqual(count,0)

    def test_new_grant_schema_wrong_package_is_not_old_authority_reuse(self):
        auth=m.decode(self.auth);auth['approved_package']='E137'
        self.package['authority']=m.canonical(auth);self.frozen['authorization_sha256']=m.sha(self.package['authority'])
        self.failed('AUTHORITY_VALIDATE')

    def test_context_bool_and_root_relocation_rejected(self):
        value=m.decode(self.context);value['package_start']=False
        self.package['context']=m.canonical(value);self.frozen['context_sha256']=m.sha(self.package['context'])
        self.failed('CONTEXT_VALIDATE')

    def test_proposal_context_and_preparation_json_stages(self):
        original=self.package
        self.package=dict(original,proposal=b'not JSON SENTINEL')
        old=self.frozen['proposal_sha256'];self.frozen['proposal_sha256']=m.sha(self.package['proposal'])
        self.failed('PROPOSAL_JSON');self.frozen['proposal_sha256']=old
        self.package=dict(original,context=b'not JSON SENTINEL')
        old=self.frozen['context_sha256'];self.frozen['context_sha256']=m.sha(self.package['context'])
        self.failed('CONTEXT_JSON');self.frozen['context_sha256']=old
        self.package=dict(original,e112=b'{"runtime_profile":{},"runtime_profile":{}}')
        evidence,_=self.failed('PREPARATION_JSON')
        self.assertEqual(evidence['reviewed_literal_code'],'DUPLICATE_JSON_KEY')

    def test_host_boot_worker_clock_and_memory_substages(self):
        cases=(('HOST_CHECK',m.platform,'node',dict(return_value='wrong')),
            ('BOOT_CHECK',m.process,'_boot_id',dict(return_value='wrong')),
            ('WORKER_IDENTITY',m.process,'_check_worker',dict(side_effect=ValueError('SENTINEL_PRIVATE'))),
            ('CLOCK_CAPTURE',m.time,'monotonic',dict(return_value=float('nan'))))
        for stage,module,name,kwargs in cases:
            self.failed(stage,patcher=lambda s,module=module,name=name,kwargs=kwargs:s.enter_context(mock.patch.object(module,name,**kwargs)))
        self.domain.peak=536870913;self.failed('INITIAL_GUARD')

    def test_compile_and_function_extraction_do_not_execute_worker_main(self):
        self.failed('WORKER_COMPILE',patcher=lambda s:s.enter_context(mock.patch('builtins.compile',side_effect=ValueError('SENTINEL_PRIVATE'))))
        empty=compile('pass','<empty>','exec')
        self.failed('FUNCTION_EXTRACTION',patcher=lambda s:s.enter_context(mock.patch('builtins.compile',return_value=empty)))

    def test_original_call_fixed_command_and_prechild_guard_stages(self):
        def bad_type(code,namespace,name):
            def call(*args):raise RuntimeError('SENTINEL_PRIVATE')
            return call
        self.failed('ORIGINAL_CALL',patcher=lambda s:s.enter_context(mock.patch.object(m,'FunctionType',side_effect=bad_type)))
        def bad_command(code,namespace,name):
            def call(package,domain,evidence):
                return namespace['direct'].base.supervise(['/bin/bash','-lc','SENTINEL_COMMAND'],'/',2002.,domain,[65536])
            return call
        evidence,count=self.failed('COMMAND_CHECK',patcher=lambda s:s.enter_context(mock.patch.object(m,'FunctionType',side_effect=bad_command)))
        self.assertEqual(count,0)
        self.tick.side_effect=[None,ValueError('SENTINEL_TICK')]
        self.failed('PRE_CHILD_GUARD')

    def test_profile_child_source_and_quote_build_stages(self):
        def binding_fail(code,namespace,name):
            def call(*args):namespace['require'](False,'PROFILE_SOURCE_BINDING')
            return call
        evidence,count=self.failed('PROFILE_SOURCE_BINDING',patcher=lambda s:s.enter_context(mock.patch.object(m,'FunctionType',side_effect=binding_fail)))
        self.assertEqual(evidence['reviewed_literal_code'],'PROFILE_SOURCE_BINDING');self.assertEqual(count,0)
        self.failed('CHILD_CODE_BUILD',patcher=lambda s:s.enter_context(mock.patch.object(m.shlex,'quote',side_effect=ValueError('SENTINEL_PRIVATE'))))

    def test_supervisor_unknown_exception_has_no_text_cause_or_traceback_leak(self):
        self.failed('SUPERVISION',patcher=lambda s:s.enter_context(mock.patch.object(m.direct.base,'supervise',side_effect=OSError('SENTINEL_PRIVATE'))))
        evidence,_=self.failed('SUPERVISION',patcher=lambda s:s.enter_context(mock.patch.object(m.direct.base,'supervise',side_effect=ValueError('CLEANUP_UNCONFIRMED'))))
        self.assertEqual(evidence['reviewed_literal_code'],'CLEANUP_UNCONFIRMED')
        evidence,_=self.failed('OBSERVATION_CHECK',self.observed(returncode=-9,failure='CASE_TIMEOUT'))
        self.assertEqual(evidence['reviewed_literal_code'],'CASE_TIMEOUT')

    def test_output_observation_json_and_schema_stages(self):
        for observed in (self.observed(output=None),self.observed(output=b'SENTINEL'*10000)):
            self.failed('OUTPUT_BOUND',observed)
        for change in (dict(cleaned=False),dict(returncode=False),dict(failure='SENTINEL'),dict(launch_attempted=False)):
            self.failed('OBSERVATION_CHECK',self.observed(**change))
        for raw in (b'not JSON SENTINEL',b'\xffSENTINEL',b'{"nonce":NaN}'):
            self.failed('OUTPUT_JSON',self.observed(output=raw))
        self.failed('OUTPUT_SCHEMA',self.observed(output=b'{"nonce":"SENTINEL"}'))

    def test_duplicate_output_key_and_precise_literal_survive_original_generic_wrap(self):
        raw=b'{"nonce":"SENTINEL","nonce":"other"}'
        evidence,count=self.failed('OUTPUT_JSON',self.observed(output=raw))
        self.assertEqual(evidence['reviewed_literal_code'],'DUPLICATE_JSON_KEY')
        self.assertEqual(count,1)

    def test_profile_adapter_known_literal_and_unknown_secret_diagnostics(self):
        def known(stack):stack.enter_context(mock.patch.object(m.adapter,'prepare_runtime',side_effect=ValueError('RUNTIME_PROFILE_DRIFT')))
        evidence,_=self.failed('PROFILE_COMPATIBILITY',patcher=known)
        self.assertEqual(evidence['reviewed_literal_code'],'RUNTIME_PROFILE_DRIFT')
        evidence,_=self.failed('PROFILE_COMPATIBILITY',patcher=lambda s:s.enter_context(mock.patch.object(m.adapter,'prepare_runtime',side_effect=ValueError('SENTINEL_PRIVATE'))))
        self.assertIsNone(evidence['reviewed_literal_code'])
        value=m.decode(self.output);value['profile']['raw_sha256']='0'*64
        evidence,_=self.failed('PROFILE_DRIFT',self.observed(output=m.canonical(value)))
        self.assertEqual(evidence['reviewed_literal_code'],'BOOTSTRAP_PROFILE_DRIFT')

    def test_post_normalization_keys_finalguard_and_receipt_whitelist(self):
        real=m.adapter.prepare_runtime
        def post_failure(stack):
            calls=[0]
            def wrapper(*args):
                calls[0]+=1
                if calls[0]==2:raise ValueError('SENTINEL_PRIVATE')
                return real(*args)
            stack.enter_context(mock.patch.object(m.adapter,'prepare_runtime',side_effect=wrapper))
        self.failed('POST_ORIGINAL_NORMALIZE',patcher=post_failure)
        def extra_key(stack):
            def wrapper(*args):
                values,receipt=real(*args);values['DEBUG']='SENTINEL';return values,receipt
            stack.enter_context(mock.patch.object(m.adapter,'prepare_runtime',side_effect=wrapper))
        self.failed('NORMALIZED_KEYS',patcher=extra_key)
        self.tick.side_effect=[None,None,ValueError('SENTINEL_FINAL')]
        self.failed('FINAL_GUARD');self.tick.side_effect=None
        def bad_receipt(stack):
            def wrapper(*args):
                values,receipt=real(*args);receipt['private']='SENTINEL';return values,receipt
            stack.enter_context(mock.patch.object(m.adapter,'prepare_runtime',side_effect=wrapper))
        self.failed('RECEIPT',patcher=bad_receipt)

    def test_one_attempt_private_original_bytecode_and_history_unchanged(self):
        with ExitStack() as stack:
            self.configure(stack)
            supervise=stack.enter_context(mock.patch.object(m.direct.base,'supervise',side_effect=lambda *a,**k:self.observed()))
            m.bootstrap(self.package,self.domain,self.tick,self.frozen)
            with self.assertRaisesRegex(ValueError,'^E138_BOOTSTRAP_ADMISSION_FAILED$'):m.bootstrap(self.package,self.domain,self.tick,self.frozen)
            self.assertEqual(supervise.call_count,1)
        from scripts import worker_pt_label_generation_e127 as original
        code=next(v for v in compile(WORKER,'<pinned>','exec').co_consts if isinstance(v,m.CodeType) and v.co_name=='capture_runtime')
        self.assertEqual(code.co_code,original.capture_runtime.__code__.co_code)
        self.assertEqual(m.sha((REPO/'src/data/physical_runtime_bootstrap_e137.py').read_bytes()),m.ORIGIN_E137_SOURCE_SHA256)

    def test_source_pins_ast_and_inert_default_freezes(self):
        for name,pin in m.SOURCE_PINS.items():self.assertEqual(m.sha((REPO/'src/data'/(name+'.py')).read_bytes()),pin)
        self.assertEqual(m.sha(WORKER),m.WORKER_SHA256);self.assertEqual(m.sha(PROFILE),m.PROFILE_SHA256)
        raw=Path(m.__file__).read_bytes();ast.parse(raw.decode('utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn:
            ns=dict(__package__='src.data');exec(compile(raw,'<inert-e138-bootstrap>','exec'),ns)
        opened.assert_not_called();spawn.assert_not_called()
        self.assertIsNone(ns['AUTH_SHA256']);self.assertIsNone(ns['PROPOSAL_SHA256'])

    def test_hostile_exception_objects_are_not_inspected_or_formatted(self):
        class Hostile(ValueError):
            def __getattribute__(self,name):raise AssertionError('SENTINEL_ATTRIBUTE')
            def __str__(self):raise AssertionError('SENTINEL_STR')
            def __repr__(self):raise AssertionError('SENTINEL_REPR')
        def sabotage(*args,**kwargs):raise Hostile('SENTINEL_PRIVATE')
        for target,stage in ((m.direct.base,'SUPERVISION'),(m.adapter,'PROFILE_COMPATIBILITY')):
            name='supervise' if target is m.direct.base else 'prepare_runtime'
            def patcher(stack):stack.enter_context(mock.patch.object(target,name,side_effect=sabotage))
            evidence,_=self.failed(stage,patcher=patcher)
            self.assertIsNone(evidence['reviewed_literal_code'])

    def test_overflowing_context_number_rejects_before_supervision(self):
        raw=self.package['context'].replace(b'9000.0',b'1e999')
        self.assertNotEqual(raw,self.package['context'])
        self.package['context']=raw;self.frozen['context_sha256']=m.sha(raw)
        evidence,count=self.failed('CONTEXT_VALIDATE')
        self.assertEqual(count,0)
        self.assertEqual(evidence['bootstrap_children'],0)


if __name__=='__main__':unittest.main()
