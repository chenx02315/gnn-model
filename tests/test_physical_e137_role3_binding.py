"""Synthetic batch/phase byte joins; no genuine A or process execution."""
import base64
import copy
import io
from pathlib import Path
import stat
import sys
from contextlib import ExitStack
import unittest
from unittest import mock

from src.data import physical_e137_role3_binding as m

BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'
PAYLOAD='6'*64


def fixture():
    repo=Path(__file__).resolve().parents[1]
    authority=(repo/'contracts/physical_f_clean_replay_authorization_e137.json').read_bytes()
    proposal=(repo/'contracts/physical_f_clean_replay_proposal_e137_v1.json').read_bytes()
    sources={name:m.sha((repo/'src/data'/(name+'.py')).read_bytes()) for name in
        ('physical_e137_root_receipt','physical_f_replay_execution_e135','physical_f_replay_execution_e137','physical_e137_batch_execution')}
    clock=m.canonical(dict(schema='physical-f-clean-replay-package-clock-e137-v1',authorization_sha256=m.core.APPROVED_AUTH_SHA,
        proposal_sha256=m.core.PROPOSAL_SHA,reader_payload_sha256='1'*64,initial_response_sha256='2'*64,start_file_sha256='3'*64,
        boot_id=BOOT,remote_start_monotonic=1000.,remote_deadline_monotonic=4600.,remote_clock_sample_monotonic=1001.,
        remote_utc_sample='2026-01-01T00:00:01.000000+0000',local_utc_start='2026-01-01T00:00:00.000000+0000',
        local_utc_deadline='2026-01-01T01:00:00.000000+0000',local_monotonic_start=900000.,local_monotonic_deadline=903600.,
        local_clock_domain=dict(host='NOT_A',clock='local-domain')))
    intent=m.canonical(dict(role='execution',attempt_consumed=True,role_index=2,connections_max=3,automatic_retries=0,payload_sha256=PAYLOAD))
    response=dict(schema='physical-f-clean-replay-execution-e137-v1',status='OBSERVED_PENDING_SCIENTIFIC_AUDIT',launch_debit=1,
        instance_sha256='4'*64,policy_sha256='5'*64,payload_sha256=PAYLOAD,source_manifest_sha256=m.sha(m.canonical(sources)),
        physical_d95_verified=False,execution_ready=False,training_release=False)
    cleanup=dict(returncode=0,cleaned=True,launch_attempted=True,cleanup_error=None)
    identity=dict(st_dev=43,st_ino=987,st_mode=stat.S_IFDIR|0o700,st_nlink=5,st_uid=1047,st_size=4096,
        st_mtime_ns=1793069176022511787,st_ctime_ns=1793069176022511787)
    bindings=dict(authorization_sha256=m.core.APPROVED_AUTH_SHA,clock_sha256=m.sha(clock),role2_intent_sha256=m.sha(intent),
        role2_payload_sha256=PAYLOAD,worker_spec_sha256='4'*64,runtime_source_sha256=sources['physical_f_replay_execution_e135'],
        worker_source_sha256=sources['physical_f_replay_execution_e137'],emitter_source_sha256=sources['physical_e137_root_receipt'])
    receipt=dict(schema='e137-final-registered-root-receipt-v1',root=m.core.ROOT,identity=identity,
        birth_continuity={k:identity[k] for k in ('st_dev','st_ino','st_uid','st_mode')},boot_id=BOOT,input_bindings=bindings,
        worker_response_sha256=m.sha(m.canonical(response)),worker_response_scope='EXACT_WORKER_RESULT_BEFORE_RECEIPT_EMBEDDING',
        worker_source_scope='PINNED_PRIVATE_SERVICES_PROVIDER_NOT_ENTIRE_EXECUTOR_CLOSURE',cleanup_evidence_sha256=m.sha(m.canonical(cleanup)),
        cleanup_observer_source_sha256=sources['physical_e137_batch_execution'],supervisor_identity=dict(pid=123,startticks=456,uid=1047),
        launch_debit=1,final_snapshot_monotonic=1200.,original_remote_deadline=4600.,no_future_mutations_proven=False,
        wrapper_must_not_write_root_after_snapshot=True,outer_raw_response_and_transport_join_required=True,
        full_role2_transport_authenticated=False,executor_source_policy_join_required=True,physical_D95_verified=False,
        execution_ready=False,training_release=False)
    stdout=m.canonical(dict(role='execution',worker_response=response,owned_root=receipt,cleanup_observation=cleanup,execution_ready=False))
    transport=m.canonical(dict(exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False,
        remote_termination_verified=False,stdout_bytes=len(stdout),stdout_sha256=m.sha(stdout),stderr_bytes=0,stderr_sha256=m.sha(b'')))
    package=dict(authority=authority,proposal=proposal,original_clock=clock,role2_stdout=stdout,role2_stderr=b'',
        role2_transport=transport,role2_intent=intent)
    policy=dict(schema='e137-batch-source-policy-redacted-v1',authorization_sha256=m.core.APPROVED_AUTH_SHA,
        proposal_sha256=m.core.PROPOSAL_SHA,original_clock_sha256=m.sha(clock),role2_payload_sha256=PAYLOAD,
        role2_intent_sha256=m.sha(intent),role2_stdout_sha256=m.sha(stdout),role2_stderr_sha256=m.sha(b''),
        role2_transport_sha256=m.sha(transport),instance_sha256='4'*64,policy_sha256='5'*64,
        source_manifest_sha256=m.sha(m.canonical(sources)),source_sha256=sources,
        emitter_source_sha256=sources['physical_e137_root_receipt'],runtime_source_sha256=sources['physical_f_replay_execution_e135'],
        worker_source_sha256=sources['physical_f_replay_execution_e137'])
    review=dict(status='PASS',reviewed=dict(payload_sha256=PAYLOAD,authorization_sha256=m.core.APPROVED_AUTH_SHA,
        proposal_sha256=m.core.PROPOSAL_SHA,policy_sha256='5'*64,source_sha256=sources))
    config=dict(schema='e137-role3-reviewed-phase-inputs-v1',package={k:base64.b64encode(v).decode('ascii') for k,v in package.items()},
        source_policy=base64.b64encode(m.canonical(policy)).decode('ascii'),role2_packet_review=base64.b64encode(m.canonical(review)).decode('ascii'),
        loaded_source_sha256={})
    third=m.canonical(dict(role='readback',attempt_consumed=True,role_index=3,connections_max=3,automatic_retries=0,payload_sha256='7'*64))
    return config,third,package,policy,review


def refresh(config,package,policy):
    stdout=package['role2_stdout']
    t=m.decode(package['role2_transport']);t.update(stdout_bytes=len(stdout),stdout_sha256=m.sha(stdout))
    package['role2_transport']=m.canonical(t)
    policy.update(role2_stdout_sha256=m.sha(stdout),role2_transport_sha256=m.sha(package['role2_transport']))
    config['package']={k:base64.b64encode(v).decode('ascii') for k,v in package.items()}
    config['source_policy']=base64.b64encode(m.canonical(policy)).decode('ascii')


class BindingTests(unittest.TestCase):
    def setUp(self):self.config,self.intent,self.package,self.policy,self.review=fixture()

    def auth(self):return m.authenticate(self.config,self.intent,'7'*64)

    def test_exact_batch_emitter_raw_joins_are_pure_and_preserve_int64(self):
        with mock.patch('builtins.open',side_effect=AssertionError('IO')) as op,mock.patch('subprocess.Popen') as proc:
            a=self.auth()
        op.assert_not_called();proc.assert_not_called()
        self.assertEqual(a['root_identity']['st_ctime_ns'],1793069176022511787)
        self.assertEqual(a['boot_id'],BOOT)
        self.assertIn('NOT_JSON_SELF_AUTHENTICATION',a['trust_scope'])

    def test_missing_root_or_unknown_cleanup_refused_before_real_capabilities(self):
        for what in ('root_none','cleanup_unknown','wrong_birth','false_debit'):
            config,intent,package,policy,review=fixture()
            value=m.decode(package['role2_stdout'])
            if what=='root_none':value['owned_root']=None
            elif what=='cleanup_unknown':value['cleanup_observation']['cleaned']=False
            elif what=='wrong_birth':value['owned_root']['birth_continuity']['st_ino']+=1
            else:value['worker_response']['launch_debit']=False
            package['role2_stdout']=m.canonical(value);refresh(config,package,policy)
            with self.assertRaises(ValueError,msg=what):m.authenticate(config,intent,'7'*64)

    def test_cleaned_scientific_failure_allows_only_same_owned_evidence(self):
        value=m.decode(self.package['role2_stdout']);value['worker_response']['status']='STOPPED_FIRST_FAILURE'
        value['cleanup_observation']['returncode']=1
        value['owned_root']['worker_response_sha256']=m.sha(m.canonical(value['worker_response']))
        value['owned_root']['cleanup_evidence_sha256']=m.sha(m.canonical(value['cleanup_observation']))
        self.package['role2_stdout']=m.canonical(value)
        t=m.decode(self.package['role2_transport']);t['exit_code']=1;self.package['role2_transport']=m.canonical(t)
        refresh(self.config,self.package,self.policy)
        self.assertEqual(self.auth()['root_identity']['st_ino'],987)

    def test_argument_alphabet_length_extra_and_payload_misbind(self):
        for args in ([],['a','b'],['x;id'],['A'*9000],['A A'],['A\nA']):
            with self.assertRaises(ValueError):m.decode_intent_argument(args)
        arg=base64.b64encode(self.intent).decode('ascii')
        self.assertEqual(m.decode_intent_argument([arg]),self.intent)
        with self.assertRaisesRegex(ValueError,'CODE_PAYLOAD_HASH'):m.authenticate(self.config,self.intent,'8'*64)

    def test_source_policy_no_private_values_wrong_map_review_or_transport_rejected(self):
        bad=copy.deepcopy(self.policy);bad['launch.env']={'SECRET':'sentinel'}
        self.config['source_policy']=base64.b64encode(m.canonical(bad)).decode('ascii')
        with self.assertRaises(ValueError):self.auth()
        self.config,self.intent,self.package,self.policy,self.review=fixture()
        t=m.decode(self.package['role2_transport']);t['exit_code']=False;self.package['role2_transport']=m.canonical(t)
        refresh(self.config,self.package,self.policy)
        with self.assertRaisesRegex(ValueError,'RAW_TRANSPORT_JOIN'):self.auth()

    def test_default_run_gate_before_monitor_or_proc_and_one_frame_failure(self):
        with mock.patch.object(m.direct,'Descendants') as domain,mock.patch.object(m.time,'monotonic') as clock:
            with self.assertRaisesRegex(ValueError,'VERIFIED_BOOTSTRAP'):m.run(m.canonical(self.config),self.intent,1300.,'7'*64)
        domain.assert_not_called();clock.assert_not_called()
        output=io.BytesIO()
        code=m.execute_payload(m.canonical(self.config),['bad;arg'],output,1300.,'7'*64)
        self.assertEqual(code,1)
        value=m.decode(output.getvalue());self.assertEqual(value['schema'],'e137-role3-partial-error-v1')
        self.assertIsNone(value['partial_result'])

    def test_actual_installer_sets_real_functions_not_caller_callbacks(self):
        pin=m.sha(Path(m.__file__).read_bytes());raw=m.canonical(self.config)
        repo=Path(__file__).resolve().parents[1]
        self.config['loaded_source_sha256']={name:m.sha((repo/'src/data'/(name+'.py')).read_bytes()) for name in m.REQUIRED_LOADED}
        raw=m.canonical(self.config)
        domain=mock.Mock(peak=1234);domain.sample.return_value={}
        expected=dict(role='readback',files=[dict(path=p,missing=True) for p in m.core.OUTPUTS],boot_id=BOOT,execution_ready=False)
        def collect(package):
            context=m.core.ROLE2_AUTHENTICATOR(package)
            self.assertEqual(context['identity']['st_ino'],987)
            self.assertEqual(m.core.BOOT_READER(),BOOT)
            self.assertEqual(m.core.RESOURCE_GUARD(),dict(rss_swap_bytes=1234,children=0))
            return expected
        with ExitStack() as stack:
            for name,pin0 in self.config['loaded_source_sha256'].items():
                stack.enter_context(mock.patch.object(sys.modules['src.data.'+name],'__source_sha256__',pin0,create=True))
            stack.enter_context(mock.patch.dict(m.core.__dict__,dict(m.core.__dict__)))
            stack.enter_context(mock.patch.object(m,'__source_sha256__',pin,create=True))
            stack.enter_context(mock.patch.object(m,'TRUSTED_CONFIG_SHA256',m.sha(raw)))
            stack.enter_context(mock.patch.object(m.core,'collect',side_effect=collect))
            stack.enter_context(mock.patch.object(m.direct,'Descendants',return_value=domain))
            stack.enter_context(mock.patch.object(m.process,'_boot_id',return_value=BOOT))
            stack.enter_context(mock.patch.object(m.time,'monotonic',return_value=1300.))
            stack.enter_context(mock.patch.object(m.time,'time',return_value=1767225900.))
            self.assertEqual(m.run(raw,self.intent,1300.,'7'*64),expected)

    def test_partial_frame_and_no_second_write_on_broken_stdout(self):
        partial=dict(role='readback',files=[dict(path=m.core.OUTPUTS[0],missing=True)],boot_id=BOOT,execution_ready=False)
        args=[base64.b64encode(self.intent).decode('ascii')]
        with mock.patch.object(m,'run',side_effect=m.core.ExportFailure('ROLE3_ROOT_CHANGED',partial)):
            output=io.BytesIO();code=m.execute_payload(b'x',args,output,1300.,'7'*64)
        self.assertEqual(code,1);self.assertEqual(m.decode(output.getvalue())['partial_result'],partial)
        writer=mock.Mock();writer.write.side_effect=OSError('broken')
        with mock.patch.object(m,'run',side_effect=m.core.ExportFailure('ROLE3_ROOT_CHANGED',partial)):
            with self.assertRaises(OSError):m.execute_payload(b'x',args,writer,1300.,'7'*64)
        self.assertEqual(writer.write.call_count,1)
