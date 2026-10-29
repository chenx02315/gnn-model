"""Virtual-FS and synthetic capability bindings; NOT genuine role2 receipts."""
import ast
import base64
import copy
import datetime
from pathlib import Path
import stat
import unittest
from unittest import mock

from src.data import physical_e137_role3_export as m
from tests.test_hf_credit_artifact_reader_e134 import Files

BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'
PIN='e'*64
UTC=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc).timestamp()


def capability(fn):
    fn.__source_sha256__=PIN
    return fn


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.bodies=[('synthetic owned artifact %d'%i).encode('ascii') for i in range(len(m.OUTPUTS))]
        self.fs=Files([dict(path=p) for p in m.OUTPUTS],self.bodies)
        self.clock=dict(schema='physical-f-clean-replay-package-clock-e137-v1',authorization_sha256='a'*64,
            proposal_sha256='b'*64,reader_payload_sha256='1'*64,initial_response_sha256='2'*64,start_file_sha256='3'*64,
            boot_id=BOOT,remote_start_monotonic=1000.,remote_deadline_monotonic=4600.,remote_clock_sample_monotonic=1001.,
            remote_utc_sample='2026-01-01T00:00:01.000000+0000',local_utc_start='2026-01-01T00:00:00.000000+0000',
            local_utc_deadline='2026-01-01T01:00:00.000000+0000',local_monotonic_start=900000.,
            local_monotonic_deadline=903600.,local_clock_domain=dict(host='LOCAL_NOT_A',clock='different-domain'))
        self.now,self.utc=1100.,UTC+100
        self.sampler=mock.Mock(return_value=dict(rss_swap_bytes=1234,children=0))
        self.authenticator=mock.Mock(side_effect=lambda package:copy.deepcopy(self.context))
        self.boot=mock.Mock(return_value=BOOT)
        self.monotonic=mock.Mock(side_effect=lambda:self.now)
        self.wall=mock.Mock(side_effect=lambda:self.utc)
        for fn in (self.sampler,self.authenticator,self.boot,self.monotonic,self.wall):fn.__source_sha256__=PIN
        self.package=dict(authority=m.canonical(dict(user_authorization_received=True,approval_source='explicit_user_reply',
                proposal_sha256='b'*64,approved_scope=dict(synthetic_only=True))),
            proposal=m.canonical(dict(scope_if_granted=dict(synthetic_only=True))),
            original_clock=m.canonical(self.clock),role2_stdout=b'SYNTHETIC ROLE2 RAW',role2_stderr=b'',
            role2_intent=m.canonical(dict(role='execution',attempt_consumed=True,role_index=2,connections_max=3,
                automatic_retries=0,payload_sha256='c'*64)),
            role3_intent=m.canonical(dict(role='readback',attempt_consumed=True,role_index=3,connections_max=3,
                automatic_retries=0,payload_sha256='d'*64)))
        self.package['role2_transport']=m.canonical(dict(exit_code=0,stdout_bytes=len(self.package['role2_stdout']),
            stdout_sha256=m.sha(self.package['role2_stdout']),stderr_bytes=0,stderr_sha256=m.sha(b''),
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False))
        # ONLY mock-time synthetic pin configuration. No actual authority/emitter.
        pins=dict(AUTH_SHA256=m.sha(self.package['authority']),ORIGINAL_CLOCK_SHA256=m.sha(self.package['original_clock']),
            ROLE2_STDOUT_SHA256=m.sha(self.package['role2_stdout']),ROLE2_STDERR_SHA256=m.sha(b''),
            ROLE2_TRANSPORT_SHA256=m.sha(self.package['role2_transport']),ROLE2_INTENT_SHA256=m.sha(self.package['role2_intent']),
            ROLE3_INTENT_SHA256=m.sha(self.package['role3_intent']),ROLE2_PAYLOAD_SHA256='c'*64,ROLE3_PAYLOAD_SHA256='d'*64)
        self.clock['authorization_sha256']=pins['AUTH_SHA256']
        self.clock['proposal_sha256']=m.sha(self.package['proposal'])
        self.package['authority']=m.canonical(dict(user_authorization_received=True,approval_source='explicit_user_reply',
            proposal_sha256=m.sha(self.package['proposal']),approved_scope=dict(synthetic_only=True)))
        pins['AUTH_SHA256']=m.sha(self.package['authority'])
        self.clock['authorization_sha256']=pins['AUTH_SHA256']
        self.package['original_clock']=m.canonical(self.clock)
        pins['ORIGINAL_CLOCK_SHA256']=m.sha(self.package['original_clock'])
        self.context=dict(schema='e137-authenticated-role2-owned-root-context-v1',root=m.ROOT,
            identity=m.identity(self.fs.info[m.ROOT]),boot_id=BOOT,authorization_sha256=pins['AUTH_SHA256'],
            original_clock_sha256=pins['ORIGINAL_CLOCK_SHA256'],role2_stdout_sha256=pins['ROLE2_STDOUT_SHA256'],
            role2_stderr_sha256=pins['ROLE2_STDERR_SHA256'],role2_transport_sha256=pins['ROLE2_TRANSPORT_SHA256'],
            role2_intent_sha256=pins['ROLE2_INTENT_SHA256'],role2_payload_sha256='c'*64,
            role3_intent_sha256=pins['ROLE3_INTENT_SHA256'],role3_payload_sha256='d'*64)
        patches=[mock.patch.object(m,k,v) for k,v in pins.items()]+[
            mock.patch.object(m,'APPROVED_AUTH_SHA',pins['AUTH_SHA256']),mock.patch.object(m,'PROPOSAL_SHA',m.sha(self.package['proposal'])),
            mock.patch.object(m,'CAPABILITY_PINS',{k:PIN for k in ('authenticate','boot','monotonic','utc','sample')}),
            mock.patch.object(m,'ROLE2_AUTHENTICATOR',self.authenticator),mock.patch.object(m,'BOOT_READER',self.boot),
            mock.patch.object(m,'MONOTONIC_READER',self.monotonic),mock.patch.object(m,'UTC_READER',self.wall),
            mock.patch.object(m,'RESOURCE_GUARD',self.sampler),mock.patch.object(m,'_USED',False),
            mock.patch.object(m.anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'open',side_effect=self.fs.open),mock.patch.object(m.os,'read',side_effect=self.fs.read),
            mock.patch.object(m.os,'close',side_effect=self.fs.close),mock.patch.object(m.os,'O_NOFOLLOW',131072,create=True),
            mock.patch.object(m.os,'O_NONBLOCK',262144,create=True)]
        for patch in patches:patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def test_default_or_unbound_capability_denies_before_any_io_callback_or_clock(self):
        for key in ('AUTH_SHA256','ORIGINAL_CLOCK_SHA256','ROLE2_AUTHENTICATOR','CAPABILITY_PINS'):
            with mock.patch.object(m,key,None):
                with self.assertRaisesRegex(ValueError,'FROZEN_CAPABILITIES'):m.collect(self.package)
        self.assertFalse(m._USED)
        for fn in (self.authenticator,self.boot,self.monotonic,self.wall,self.sampler):fn.assert_not_called()
        self.assertEqual(self.fs.opened,[])

    def test_full_fixed35_in_original_remote_clock_domain_no_process_or_scan(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            value=m.collect(self.package)
        spawn.assert_not_called();scan.assert_not_called()
        self.assertEqual([r['path'] for r in value['files']],list(m.OUTPUTS))
        self.assertEqual(self.fs.opened,list(m.OUTPUTS))
        self.assertIs(value['execution_ready'],False)
        self.assertEqual(value['boot_id'],BOOT)
        m.validate_result(value,complete=True)
        self.assertEqual([base64.b64decode(r['body_base64']) for r in value['files']],self.bodies)
        with self.assertRaisesRegex(ValueError,'FROZEN_CAPABILITIES'):m.collect(self.package)
        self.assertEqual(self.authenticator.call_count,1)

    def test_forged_owned_bool_and_context_crossjoins_never_reach_filesystem(self):
        self.authenticator.side_effect=None;self.authenticator.return_value=dict(owned=True,status='PASS')
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertIsNone(error.exception.partial_result)
        self.assertEqual(self.fs.opened,[])
        self.assertEqual(error.exception.code,'ROLE3_AUTHENTICATED_INSTANCE_CONTEXT_REQUIRED')

    def test_wrong_raw_sha_or_retry_intent_is_rejected_and_consumed(self):
        self.package['role2_stdout']+=b'forged'
        with self.assertRaisesRegex(ValueError,'TRUSTED_RAW_BYTES'):m.collect(self.package)
        self.assertTrue(m._USED)
        self.authenticator.assert_not_called();self.monotonic.assert_not_called()
        self.assertEqual(self.fs.opened,[])

    def test_missing_owned_subdirectory_and_missing_leaf_keep_other_outputs(self):
        del self.fs.info[m.ROOT+'/snapshots']
        del self.fs.info[m.OUTPUTS[1]]
        value=m.collect(self.package)
        self.assertEqual(value['files'][1],dict(path=m.OUTPUTS[1],missing=True))
        absent=[r for r in value['files'] if '/snapshots/' in r['path']]
        self.assertEqual(len(absent),11)
        self.assertTrue(all(r==dict(path=r['path'],missing=True,reason='FIXED_PARENT_ABSENT') for r in absent))
        self.assertTrue(any(r['path']==m.ROOT+'/journal/stdout.log' and 'sha256' in r for r in value['files']))

    def test_missing_or_replaced_root_is_never_a_successful_missing_file(self):
        del self.fs.info[m.ROOT]
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.partial_result['files'],[])
        self.assertEqual(self.fs.opened,[])

    def test_preopen_special_owner_link_size_cap_never_opens_bad_file(self):
        self.fs.info[m.OUTPUTS[0]].st_mode=stat.S_IFSOCK|0o600
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.code,'ROLE3_OWNED_IDENTITY_REQUIRED')
        self.assertEqual(self.fs.opened,[])

    def test_full_identity_mutation_preserves_only_completed_prefix(self):
        path=m.OUTPUTS[1]
        def mutate(p):
            if p==path:self.fs.info[p].st_ctime_ns+=1
        self.fs.read_hook=mutate
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.code,'ROLE3_OUTPUT_CHANGED')
        partial=error.exception.partial_result
        self.assertEqual([r['path'] for r in partial['files']],[m.OUTPUTS[0]])
        m.validate_result(partial)
        self.assertFalse(error.exception.durable_publication_verified)

    def test_ancestor_or_root_swap_cannot_pass_identity_checks(self):
        target=m.OUTPUTS[1]
        def swap(path):
            if path==target:self.fs.info[m.ROOT].st_ino+=1
        self.fs.read_hook=swap
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertIn('ROOT',error.exception.code)
        self.assertEqual(len(error.exception.partial_result['files']),1)

    def test_reopened_parent_swap_is_rejected_even_with_same_file_bytes(self):
        original=self.fs.directory;count=[0]
        parent=m.ROOT+'/code'
        def directory(path):
            if path==parent:
                count[0]+=1
                if count[0]==2:self.fs.info[parent].st_ino+=1
            return original(path)
        with mock.patch.object(m.anchored,'_directory',side_effect=directory):
            with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.code,'ROLE3_PARENT_REPLACED')

    def test_original_expiry_boot_swap_clock_reset_memory_and_children_stop(self):
        self.now=4600.;self.utc=UTC+3600
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.code,'ROLE3_REMOTE_START_EXPIRED')
        self.assertEqual(self.fs.opened,[])

    def test_capability_error_is_sanitized_no_exception_message_export(self):
        self.sampler.side_effect=RuntimeError('SECRET_SENTINEL /outside/private')
        with self.assertRaises(m.ExportFailure) as error:m.collect(self.package)
        self.assertEqual(error.exception.code,'ROLE3_CAPABILITY_OR_IO_FAILED')
        self.assertNotIn('SECRET',str(error.exception));self.assertIsNone(error.exception.partial_result)

    def test_chunks_huge_integer_identity_and_interface_ast(self):
        path=m.ROOT+'/journal/stdout.log';raw=b'x'*150000
        self.fs.body[path]=raw;self.fs.info[path].st_size=len(raw)
        self.fs.info[path].st_ctime_ns=1793069176022511787
        original=self.fs.read;counts=[]
        def read(fd,count):counts.append(count);return original(fd,count)
        with mock.patch.object(m.os,'read',side_effect=read):value=m.collect(self.package)
        self.assertLessEqual(max(counts),65536)
        row=next(r for r in value['files'] if r['path']==path)
        self.assertEqual(row['identity']['st_ctime_ns'],1793069176022511787)
        from scripts import run_physical_f_clean_replay_e137 as controller
        self.assertEqual(m.OUTPUTS,controller.OUTPUTS)
        for path in (Path(m.__file__),Path(__file__)):ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))

    def test_partial_validation_rejects_unknown_fields_extra_path_and_wrong_hash(self):
        value=m.collect(self.package)
        for bad in (dict(value,owned=True),dict(value,files=list(reversed(value['files'])))):
            with self.assertRaises(ValueError):m.validate_result(bad)
        value['files'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'RETAINED_BODY_HASH'):m.validate_result(value)


if __name__ == '__main__':
    unittest.main()
