"""Synthetic virtual creation/cleanup capabilities; no actual remote/process."""
import ast
import copy
import datetime
from pathlib import Path
import stat
import unittest
from unittest import mock

from src.data import physical_e137_root_receipt as m
from tests.test_hf_credit_artifact_reader_e134 import Files

BOOT='3ebeb9bb-410c-476c-a000-5c625f590473'
PIN='e'*64
UTC=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc).timestamp()


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fs=Files([],[])
        self.fs.add(m.ROOT.rsplit('/',1)[0],directory=True)
        repo=Path(__file__).resolve().parents[1]
        runtime=(repo/'src/data/physical_f_replay_execution_e135.py').read_bytes()
        provider=(repo/'src/data/physical_f_replay_execution_e137.py').read_bytes()
        proposal=m.canonical(dict(scope_if_granted=dict(synthetic_only=True)))
        authority=m.canonical(dict(approval_source='explicit_user_reply',user_authorization_received=True,
            proposal_sha256=m.sha(proposal),approved_scope=dict(synthetic_only=True)))
        clock=dict(schema=m.worker.CLOCK_SCHEMA,authorization_sha256=m.sha(authority),proposal_sha256=m.sha(proposal),
            reader_payload_sha256='1'*64,initial_response_sha256='2'*64,start_file_sha256='3'*64,boot_id=BOOT,
            remote_start_monotonic=1000.,remote_deadline_monotonic=4600.,remote_clock_sample_monotonic=1001.,
            remote_utc_sample='2026-01-01T00:00:01.000000+0000',local_utc_start='2026-01-01T00:00:00.000000+0000',
            local_utc_deadline='2026-01-01T01:00:00.000000+0000',local_monotonic_start=900000.,
            local_monotonic_deadline=903600.,local_clock_domain=dict(host='LOCAL_NOT_A',clock='different-clock'))
        intent=m.canonical(dict(role='execution',attempt_consumed=True,role_index=2,connections_max=3,
            automatic_retries=0,payload_sha256='c'*64))
        self.package=dict(authority=authority,proposal=proposal,original_clock=m.canonical(clock),role2_intent=intent,
            worker_spec=b'{"synthetic_only":true}',runtime_source=runtime,worker_source=provider)
        self.response=m.canonical(dict(schema=m.worker.SCHEMA,launch_debit=1,status='SYNTHETIC_RESULT'))
        self.observation=m.canonical(dict(cleaned=True,returncode=0,launch_attempted=True,cleanup_error=None))
        self.now,self.utc=1100.,UTC+100
        self.monotonic=mock.Mock(side_effect=lambda:self.now)
        self.wall=mock.Mock(side_effect=lambda:self.utc)
        self.boot=mock.Mock(return_value=BOOT)
        self.cleanup=mock.Mock(side_effect=self.cleanup_proof)
        for fn in (self.monotonic,self.wall,self.boot,self.cleanup):fn.__source_sha256__=PIN
        pins=dict(AUTH_SHA256=m.sha(authority),CLOCK_SHA256=m.sha(self.package['original_clock']),
            ROLE2_INTENT_SHA256=m.sha(intent),ROLE2_PAYLOAD_SHA256='c'*64,
            WORKER_SPEC_SHA256=m.sha(self.package['worker_spec']),RUNTIME_SOURCE_SHA256=m.sha(runtime),
            WORKER_SOURCE_SHA256=m.sha(provider),TRUSTED_SELF_SOURCE_SHA256=PIN)
        patches=[mock.patch.object(m,k,v) for k,v in pins.items()]+[
            mock.patch.object(m,'APPROVED_AUTH_SHA',pins['AUTH_SHA256']),mock.patch.object(m,'PROPOSAL_SHA',m.sha(proposal)),
            mock.patch.object(m,'__source_sha256__',PIN,create=True),
            mock.patch.object(m.worker,'__source_sha256__',m.sha(provider),create=True),
            mock.patch.object(m.anchored,'__source_sha256__',m.ANCHOR_SOURCE_SHA,create=True),
            mock.patch.object(m,'CAPABILITY_PINS',{k:PIN for k in ('cleanup','boot','monotonic','utc')}),
            mock.patch.object(m,'CLEANUP_OBSERVER',self.cleanup),mock.patch.object(m,'BOOT_READER',self.boot),
            mock.patch.object(m,'MONOTONIC_READER',self.monotonic),mock.patch.object(m,'UTC_READER',self.wall),
            mock.patch.object(m,'_FACTORY_USED',False),
            mock.patch.object(m.anchored,'_directory',side_effect=self.fs.directory),
            mock.patch.object(m.anchored,'_mkdir',side_effect=self.mkdir),
            mock.patch.object(m.os,'stat',side_effect=self.fs.stat),mock.patch.object(m.os,'fstat',side_effect=self.fs.fstat),
            mock.patch.object(m.os,'close',side_effect=self.fs.close)]
        for patch in patches:patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:self.assertEqual(self.fs.handles,{}))

    def mkdir(self,parent,name):
        path=self.fs.handles[parent][0]+'/'+name
        if path in self.fs.info:raise FileExistsError()
        self.fs.add(path,directory=True)
        self.fs.info[path].st_mode=stat.S_IFDIR|0o700
        ancestor=self.fs.info[self.fs.handles[parent][0]]
        ancestor.st_size+=10;ancestor.st_nlink+=1;ancestor.st_mtime_ns+=10;ancestor.st_ctime_ns+=10
        return self.fs.directory(path)

    def cleanup_proof(self,files,cleanup_raw,response_raw,binding):
        self.assertIn(m.ROOT,files.owned)
        return dict(schema='e137-supervisor-final-cleanup-observation-v1',root=m.ROOT,boot_id=BOOT,
            cleanup_observation_sha256=m.sha(cleanup_raw),worker_response_sha256=m.sha(response_raw),
            clock_sha256=binding['clock_sha256'],role2_intent_sha256=binding['role2_intent_sha256'],
            owner_identity=dict(pid=123,startticks=456,uid=1047),active_descendant_pids=[],pending_root_writes=0,
            launch_debit=m.decode(response_raw)['launch_debit'])

    def create(self):
        session=m.tracked_services(self.package)
        files=session.services.Files(mock.Mock())
        m.os.close(files.directory(m.ROOT,True))
        return session,files

    def test_default_gates_deny_before_fs_time_or_callback(self):
        for key in ('AUTH_SHA256','CLOCK_SHA256','CLEANUP_OBSERVER','TRUSTED_SELF_SOURCE_SHA256','CAPABILITY_PINS'):
            with mock.patch.object(m,key,None):
                with self.assertRaisesRegex(ValueError,'FROZEN_SOURCE_AUTH'):m.tracked_services(self.package)
        self.assertFalse(m._FACTORY_USED)
        for fn in (self.monotonic,self.wall,self.boot,self.cleanup):fn.assert_not_called()
        self.assertNotIn(m.ROOT,self.fs.info)

    def test_actual_private_class_registration_final8_and_no_old_global_mutation(self):
        old_root=m.worker.legacy.ROOT
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m.os,'scandir') as scan:
            session,files=self.create()
            result=session.emit(files,self.response,self.observation)
        spawn.assert_not_called();scan.assert_not_called()
        self.assertEqual(result['identity'],m.identity(self.fs.info[m.ROOT]))
        self.assertEqual(result['root'],m.ROOT)
        self.assertEqual(result['worker_response_sha256'],m.sha(self.response))
        self.assertTrue(result['outer_raw_response_and_transport_join_required'])
        self.assertFalse(result['full_role2_transport_authenticated'])
        self.assertFalse(result['physical_D95_verified'])
        self.assertFalse(result['execution_ready'])
        self.assertEqual(m.worker.legacy.ROOT,old_root)
        self.assertIsNot(session.services.Files,m.worker.legacy.Files)

    def test_legitimate_child_creation_changes_metadata_but_preserves_birth_core(self):
        session,files=self.create()
        born=m.identity(self.fs.info[m.ROOT])
        m.os.close(files.directory(m.ROOT+'/journal',True))
        current=m.identity(self.fs.info[m.ROOT])
        self.assertNotEqual(born['st_ctime_ns'],current['st_ctime_ns'])
        self.assertNotEqual(born['st_size'],current['st_size'])
        result=session.emit(files,self.response,self.observation)
        self.assertEqual(result['identity'],current)
        self.assertEqual(result['birth_continuity'],{k:born[k] for k in m.CORE_FIELDS})

    def test_copied_owned_mapping_or_copied_instance_cannot_register(self):
        session,files=self.create()
        forged=session.services.Files(mock.Mock());forged.owned=dict(files.owned)
        with self.assertRaisesRegex(m.RootReceiptFailure,'GENUINE_REGISTERED_FILES') as error:
            session.emit(forged,self.response,self.observation)
        self.assertIsNone(error.exception.partial_receipt)
        self.cleanup.assert_not_called()

    def test_wrong_owned_inode_is_not_repaired_from_current_directory(self):
        session,files=self.create()
        dev,ino=files.owned[m.ROOT];files.owned[m.ROOT]=(dev,ino+1)
        with self.assertRaisesRegex(m.RootReceiptFailure,'BIRTH_OWNED_CONTINUITY'):session.emit(files,self.response,self.observation)
        self.cleanup.assert_not_called()

    def test_replaced_root_or_uid_mode_change_is_not_legitimate_time_growth(self):
        session,files=self.create()
        self.fs.info[m.ROOT].st_ino+=1
        with self.assertRaisesRegex(m.RootReceiptFailure,'BIRTH_IDENTITY_CHANGED'):session.emit(files,self.response,self.observation)

    def test_reopened_ancestor_replacement_or_final_mutation_rejects_full8(self):
        session,files=self.create()
        original=self.fs.directory;calls=[0]
        def directory(path):
            if path==m.ROOT:
                calls[0]+=1
                if calls[0]==2:self.fs.info[path].st_ino+=1
            return original(path)
        with mock.patch.object(m.anchored,'_directory',side_effect=directory):
            with self.assertRaisesRegex(m.RootReceiptFailure,'FINAL_SNAPSHOT_UNSTABLE'):session.emit(files,self.response,self.observation)

    def test_snapshot_mutation_during_final_guard_has_no_qualified_receipt(self):
        session,files=self.create()
        calls=[0]
        def boot():
            calls[0]+=1
            if calls[0]==3:self.fs.info[m.ROOT].st_ctime_ns+=1
            return BOOT
        self.boot.side_effect=boot
        with self.assertRaisesRegex(m.RootReceiptFailure,'CHANGED_DURING_GUARD') as error:
            session.emit(files,self.response,self.observation)
        self.assertFalse(error.exception.partial_receipt['qualified_final_root_receipt'])
        self.assertIsNone(error.exception.partial_receipt['final_root_identity'])

    def test_unknown_cleanup_or_alive_children_retains_only_unqualified_diagnostic(self):
        session,files=self.create()
        proof=self.cleanup_proof(files,self.observation,self.response,dict(clock_sha256=m.CLOCK_SHA256,
            role2_intent_sha256=m.ROLE2_INTENT_SHA256))
        proof['active_descendant_pids']=[999]
        self.cleanup.side_effect=None;self.cleanup.return_value=proof
        with self.assertRaisesRegex(m.RootReceiptFailure,'SOURCE_BOUND_FINAL_CLEANUP') as error:
            session.emit(files,self.response,self.observation)
        self.assertIsNone(error.exception.partial_receipt['final_root_identity'])
        self.assertFalse(error.exception.partial_receipt['qualified_final_root_receipt'])

    def test_cleaned_bool_alone_and_boolean_launch_debit_do_not_suffice(self):
        session,files=self.create()
        self.cleanup.side_effect=None;self.cleanup.return_value=dict(cleaned=True)
        with self.assertRaisesRegex(m.RootReceiptFailure,'SOURCE_BOUND_FINAL_CLEANUP'):session.emit(files,self.response,self.observation)

    def test_boolean_launch_debit_or_missing_cleanup_error_is_unknown_not_clean(self):
        session,files=self.create()
        response=m.canonical(dict(schema=m.worker.SCHEMA,launch_debit=True))
        with self.assertRaisesRegex(m.RootReceiptFailure,'EXACT_WORKER_RESULT_AND_DEBIT'):
            session.emit(files,response,self.observation)
        self.cleanup.assert_not_called()

    def test_absent_raw_cleanup_error_field_cannot_be_assumed_none(self):
        session,files=self.create()
        observation=m.canonical(dict(cleaned=True,returncode=0,launch_attempted=True))
        with self.assertRaisesRegex(m.RootReceiptFailure,'RAW_CLEANUP_OBSERVATION_REQUIRED'):
            session.emit(files,self.response,observation)
        self.cleanup.assert_not_called()

    def test_expiry_or_boot_mismatch_before_final_snapshot(self):
        session,files=self.create();self.now=4600.;self.utc=UTC+3600
        with self.assertRaisesRegex(m.RootReceiptFailure,'ORIGINAL_BOOT_CLOCK_OR_EXPIRY'):session.emit(files,self.response,self.observation)
        self.cleanup.assert_not_called()

    def test_replays_and_writes_after_emission_are_denied(self):
        session,files=self.create();session.emit(files,self.response,self.observation)
        with self.assertRaisesRegex(m.RootReceiptFailure,'SINGLE_FINAL_EMISSION'):session.emit(files,self.response,self.observation)
        with self.assertRaisesRegex(ValueError,'WRITES_AFTER_FINAL_EMISSION'):files.directory(m.ROOT)
        with self.assertRaisesRegex(ValueError,'FROZEN_SOURCE_AUTH'):m.tracked_services(self.package)

    def test_before_creation_has_no_owned_proof_and_crossgrant_raw_rejects_before_time(self):
        session=m.tracked_services(self.package);files=session.services.Files(mock.Mock())
        with self.assertRaisesRegex(m.RootReceiptFailure,'GENUINE_REGISTERED_FILES') as error:session.emit(files,self.response,self.observation)
        self.assertIsNone(error.exception.partial_receipt)

    def test_wrong_source_or_authority_pin_denies_before_factory_and_clock(self):
        self.package['authority']+=b' '
        with self.assertRaisesRegex(ValueError,'PINNED_AUTHORITY'):m.tracked_services(self.package)
        self.monotonic.assert_not_called();self.cleanup.assert_not_called()
        self.assertNotIn(m.ROOT,self.fs.info)

    def test_swap_between_exclusive_mkdir_child_close_and_path_reopen_cannot_register(self):
        session=m.tracked_services(self.package);files=session.services.Files(mock.Mock())
        swapped=[False]
        def close(fd):
            path=self.fs.handles[fd][0]
            self.fs.close(fd)
            if path==m.ROOT and not swapped[0]:
                swapped[0]=True
                self.fs.info[m.ROOT].st_ino+=1
        with mock.patch.object(m.os,'close',side_effect=close):
            with self.assertRaisesRegex(ValueError,'CREATION_REOPEN_IDENTITY_CHANGED'):
                files.directory(m.ROOT,True)
        with self.assertRaisesRegex(m.RootReceiptFailure,'GENUINE_REGISTERED_FILES') as error:
            session.emit(files,self.response,self.observation)
        self.assertIsNone(error.exception.partial_receipt)

    def test_zero_launch_debit_failure_can_still_emit_only_after_real_cleanup_capability(self):
        session,files=self.create()
        response=m.canonical(dict(schema=m.worker.SCHEMA,launch_debit=0,status='SYNTHETIC_FAILURE_AFTER_CREATION'))
        result=session.emit(files,response,self.observation)
        self.assertEqual(result['launch_debit'],0)
        self.assertEqual(result['worker_response_sha256'],m.sha(response))
        self.assertFalse(result['execution_ready'])

    def test_sanitized_callback_failure_no_secret_or_full_identity_claim(self):
        session,files=self.create();self.cleanup.side_effect=RuntimeError('SECRET /outside/path')
        with self.assertRaises(m.RootReceiptFailure) as error:session.emit(files,self.response,self.observation)
        self.assertEqual(error.exception.code,'ROOT_RECEIPT_CAPABILITY_OR_IO_FAILED')
        self.assertNotIn('SECRET',str(error.exception))
        self.assertIsNone(error.exception.partial_receipt['final_root_identity'])

    def test_python36_inert_schema_and_large_nanoseconds(self):
        session,files=self.create();self.fs.info[m.ROOT].st_ctime_ns=1793069176022511787
        result=session.emit(files,self.response,self.observation)
        self.assertEqual(result['identity']['st_ctime_ns'],1793069176022511787)
        self.assertLessEqual(len(m.canonical(result)),8192)
        for path in (Path(m.__file__),Path(__file__)):ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,6))


if __name__ == '__main__':
    unittest.main()
