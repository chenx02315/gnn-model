"""Mock-only fixed host inspection tests; never query actual LSF or a remote host."""
import ast
import base64
import importlib.util
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/inspect_acceptance_host_queue_e98.py'
SPEC = importlib.util.spec_from_file_location('host_queue_e98_test', str(PATH))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def info(**changes):
    value=dict(st_dev=43,st_ino=55,st_size=100,st_mtime_ns=1,st_ctime_ns=2,
        st_uid=0,st_gid=10007,st_mode=stat.S_IFREG|0o755,st_nlink=4)
    value.update(changes); return types.SimpleNamespace(**value)


def base():
    return types.SimpleNamespace(_read=mock.Mock(return_value=(b'config', info())),
        _directory=mock.Mock(return_value=10),
        _client=mock.Mock(return_value=dict(status='CLIENT_COMPLETE',returncode=0,
            stdout=b'HOST bupt-vncs2 closed',stderr=b'')))


class HostQueueTests(unittest.TestCase):
    def run_observe(self, frozen, metadata=None, config_sha=None):
        with mock.patch.object(m.sys,'platform','linux'), \
                mock.patch.object(m.platform,'node',return_value='bupt-vncs2'), \
                mock.patch.object(m,'_base',return_value=frozen), \
                mock.patch.object(m,'CONFIG_SHA256',config_sha or m.sha(b'config')), \
                mock.patch.object(m.os,'stat',side_effect=metadata or [info(),info()]), \
                mock.patch.object(m.os,'close'):
            return m.observe(b'mocked source')

    def test_exact_single_argv_and_only_fixed_config_read(self):
        frozen=base(); result=self.run_observe(frozen)
        frozen._client.assert_called_once_with([m.BINDIR+'bhosts','-l','bupt-vncs2'])
        frozen._read.assert_called_once_with('/cad/lsf/conf/lsf.conf',262144)
        frozen._directory.assert_called_once_with(m.BINDIR.rstrip('/'))
        self.assertEqual(result['schema'],'e98-host-queue-observation-v1')
        self.assertEqual(result['job_scope'],394238)
        self.assertTrue(result['observation_only'])
        self.assertEqual(result['jobs_submitted'],0); self.assertEqual(result['resume_calls'],0)

    def test_first_observation_not_frozen_executable_authentication(self):
        result=self.run_observe(base())
        self.assertEqual(result['identity_evidence'],'FIRST_OBSERVATION_NOT_PREVIOUSLY_PINNED')
        self.assertFalse(result['executable_body_read'])
        self.assertFalse(result['causal_queue_reason_claimed'])

    def test_wrong_host_before_any_source_or_command(self):
        with mock.patch.object(m.platform,'node',return_value='other'), \
                mock.patch.object(m,'_base') as loader:
            with self.assertRaises(m.HostInspectionError): m.observe(b'')
            loader.assert_not_called()

    def test_wrong_config_blocks_directory_open_and_command(self):
        frozen=base()
        with self.assertRaisesRegex(m.HostInspectionError,'CONFIG_PIN'):
            self.run_observe(frozen,config_sha='0'*64)
        frozen._directory.assert_not_called(); frozen._client.assert_not_called()

    def test_wrong_file_identity_rejected_before_command(self):
        for change in (dict(st_uid=1),dict(st_mode=stat.S_IFLNK|0o755),
                       dict(st_mode=stat.S_IFDIR|0o755),dict(st_mode=stat.S_IFREG|0o777),
                       dict(st_mode=stat.S_IFREG|0o644),dict(st_size=0),dict(st_nlink=0)):
            frozen=base()
            with self.assertRaisesRegex(m.HostInspectionError,'IDENTITY_UNSAFE'):
                self.run_observe(frozen,metadata=[info(**change)])
            frozen._client.assert_not_called()

    def test_before_after_metadata_drift_is_fatal_no_retry(self):
        for change in (dict(st_ino=56),dict(st_size=101),dict(st_ctime_ns=3),dict(st_nlink=5)):
            frozen=base()
            with self.assertRaisesRegex(m.HostInspectionError,'METADATA_DRIFT'):
                self.run_observe(frozen,metadata=[info(),info(**change)])
            frozen._client.assert_called_once()

    def test_nofollow_directory_error_never_queries(self):
        frozen=base(); frozen._directory.side_effect=OSError('symlink rejected')
        with self.assertRaises(OSError): self.run_observe(frozen)
        frozen._client.assert_not_called()

    def test_original_output_body_hash_and_cap(self):
        frozen=base(); frozen._client.return_value['stdout']=b'x'*8192
        result=self.run_observe(frozen)
        body=result['output']['stdout']
        self.assertEqual(body['bytes'],8192)
        self.assertEqual(base64.b64decode(body['base64']),b'x'*8192)
        self.assertEqual(body['sha256'],m.sha(b'x'*8192))
        self.assertLessEqual(len(m.encode(result)),32768)
        frozen=base(); frozen._client.return_value['stdout']=b'x'*8193
        with self.assertRaisesRegex(m.HostInspectionError,'CLIENT_OUTPUT_BOUND'):
            self.run_observe(frozen)

    def test_failed_client_is_observation_not_success_or_retry(self):
        frozen=base(); frozen._client.return_value.update(status='CLIENT_FAILURE_UNKNOWN',returncode=None)
        result=self.run_observe(frozen)
        self.assertEqual(result['client_status'],'CLIENT_FAILURE_UNKNOWN')
        self.assertFalse(result['causal_queue_reason_claimed'])
        frozen._client.assert_called_once()

    def test_frozen_base_pin_before_execution(self):
        with self.assertRaisesRegex(m.HostInspectionError,'FROZEN_BASE_PIN'):
            m._base(b'raise RuntimeError("not executed")')

    def test_prepare_local_only_exact_review_and_independent_base_namespace(self):
        source=PATH.with_name('register_acceptance_job_e98.py').read_bytes()
        with mock.patch('subprocess.Popen') as spawn:
            frozen=m._base(source)
            plan=m.prepare_payload(m.sha(PATH.read_bytes()))
        spawn.assert_not_called()
        self.assertIsNot(frozen.__dict__,m.__dict__)
        self.assertEqual(plan['response_cap'],32768)
        compile(plan['payload'],'<not executed>','exec')
        with self.assertRaisesRegex(m.HostInspectionError,'HELPER_REVIEW_PIN'):
            m.prepare_payload('0'*64)

    def test_python36_no_automatic_entry_or_argument_extension(self):
        source=PATH.read_text()
        kwargs={'feature_version':(3,6)} if sys.version_info>=(3,8) else {}
        ast.parse(source,**kwargs)
        self.assertNotIn('__main__',source)
        self.assertNotIn('os.listdir',source)
        self.assertNotIn('transport(',source)
        with self.assertRaises(TypeError): m.observe(b'', ['extra'])


class ControllerTests(unittest.TestCase):
    def response(self):
        return dict(schema='e98-host-queue-observation-v1',host='bupt-vncs2',job_scope=394238,
            observation_only=True,jobs_submitted=0,resume_calls=0,cancellation_calls=0,
            client_status='CLIENT_COMPLETE',client_returncode=0)

    def invoke(self, response, argv=None):
        from scripts import execute_acceptance_host_queue_e98 as controller
        with mock.patch.object(controller.sys,'argv',argv or ['controller','helper_sha','payload_sha']), \
                mock.patch.object(controller.inspector,'prepare_payload',return_value=dict(
                    payload=b'reviewed payload',response_cap=32768)) as prepare, \
                mock.patch.object(controller.control,'execute_phase',return_value=dict(
                    phase='exclusive_local_phase',response=response)) as execute, \
                mock.patch('builtins.print'):
            controller.main()
        return prepare,execute

    def test_fixed_operation_payload_and_cap(self):
        prepare,execute=self.invoke(self.response())
        prepare.assert_called_once_with('helper_sha')
        execute.assert_called_once_with('host_queue_observation',b'reviewed payload','payload_sha',32768)

    def test_bad_identity_and_mutation_flags_rejected(self):
        for key,value in (('schema','other'),('host','other'),('job_scope',394230),
                          ('observation_only',False),('jobs_submitted',1),('jobs_submitted',False),
                          ('resume_calls',1),('resume_calls',False),
                          ('cancellation_calls',1),('cancellation_calls',False)):
            response=self.response();response[key]=value
            with self.assertRaisesRegex(ValueError,'FIXED_HOST_OBSERVATION_IDENTITY'):
                self.invoke(response)

    def test_wrong_argument_count_never_prepares_or_transports(self):
        from scripts import execute_acceptance_host_queue_e98 as controller
        for argv in (['controller'],['controller','one'],['controller','one','two','three']):
            with mock.patch.object(controller.sys,'argv',argv), \
                    mock.patch.object(controller.inspector,'prepare_payload') as prepare, \
                    mock.patch.object(controller.control,'execute_phase') as execute:
                with self.assertRaisesRegex(ValueError,'REVIEWED_HELPER_AND_PAYLOAD_SHA_REQUIRED'):
                    controller.main()
                prepare.assert_not_called();execute.assert_not_called()

    def test_failed_unknown_or_invalid_returncode_is_not_complete_and_never_retried(self):
        from scripts import execute_acceptance_host_queue_e98 as controller
        for changes in (dict(client_returncode=1),dict(client_returncode=None),
                        dict(client_returncode=False),dict(client_returncode=True),
                        dict(client_status='CLIENT_FAILURE_UNKNOWN'),dict(client_status='UNKNOWN')):
            response=self.response();response.update(changes)
            with mock.patch.object(controller.sys,'argv',['controller','helper_sha','payload_sha']), \
                    mock.patch.object(controller.inspector,'prepare_payload',return_value=dict(
                        payload=b'reviewed payload',response_cap=32768)), \
                    mock.patch.object(controller.control,'execute_phase',return_value=dict(
                        phase='exclusive_local_phase',response=response)) as execute:
                with self.assertRaisesRegex(ValueError,'HOST_QUERY_NOT_COMPLETE_EVIDENCE_SAVED_NO_RETRY'):
                    controller.main()
                execute.assert_called_once_with('host_queue_observation',b'reviewed payload','payload_sha',32768)


if __name__=='__main__': unittest.main()
