"""Actual local capture preparation, no deployment or remote operations.

Native receipt fixture uses explicitly synthetic source metadata/clock only.
No successful fake transport/validator stands in for a real capture.
"""
import copy
import datetime
import pickle
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from scripts import run_physical_f_clean_replay_e138 as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch('subprocess.Popen') as spawn,mock.patch('subprocess.run') as query, \
                mock.patch.object(m.controller.storage.PhaseStore,'create') as create:
            cls.prepared=m.prepare_capture()
        spawn.assert_not_called();query.assert_not_called();create.assert_not_called()

    def record(self,prepared=None):
        prepared=prepared or self.prepared
        return m.canonical(dict(schema='e138-independent-exact-packet-review-v1',role=prepared._role,
            request_sha256=m.sha(m.canonical(prepared.public_review_request())),
            review_scope='EXACT_PAYLOAD_COMMAND_SOURCE_POLICY'))

    def test_actual_grant_packet_hashes_and_no_fake_current_outputs(self):
        p=self.prepared;request=p.public_review_request()
        self.assertEqual(request['authorization_sha256'],m.AUTH_SHA256)
        self.assertEqual(request['proposal_sha256'],m.PROPOSAL_SHA256)
        self.assertEqual(request['payload_bytes'],483685)
        self.assertEqual(request['payload_sha256'],'9da7a8aec1ffddff883212f82bfa1db0d30338a4d4f2f61ada54fbd65e023b12')
        self.assertEqual(set(p._material['inputs']),{'authority','proposal'})
        self.assertEqual(len(request['projection']['source_sha256']),35)
        self.assertEqual(m.sha(p._plan['remote_command'].encode('utf-8')),request['command_sha256'])
        self.assertIsNone(request['previous_role_accepted_sha256'])
        self.assertNotIn('original_clock',p._material['inputs'])
        self.assertFalse(request['execution_ready'])

    def test_default_start_denies_before_phase_clock_or_process(self):
        with mock.patch.object(m,'REVIEW_PINS',None),mock.patch.object(m.controller.Controller,'create_pinned') as create, \
                mock.patch('subprocess.Popen') as spawn,mock.patch('subprocess.run') as query:
            with self.assertRaisesRegex(ValueError,'INDEPENDENT_REVIEW_PIN_REQUIRED'):
                m.start(self.prepared,self.record())
        create.assert_not_called();spawn.assert_not_called();query.assert_not_called()

    def test_independently_installed_record_exact_binding_only(self):
        record=self.record()
        with mock.patch.object(m,'REVIEW_PINS',{'capture':m.sha(record)}), \
                mock.patch.object(m.controller.Controller,'create_pinned') as create:
            m._check_review(self.prepared,record)
            with self.assertRaisesRegex(ValueError,'RECORD_PIN'):
                m._check_review(self.prepared,record+b' ')
        create.assert_not_called()
        fake=m.canonical(dict(status='PASS'))
        with mock.patch.object(m,'REVIEW_PINS',{'capture':m.sha(fake)}):
            with self.assertRaisesRegex(ValueError,'RECORD_BINDING'):m._check_review(self.prepared,fake)

    def test_candidate_payload_drift_not_released_by_original_review(self):
        p=m.Prepared()
        for name in m.Prepared.__slots__:setattr(p,name,getattr(self.prepared,name))
        p._plan=dict(p._plan,payload=p._plan['payload']+b'# drift')
        record=self.record()
        with mock.patch.object(m,'REVIEW_PINS',{'capture':m.sha(record)}):
            with self.assertRaisesRegex(ValueError,'PACKET_DRIFT'):m._check_review(p,record)

    def test_transient_configuration_restored_after_failure(self):
        names=((m.controller,'AUTHORIZATION_SHA256'),(m.controller,'PROPOSAL_SHA256'),
            (m.controller,'PINNED_RELEASE'),(m.transport,'AUTHORIZATION_SHA256'),
            (m.transport,'PROPOSAL_SHA256'),(m.transport,'FROZEN'))
        before=[getattr(module,name) for module,name in names]
        with self.assertRaisesRegex(RuntimeError,'synthetic'):
            with m._configuration(self.prepared._release):
                self.assertEqual(m.controller.AUTHORIZATION_SHA256,m.AUTH_SHA256)
                self.assertEqual(m.transport.FROZEN['proposal_sha256'],m.PROPOSAL_SHA256)
                raise RuntimeError('synthetic')
        for (module,name),value in zip(names,before):self.assertIs(getattr(module,name),value)

    def test_private_actual_native_clock_accepts_synthetic_receipt_without_global_tag_mutation(self):
        from tests.test_physical_replay_capture_e138 import CaptureTests
        cap=m.controller.clock.capture
        case=CaptureTests();case.setUp()
        try:
            case.authority=self.prepared._authority;case.proposal=self.prepared._proposal
            with mock.patch.object(cap,'AUTH_SHA',m.AUTH_SHA256),mock.patch.object(cap,'PROPOSAL_SHA',m.PROPOSAL_SHA256):
                receipt=case.capture()
            constants={name:copy.deepcopy(getattr(cap,name)) for name in ('PATTERN','INPUT_PINS','TREE_PIN')}
        finally:case.doCleanups()
        old_modules={k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')}
        old_tag=getattr(cap.contract,'__source_sha256__',None)
        private=m._private_capture_clock(self.prepared)
        private_cap=private.build.__globals__['capture']
        for name,value in constants.items():setattr(private_cap,name,value)
        utc=datetime.datetime(2026,11,6,tzinfo=datetime.timezone.utc)
        domain=dict(host='synthetic-local',clock='synthetic-monotonic')
        start=dict(schema='e138-local-original-clock-v1',authorization_sha256=m.AUTH_SHA256,
            proposal_sha256=m.PROPOSAL_SHA256,start=1000.,end=4600.,domain=domain,
            utc_start=utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
            utc_end=(utc+datetime.timedelta(seconds=3600)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
        frame=dict(role='capture',capture=receipt,boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
            remote_start_monotonic=50000.,remote_sample_monotonic=50000.,
            remote_utc_sample=utc.strftime('%Y-%m-%dT%H:%M:%S.%f%z'),execution_ready=False)
        raw=private.build(m.canonical(frame),m.canonical(start),m.sha(self.prepared._plan['payload']),
            self.prepared._authority,self.prepared._proposal,m.AUTH_SHA256,m.PROPOSAL_SHA256,
            1001.,utc.timestamp()+1,domain)
        self.assertEqual(m.contract.decode(raw)['start_file_sha256'],m.sha(m.canonical(start)))
        self.assertEqual(old_modules,{k:v for k,v in sys.modules.items() if k=='src' or k.startswith('src.')})
        self.assertEqual(getattr(cap.contract,'__source_sha256__',None),old_tag)
        self.assertIsNot(private_cap,cap)

    def test_staged_preparation_failure_closes_original_phase_without_retry(self):
        for role,index in (('execution',1),('readback',2)):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as temporary:
                c=types.SimpleNamespace(index=index,terminal=False,authority=self.prepared._authority,
                    proposal=self.prepared._proposal,original_clock=b'synthetic-clock',
                    store=types.SimpleNamespace(phase=Path(temporary),remaining=lambda:3000))
                def stop(reason):c.terminal=True
                c._stop=stop
                run=m.ReviewedRun();run._controller=c;run._capture=self.prepared
                run._execution=self.prepared;run._accepted={}
                with self.assertRaisesRegex(ValueError,'STAGED_PREPARATION_STOPPED_FIRST_FAILURE') as caught:
                    getattr(run,'prepare_'+role)()
                self.assertTrue(c.terminal);self.assertIsNone(caught.exception.__context__)
                with self.assertRaisesRegex(ValueError,'STAGED_PREPARATION_STOPPED_FIRST_FAILURE'):
                    getattr(run,'prepare_'+role)()

    def test_private_material_not_accidentally_serialized(self):
        with self.assertRaisesRegex(TypeError,'NOT_SERIALIZABLE'):pickle.dumps(self.prepared)
        self.assertIn('PRIVATE_RAM_ONLY',repr(self.prepared))
        request=self.prepared.public_review_request()
        self.assertNotIn('payload',request);self.assertNotIn('remote_command',request)
        self.assertLessEqual(len(m.canonical(request)),65536)


if __name__=='__main__':unittest.main()
