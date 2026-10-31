"""Pure joins of a native receipt produced by actual methods over virtual FS."""
import copy
import unittest
from unittest import mock
from src.data import physical_e138_role2_join as m


class Tests(unittest.TestCase):
    def setUp(self):
        from tests.test_physical_e138_root_receipt import ReceiptTests
        self.case=ReceiptTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        response=m.decode(self.case.response);response['status']='OBSERVED_PENDING_SCIENTIFIC_AUDIT'
        self.case.response=m.canonical(response)
        session,files=self.case.create()
        self.receipt=session.emit(files,self.case.response,self.case.observation)
        self.outer=dict(role='execution',worker_response=response,owned_root=self.receipt,
            cleanup_observation=m.decode(self.case.observation),execution_ready=False)
        self.package={key:self.case.package[key] for key in ('authority','proposal','original_clock','role2_intent')}
        self.package.update(role2_stdout=m.canonical(self.outer),role2_stderr=b'',
            role3_intent=m.canonical(dict(role='readback',attempt_consumed=True,role_index=3,
                connections_max=3,automatic_retries=0,payload_sha256='a'*64)))
        self.frozen=dict(raw_sha256={},role2_payload_sha256=m.decode(self.package['role2_intent'])['payload_sha256'],
            role3_payload_sha256='a'*64,input_bindings=copy.deepcopy(self.receipt['input_bindings']),
            cleanup_observer_source_sha256=self.receipt['cleanup_observer_source_sha256'])
        self.update_raw()
        patch=mock.patch.object(m,'FREEZE',self.frozen);patch.start();self.addCleanup(patch.stop)

    def update_raw(self):
        self.package['role2_stdout']=m.canonical(self.outer)
        self.package['role2_transport']=m.canonical(dict(exit_code=0,timeout=False,overflow=False,
            write_failed=False,threads_incomplete=False,stdout_bytes=len(self.package['role2_stdout']),stderr_bytes=0,
            stdout_sha256=m.sha(self.package['role2_stdout']),stderr_sha256=m.sha(b'')))
        self.refreeze()

    def refreeze(self):
        # Synthetic expected pins only, never a production trust origin.
        self.frozen['raw_sha256']={key:m.sha(raw) for key,raw in self.package.items()}

    def test_actual_native_receipt_pure_join_and_default_denial(self):
        with mock.patch('builtins.open') as opened,mock.patch('time.monotonic') as now:
            context=m.join(self.package)
            with mock.patch.object(m,'FREEZE',None):
                with self.assertRaisesRegex(ValueError,'E138_JOIN_FREEZE_REQUIRED'):m.join(None)
        opened.assert_not_called();now.assert_not_called()
        self.assertEqual(context['identity'],self.receipt['identity'])
        self.assertEqual(context['proposal_sha256'],m.sha(self.package['proposal']))

    def test_raw_drift_and_payload_replay_rejected(self):
        with self.assertRaisesRegex(ValueError,'E138_JOIN_RAW_PIN'):
            m.join(dict(self.package,role2_stdout=self.package['role2_stdout']+b' '))
        self.frozen['role3_payload_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'E138_JOIN_CONSUMED_INTENT'):m.join(self.package)

    def test_transport_failure_or_nonzero_exit_rejected_even_with_synthetic_refreeze(self):
        original=self.package['role2_transport']
        for change in (dict(exit_code=1),dict(exit_code=False),dict(timeout=True),dict(stdout_bytes=True)):
            transport=m.decode(original);transport.update(change)
            self.package['role2_transport']=m.canonical(transport);self.refreeze()
            with self.assertRaisesRegex(ValueError,'E138_JOIN_COMPLETE_TRANSPORT_REQUIRED'):m.join(self.package)

    def test_missing_root_unknown_cleanup_and_mutated_hash_reject(self):
        original=copy.deepcopy(self.outer)
        for change in ('no_root','cleanup','hash','identity','birth_bool'):
            self.outer=copy.deepcopy(original)
            if change=='no_root':self.outer['owned_root']=None
            elif change=='cleanup':self.outer['cleanup_observation']['cleaned']=False
            elif change=='hash':self.outer['owned_root']['worker_response_sha256']='0'*64
            elif change=='identity':self.outer['owned_root']['identity']['st_uid']=0
            else:self.outer['owned_root']['birth_continuity']['st_dev']=True
            self.update_raw()
            with self.assertRaises(ValueError):m.join(self.package)

    def test_cleaned_tool_failure_remains_readable_but_not_scientific_pass(self):
        self.outer['worker_response']['status']='STOPPED_FIRST_FAILURE'
        self.outer['owned_root']['worker_response_sha256']=m.sha(m.canonical(self.outer['worker_response']))
        self.update_raw()
        self.assertEqual(m.join(self.package)['root'],m.contract.ROOT)

    def test_snapshot_scope_and_flags_are_strict(self):
        original=copy.deepcopy(self.outer)
        for change in (dict(final_snapshot_monotonic=True),dict(final_snapshot_monotonic=4600.),
                dict(physical_D95_verified=True),dict(full_role2_transport_authenticated=True)):
            self.outer=copy.deepcopy(original);self.outer['owned_root'].update(change);self.update_raw()
            with self.assertRaisesRegex(ValueError,'E138_JOIN_RECEIPT_SCOPE'):m.join(self.package)
