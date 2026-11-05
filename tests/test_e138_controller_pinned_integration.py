"""Real controller + pinned helper; mocked SSH/keygen only, no live authority."""
import copy
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from scripts import e138_controller as m
from scripts import e138_pinned_transport as pinned
from tests import test_e138_controller as boundary
from tests import test_e138_controller_native_integration as native
from tests import test_e138_pinned_transport as transport_fixture


class Tests(unittest.TestCase):
    def setUp(self):
        self.base=boundary.Tests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.release=dict(authorization_sha256=self.base.auth,proposal_sha256=self.base.prop,
            adapter_source_sha256=m.sha(Path(pinned.__file__).read_bytes()),
            host=pinned.HOST,host_key=pinned.HOST_KEY,helper_sha256=pinned.HELPER_SHA256,
            scope=pinned.PinnedTransport.scope,local_source_sha256=m.local_source_closure(),
            roles={role:None for role in m.ROLES})
        self.patch(m,'AUTHORIZATION_SHA256',self.base.auth)
        self.patch(m,'PROPOSAL_SHA256',self.base.prop)
        self.patch(m,'PINNED_RELEASE',self.release)
        self.patch(pinned,'AUTHORIZATION_SHA256',self.base.auth)
        self.patch(pinned,'PROPOSAL_SHA256',self.base.prop)
        self.patch(pinned,'FROZEN',dict(authorization_sha256=self.base.auth,proposal_sha256=self.base.prop))

    def patch(self,obj,key,value):
        p=mock.patch.object(obj,key,value,create=True);p.start();self.addCleanup(p.stop)

    def create(self):
        return m.Controller.create_pinned(self.base.tmp.name,self.base.authority,self.base.proposal)

    def review(self,c):
        material=self.base.material
        descriptor=copy.deepcopy(self.base.release['roles']['capture'])
        plan=m._private_function(m.packet.prepare,EXPECTED=descriptor['packet'])(**material)
        review=m.canonical(dict(projection=plan['projection'],projection_sha256=plan['projection_sha256'],
            payload_sha256=m.sha(plan['payload']),remote_command=plan['remote_command'],host=pinned.HOST,
            scope=pinned.PinnedTransport.scope,host_key=pinned.HOST_KEY,helper_sha256=pinned.HELPER_SHA256,
            adapter_source_sha256=self.release['adapter_source_sha256'],
            local_source_sha256=self.release['local_source_sha256']))
        descriptor['review_sha256']=m.sha(review)
        c.install_review('capture',descriptor)
        return material,review

    def capture_frame(self):
        fixture=native.NativeTests();fixture.base=self.base
        self.addCleanup(fixture.doCleanups)
        return fixture.capture()

    def mock_key(self,c):
        fixture=transport_fixture.Tests()
        self.addCleanup(fixture.doCleanups)
        return fixture.key(c.adapter)

    def test_default_factory_denies_before_io_or_adapter_constructor(self):
        with mock.patch.object(m,'PINNED_RELEASE',None),mock.patch.object(Path,'read_bytes') as read, \
                mock.patch.object(pinned.PinnedTransport,'__init__') as constructor:
            with self.assertRaisesRegex(ValueError,'NO_PINNED_RELEASE'):self.create()
        read.assert_not_called();constructor.assert_not_called()

    def test_capture_success_persists_full_native_before_seven_key_projection(self):
        c=self.create();frame=self.capture_frame();key=self.mock_key(c)
        process=transport_fixture.Process();process.stdout=__import__('io').BytesIO(frame)
        with mock.patch('subprocess.Popen',return_value=process) as spawn:
            receipt=c.run_role(*self.review(c))
        root=c.store.phase/'capture'
        saved=m.contract.decode((root/'native_transport.json').read_bytes())
        self.assertEqual(set(saved['result']),pinned.RESULT_KEYS)
        self.assertIs(saved['result']['remote_termination_verified'],False)
        self.assertEqual((root/'native_stdout.raw').read_bytes(),frame)
        self.assertEqual((root/'stdout.raw').read_bytes(),frame)
        self.assertNotIn('remote_termination_verified',m.contract.decode((root/'transport.json').read_bytes()))
        self.assertIs(m.contract.decode(receipt)['remote_authentication_proven'],False)
        self.assertEqual(c.original_clock,(c.store.phase/'original_clock.json').read_bytes())
        self.assertEqual(spawn.call_count,1);self.assertEqual(key.call_count,1)

    def test_malformed_eighth_field_preserves_raw_then_terminal(self):
        for flag in (True,0,'False',None,'MISSING','EXTRA'):
            with self.subTest(flag=flag),tempfile.TemporaryDirectory() as staging:
                c=m.Controller.create_pinned(staging,self.base.authority,self.base.proposal)
                result=dict(stdout=b'raw-prefix',stderr=b'',exit_code=0,timeout=False,overflow=False,
                    write_failed=False,threads_incomplete=False,remote_termination_verified=flag)
                if flag=='MISSING':result.pop('remote_termination_verified')
                if flag=='EXTRA':result.update(remote_termination_verified=False,unknown_private_object=object())
                with mock.patch.object(c.adapter,'send',return_value=result), \
                        mock.patch.object(m.clock,'build') as validate:
                    with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(*self.review(c))
                validate.assert_not_called()
                self.assertEqual((c.store.phase/'capture/native_stdout.raw').read_bytes(),b'raw-prefix')
                self.assertEqual((c.store.phase/'capture/stdout.raw').read_bytes(),b'raw-prefix')
                saved=(c.store.phase/'capture/native_transport.json').read_bytes()
                self.assertNotIn(b'unknown_private_object',saved)
                self.assertTrue(c.terminal)

    def test_stderr_above_store_cap_is_retained_in_full_native_evidence(self):
        c=self.create();stderr=b'e'*65537
        result=dict(stdout=b'prefix',stderr=stderr,exit_code=0,timeout=False,overflow=False,
            write_failed=False,threads_incomplete=False,remote_termination_verified=False)
        with mock.patch.object(c.adapter,'send',return_value=result),mock.patch.object(m.clock,'build') as validate:
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(*self.review(c))
        validate.assert_not_called()
        self.assertEqual((c.store.phase/'capture/native_stderr.raw').read_bytes(),stderr)
        saved=m.contract.decode((c.store.phase/'capture/native_transport.json').read_bytes())
        self.assertEqual(saved['result']['stderr']['sha256'],m.sha(stderr))
        self.assertFalse(saved['result']['stderr']['prefix_only'])

    def test_transitive_dependency_drift_denies_before_adapter(self):
        self.release['local_source_sha256']['src.data.prospective_generation_process_e113']='0'*64
        with mock.patch.object(pinned.PinnedTransport,'__init__') as constructor:
            with self.assertRaisesRegex(ValueError,'SOURCE_CLOSURE'):self.create()
        constructor.assert_not_called()
        self.assertFalse((Path(self.base.tmp.name)/m.storage.PHASE).exists())

    def test_constructor_elapsed_time_closes_original_phase_without_reset(self):
        original=pinned.PinnedTransport.__init__;now=m.time.monotonic;offset=[0.]
        def delayed(adapter,*args):
            original(adapter,*args);offset[0]=3601.
        with mock.patch.object(pinned.PinnedTransport,'__init__',delayed), \
                mock.patch.object(m.time,'monotonic',side_effect=lambda:now()+offset[0]):
            with self.assertRaisesRegex(ValueError,'CONSTRUCTION_FAILED'):self.create()
        phase=Path(self.base.tmp.name)/m.storage.PHASE
        self.assertTrue((phase/'start.json').exists());self.assertTrue((phase/'closed.json').exists())

    def test_full_receipt_write_failure_stops_without_validation_or_retry(self):
        c=self.create();original=m.storage.write_new
        def write(path,raw):
            if path.name=='native_transport.json':raise OSError('PRIVATE_WRITE_FAILURE')
            return original(path,raw)
        result=dict(stdout=b'prefix',stderr=b'',exit_code=0,timeout=False,overflow=False,
            write_failed=False,threads_incomplete=False,remote_termination_verified=False)
        with mock.patch.object(c.adapter,'send',return_value=result), \
                mock.patch.object(m.storage,'write_new',side_effect=write),mock.patch.object(m.clock,'build') as validate:
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(*self.review(c))
        validate.assert_not_called();self.assertTrue(c.terminal)
        self.assertEqual((c.store.phase/'capture/native_stdout.raw').read_bytes(),b'prefix')

    def test_bad_native_fields_never_serialize_private_values(self):
        c=self.create()
        result=dict(stdout=b'prefix',stderr=b'',exit_code='PRIVATE_EXIT',timeout='PRIVATE_TIMEOUT',
            overflow=False,write_failed=False,threads_incomplete=False,
            remote_termination_verified='PRIVATE_REMOTE_FLAG')
        with mock.patch.object(c.adapter,'send',return_value=result):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(*self.review(c))
        saved=(c.store.phase/'capture/native_transport.json').read_bytes()
        self.assertNotIn(b'PRIVATE',saved)
        self.assertIn(b'invalid_native_field',saved)

    def test_adapter_exception_is_local_failure_not_invented_native_receipt(self):
        c=self.create()
        with mock.patch.object(c.adapter,'send',side_effect=OSError('PRIVATE_ADAPTER_EXCEPTION')):
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(*self.review(c))
        saved=m.contract.decode((c.store.phase/'capture/native_transport.json').read_bytes())
        self.assertEqual(saved['receipt_origin'],'LOCAL_ADAPTER_EXCEPTION')
        self.assertFalse(saved['native_result_received']);self.assertFalse(saved['exact_native_keys'])
        self.assertEqual(saved['result']['remote_termination_verified'],{'missing':True})

    def test_source_recheck_elapsed_time_is_debited_before_send(self):
        c=self.create();material,review=self.review(c)
        original=m.local_source_closure;now=m.time.monotonic;offset=[0.]
        def slow():
            result=original();offset[0]=3601.;return result
        with mock.patch.object(m,'local_source_closure',side_effect=slow), \
                mock.patch.object(m.time,'monotonic',side_effect=lambda:now()+offset[0]), \
                mock.patch.object(c.adapter,'send') as send:
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(material,review)
        send.assert_not_called()
        self.assertTrue((c.store.phase/'capture/intent.json').exists())

    def test_identity_bound_review_rejects_simulation_scope(self):
        c=self.create();material,review=self.review(c)
        changed=m.contract.decode(review);changed['scope']='LOCAL_SIMULATION_ONLY'
        changed=m.canonical(changed)
        c.freeze['roles']['capture']['review_sha256']=m.sha(changed)
        with mock.patch.object(c.adapter,'send') as send:
            with self.assertRaisesRegex(ValueError,'STOPPED_FIRST_FAILURE'):c.run_role(material,changed)
        send.assert_not_called()


if __name__=='__main__':unittest.main()
