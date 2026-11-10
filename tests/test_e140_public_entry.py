"""LOCAL E140 actual capture preparation; SYNTHETIC grant-read fixtures only.

Staged transitions are explicit doubles, not pinned construction or transport.
No actual E140 grant, phase, process or connection is created.
"""
import copy
from contextlib import contextmanager
import json
import types
import unittest
from unittest import mock
from scripts import run_physical_f_clean_replay_e140 as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sha=m.materials.origin.sha; s=m.session_source
        adapter=sha((m.REPO/s.SELF).read_bytes()); native,scripts=s.effective_maps()
        cls.freeze=dict(session=dict(origin_sha256=s.origin_manifest(adapter),adapter_sha256=adapter,
            effective_native_sha256=native,effective_script_sha256=scripts,binding_sha256=s.binding_digest()),
            origin_sha256=m.origin_manifest(sha((m.REPO/m.SELF).read_bytes())),
            effective_entry_sha256=m.candidate.EFFECTIVE_SHA256,binding_sha256=m.binding_digest())
        policy=json.loads(m.materials.prepare().private_bytes()['execution_inputs']['policy'])
        cls.authority=m.materials.origin.contract.canonical(dict(schema='e140-explicit-whole-package-authorization-v1',
            approved_package='E140',approval_source='explicit_user_reply',user_reply='SYNTHETIC NOT USER CONSENT',
            user_authorization_received=True,proposal_sha256=m.PROPOSAL_SHA256,approved_scope=policy,execution_ready=False))

    @contextmanager
    def configured(self):
        with mock.patch.object(m,'AUTH_SHA256',m.materials.origin.sha(self.authority)),mock.patch.object(m,'SOURCE_FREEZE',copy.deepcopy(self.freeze)):
            yield

    @contextmanager
    def grant_fixture(self,entry):
        namespace=entry._backend._facade._read.__func__.__globals__
        original=namespace['_bounded_read']
        def read(path,cap,pin,root):
            if path==m.REPO/'contracts/physical_f_clean_replay_authorization_e140.json':
                self.assertEqual(pin,m.materials.origin.sha(self.authority));return self.authority
            return original(path,cap,pin,root)
        with mock.patch.dict(namespace,_bounded_read=read):yield

    def test_default_zero_io_and_compile_and_future_reviews_denied(self):
        for auth in (None,'a'*64):
            with mock.patch.object(m,'AUTH_SHA256',auth),mock.patch('pathlib.Path.open') as opened,mock.patch('builtins.compile') as compiled:
                with self.assertRaises(ValueError):
                    with m.open_entry():pass
            opened.assert_not_called();compiled.assert_not_called()
        with self.configured(),mock.patch.object(m,'REVIEW_PINS',{'execution':'1'*64}),mock.patch('pathlib.Path.open') as opened:
            with self.assertRaises(ValueError):
                with m.open_entry():pass
        opened.assert_not_called()

    def test_actual_e140_capture35_effective_entry_wrapper_manifest_no_process(self):
        with self.configured(),m.open_entry() as entry,self.grant_fixture(entry),mock.patch('subprocess.Popen') as spawn,mock.patch('time.monotonic') as clock:
            prepared=entry.prepare_capture();request=prepared.public_review_request()
            self.assertEqual(request['schema'],'e140-independent-exact-packet-review-request-v1')
            pins=request['projection']['source_sha256'];self.assertEqual(len(pins),35)
            for name,pin in pins.items():self.assertEqual(pin,self.freeze['session']['effective_native_sha256'][name])
            manifest=request['entry_source_sha256']
            self.assertEqual(manifest[m.candidate.KEY],m.candidate.EFFECTIVE_SHA256)
            self.assertEqual(manifest['effective.scripts.e140_public_entry'],m.derivation.EFFECTIVE_SHA256)
            self.assertEqual(manifest['scripts.run_physical_f_clean_replay_e139'],m.derivation.ORIGIN_SHA256)
            self.assertEqual(manifest['bindings.e140_public_entry'],m.binding_digest())
            self.assertEqual(request['root'],m.session_source.native.ROOT)
            self.assertFalse(request['execution_ready'])
            self.assertNotIn('__file__',entry._backend._entry.__dict__)
        spawn.assert_not_called();clock.assert_not_called()

    def test_same_handle_staged_reviews_and_front_drift_proxy_denial(self):
        with self.configured(),m.open_entry() as entry,self.grant_fixture(entry):
            entry.install_review_pin('capture','1'*64)
            prepared=entry.prepare_capture()
            c=types.SimpleNamespace(index=1,terminal=False)
            entry._backend._session._controllers.append(c)
            native=types.SimpleNamespace(_controller=c,execute=mock.Mock(side_effect=lambda *a:setattr(c,'index',2)))
            with mock.patch.object(entry._backend._entry,'start',return_value=native):run=entry.start(prepared,b'TEST_ONLY_RECORD')
            entry.install_review_pin('execution','2'*64)
            run.execute('TEST_ONLY_PREPARED',b'TEST_ONLY_RECORD')
            entry.install_review_pin('readback','3'*64)
            self.assertIsNone(m.REVIEW_PINS)
            with self.assertRaises(ValueError):entry.install_review_pin('readback','4'*64)
            with mock.patch.object(m,'AUTH_SHA256','0'*64):
                with self.assertRaisesRegex(ValueError,'FRONT_CONFIGURATION_DRIFT'):run.prepare_readback()
        with self.assertRaisesRegex(ValueError,'ENTRY_CLOSED'):entry.prepare_capture()
        with self.assertRaisesRegex(ValueError,'ENTRY_CLOSED'):run.prepare_execution()
        self.assertIsNone(m.session_source.FROZEN)

    def test_effective_provider_origin_and_configuration_drift_refused(self):
        for failure in ('provider','effective_entry','origin','config'):
            with self.subTest(failure=failure),self.configured(),m.open_entry() as entry:
                b=entry._backend
                if failure=='provider':b._entry.SOURCE_BYTES=lambda key:b'UNREVIEWED'
                if failure=='effective_entry':b._entry_bytes+=b' '
                if failure=='origin':
                    b._frozen['origin_sha256']['scripts/e140_entry_candidate.py']='0'*64
                if failure=='config':b._entry.REVIEW_PINS={'execution':'0'*64}
                with self.assertRaises(ValueError):entry.prepare_capture()

    def test_unknown_sources_paths_reverse_derivation_and_no_oldglobal_changes(self):
        previous=(m.old.AUTH_SHA256,m.old.REVIEW_PINS,m.old.SOURCE_FREEZE)
        with self.configured(),m.open_entry() as entry:
            with self.assertRaises(ValueError):entry._backend._source_bytes('unknown')
            with self.assertRaises(ValueError):entry._backend._facade._read(m.REPO/'secret',4096)
        self.assertEqual(previous,(m.old.AUTH_SHA256,m.old.REVIEW_PINS,m.old.SOURCE_FREEZE))
        raw=(m.REPO/'scripts/run_physical_f_clean_replay_e139.py').read_bytes()
        effective=m.derivation.build(raw).private_sources()[m.derivation.KEY]
        for old,new,count in reversed(m.derivation.REPLACEMENTS):
            self.assertEqual(effective.count(new.encode()),count);effective=effective.replace(new.encode(),old.encode())
        self.assertEqual(effective,raw)


if __name__=='__main__':unittest.main()
