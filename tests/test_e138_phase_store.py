"""Temporary local evidence only; no real grant, host or tool invocation."""
import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import e138_phase_store as m


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=m.PhaseStore(self.tmp.name,'a'*64,'b'*64)
        self.result=dict(stdout=b'{"synthetic":true}',stderr=b'',exit_code=0,
            timeout=False,overflow=False,write_failed=False,threads_incomplete=False)

    def begin(self):self.store.create();return self.store.reserve('capture','c'*64)

    def test_no_io_or_subprocess_on_construction(self):
        with mock.patch('subprocess.Popen') as spawn,mock.patch.object(m,'write_new') as write:
            m.PhaseStore(self.tmp.name,'a'*64,'b'*64)
        spawn.assert_not_called();write.assert_not_called()

    def test_phase_create_exclusive_no_restart(self):
        self.store.create()
        second=m.PhaseStore(self.tmp.name,'a'*64,'b'*64)
        with self.assertRaises(FileExistsError):second.create()
        with self.assertRaisesRegex(m.StoreFailure,'CREATE_ONCE'):self.store.create()

    def test_validator_observes_all_fsynced_raw_before_decode(self):
        self.begin();directory=self.store.phase/'capture'
        def validate(stdout,stderr,transport):
            self.assertEqual((directory/'stdout.raw').read_bytes(),stdout)
            self.assertEqual((directory/'stderr.raw').read_bytes(),stderr)
            self.assertEqual((directory/'transport.json').read_bytes(),transport)
            self.assertFalse((directory/'accepted.json').exists())
            self.assertEqual(json.loads(transport)['stdout_sha256'],m.sha(stdout))
            return b'fixed synthetic validation'
        self.assertEqual(self.store.record(self.result,validate),b'fixed synthetic validation')
        accepted=json.loads((directory/'accepted.json').read_bytes())
        self.assertFalse(accepted['remote_authentication_proven']);self.assertFalse(accepted['execution_ready'])

    def test_raw_invalid_json_is_retained_before_validator_failure(self):
        self.begin();self.result['stdout']=b'not JSON PRIVATE'
        def bad(*args):raise ValueError('PRIVATE')
        with self.assertRaisesRegex(m.StoreFailure,'VALIDATION_FAILED_NO_RETRY') as caught:
            self.store.record(self.result,bad)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual((self.store.phase/'capture/stdout.raw').read_bytes(),b'not JSON PRIVATE')
        self.assertNotIn(b'PRIVATE',(self.store.phase/'closed.json').read_bytes())
        with self.assertRaises(m.StoreFailure):self.store.reserve('execution','d'*64)

    def test_every_transport_failure_retains_raw_and_skips_validation(self):
        for changes in ({'exit_code':None},{'exit_code':1},{'stderr':b'PRIVATE'},
                {'timeout':True},{'overflow':True},{'write_failed':True},{'threads_incomplete':True}):
            with self.subTest(changes=changes),tempfile.TemporaryDirectory() as tmp:
                store=m.PhaseStore(tmp,'a'*64,'b'*64);store.create();store.reserve('capture','c'*64)
                validator=mock.Mock();result=dict(self.result,**changes)
                with self.assertRaisesRegex(m.StoreFailure,'TRANSPORT_FAILED_NO_RETRY'):store.record(result,validator)
                validator.assert_not_called();self.assertEqual((store.phase/'capture/stdout.raw').read_bytes(),result['stdout'])
                self.assertTrue((store.phase/'closed.json').exists())

    def test_order_single_use_and_three_roles(self):
        self.store.create()
        for role in m.ROLES:
            intent=self.store.reserve(role,'c'*64)
            self.assertEqual(intent['role_index'],m.ROLES.index(role)+1)
            with self.assertRaises(m.StoreFailure):self.store.reserve(role,'c'*64)
            self.store.record(self.result,lambda *args:b'not scientific proof')
        with self.assertRaises(m.StoreFailure):self.store.reserve('capture','c'*64)

    def test_no_skipping_roles(self):
        self.store.create()
        for role in ('execution','readback'):
            with self.assertRaises(m.StoreFailure):self.store.reserve(role,'c'*64)
        self.assertFalse((self.store.phase/'execution').exists())

    def test_partial_save_failure_keeps_tombstone_and_no_validator(self):
        self.begin();real=m.write_new;validator=mock.Mock()
        def write(path,raw):
            if path.name=='stderr.raw':raise OSError('PRIVATE')
            return real(path,raw)
        with mock.patch.object(m,'write_new',side_effect=write):
            with self.assertRaisesRegex(m.StoreFailure,'RAW_SAVE_FAILED'):self.store.record(self.result,validator)
        validator.assert_not_called();self.assertTrue((self.store.phase/'capture/stdout.raw').exists())
        self.assertFalse((self.store.phase/'capture/accepted.json').exists())
        with self.assertRaises(m.StoreFailure):self.store.reserve('capture','c'*64)

    def test_clock_not_reset_and_expired_before_reserve(self):
        self.store.create();start=(self.store.phase/'start.json').read_bytes()
        with mock.patch.object(m.time,'monotonic',return_value=self.store._start+3601):
            with self.assertRaisesRegex(m.StoreFailure,'ORIGINAL_CLOCK'):self.store.reserve('capture','c'*64)
        self.assertEqual(start,(self.store.phase/'start.json').read_bytes())
        self.assertFalse((self.store.phase/'capture').exists())

    def test_exact_types_and_caps(self):
        for changes in ({'exit_code':True},{'timeout':0},{'stdout':b'x'*6291457},{'stderr':b'x'*65537}):
            with self.subTest(changes=list(changes)),tempfile.TemporaryDirectory() as tmp:
                store=m.PhaseStore(tmp,'a'*64,'b'*64);store.create();store.reserve('capture','c'*64)
                validator=mock.Mock()
                with self.assertRaisesRegex(m.StoreFailure,'BOUNDED_TRANSPORT_RECORD'):
                    store.record(dict(self.result,**changes),validator)
                with self.assertRaises(m.StoreFailure):store.record(self.result,validator)
                with self.assertRaises(m.StoreFailure):store.reserve('execution','c'*64)
                validator.assert_not_called()

    def test_start_write_failure_is_terminal_even_without_close_record(self):
        with mock.patch.object(m,'write_new',side_effect=OSError('PRIVATE')):
            with self.assertRaisesRegex(m.StoreFailure,'START_SAVE_FAILED') as caught:self.store.create()
        self.assertIsNone(caught.exception.__context__)
        self.assertTrue(self.store.phase.is_dir())
        with self.assertRaises(m.StoreFailure):self.store.reserve('capture','c'*64)
        with self.assertRaises(m.StoreFailure):self.store.create()

    def test_intent_write_failure_and_close_write_failure_are_terminal(self):
        self.store.create()
        with mock.patch.object(m,'write_new',side_effect=OSError('PRIVATE')):
            with self.assertRaisesRegex(m.StoreFailure,'INTENT_SAVE_FAILED') as caught:
                self.store.reserve('capture','c'*64)
        self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(m.StoreFailure):self.store.reserve('capture','c'*64)
        with tempfile.TemporaryDirectory() as tmp:
            store=m.PhaseStore(tmp,'a'*64,'b'*64);store.create();store.reserve('capture','c'*64)
            with mock.patch.object(m,'write_new',side_effect=OSError('PRIVATE')):
                with self.assertRaisesRegex(m.StoreFailure,'CLOSE_SAVE_FAILED') as caught:store.close('CONTROLLER_STOP')
            self.assertIsNone(caught.exception.__context__)
            with self.assertRaises(m.StoreFailure):store.record(self.result,lambda *a:b'ignored')

    def test_validation_receipt_bound_and_no_exception_leak(self):
        self.begin()
        with self.assertRaisesRegex(m.StoreFailure,'VALIDATION_FAILED_NO_RETRY'):
            self.store.record(self.result,lambda *args:b'x'*65537)
        self.assertFalse((self.store.phase/'capture/validation.raw').exists())

    def test_interrupt_and_missing_validator_cannot_replace_first_result(self):
        for validator in (None,mock.Mock(side_effect=KeyboardInterrupt)):
            with tempfile.TemporaryDirectory() as tmp:
                store=m.PhaseStore(tmp,'a'*64,'b'*64);store.create();store.reserve('capture','c'*64)
                with self.assertRaises(m.StoreFailure):store.record(self.result,validator)
                with self.assertRaises(m.StoreFailure):store.record(self.result,lambda *a:b'replacement')

    def test_python36_syntax(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
