"""Offline packets and synthetic local ledger; no connection or tool launch."""
import ast
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import run_physical_f_clean_replay_e137 as m
from scripts import acceptance_transport_e98 as control


class Tests(unittest.TestCase):
    def test_actual_authority_exact_reply_and_no_engine_guess(self):
        repo = Path(__file__).resolve().parents[1]
        raw,proposal = (repo/m.AUTH).read_bytes(),(repo/m.PROPOSAL).read_bytes()
        m._authority(raw,proposal)
        self.assertEqual(m.decode(raw)['user_reply'],'\u90a3\u5c31\u6279\u51c6')
        self.assertIsNone(m.ENGINE_PATH_ALLOWLIST)
        self.assertFalse(m.readiness()['ready'])
        with self.assertRaises(ValueError):
            m._authority(raw+b' ',proposal)
        self.assertIsNone(m.capture.AUTH_SHA)

    def test_packet_complete_source_inert_loading_ast36(self):
        with mock.patch.object(control,'load_transport') as load:
            plan = m.prepare()
        load.assert_not_called()
        self.assertEqual(len(plan['source_sha256']),36)
        self.assertFalse(plan['readiness']['ready'])
        ast.parse(plan['payload'].decode('ascii'),feature_version=(3,6))
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        ast.parse(Path(__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        saved = {k:v for k,v in sys.modules.items() if k == 'src' or k.startswith('src.')}
        try:
            with mock.patch('builtins.open') as opened:
                exec(compile(plan['payload'].decode('ascii').split('result=sys.modules')[0],'<inert-e137-closure>','exec'),{})
            opened.assert_not_called()
        finally:
            for key in list(sys.modules):
                if key == 'src' or key.startswith('src.'):
                    del sys.modules[key]
            sys.modules.update(saved)

    def test_first_connection_blocked_even_exact_packet_review(self):
        plan = m.prepare()
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp)/'review.json'
            control.write_new(review,control.encode(dict(status='PASS',reviewed={k:plan[k] for k in m.REVIEW_KEYS})))
            with mock.patch.object(control,'load_transport') as load:
                with self.assertRaisesRegex(ValueError,'WHOLE_PACKAGE_ENGINE_BINDER_VALIDATOR_UNRESOLVED'):
                    m.execute('capture',review,plan['payload_sha256'])
            load.assert_not_called()
        with self.assertRaisesRegex(ValueError,'ENGINE_SELECTION_AND_ACK_PROTOCOL_UNRESOLVED'):
            m.prepare('execution')

    def test_create_once_roles_raw_first_failure_no_retry_clock_not_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = m.RoleLedger(tmp)
            first = ledger.reserve('capture','1'*64)
            started = (ledger.phase/'start.json').read_bytes()
            ledger.save_raw('capture',b'raw',b'',dict(exit_code=0))
            self.assertTrue((first/'stdout.json').exists())
            with self.assertRaises(FileExistsError):
                ledger.reserve('capture','1'*64)
            with self.assertRaisesRegex(ValueError,'PREVIOUS_ROLE_NOT_VALIDATED'):
                ledger.reserve('execution','2'*64)
            control.write_new(first/'validated.json',b'{}')
            with mock.patch.object(ledger,'validate_cached'):
                ledger.reserve('execution','2'*64)
            self.assertEqual(started,(ledger.phase/'start.json').read_bytes())
            ledger.close_failure('execution','SYNTHETIC_FAILURE')
            with self.assertRaisesRegex(ValueError,'FAILURE_EVIDENCE_ROOT_OWNERSHIP_UNPROVEN'):
                ledger.reserve('readback','3'*64)

    def test_failure_evidence_exception_not_replaced_by_json_or_bool(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = m.RoleLedger(tmp)
            first = ledger.reserve('capture','1'*64)
            control.write_new(first/'validated.json',b'{}')
            with mock.patch.object(ledger,'validate_cached'):
                second = ledger.reserve('execution','2'*64)
            ledger.close_failure('execution','SYNTHETIC_FAILURE')
            control.write_new(second/'owned_root_receipt.json',control.encode(dict(owned=True,root=m.ROOT)))
            with self.assertRaisesRegex(ValueError,'FAILURE_EVIDENCE_ROOT_RECEIPT_AUTHENTICATOR_UNAVAILABLE'):
                ledger.reserve('readback','3'*64)
            self.assertFalse((ledger.phase/'readback').exists())
            with self.assertRaisesRegex(ValueError,'FIRST_FAILURE_CLOSED_SCIENTIFIC_EXECUTION'):
                ledger.reserve('execution','2'*64)
            with mock.patch.object(m,'remaining',side_effect=ValueError('ORIGINAL_PACKAGE_EXPIRED')):
                with self.assertRaisesRegex(ValueError,'ORIGINAL_PACKAGE_EXPIRED'):
                    ledger.reserve('readback','3'*64)
            # Even an existing role3 intent cannot be retried after failure.
            (ledger.phase/'readback').mkdir()
            with self.assertRaisesRegex(ValueError,'FAILURE_EVIDENCE_ALREADY_CONSUMED'):
                ledger.reserve('readback','3'*64)

    def test_no_execution_debit_cannot_recover_and_new_clock_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = m.RoleLedger(tmp)
            ledger.reserve('capture','1'*64)
            ledger.close_failure('capture','SYNTHETIC_FAILURE')
            with self.assertRaisesRegex(ValueError,'FAILURE_EVIDENCE_REQUIRES_ROLE2_DEBIT'):
                ledger.reserve('readback','3'*64)
            first = m.decode((ledger.phase/'start.json').read_bytes())
            first['end'] += 3600
            with self.assertRaisesRegex(ValueError,'ORIGINAL_MONOTONIC_DEADLINE'):
                m.remaining(first)

    def test_fixed_new_outputs_only_no_sources_pdf_or_scan_search(self):
        self.assertEqual(len(m.OUTPUTS),len(set(m.OUTPUTS)))
        self.assertTrue(all(path == m.ROOT+'.initial_intent.json' or path.startswith(m.ROOT+'/') for path in m.OUTPUTS))
        self.assertTrue(all(not path.endswith(('.pdf','tester.stil')) for path in m.OUTPUTS))
        self.assertIn(m.ROOT+'/snapshots/loaded.patterns.rpt',m.OUTPUTS)
        self.assertIn(m.ROOT+'/journal/observation_exception.json',m.OUTPUTS)

    def test_cached_validation_not_file_existence_and_exact_hash_joins(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = m.RoleLedger(tmp)
            first = ledger.reserve('capture','1'*64)
            raw = m.canonical(dict(role='readback',execution_ready=False))
            intent = dict(role='readback',payload_sha256='3'*64,attempt_consumed=True,role_index=3,connections_max=3,automatic_retries=0)
            transport = dict(exit_code=0,timeout=False,overflow=False,write_failed=False,threads_incomplete=False,
                stdout_sha256=m.sha(raw),stderr_sha256=m.sha(b''))
            clock = (ledger.phase/'start.json').read_bytes()
            record = dict(schema='e137-local-role-validation-v1',role='readback',authorization_sha256=m.AUTH_SHA,
                clock_sha256=m.sha(clock),payload_sha256='3'*64,stdout_sha256=m.sha(raw),stderr_sha256=m.sha(b''),
                transport_sha256=m.sha(m.canonical(transport)))
            self.assertEqual(m.validate_cached_role(record,'readback',clock,intent,raw,b'',transport)['role'],'readback')
            for key,bad in [('role','capture'),('authorization_sha256','old'),('clock_sha256','new'),('payload_sha256','fake')]:
                with self.assertRaisesRegex(ValueError,'ROLE_VALIDATED_CONTENT_BINDING'):
                    m.validate_cached_role(dict(record,**{key:bad}),'readback',clock,intent,raw,b'',transport)
            control.write_new(first/'validated.json',b'{}')
            with self.assertRaises(Exception):ledger.reserve('execution','2'*64)

    def test_transport_raw_saved_before_failing_validator_no_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = m.RoleLedger(tmp)
            directory = ledger.reserve('capture',m.sha(b'inert'))
            helper = mock.Mock()
            helper.transport.return_value = dict(stdout=b'raw invalid',stderr=b'error',exit_code=0,timeout=False,
                overflow=False,write_failed=False,threads_incomplete=False)
            def reject(raw):
                self.assertEqual((directory/'stdout.json').read_bytes(),raw)
                self.assertTrue((directory/'transport.json').exists())
                raise ValueError('INVALID_ROLE_RESPONSE')
            with self.assertRaisesRegex(ValueError,'INVALID_ROLE_RESPONSE'):
                ledger.capture_transport('capture',helper,b'inert',100,reject)
            with self.assertRaisesRegex(ValueError,'FIRST_FAILURE_CLOSED_PACKAGE'):
                ledger.capture_transport('capture',helper,b'inert',100,reject)
            self.assertEqual(helper.transport.call_count,1)
            self.assertTrue((ledger.phase/'closed.json').exists())

    def test_transport_rejects_wrong_role_payload_false_debit_and_closed_package(self):
        for change in (dict(role='execution'),dict(payload_sha256='0'*64),dict(attempt_consumed=False),
                dict(connections_max=True),dict(unexpected=True)):
            with tempfile.TemporaryDirectory() as tmp:
                ledger = m.RoleLedger(tmp);directory=ledger.reserve('capture',m.sha(b'inert'))
                path=directory/'intent.json';value=m.decode(path.read_bytes());value.update(change)
                with path.open('wb') as saved:saved.write(m.canonical(value))
                helper=mock.Mock()
                with self.assertRaisesRegex(ValueError,'EXACT_ROLE_DEBIT_AND_PAYLOAD'):
                    ledger.capture_transport('capture',helper,b'inert',100,mock.Mock())
                helper.transport.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            ledger=m.RoleLedger(tmp);ledger.reserve('capture',m.sha(b'inert'));ledger.close_failure('capture','TEST')
            helper=mock.Mock()
            with self.assertRaisesRegex(ValueError,'FIRST_FAILURE_CLOSED_PACKAGE'):
                ledger.capture_transport('capture',helper,b'inert',100,mock.Mock())
            helper.transport.assert_not_called()

    def test_raw_write_failure_closes_role_and_false_exit_is_not_success(self):
        for broken_save in (True,False):
            with tempfile.TemporaryDirectory() as tmp:
                ledger=m.RoleLedger(tmp);directory=ledger.reserve('capture',m.sha(b'inert'))
                helper=mock.Mock();helper.transport.return_value=dict(stdout=b'raw',stderr=b'',exit_code=False,
                    timeout=False,overflow=False,write_failed=False,threads_incomplete=False)
                validator=mock.Mock()
                if broken_save:
                    with mock.patch.object(ledger,'save_raw',side_effect=OSError('DISK_FAILURE')):
                        with self.assertRaises(OSError):ledger.capture_transport('capture',helper,b'inert',100,validator)
                else:
                    with self.assertRaisesRegex(ValueError,'ROLE_TRANSPORT_FAILED'):
                        ledger.capture_transport('capture',helper,b'inert',100,validator)
                self.assertTrue((ledger.phase/'closed.json').exists());validator.assert_not_called()
                self.assertEqual(helper.transport.call_count,1)
        with tempfile.TemporaryDirectory() as tmp:
            ledger=m.RoleLedger(tmp);ledger.reserve('capture','1'*64)
            first=m.decode((ledger.phase/'start.json').read_bytes());first['start']=False
            with self.assertRaisesRegex(ValueError,'EXACT_ORIGINAL_CLOCK_FIELDS'):m.remaining(first)

    def test_failure_marker_write_failure_propagates_without_claiming_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger=m.RoleLedger(tmp);ledger.reserve('capture',m.sha(b'inert'))
            helper=mock.Mock();helper.transport.side_effect=ValueError('TRANSPORT_FAILED')
            with mock.patch.object(ledger,'close_failure',side_effect=OSError('MARKER_WRITE_FAILED')):
                with self.assertRaisesRegex(OSError,'MARKER_WRITE_FAILED'):
                    ledger.capture_transport('capture',helper,b'inert',100,mock.Mock())
            self.assertFalse((ledger.phase/'closed.json').exists())
            self.assertTrue((ledger.phase/'capture/transport_consumed.json').exists())

    def test_missing_subdirectory_preserves_original_root_anchor(self):
        from types import SimpleNamespace
        import stat
        info = SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFDIR|0o700,st_uid=1047,st_nlink=2,
            st_size=4096,st_mtime_ns=1,st_ctime_ns=1)
        expected = m.capture.source.identity(info)
        with mock.patch.object(m.execution.io,'_directory',side_effect=[10,FileNotFoundError(),11]),\
                mock.patch.object(m.os,'fstat',return_value=info),mock.patch.object(m.os,'close') as close:
            self.assertIsNone(m.open_output_parent(m.ROOT+'/journal/observation.json',expected))
        self.assertEqual([c.args[0] for c in close.call_args_list],[11,10])
        with mock.patch.object(m.execution.io,'_directory',side_effect=FileNotFoundError()):
            with self.assertRaises(FileNotFoundError):m.open_output_parent(m.ROOT+'/journal/observation.json',expected)
        wrong = dict(expected,st_ino=999)
        with mock.patch.object(m.execution.io,'_directory',return_value=10),mock.patch.object(m.os,'fstat',return_value=info),\
                mock.patch.object(m.os,'close'):
            with self.assertRaisesRegex(ValueError,'OWNED_EXPORT_ROOT_CHANGED'):
                m.open_output_parent(m.ROOT+'/journal/observation.json',wrong)


if __name__ == '__main__':
    unittest.main()
