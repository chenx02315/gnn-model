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


if __name__ == '__main__':
    unittest.main()
