"""Read-only executed grant evidence and counterfactual decoder checks only."""
from pathlib import Path
import pickle
import unittest
from unittest import mock

from scripts import e138_authority_encoding_candidate as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo=Path(__file__).resolve().parents[1]
        cls.authority=(repo/'contracts/physical_f_clean_replay_authorization_e138.json').read_bytes()
        cls.proposal=(repo/'contracts/physical_f_clean_replay_proposal_e138_v1.json').read_bytes()

    def test_executed_utf8_grant_reproduces_frozen_decoder_failure(self):
        self.assertEqual(m.contract.sha(self.authority),m.EXECUTED_AUTH_SHA256)
        self.assertEqual(m.contract.sha(self.proposal),m.EXECUTED_PROPOSAL_SHA256)
        value=m.contract.decode(self.authority)
        self.assertEqual(value['approved_scope'],m.contract.POLICY)
        with self.assertRaises(UnicodeDecodeError):m.bootstrap.decode(self.authority)

    def test_ascii_candidate_both_decoders_semantically_equal_no_release(self):
        original=m.contract.decode(self.authority)
        candidate=m.build(self.authority,self.proposal)
        raw=candidate.private_candidate_bytes();metadata=candidate.public_metadata()
        self.assertTrue(raw.isascii())
        self.assertEqual(m.contract.decode(raw),original)
        self.assertEqual(m.bootstrap.decode(raw),original)
        self.assertNotEqual(m.contract.sha(raw),m.EXECUTED_AUTH_SHA256)
        self.assertEqual(metadata['status'],'NOT_AUTHORIZATION_NOT_RELEASE')
        self.assertFalse(metadata['authorization_created'])
        self.assertFalse(metadata['executed_attempt_reuse_permitted'])
        self.assertFalse(metadata['execution_ready'])
        self.assertFalse(metadata['tool_execution_verified'])
        self.assertTrue(metadata['future_live_package_requires_new_explicit_authorization'])
        self.assertTrue(metadata['future_live_package_requires_new_phase_and_audit'])
        self.assertNotIn('user_reply',metadata)
        self.assertEqual(m.bootstrap.AUTH_SHA256,None)

    def test_build_is_pure_no_file_process_host_or_authority_pin_changes(self):
        pins=(m.bootstrap.AUTH_SHA256,m.bootstrap.PROPOSAL_SHA256,m.contract.FROZEN)
        with mock.patch('builtins.open') as opened,mock.patch('subprocess.Popen') as spawn, \
                mock.patch('subprocess.run') as query,mock.patch.object(m.bootstrap.platform,'node') as host:
            candidate=m.build(self.authority,self.proposal)
        opened.assert_not_called();spawn.assert_not_called();query.assert_not_called();host.assert_not_called()
        self.assertEqual(pins,(m.bootstrap.AUTH_SHA256,m.bootstrap.PROPOSAL_SHA256,m.contract.FROZEN))
        with self.assertRaisesRegex(TypeError,'NOT_SERIALIZABLE'):pickle.dumps(candidate)
        self.assertIn('NOT_AUTHORIZATION_NOT_RELEASE',repr(candidate))

    def test_duplicate_nonfinite_and_oversize_inputs_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}'):
            with self.subTest(raw=raw),self.assertRaisesRegex(ValueError,'JSON_REJECTED'):
                m.build(raw,self.proposal)
            with self.subTest(proposal=raw),self.assertRaisesRegex(ValueError,'JSON_REJECTED'):
                m.build(self.authority,raw)
        for authority,proposal in ((b'x'*(m.CAP+1),self.proposal),(self.authority,b'x'*(m.CAP+1)),
                                  (b'',self.proposal),(self.authority,'not bytes')):
            with self.assertRaisesRegex(ValueError,'INPUT_BOUND'):m.build(authority,proposal)

    def test_different_valid_json_not_accepted_as_the_executed_grant(self):
        altered=m.contract.decode(self.authority);altered['user_reply']='different reply'
        with self.assertRaisesRegex(ValueError,'EXECUTED_INPUT_PINS'):
            m.build(m.contract.canonical(altered),self.proposal)

    def test_real_frozen_bootstrap_original_fails_ascii_and_candidate_passes_authority_stages(self):
        from tests import test_physical_runtime_bootstrap_e138 as fixture
        candidate=m.build(self.authority,self.proposal).private_candidate_bytes()
        # Test-only pins and malformed context: stop strictly after authority
        # validation. No runtime/profile child or tool launch is attempted.
        for raw,expected in ((self.authority,'AUTHORITY_JSON'),(candidate,'CONTEXT_JSON')):
            case=fixture.Tests();case.setUp()
            try:
                case.package.update(authority=raw,proposal=self.proposal,context=b'not-json')
                case.frozen.update(authorization_sha256=m.contract.sha(raw),
                    proposal_sha256=m.contract.sha(self.proposal),context_sha256=m.contract.sha(b'not-json'))
                with mock.patch('subprocess.Popen') as spawn,mock.patch('subprocess.run') as query:
                    evidence,calls=case.failed(expected)
                self.assertEqual(calls,0);case.tick.assert_not_called()
                self.assertEqual(evidence['stage_attempted'],expected)
                self.assertEqual(evidence['bootstrap_children'],0)
                spawn.assert_not_called();query.assert_not_called()
            finally:case.doCleanups()


if __name__=='__main__':unittest.main()
