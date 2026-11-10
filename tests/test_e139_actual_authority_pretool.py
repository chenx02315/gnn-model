"""Actual Nov10 E139 authorization bytes; LOCAL pretool evidence only.

No serialization candidate, synthetic grant, phase, host call or remote child.
Test-only source/input freezes express consistency checks, not packet review.
The deliberate invalid context stops bootstrap BEFORE environment/tool access.
"""
import base64
from contextlib import ExitStack
import hashlib
from pathlib import Path
import types
import unittest
from unittest import mock

from scripts import e139_local_materials as materials
from scripts import e139_local_source_session as sessions

REPO = Path(__file__).resolve().parents[1]
AUTH_SHA = '9e8b899d529983e29493ea253b32c58e543afca307b7e6bff6be8e599fd37e54'
sha = lambda raw: hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (REPO/'contracts/physical_f_clean_replay_authorization_e139.json').open('rb') as stream:
            cls.authority = stream.read(65537)
        if len(cls.authority) != 1801 or sha(cls.authority) != AUTH_SHA:
            raise AssertionError('actual authorization exact-byte pin mismatch; no substitute allowed')
        cls.proposal = (REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()
        cls.local = materials.prepare().private_bytes()
        adapter = sha(Path(sessions.__file__).read_bytes())
        native, scripts = sessions.effective_maps()
        cls.freeze = dict(origin_sha256=sessions.origin_manifest(adapter), adapter_sha256=adapter,
            binding_sha256=sessions.binding_digest(), effective_native_sha256=native, effective_script_sha256=scripts)
        cls.worker = (REPO/'scripts/worker_e138_batch.py').read_bytes()

    def test_actual_exact_reply_contract_and_ascii_bootstrap_decoder_agree(self):
        with mock.patch.object(sessions, 'FROZEN', self.freeze), sessions.local_session() as session:
            contract = session.native_modules['physical_e138_contract']
            bootstrap = session.native_modules['physical_runtime_bootstrap_e138']
            with mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn:
                admitted = contract.check_authority(self.authority, self.proposal, AUTH_SHA, sha(self.proposal))
                native = contract.decode(self.authority)
                boot = bootstrap.decode(self.authority)
            self.assertEqual(native, boot)
            self.assertEqual(native['user_reply'], '批准 E139 整包')
            self.assertTrue(self.authority.isascii())
            self.assertEqual(sha(self.authority), AUTH_SHA)
            self.assertEqual(admitted['package'], 'E139')
            self.assertFalse(admitted['execution_ready'])
            opened.assert_not_called(); spawn.assert_not_called()

    def test_actual_authority_bootstrap_context_json_stop_zero_children_and_host(self):
        with mock.patch.object(sessions, 'FROZEN', self.freeze), sessions.local_session() as session:
            b = session.native_modules['physical_runtime_bootstrap_e138']
            inputs = self.local['execution_inputs']
            package = dict(authority=self.authority, proposal=self.proposal, context=b'INTENTIONALLY_INVALID_CONTEXT',
                e112=inputs['e112'], worker_source=inputs['parent_worker_source'], profile_source=inputs['profile_source'])
            frozen = dict(authorization_sha256=AUTH_SHA, proposal_sha256=sha(self.proposal),
                context_sha256=sha(package['context']), expected_boot_id='3ebeb9bb-410c-476c-a000-5c625f590473',
                root=b.ROOT, phase=b.PHASE)
            for module in (b.direct, b.direct.base, b.process, b.profile, b.adapter, b.pins):
                self.assertEqual(module.__source_sha256__, b.SOURCE_PINS[module.__name__.rsplit('.', 1)[1]])
            evidence = {}; tick = mock.Mock()
            with ExitStack() as stack:
                for attr, key in (('AUTH_SHA256','authorization_sha256'), ('PROPOSAL_SHA256','proposal_sha256'),
                                  ('CONTEXT_SHA256','context_sha256'), ('EXPECTED_BOOT_ID','expected_boot_id')):
                    stack.enter_context(mock.patch.object(b, attr, frozen[key]))
                host = stack.enter_context(mock.patch.object(b.platform, 'node'))
                supervise = stack.enter_context(mock.patch.object(b.direct.base, 'supervise'))
                now = stack.enter_context(mock.patch.object(b.time, 'monotonic'))
                opened = stack.enter_context(mock.patch('builtins.open'))
                spawn = stack.enter_context(mock.patch('subprocess.Popen'))
                mkdir = stack.enter_context(mock.patch.object(Path, 'mkdir'))
                with self.assertRaisesRegex(ValueError, '^E138_BOOTSTRAP_CONTEXT_JSON_FAILED$'):
                    b.bootstrap(package, None, tick, frozen, evidence)
            for call in (host, supervise, now, opened, spawn, mkdir, tick):
                call.assert_not_called()
            self.assertIs(package['authority'], self.authority)
            self.assertEqual(evidence['schema'], 'e139-private-runtime-bootstrap-v1')
            self.assertEqual(evidence['stage_attempted'], 'CONTEXT_JSON')
            self.assertEqual(evidence['bootstrap_children'], 0)
            self.assertFalse(evidence['execution_ready'])

    def test_same_actual_bytes_envelope_and_real_worker_preflight_input_source_joins(self):
        with mock.patch.object(sessions, 'FROZEN', self.freeze), sessions.local_session() as session:
            envelope = session.modules['e138_reviewed_envelope']
            bundle = self.local['roles']['capture']
            loader = session._scripts['e138_source_session']
            package = dict(authority=self.authority, proposal=self.proposal)
            template = dict(role='capture', loader_sha256=sha(loader), source_sha256=dict(bundle['source_sha256']),
                source_order=bundle['source_order'], input_sha256={k: sha(v) for k, v in package.items()},
                authorization_sha256=AUTH_SHA, proposal_sha256=sha(self.proposal), assembly=None)
            payload_sha = 'a' * 64  # Preflight-only invocation fixture; no payload execution claimed.
            intent = envelope.intent('capture', payload_sha)
            frozen, joined = envelope.derive(template, package, intent, payload_sha)
            worker = types.ModuleType('_ACTUAL_AUTHORITY_PREFLIGHT_ONLY')
            exec(compile(self.worker, '<pinned-worker-preflight-only>', 'exec'), worker.__dict__)
            worker.FROZEN = frozen
            rows = [dict(name=n, sha256=bundle['source_sha256'][n],
                body_base64=base64.b64encode(bundle['sources'][n]).decode('ascii')) for n in bundle['source_order']]
            with mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn, \
                 mock.patch.object(worker.platform, 'node') as host, mock.patch.object(Path, 'mkdir') as mkdir:
                checked, sources = worker._preflight(joined, rows, loader, intent, payload_sha, 1000.)
                bad = dict(joined, authority=self.authority + b' ')
                with self.assertRaisesRegex(ValueError, 'E138_WORKER_INPUT_BYTES'):
                    worker._preflight(bad, rows, loader, intent, payload_sha, 1000.)
            for call in (opened, spawn, host, mkdir):
                call.assert_not_called()
            self.assertIs(joined['authority'], self.authority)
            self.assertEqual(checked['authorization_sha256'], AUTH_SHA)
            self.assertEqual(sources, bundle['sources'])


if __name__ == '__main__':
    unittest.main()
