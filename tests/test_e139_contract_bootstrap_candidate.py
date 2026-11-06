"""Synthetic two-module identity checks only, not an actual-grant E139 run."""
import ast
import copy
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from scripts import e139_contract_bootstrap_candidate as m
from src.data import physical_e138_contract as historical
from src.data import physical_runtime_bootstrap_e138 as old_bootstrap

REPO = Path(__file__).resolve().parents[1]


def sources():
    return {name: (REPO / 'src/data' / (name + '.py')).read_bytes()
            for name in (m.CONTRACT, m.BOOTSTRAP)}


def isolated_module(name, raw):
    # Trusted locally pinned source only. Do not install in sys.modules or
    # claim this pair is a complete private graph/source-session integration.
    module = types.ModuleType('src.data.' + name)
    module.__package__ = 'src.data'
    exec(compile(raw, '<synthetic-e139-' + name + '>', 'exec'), module.__dict__)
    return module


class Tests(unittest.TestCase):
    def setUp(self):
        self.original = sources()
        self.result = m.build(self.original)
        self.effective = self.result.private_sources()
        self.contract = isolated_module(m.CONTRACT, self.effective[m.CONTRACT])
        self.bootstrap = isolated_module(m.BOOTSTRAP, self.effective[m.BOOTSTRAP])
        self.proposal = (REPO / 'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()

    def synthetic_authority(self):
        return self.contract.canonical(dict(
            schema='e139-explicit-whole-package-authorization-v1', approved_package='E139',
            approval_source='explicit_user_reply', user_reply='SYNTHETIC ONLY: “批准 E139 整包',
            user_authorization_received=True, proposal_sha256=self.contract.sha(self.proposal),
            approved_scope=copy.deepcopy(self.contract.POLICY), execution_ready=False))

    def test_exact_effective_pins_syntax_and_historical_bytes_preserved(self):
        for name, raw in self.effective.items():
            self.assertEqual(historical.sha(raw), m.EFFECTIVE_PINS[name])
            ast.parse(raw, feature_version=(3, 6))
            self.assertEqual(historical.sha(self.original[name]), m.ORIGIN_PINS[name])
        self.assertEqual(sources(), self.original)
        self.assertEqual(historical.ROOT, m.ROOT_OLD)
        self.assertEqual(old_bootstrap.ROOT, m.ROOT_OLD)
        self.assertIsNone(historical.FROZEN)
        self.assertIsNone(old_bootstrap.AUTH_SHA256)
        self.assertIsNot(sys.modules['src.data.' + m.CONTRACT], self.contract)
        self.assertIsNot(sys.modules['src.data.' + m.BOOTSTRAP], self.bootstrap)

    def test_new_identity_unchanged_budgets_and_default_disabled(self):
        expected = copy.deepcopy(historical.POLICY)
        expected.update(schema='e139-fixed-f-replay-policy-v1', package='E139',
                        new_remote_root=m.ROOT_NEW, new_local_phase=m.PHASE_NEW)
        self.assertEqual(self.contract.canonical(expected), self.contract.canonical(self.contract.POLICY))
        self.assertEqual(self.contract.decode(self.proposal)['scope_if_granted'], expected)
        self.assertEqual(self.bootstrap.ROOT, m.ROOT_NEW)
        self.assertEqual(self.bootstrap.PHASE, m.PHASE_NEW)
        self.assertEqual(self.contract.OLD_AUTH_SHA256, m.CONSUMED_E138_AUTH)
        self.assertIsNone(self.contract.FROZEN)
        self.assertIsNone(self.bootstrap.AUTH_SHA256)
        with self.assertRaises(ValueError): self.contract.admit({})

    def test_old_authority_not_released_and_changed_policy_rejected(self):
        raw = (REPO / 'contracts/physical_f_clean_replay_authorization_e138.json').read_bytes()
        with self.assertRaises(ValueError):
            self.contract.check_authority(raw, self.proposal, historical.sha(raw), historical.sha(self.proposal))
        raw = self.synthetic_authority()
        value = self.contract.check_authority(raw, self.proposal, historical.sha(raw), historical.sha(self.proposal))
        self.assertEqual(value['package'], 'E139')
        self.assertFalse(value['execution_ready'])
        bad = self.contract.decode(raw); bad['approved_scope']['automatic_retries'] = 1
        raw = self.contract.canonical(bad)
        with self.assertRaises(ValueError):
            self.contract.check_authority(raw, self.proposal, historical.sha(raw), historical.sha(self.proposal))

    def test_build_no_io_and_no_registry_or_historical_mutation(self):
        before = dict(sys.modules)
        with mock.patch('builtins.open') as opened, mock.patch('subprocess.Popen') as spawn:
            result = m.build(self.original)
        opened.assert_not_called(); spawn.assert_not_called()
        self.assertEqual(dict(sys.modules), before)
        changed = result.private_sources(); changed.clear()
        self.assertEqual(result.private_sources(), self.effective)
        spec = m.specification(); spec['rules'].clear()
        self.assertTrue(m.specification()['rules'])
        with self.assertRaises(ValueError): m.build(dict(self.original, unexpected=b'x'))
        changed = dict(self.original); changed[m.CONTRACT] += b' '
        with self.assertRaises(ValueError): m.build(changed)

    def test_synthetic_ascii_unicode_passes_both_decoders_then_stops_before_host(self):
        from tests import test_physical_runtime_bootstrap_e138 as fixture
        raw = self.synthetic_authority()
        self.assertTrue(raw.isascii())
        self.assertEqual(self.contract.decode(raw), self.bootstrap.decode(raw))
        self.assertIn('“批准 E139 整包', self.contract.decode(raw)['user_reply'])
        with mock.patch.object(fixture, 'm', self.bootstrap):
            case = fixture.Tests(); case.setUp()
            try:
                case.package.update(authority=raw, proposal=self.proposal, context=b'not-json')
                case.frozen.update(authorization_sha256=historical.sha(raw),
                    proposal_sha256=historical.sha(self.proposal), context_sha256=historical.sha(b'not-json'))
                hosts = []
                def no_host(stack):
                    hosts.append(stack.enter_context(mock.patch.object(self.bootstrap.platform, 'node')))
                with mock.patch('subprocess.Popen') as spawn, mock.patch('subprocess.run') as query:
                    evidence, calls = case.failed('CONTEXT_JSON', patcher=no_host)
                self.assertEqual(calls, 0); self.assertEqual(evidence['bootstrap_children'], 0)
                self.assertEqual(evidence['schema'], 'e139-private-runtime-bootstrap-v1')
                case.tick.assert_not_called(); spawn.assert_not_called(); query.assert_not_called()
                self.assertEqual(len(hosts), 1); hosts[0].assert_not_called()
            finally: case.doCleanups()

    def test_default_and_both_consumed_hashes_stop_at_admission_zero_io(self):
        for pin in (None, self.bootstrap.OLD_E137_AUTH_SHA256, m.CONSUMED_E138_AUTH):
            with mock.patch.object(self.bootstrap, 'AUTH_SHA256', pin), \
                 mock.patch.object(self.bootstrap.platform, 'node') as host, \
                 mock.patch.object(self.bootstrap.direct.base, 'supervise') as supervise:
                evidence = {}
                with self.assertRaisesRegex(ValueError, 'E138_BOOTSTRAP_ADMISSION_FAILED'):
                    self.bootstrap.bootstrap({}, None, None, {}, evidence)
            host.assert_not_called(); supervise.assert_not_called()
            self.assertEqual(evidence['bootstrap_children'], 0)


if __name__ == '__main__': unittest.main()
