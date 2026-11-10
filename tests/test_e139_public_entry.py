"""Actual private capture preparation, synthetic grant read fixture only.

No actual authorization file, local phase, transport or process is created.
These tests do not establish pinned construction or remote execution.
"""
import copy
from contextlib import contextmanager
import json
import types
from pathlib import Path
import unittest
from unittest import mock

from scripts import run_physical_f_clean_replay_e139 as m


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = m.session_source
        adapter = m.materials.sha((m.REPO / s.SELF).read_bytes())
        native, scripts = s.effective_maps()
        cls.freeze = dict(session=dict(origin_sha256=s.origin_manifest(adapter),
            effective_native_sha256=native, effective_script_sha256=scripts,
            adapter_sha256=adapter, binding_sha256=s.binding_digest()),
            origin_sha256=m.origin_manifest(m.materials.sha((m.REPO / m.SELF).read_bytes())),
            effective_entry_sha256=m.candidate.EFFECTIVE_SHA256, binding_sha256=m.binding_digest())
        cls.proposal = (m.REPO / 'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()
        policy = json.loads(m.materials.prepare().private_bytes()['execution_inputs']['policy'])
        cls.authority = m.materials.canonical(dict(schema='e139-explicit-whole-package-authorization-v1',
            approved_package='E139', approval_source='explicit_user_reply',
            user_reply='SYNTHETIC TEST ONLY NOT USER CONSENT 中文不是授权',
            user_authorization_received=True, proposal_sha256=m.PROPOSAL_SHA256,
            approved_scope=policy, execution_ready=False))

    @contextmanager
    def configured(self):
        with mock.patch.object(m, 'AUTH_SHA256', m.materials.sha(self.authority)), \
             mock.patch.object(m, 'SOURCE_FREEZE', copy.deepcopy(self.freeze)):
            yield

    @contextmanager
    def grant_fixture(self, raw=None):
        # Replace just the exact fixed grant read; all source reads are real.
        original = m._bounded_read
        raw = self.authority if raw is None else raw
        def reader(path, cap, pin, root):
            if path == m.REPO / 'contracts/physical_f_clean_replay_authorization_e139.json':
                self.assertEqual(cap, 65536)
                self.assertEqual(pin, m.materials.sha(raw))
                return raw
            return original(path, cap, pin, root)
        with mock.patch.object(m, '_bounded_read', side_effect=reader):
            yield

    def test_default_authority_and_missing_freeze_denied_before_io_compile_lock(self):
        for auth in (None, 'a'*64):
            with mock.patch.object(m, 'AUTH_SHA256', auth), mock.patch.object(m, 'SOURCE_FREEZE', None), \
                 mock.patch('pathlib.Path.open') as opened, mock.patch('builtins.compile') as compiled:
                with self.assertRaises(ValueError):
                    with m.open_entry(): pass
            opened.assert_not_called(); compiled.assert_not_called()
            self.assertFalse(m._LOCK.locked())

    def test_actual_private_capture_effective35_payload_provenance_and_no_execution(self):
        with self.configured(), self.grant_fixture(), mock.patch('subprocess.Popen') as spawn, \
             mock.patch('time.monotonic') as clock, m.open_entry() as entry:
            prepared = entry.prepare_capture()
            request = prepared.public_review_request()
            self.assertEqual(request['schema'], 'e139-independent-exact-packet-review-request-v1')
            projection = request['projection']
            self.assertEqual(len(projection['source_order']), 35)
            pins = self.freeze['session']['effective_native_sha256']
            for name, pin in projection['source_sha256'].items():
                self.assertEqual(pin, pins[name])
            self.assertEqual(projection['compiler_sha256'], m.session_source.packet_candidate.EFFECTIVE_SHA256)
            self.assertFalse(request['execution_ready'])
            manifest = request['entry_source_sha256']
            self.assertEqual(manifest[m.candidate.KEY], m.candidate.EFFECTIVE_SHA256)
            self.assertEqual(manifest['scripts.run_physical_f_clean_replay_e139'], self.freeze['origin_sha256'][m.SELF])
            self.assertEqual(manifest['bindings.e139_public_entry'], m.binding_digest())
            self.assertIs(entry._entry.controller.local_source_closure.__self__, entry._session)
            self.assertNotIn('__file__', entry._entry.__dict__)
            with self.assertRaisesRegex(ValueError, 'REVIEW_PIN_REQUIRED'):
                entry.start(prepared, b'NOT A REVIEW')
        spawn.assert_not_called(); clock.assert_not_called()

    def test_unknown_source_and_unowned_evidence_paths_refused_before_read(self):
        with self.configured(), m.open_entry() as entry:
            with self.assertRaisesRegex(ValueError, 'SOURCE_KEY'):
                entry._source_bytes('scripts.unknown')
            for path in (m.REPO / 'secret', m.STAGING / m.session_source.native.pair.PHASE_NEW / 'capture/stdout.raw'):
                with mock.patch.object(m, '_bounded_read', wraps=m._bounded_read) as read:
                    with self.assertRaisesRegex(ValueError, 'UNOWNED_OR_UNKNOWN_PATH'):
                        entry._facade._read(path, 4096)
                self.assertNotIn(mock.call(path, 4096, None, m.STAGING), read.call_args_list)

    def test_stale_methods_and_providers_denied_zero_io_and_session_freeze_restored(self):
        with self.configured(), m.open_entry() as entry:
            provider = entry._provider
        self.assertIsNone(m.session_source.FROZEN)
        for method in (entry.prepare_capture, entry.public_source_manifest,
                       lambda: provider('scripts.worker_e138_batch')):
            with mock.patch('pathlib.Path.open') as opened:
                with self.assertRaisesRegex(ValueError, 'ENTRY_CLOSED'):
                    method()
            opened.assert_not_called()

    def test_provider_effective_source_and_binding_configuration_drift_failclosed(self):
        for failure in ('provider', 'effective', 'configuration', 'origin', 'fixed_root'):
            with self.subTest(failure=failure), self.configured(), m.open_entry() as entry:
                if failure == 'provider':
                    entry._entry.SOURCE_BYTES = lambda key: b'UNTRUSTED'
                    with self.assertRaisesRegex(ValueError, 'PROVIDER_BINDING_DRIFT'):
                        entry.prepare_capture()
                elif failure == 'effective':
                    entry._sources['scripts.worker_e138_batch'] += b' '
                    with self.assertRaisesRegex(ValueError, 'EFFECTIVE_SOURCE_DRIFT'):
                        entry._source_bytes('scripts.worker_e138_batch')
                elif failure == 'configuration':
                    with mock.patch.dict(m.BINDINGS, materials='DRIFT'):
                        with self.assertRaisesRegex(ValueError, 'CONFIGURATION_DRIFT'):
                            entry.prepare_capture()
                elif failure == 'origin':
                    original = m._bounded_read
                    def reader(path, *args):
                        if path == m.REPO / 'scripts/e138_deployment_materials.py':
                            raise ValueError('TEST_ONLY_ORIGIN_DRIFT')
                        return original(path, *args)
                    with mock.patch.object(m, '_bounded_read', side_effect=reader):
                        with self.assertRaisesRegex(ValueError, 'ORIGIN_DRIFT'):
                            entry.prepare_capture()
                else:
                    with mock.patch.object(m, 'STAGING', m.REPO / 'NOT_THE_FIXED_STAGING'):
                        with self.assertRaisesRegex(ValueError, 'FIXED_ROOT_DRIFT'):
                            entry.prepare_capture()

    def test_noncanonical_or_nonascii_future_grant_refused_before_packet(self):
        for raw in (self.authority + b'\n', self.authority.decode('ascii').replace('\\u4e2d', '中').encode('utf-8')):
            with self.configured(), mock.patch.object(m, 'AUTH_SHA256', m.materials.sha(raw)), \
                 self.grant_fixture(raw), m.open_entry() as entry:
                with mock.patch.object(entry._entry.packet, 'prepare') as packet:
                    with self.assertRaisesRegex(ValueError, 'CANONICAL_ASCII_GRANT'):
                        entry.prepare_capture()
                packet.assert_not_called()

    def test_fixed_freeze_rosters_reject_missing_extra_wrong_effective_before_source_io(self):
        for change in ('missing', 'extra', 'effective'):
            frozen = copy.deepcopy(self.freeze)
            if change == 'missing': del frozen['origin_sha256']['scripts/e138_deployment_materials.py']
            if change == 'extra': frozen['origin_sha256']['secret'] = '0'*64
            if change == 'effective': frozen['effective_entry_sha256'] = '0'*64
            with self.configured(), mock.patch.object(m, 'SOURCE_FREEZE', frozen), \
                 mock.patch('pathlib.Path.open') as opened:
                with self.assertRaises(ValueError):
                    with m.open_entry(): pass
            opened.assert_not_called()

    def test_same_entry_late_execution_readback_review_installation_regression(self):
        # Lifecycle doubles advance simulated role indices only; no actual
        # pinned factory, phase, transport or prior remote result is claimed.
        with self.configured(), self.grant_fixture(), m.open_entry() as entry, \
             mock.patch('subprocess.Popen') as spawn, mock.patch('time.monotonic') as clock:
            entry.install_review_pin('capture', '1'*64)
            prepared = entry.prepare_capture()
            c = types.SimpleNamespace(index=1, terminal=False)
            entry._session._controllers.append(c)
            native_run = types.SimpleNamespace(_controller=c,
                execute=mock.Mock(side_effect=lambda *args: setattr(c, 'index', 2)))
            with mock.patch.object(entry._entry, 'start', return_value=native_run) as start:
                run = entry.start(prepared, b'TEST_ONLY_REVIEW_RECORD')
            start.assert_called_once_with(prepared, b'TEST_ONLY_REVIEW_RECORD')
            # Old workaround changed the snapshotted global and was refused.
            with mock.patch.object(m, 'REVIEW_PINS', {'execution': '2'*64}):
                with self.assertRaisesRegex(ValueError, 'CONFIGURATION_DRIFT'):
                    entry.install_review_pin('execution', '2'*64)
            entry.install_review_pin('execution', '2'*64)
            self.assertIsNone(m.REVIEW_PINS)
            self.assertEqual(entry._entry.REVIEW_PINS, {'capture':'1'*64, 'execution':'2'*64})
            self.assertIsNot(entry._entry.REVIEW_PINS, entry._installed_reviews)
            run.execute('TEST_ONLY_PREPARED_EXECUTION_DOUBLE', b'TEST_ONLY_RECORD')
            entry.install_review_pin('readback', '3'*64)
            self.assertEqual(entry._entry.REVIEW_PINS['readback'], '3'*64)
            self.assertIs(entry._run, run)
            with self.assertRaisesRegex(ValueError, 'START_ALREADY_ATTEMPTED'):
                entry.start(prepared, b'TEST_ONLY')
        spawn.assert_not_called(); clock.assert_not_called()
        self.assertIsNone(m.session_source.FROZEN)
        self.assertIsNone(m.REVIEW_PINS)

    def test_review_install_duplicate_wrongtype_outoforder_and_untracked_terminal_denied(self):
        with self.configured(), self.grant_fixture(), m.open_entry() as entry:
            for role, pin in (('execution','1'*64), ('readback','1'*64), ('unknown','1'*64),
                              ([], '1'*64), ('capture', None), ('capture', b'a'*64)):
                with self.assertRaises(ValueError):
                    entry.install_review_pin(role, pin)
            entry.install_review_pin('capture', '1'*64)
            with self.assertRaisesRegex(ValueError, 'ALREADY_INSTALLED'):
                entry.install_review_pin('capture', '2'*64)
            c = types.SimpleNamespace(index=1, terminal=False)
            entry._run = m._Run(entry, types.SimpleNamespace(_controller=c))
            with self.assertRaisesRegex(ValueError, 'ROLE_ORDER'):
                entry.install_review_pin('execution', '2'*64)
            entry._session._controllers.append(c)
            c.terminal = True
            with self.assertRaisesRegex(ValueError, 'ROLE_ORDER'):
                entry.install_review_pin('execution', '2'*64)
            c.terminal = False
            with self.assertRaisesRegex(ValueError, 'ROLE_ORDER'):
                entry.install_review_pin('readback', '3'*64)

    def test_future_preinstalled_reviews_rejected_before_io(self):
        for role in ('execution', 'readback'):
            with self.configured(), mock.patch.object(m, 'REVIEW_PINS', {role:'1'*64}), \
                 mock.patch('pathlib.Path.open') as opened:
                with self.assertRaisesRegex(ValueError, 'REVIEW_PINS'):
                    with m.open_entry(): pass
            opened.assert_not_called()

    def test_installation_rechecks_authority_source_and_global_configuration(self):
        with self.configured(), self.grant_fixture(), m.open_entry() as entry:
            with mock.patch.object(m, 'AUTH_SHA256', '0'*64):
                with self.assertRaisesRegex(ValueError, 'CONFIGURATION_DRIFT'):
                    entry.install_review_pin('capture', '1'*64)
            with mock.patch.object(entry._entry, '_grant', side_effect=ValueError('TEST_ONLY_GRANT_FILE_DRIFT')):
                with self.assertRaisesRegex(ValueError, 'GRANT_FILE_DRIFT'):
                    entry.install_review_pin('capture', '1'*64)
            with mock.patch.object(entry._session, 'local_source_closure', side_effect=ValueError('TEST_ONLY_SOURCE_DRIFT')):
                with self.assertRaisesRegex(ValueError, 'SOURCE_DRIFT'):
                    entry.install_review_pin('capture', '1'*64)
            self.assertEqual(entry._installed_reviews, {})
            entry.install_review_pin('capture', '1'*64)
        with self.assertRaisesRegex(ValueError, 'ENTRY_CLOSED'):
            entry.install_review_pin('execution', '2'*64)


if __name__ == '__main__':
    unittest.main()
