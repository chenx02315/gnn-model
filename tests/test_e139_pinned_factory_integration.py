"""Actual private pinned factory/PhaseStore/transport constructor, NO SSH.

Synthetic consistency records and test-only releases are RAM-only, NOT consent.
Time sources, the local node label, and selected file-read returns are substituted. No factory,
PhaseStore method, transport constructor, helper identity or source tag is faked.
One run_role uses a substituted send response based on pinned historical E138
metadata, not a new capture. Subprocess/network entrypoints remain guarded.
Temporary phase files prove local lifecycle only, not remote execution.
"""
import copy
from contextlib import contextmanager, ExitStack
import datetime
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import e139_local_source_session as session_source
from tests import test_e139_local_entry_integration as entry_fixture

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / 'scripts/run_prospective_metadata_v1.py'


class Clock:
    def __init__(self):
        self.value = 1000.
        self.epoch = datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)
        outer = self
        class DateTime(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                value = outer.epoch + datetime.timedelta(seconds=outer.value - 1000.)
                return value.astimezone(tz) if tz else value.replace(tzinfo=None)
        self.datetime = DateTime


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        adapter_pin = session_source._sha(Path(session_source.__file__).read_bytes())
        native_pins, script_pins = session_source.effective_maps()
        cls.freeze = dict(origin_sha256=session_source.origin_manifest(adapter_pin),
            effective_native_sha256=native_pins, effective_script_sha256=script_pins,
            adapter_sha256=adapter_pin, binding_sha256=session_source.binding_digest())
        cls.proposal = (REPO/'contracts/physical_f_clean_replay_proposal_e139_v1.json').read_bytes()

    @contextmanager
    def private(self):
        with mock.patch.object(session_source, 'FROZEN', self.freeze), session_source.local_session() as session:
            yield session

    def authority(self, session):
        contract = session.native_modules['physical_e138_contract']
        return contract.canonical(dict(schema='e139-explicit-whole-package-authorization-v1',
            approved_package='E139', approval_source='explicit_user_reply',
            user_reply='SYNTHETIC FACTORY TEST ONLY 中文“不是实际授权”', user_authorization_received=True,
            proposal_sha256=contract.sha(self.proposal), approved_scope=copy.deepcopy(contract.POLICY),
            execution_ready=False))

    @contextmanager
    def configured(self, session, authority=None):
        controller = session.modules['e138_controller']
        transport = session.modules['e138_pinned_transport']
        contract = session.native_modules['physical_e138_contract']
        authority = self.authority(session) if authority is None else authority
        closure = session.local_source_closure()
        release = dict(authorization_sha256=contract.sha(authority), proposal_sha256=contract.sha(self.proposal),
            adapter_source_sha256=closure['scripts.e138_pinned_transport'], host=transport.HOST,
            host_key=transport.HOST_KEY, helper_sha256=transport.HELPER_SHA256, scope=transport.PinnedTransport.scope,
            local_source_sha256=closure, roles={role: None for role in controller.ROLES})
        with ExitStack() as stack:
            for module in (controller, transport):
                stack.enter_context(mock.patch.object(module, 'AUTHORIZATION_SHA256', contract.sha(authority)))
                stack.enter_context(mock.patch.object(module, 'PROPOSAL_SHA256', contract.sha(self.proposal)))
            stack.enter_context(mock.patch.object(controller, 'PINNED_RELEASE', release))
            stack.enter_context(mock.patch.object(transport, 'FROZEN', dict(
                authorization_sha256=contract.sha(authority), proposal_sha256=contract.sha(self.proposal))))
            # Windows platform.node() may spawn a local host query. Keep this
            # synthetic clock-domain label stable without any child process.
            stack.enter_context(mock.patch.object(controller.storage.platform, 'node', return_value='SYNTHETIC_LOCAL_NODE'))
            popen = stack.enter_context(mock.patch('subprocess.Popen', side_effect=AssertionError('NO CHILD/SSH')))
            query = stack.enter_context(mock.patch('subprocess.run', side_effect=AssertionError('NO HOST QUERY')))
            yield controller, transport, authority, popen, query
            popen.assert_not_called(); query.assert_not_called()

    def test_actual_factory_constructor_phase_clock_and_cost_in_original_deadline(self):
        clock = Clock()
        original_read = Path.read_bytes
        helper_reads = []
        def measured_read(path):
            raw = original_read(path)
            if path == HELPER:
                helper_reads.append(path)
                clock.value += 7.5  # Deterministic constructor read/compile cost substitute.
            return raw
        with tempfile.TemporaryDirectory(prefix='e139_factory_') as temporary, self.private() as session:
            with self.configured(session) as (controller, transport, authority, _, _), \
                 mock.patch.object(controller.time, 'monotonic', side_effect=lambda: clock.value), \
                 mock.patch.object(controller.storage.datetime, 'datetime', clock.datetime), \
                 mock.patch.object(Path, 'read_bytes', measured_read):
                instance = controller.Controller.create_pinned(temporary, authority, self.proposal)
                self.assertIs(type(instance), controller.Controller)
                self.assertIs(type(instance.adapter), transport.PinnedTransport)
                self.assertIs(instance._adapter_type, transport.PinnedTransport)
                self.assertTrue(instance._pinned_mode)
                self.assertIn(instance, session._controllers)
                self.assertEqual(instance.store.phase, Path(temporary)/'v6_e139_clean_F_replay_r1')
                start_raw = (instance.store.phase/'start.json').read_bytes()
                start = controller.contract.decode(start_raw)
                self.assertEqual(start, instance.start)
                self.assertEqual(start['start'], 1000.)
                self.assertEqual(start['end'], 4600.)
                self.assertEqual(instance.store.remaining(), 3592.5)
                self.assertEqual(helper_reads, [HELPER])
                self.assertEqual(instance.adapter._namespace['HOSTS']['A'],
                    (transport.ENDPOINT, transport.ENDPOINT, transport.HOST_KEY))
                self.assertEqual(instance.adapter._index, 0)
                self.assertFalse(instance.adapter._terminal)
                self.assertEqual(sorted(p.name for p in instance.store.phase.iterdir()), ['start.json'])
                with self.assertRaises(FileExistsError):
                    controller.Controller.create_pinned(temporary, authority, self.proposal)
                self.assertEqual((instance.store.phase/'start.json').read_bytes(), start_raw)
                self.assertEqual(helper_reads, [HELPER])
            self.assertIsNone(controller.AUTHORIZATION_SHA256)
            self.assertIsNone(controller.PROPOSAL_SHA256)
            self.assertIsNone(controller.PINNED_RELEASE)
            self.assertIsNone(transport.FROZEN)
            self.assertIsNone(transport.AUTHORIZATION_SHA256)
            self.assertIsNone(transport.PROPOSAL_SHA256)
            self.assertIs(type(instance.adapter), transport.PinnedTransport)
            phase = instance.store.phase
        # Temporary staging is cleaned only by TemporaryDirectory, no old phase touched.
        self.assertFalse(phase.exists())
        self.assertTrue(instance.terminal); self.assertTrue(instance.adapter._terminal)
        with mock.patch('subprocess.Popen') as popen, mock.patch.object(Path, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_CLOSED'):
                instance.run_role({}, b'')
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_CLOSED'):
                controller.Controller.create_pinned('UNUSED', authority, self.proposal)
        popen.assert_not_called(); opened.assert_not_called()

    def test_source_or_configuration_drift_rejected_before_phase_creation(self):
        original_open = Path.open
        def changed_origin(path, *args, **kwargs):
            if path == REPO/'scripts/e138_packet.py':
                return io.BytesIO(b'patched read result only; no protected file changes')
            return original_open(path, *args, **kwargs)
        for kind in ('origin', 'configuration'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='e139_drift_') as temporary, \
                 self.private() as session, self.configured(session) as (controller, _, authority, _, _):
                with ExitStack() as stack:
                    if kind == 'origin':
                        stack.enter_context(mock.patch.object(Path, 'open', changed_origin))
                    else:
                        stack.enter_context(mock.patch.object(controller.storage, 'PHASE', 'WRONG_PHASE'))
                    with self.assertRaisesRegex(ValueError, 'E139_SESSION_(ORIGIN_DRIFT|BINDING_DRIFT)'):
                        controller.Controller.create_pinned(temporary, authority, self.proposal)
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_actual_constructor_failure_preserves_start_and_closes_same_phase(self):
        original_read = Path.read_bytes
        def changed_helper(path):
            return b'changed helper return ONLY' if path == HELPER else original_read(path)
        with tempfile.TemporaryDirectory(prefix='e139_helper_fail_') as temporary, self.private() as session, \
             self.configured(session) as (controller, transport, authority, _, _), \
             mock.patch.object(Path, 'read_bytes', changed_helper):
            with self.assertRaisesRegex(ValueError, 'E138_CONTROLLER_PINNED_CONSTRUCTION_FAILED'):
                controller.Controller.create_pinned(temporary, authority, self.proposal)
            phase = Path(temporary)/'v6_e139_clean_F_replay_r1'
            start_raw = (phase/'start.json').read_bytes()
            start = controller.contract.decode(start_raw)
            closed = controller.contract.decode((phase/'closed.json').read_bytes())
            self.assertEqual(start['end'] - start['start'], 3600)
            self.assertEqual(closed['reason'], 'CONTROLLER_STOP')
            self.assertFalse(closed['execution_ready'])
            self.assertEqual(session._controllers, [])
            self.assertEqual(sorted(p.name for p in phase.iterdir()), ['closed.json', 'start.json'])
            with self.assertRaises(FileExistsError):
                controller.Controller.create_pinned(temporary, authority, self.proposal)
            self.assertEqual((phase/'start.json').read_bytes(), start_raw)

    def test_transport_external_freeze_failure_closes_created_phase_without_helper_read(self):
        with tempfile.TemporaryDirectory(prefix='e139_transport_gate_') as temporary, self.private() as session, \
             self.configured(session) as (controller, transport, authority, _, _), \
             mock.patch.object(transport, 'FROZEN', None), mock.patch.object(Path, 'read_bytes') as helper_read:
            with self.assertRaisesRegex(ValueError, 'E138_CONTROLLER_PINNED_CONSTRUCTION_FAILED'):
                controller.Controller.create_pinned(temporary, authority, self.proposal)
            helper_read.assert_not_called()
            self.assertTrue((Path(temporary)/'v6_e139_clean_F_replay_r1/closed.json').is_file())

    def test_pinned_identity_mismatch_rejected_before_phase_or_helper(self):
        with tempfile.TemporaryDirectory(prefix='e139_identity_') as temporary, self.private() as session, \
             self.configured(session) as (controller, _, authority, _, _):
            bad = copy.deepcopy(controller.PINNED_RELEASE)
            bad['host_key'] = 'NOT_THE_FIXED_A_HOST_KEY'
            with mock.patch.object(controller, 'PINNED_RELEASE', bad), mock.patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(ValueError, 'E138_CONTROLLER_PINNED_IDENTITY'):
                    controller.Controller.create_pinned(temporary, authority, self.proposal)
            read.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_controller_default_release_remains_none_and_zero_io(self):
        with self.private() as session:
            controller = session.modules['e138_controller']
            transport = session.modules['e138_pinned_transport']
            self.assertIsNone(controller.PINNED_RELEASE); self.assertIsNone(transport.FROZEN)
            with mock.patch.object(Path, 'open') as opened, mock.patch.object(Path, 'mkdir') as mkdir, \
                 mock.patch('subprocess.Popen') as popen:
                with self.assertRaisesRegex(ValueError, 'E138_CONTROLLER_NO_PINNED_RELEASE'):
                    controller.Controller.create_pinned('UNUSED', b'', b'')
            opened.assert_not_called(); mkdir.assert_not_called(); popen.assert_not_called()

    def test_same_real_instance_capture_and_next_packet_after_constructor_config_restored(self):
        # This ONE authorized fixed historical metadata fixture is SHA checked
        # BEFORE parse. It is preserved E138 observation, NOT new E139 capture.
        historical_path = REPO.parent/'runtime_training_staging_20260928/v6_e138_clean_F_replay_r1/capture/stdout.raw'
        with historical_path.open('rb') as stream:
            historical_raw = stream.read(6291457)
        self.assertLessEqual(len(historical_raw), 6291456)
        self.assertEqual(session_source._sha(historical_raw),
                         'cfe817444f1753887b886ba08575e7b2218e4479a211b326b60fd923d0976230')
        entry_fixture.Tests.setUpClass()
        helper = entry_fixture.Tests()
        clock = Clock()
        with tempfile.TemporaryDirectory(prefix='e139_capture_sim_') as temporary, self.private() as session:
            entry, authority, _ = helper.entry(session)
            entry.AUTH_SHA256 = session_source._sha(authority)
            controller = session.modules['e138_controller']
            transport = session.modules['e138_pinned_transport']
            with mock.patch.object(controller.time, 'monotonic', side_effect=lambda: clock.value), \
                 mock.patch.object(controller.storage.datetime, 'datetime', clock.datetime), \
                 mock.patch.object(controller.storage.platform, 'node', return_value='SYNTHETIC_LOCAL_NODE'), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('NO SSH')) as popen, \
                 mock.patch('subprocess.run', side_effect=AssertionError('NO HOST QUERY')) as query:
                with self.configured(session, authority):
                    instance = controller.Controller.create_pinned(temporary, authority, self.proposal)
                for module in (controller, transport):
                    self.assertIsNone(module.AUTHORIZATION_SHA256)
                    self.assertIsNone(module.PROPOSAL_SHA256)
                self.assertIsNone(controller.PINNED_RELEASE); self.assertIsNone(transport.FROZEN)
                adapter = instance.adapter
                prepared = entry.prepare_capture()
                instance.install_review('capture', prepared._descriptor)
                start_before = (instance.store.phase/'start.json').read_bytes()
                contract = session.native_modules['physical_e138_contract']
                capture = session.native_modules['physical_replay_capture_e138']
                simulated = contract.decode(historical_raw)
                # Adapt identity/cohort fields ONLY, never scientific pins,
                # inventory bytes, source paths, bounds or receipt validators.
                simulated['capture'].update(schema=capture.SCHEMA,
                    authorization_sha256=contract.sha(authority), proposal_sha256=contract.sha(self.proposal),
                    dependency_sha256=dict(capture.DEPENDENCY_SHA256))
                simulated.update(remote_start_monotonic=1000., remote_sample_monotonic=1000.,
                    remote_utc_sample=clock.epoch.strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                raw = contract.canonical(simulated)
                calls = []
                def send(adapter_self, **call):
                    self.assertIs(adapter_self, adapter)
                    self.assertEqual(call['payload'], prepared._plan['payload'])
                    self.assertEqual(call['remote_command'], prepared._plan['remote_command'])
                    self.assertEqual(call['role'], 'capture')
                    self.assertTrue((instance.store.phase/'capture/intent.json').is_file())
                    calls.append(call)
                    return dict(stdout=raw, stderr=b'', exit_code=0, timeout=False, overflow=False,
                        write_failed=False, threads_incomplete=False, remote_termination_verified=False)
                # ONLY low-level transport return bytes substituted here.
                with mock.patch.object(transport.PinnedTransport, 'send', send):
                    instance.run_role(prepared._material, prepared._review)
                self.assertEqual(len(calls), 1)
                self.assertEqual(instance.index, 1)
                self.assertIs(instance.adapter, adapter)
                self.assertFalse(instance.terminal)
                self.assertEqual((instance.store.phase/'capture/stdout.raw').read_bytes(), raw)
                self.assertEqual((instance.store.phase/'original_clock.json').read_bytes(), instance.original_clock)
                self.assertEqual((instance.store.phase/'start.json').read_bytes(), start_before)
                self.assertEqual(contract.decode(instance.original_clock)['local_monotonic_deadline'], 4600.)
                inputs = dict(prepared._local['execution_inputs'], authority=authority, proposal=self.proposal,
                    original_clock=instance.original_clock, role1_response=raw)
                next_packet = entry._prepare('execution', inputs, prepared._local, authority, self.proposal,
                    prepared._release, previous_sha=contract.sha((instance.store.phase/'capture/accepted.json').read_bytes()))
                self.assertEqual(next_packet._role, 'execution')
                self.assertEqual(next_packet._material['inputs']['original_clock'], instance.original_clock)
                self.assertIs(instance.adapter, adapter)
                self.assertEqual(len(session._controllers), 1)
                self.assertEqual(instance.store.remaining(), 3600.)
            popen.assert_not_called(); query.assert_not_called()


if __name__ == '__main__':
    unittest.main()
