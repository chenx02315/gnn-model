"""Fixed local source/configuration tests; no real grants, phase or remote.

The sole substituted constructor test exercises lifecycle tracking only; it
does not claim pinned-controller admission or transport construction succeeded.
"""
import ast
import copy
import io
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from scripts import e139_local_source_session as m
from scripts import e138_controller as historical


class Tests(unittest.TestCase):
    def frozen(self):
        binding = m._sha(Path(m.__file__).read_bytes())
        native, scripts = m.effective_maps()
        return dict(origin_sha256=m.origin_manifest(binding), adapter_sha256=binding,
                    binding_sha256=m.binding_digest(),
                    effective_native_sha256=native, effective_script_sha256=scripts)

    def snapshot(self):
        return {k: v for k, v in sys.modules.items()
                if k in ('scripts', 'src') or k.startswith(('scripts.', 'src.'))}

    def test_default_no_source_freeze_zero_io_compile_registry_phase(self):
        before = self.snapshot()
        with mock.patch.object(m, 'FROZEN', None), mock.patch.object(Path, 'open') as opened, \
             mock.patch.object(Path, 'lstat') as info, mock.patch('builtins.compile') as compiled:
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_NO_SOURCE_FREEZE'):
                with m.local_session():
                    self.fail('entered')
        opened.assert_not_called(); info.assert_not_called(); compiled.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_private_aliases_delayed_import_bindings_pins_and_historical_globals(self):
        frozen = self.frozen()
        before = self.snapshot()
        old_phase = historical.storage.PHASE
        old_packet = historical.packet
        old_closure = historical.local_source_closure
        with mock.patch.object(m, 'FROZEN', frozen), m.local_session() as session:
            controller = session.modules['e138_controller']
            contract = session.native_modules['physical_e138_contract']
            self.assertIs(controller.contract, contract)
            self.assertIs(controller.require, contract.require)
            self.assertIs(controller.packet, session.modules['e138_packet'])
            self.assertIs(controller.clock.contract, contract)
            self.assertIs(controller.joiner.contract, contract)
            self.assertEqual(controller.storage.PHASE, 'v6_e139_clean_F_replay_r1')
            delayed = __import__('scripts', fromlist=['e138_pinned_transport']).e138_pinned_transport
            self.assertIs(delayed, session.modules['e138_pinned_transport'])
            self.assertIs(delayed.contract, contract)
            self.assertEqual(Path(delayed.__file__), m.REPO / 'scripts/e138_pinned_transport.py')
            self.assertEqual(sys.modules['scripts'].__path__, [])
            self.assertFalse(session.binding_manifest['external_release_installed'])
            closure = controller.local_source_closure()
            for name, pin in frozen['effective_native_sha256'].items():
                self.assertEqual(closure['src.data.' + name], pin)
                self.assertEqual(session.native_modules[name].__source_sha256__, pin)
            for name, pin in frozen['effective_script_sha256'].items():
                self.assertEqual(closure['scripts.' + name], pin)
                self.assertEqual(session.modules[name].__source_sha256__, pin)
            self.assertEqual(closure['scripts.e139_local_source_session'], frozen['adapter_sha256'])
            self.assertEqual(closure['bindings.e139_local_source_session'], frozen['binding_sha256'])
            self.assertEqual(controller.packet.SOURCE_BYTES('scripts.e138_packet'), session._scripts['e138_packet'])
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_PACKET_SOURCE_KEY'):
                controller.packet.SOURCE_BYTES('scripts.e138_controller')
            self.assertIsNone(controller.RELEASE); self.assertIsNone(controller.PINNED_RELEASE)
            self.assertIsNone(controller.packet.EXPECTED); self.assertIsNone(delayed.FROZEN)
            self.assertIsNone(contract.FROZEN)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(historical.storage.PHASE, old_phase)
        self.assertIs(historical.packet, old_packet)
        self.assertIs(historical.local_source_closure, old_closure)

    def test_private_constructors_remain_disabled_before_io_or_phase(self):
        with mock.patch.object(m, 'FROZEN', self.frozen()), m.local_session() as session:
            controller = session.modules['e138_controller']
            with mock.patch.object(Path, 'open') as opened, mock.patch.object(Path, 'mkdir') as mkdir, \
                 mock.patch('subprocess.Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'E138_CONTROLLER_NO_PINNED_RELEASE'):
                    controller.Controller.create_pinned('UNUSED', b'', b'')
                with self.assertRaisesRegex(ValueError, 'E139_SESSION_SIMULATION_UNSUPPORTED'):
                    controller.Controller('UNUSED', b'', b'', None)
            opened.assert_not_called(); mkdir.assert_not_called(); spawn.assert_not_called()

    def test_frozen_origin_and_effective_roster_rejections_before_io(self):
        frozen = self.frozen()
        for key in ('origin_sha256', 'effective_native_sha256', 'effective_script_sha256'):
            bad = copy.deepcopy(frozen)
            target = next(iter(bad[key])); bad[key][target] = '0' * 64
            with self.subTest(key=key), mock.patch.object(m, 'FROZEN', bad), \
                 mock.patch.object(Path, 'open') as opened:
                with self.assertRaises(ValueError):
                    with m.local_session():
                        self.fail('entered')
            opened.assert_not_called()
        bad = copy.deepcopy(frozen); bad['binding_sha256'] = '0' * 64
        with mock.patch.object(m, 'FROZEN', bad), mock.patch.object(Path, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_BINDING_DIGEST'):
                with m.local_session():
                    self.fail('entered')
        opened.assert_not_called()

    def test_runtime_bindings_and_manifest_drift_reject_before_origin_io(self):
        with mock.patch.object(m, 'FROZEN', self.frozen()), m.local_session() as session:
            changes = ((session.modules['e138_phase_store'], 'PHASE', 'old-phase'),
                       (session.modules['e138_packet'], 'SOURCE_BYTES', lambda key: b''),
                       (session.modules['e138_controller_clock'], 'runtime', object()),
                       (session.modules['e138_controller'], 'contract', object()),
                       (session, 'binding_manifest', {}))
            for target, name, value in changes:
                with mock.patch.object(target, name, value), mock.patch.object(Path, 'open') as opened:
                    with self.assertRaisesRegex(ValueError, 'E139_SESSION_BINDING_DRIFT'):
                        session.local_source_closure()
                opened.assert_not_called()
            with mock.patch.dict(m.BINDINGS, {'external_release_installed': True}), \
                 self.assertRaisesRegex(ValueError, 'E139_SESSION_BINDING_DRIFT'):
                session.local_source_closure()

    def test_actual_origin_drift_and_provider_rechecks_on_every_call(self):
        frozen = self.frozen()
        original_open = Path.open
        def drift(path, *args, **kwargs):
            if path == m.REPO / 'scripts/e138_packet.py':
                return io.BytesIO(b'changed origin bytes')
            return original_open(path, *args, **kwargs)
        before = self.snapshot()
        with mock.patch.object(m, 'FROZEN', frozen), mock.patch.object(Path, 'open', drift):
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_ORIGIN_DRIFT'):
                with m.local_session():
                    self.fail('entered')
        self.assertEqual(before, self.snapshot())
        with mock.patch.object(m, 'FROZEN', frozen), m.local_session() as session:
            session.local_source_closure()
            with mock.patch.object(Path, 'open', drift), self.assertRaisesRegex(ValueError, 'E139_SESSION_ORIGIN_DRIFT'):
                session.local_source_closure()

    def test_effective_byte_tamper_rejected_before_registry_changes(self):
        before = self.snapshot()
        class Tampered:
            def private_sources(self):
                return {m.packet_candidate.KEY: b'not the reviewed effective packet'}
        with mock.patch.object(m, 'FROZEN', self.frozen()), \
             mock.patch.object(m.packet_candidate, 'build', return_value=Tampered()):
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_EFFECTIVE_DRIFT'):
                with m.local_session():
                    self.fail('entered')
        self.assertEqual(before, self.snapshot())
        with mock.patch.object(m, 'FROZEN', self.frozen()), m.local_session() as session:
            session._scripts['e138_packet'] = b'effective RAM drift'
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_EFFECTIVE_DRIFT'):
                session.local_source_closure()
            with self.assertRaisesRegex(ValueError, 'E139_SESSION_EFFECTIVE_DRIFT'):
                session.modules['e138_packet'].SOURCE_BYTES('scripts.e138_packet')

    def test_exception_restore_single_active_and_no_disk_import_fallback(self):
        before = self.snapshot()
        with mock.patch.object(m, 'FROZEN', self.frozen()):
            with self.assertRaisesRegex(RuntimeError, 'body failure'):
                with m.local_session() as session:
                    with self.assertRaisesRegex(ValueError, 'E139_SESSION_SINGLE_ACTIVE'):
                        with m.local_session():
                            self.fail('nested')
                    with self.assertRaises(ModuleNotFoundError):
                        __import__('scripts.run_prospective_metadata_v1')
                    raise RuntimeError('body failure')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(session._alive)

    def test_consumer_initialization_exception_restores_both_registries(self):
        before = self.snapshot()
        original_exec = exec
        def failing_exec(code, namespace, *args):
            if getattr(code, 'co_filename', '') == '<e139-local-e138_controller>':
                raise RuntimeError('consumer initialization failure')
            return original_exec(code, namespace, *args)
        with mock.patch.object(m, 'FROZEN', self.frozen()), mock.patch('builtins.exec', failing_exec):
            with self.assertRaisesRegex(RuntimeError, 'consumer initialization failure'):
                with m.local_session():
                    self.fail('entered')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(m._LOCK.locked())

    def test_native_failure_before_enter_and_inside_enter_without_double_exit(self):
        original_exec = exec
        for when in ('before', 'inside'):
            calls = []
            before = self.snapshot()
            def intercepted_exec(code, namespace, *args):
                private_loader = namespace.get('__name__') == '_e139_local_native_loader'
                if private_loader and when == 'before':
                    raise RuntimeError('before native enter')
                result = original_exec(code, namespace, *args)
                if private_loader:
                    factory = namespace['source_session']
                    def wrapped(rows):
                        real = factory(rows)
                        class FailingEnter:
                            def __enter__(self):
                                calls.append('enter')
                                # Actual loader owns and performs its rollback.
                                with real:
                                    raise RuntimeError('inside native enter')
                            def __exit__(self, *exc):
                                calls.append('unexpected_exit')
                                raise AssertionError('double exit after failed enter')
                        return FailingEnter()
                    namespace['source_session'] = wrapped
                return result
            with self.subTest(when=when), mock.patch.object(m, 'FROZEN', self.frozen()), \
                 mock.patch('builtins.exec', intercepted_exec):
                with self.assertRaisesRegex(RuntimeError, when + ' native enter'):
                    with m.local_session():
                        self.fail('entered')
            self.assertNotIn('unexpected_exit', calls)
            self.assertEqual(before, self.snapshot())
            self.assertFalse(m._LOCK.locked())

    def test_native_exit_failure_after_actual_restore_still_restores_scripts_and_lock(self):
        original_exec = exec
        before = self.snapshot()
        calls = []
        def intercepted_exec(code, namespace, *args):
            result = original_exec(code, namespace, *args)
            if namespace.get('__name__') == '_e139_local_native_loader':
                factory = namespace['source_session']
                def wrapped(rows):
                    real = factory(rows)
                    class FailingExit:
                        def __enter__(self):
                            return real.__enter__()
                        def __exit__(self, *exc):
                            real.__exit__(*exc)  # Actual src restoration FIRST.
                            calls.append('restored_native')
                            raise RuntimeError('after native restore')
                    return FailingExit()
                namespace['source_session'] = wrapped
            return result
        with mock.patch.object(m, 'FROZEN', self.frozen()), mock.patch('builtins.exec', intercepted_exec):
            with self.assertRaisesRegex(RuntimeError, 'after native restore'):
                with m.local_session():
                    pass
        self.assertEqual(calls, ['restored_native'])
        self.assertEqual(before, self.snapshot())
        self.assertFalse(m._LOCK.locked())

    def test_close_failure_cannot_skip_native_scripts_restore_or_lock_release(self):
        original_close = m.Session.close
        before = self.snapshot()
        def failing_close(session):
            original_close(session)
            raise RuntimeError('close error after terminalization')
        with mock.patch.object(m, 'FROZEN', self.frozen()), mock.patch.object(m.Session, 'close', failing_close):
            with self.assertRaisesRegex(RuntimeError, 'close error after terminalization'):
                with m.local_session() as session:
                    pass
        self.assertFalse(session._alive)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(m._LOCK.locked())

    def test_wrapped_lifecycle_tracking_and_stale_operations_terminal_zero_io(self):
        # Substitute ONLY the disabled constructor result to isolate lifecycle;
        # no authority, release, source tag, PhaseStore or transport is created.
        with mock.patch.object(m, 'FROZEN', self.frozen()), m.local_session() as session:
            cls = session.modules['e138_controller'].Controller
            base = cls.__mro__[1]
            def lifecycle_constructor(cls, *args, **kwargs):
                instance = cls.__new__(cls)
                instance.terminal = False
                instance.adapter = types.SimpleNamespace(_terminal=False)
                return instance
            with mock.patch.object(base, 'create_pinned', classmethod(lifecycle_constructor)):
                instance = cls.create_pinned()
            self.assertIn(instance, session._controllers)
            provider = session.modules['e138_packet'].SOURCE_BYTES
        self.assertTrue(instance.terminal); self.assertTrue(instance.adapter._terminal)
        with mock.patch.object(Path, 'open') as opened, mock.patch('subprocess.Popen') as spawn:
            for call in (lambda: cls.create_pinned(), lambda: instance.run_role({}, b''),
                         lambda: provider('scripts.e138_packet'), session.local_source_closure):
                with self.assertRaisesRegex(ValueError, 'E139_SESSION_CLOSED'):
                    call()
        opened.assert_not_called(); spawn.assert_not_called()

    def test_syntax_and_bindings_snapshot(self):
        ast.parse(Path(m.__file__).read_bytes(), feature_version=(3, 6))
        self.assertEqual(m.BINDINGS['schema'], 'e139-local-source-session-bindings-v1')


if __name__ == '__main__':
    unittest.main()
