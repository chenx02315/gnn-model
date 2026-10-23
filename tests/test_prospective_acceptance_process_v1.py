"""Only mocks: never starts processes or reads real Linux proc/cgroups."""
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from src.data import prospective_acceptance_process_v1 as process
from src.data import prospective_tessent_acceptance_v1 as recipe

ROOT = Path(__file__).resolve().parents[1]
E85 = (ROOT / 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes()
E93 = (ROOT / 'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes()


def authority():
    return dict(schema='e96-acceptance-authorization-v1', approved=True,
                job_id=123, memory_cap_bytes=1024,
                recipe_sha256=recipe.compile_acceptance(E85, E93, recipe.E85_SHA256,
                                                       recipe.E93_SHA256)['recipe_sha256'],
                scope='E94_FOUR_NO_PATTERN_ACCEPTANCE_ONLY')


class Tests(unittest.TestCase):
    def setUp(self):
        self.scratch = Mock()
        self.scratch.summary.return_value = {'mock_only': True}
        patcher = patch.object(process, 'ScratchMonitor', return_value=self.scratch)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unauthorized_never_popen(self):
        with patch.object(process.subprocess, 'Popen') as popen:
            a = authority()
            a['approved'] = False
            with self.assertRaises(ValueError):
                process.AcceptanceProcess(E85, E93, a)
            popen.assert_not_called()

    def test_environment_closed(self):
        for env in ({'LD_PRELOAD': 'evil'}, {'PATH': '/evil'}, {'LM_LICENSE_FILE': '\n'}):
            with self.assertRaises(ValueError):
                process.AcceptanceProcess(E85, E93, authority(), env)
        actual = process._environment('/scratch', {})
        self.assertEqual(actual['PATH'], '/usr/bin:/bin')
        self.assertNotIn('LSB_JOBID', actual)

    def simulate(self, *, rc=0, capture=None, clean=True, pin=True, sink=None):
        backend = process.AcceptanceProcess(E85, E93, authority(), event_sink=sink or Mock(return_value={'seq': 1, 'sha256': 'a'*64}))
        child = Mock(pid=456, returncode=rc, stdout=io.BytesIO(), stderr=io.BytesIO())
        domain = Mock(membership=b'fixed')
        domain.proof = dict(process_identity={'boot_id': 'boot'},
                            actual_hard_caps={'memory_limit_bytes': 1024},
                            read_evidence={'kernel': {'sha256': 'a'*64}})
        domain.cleanup.return_value = clean
        domain.monitor.side_effect = lambda: domain.scratch_monitor.sample()
        marker = b'E94_TRANSLATED_STATUS_ACCEPTANCE=PASS aes_core H_TO_M\n'
        effects = capture if isinstance(capture, Exception) else None
        def capture_streams(proc, domain, deadline, buffers):
            if callable(capture):
                return capture(proc, domain, deadline, buffers)
            if isinstance(capture, tuple):
                buffers['stdout'].extend(capture[0])
                buffers['stderr'].extend(capture[1])
                return
            buffers['stdout'].extend(marker if capture is None or effects else capture)
            if effects:
                raise effects
        with patch.object(process, '_Domain', return_value=domain) as preflight, \
             patch('src.data.prospective_acceptance_materializer_v1.verify_materialized_item',
                   return_value={'verified': pin}), \
             patch.object(process.subprocess, 'Popen', return_value=child) as popen, \
             patch.object(process, '_save_logs') as logs, \
             patch.object(process, '_identity', return_value=(456, 789, 456)), \
             patch.object(process, '_capture', side_effect=capture_streams):
            receipt = backend.run_item('aes_core', 'H_TO_M')
            preflight.assert_called_once()
            if not pin:
                popen.assert_not_called()
            if receipt['accepted']:
                self.assertFalse(backend.aborted)
            else:
                again = backend.run_item('aes_core', 'H_TO_M')
                self.assertFalse(again['accepted'])
                self.assertLessEqual(popen.call_count, 1)
        return receipt

    def test_success_fixed_spawn(self):
        self.assertTrue(self.simulate()['accepted'])
        self.assertGreaterEqual(self.scratch.sample.call_count, 2)

    def test_scratch_prelaunch_failure_prevents_spawn(self):
        self.scratch.sample.side_effect = ValueError('SCRATCH_BYTES_THRESHOLD')
        result = self.simulate()
        self.assertFalse(result['accepted'])
        self.assertEqual(result['spawn_attempts'], 0)

    def test_scratch_capture_failure_still_cleans_and_disables(self):
        self.scratch.sample.side_effect = [None, ValueError('SCRATCH_BYTES_THRESHOLD'), None]
        result = self.simulate(capture=lambda proc, domain, deadline, buffers: domain.monitor())
        self.assertFalse(result['accepted'])
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['spawn_attempts'], 1)

    def test_final_scratch_growth_rejects_after_cleanup(self):
        self.scratch.sample.side_effect = [None, ValueError('SCRATCH_BYTES_THRESHOLD')]
        result = self.simulate()
        self.assertFalse(result['accepted'])
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(self.scratch.sample.call_count, 2)

    def test_real_monitor_method_propagates_scratch_failure(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.pids = Mock(return_value={100})
        domain.membership = b'fixed'
        domain.scratch_monitor = Mock()
        domain.scratch_monitor.sample.side_effect = ValueError('SCRATCH_BYTES_THRESHOLD')
        with patch.object(process.memory, '_read_fixed', return_value=b'fixed'):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_BYTES_THRESHOLD'):
                domain.monitor()

    def test_failure_routes_no_retry(self):
        for kwargs in ({'rc': 1}, {'capture': ValueError('TIMEOUT')},
                       {'capture': ValueError('CAPTURE_OVERFLOW')},
                       {'clean': False}, {'pin': False},
                       {'capture': b'WARNING\n'},
                       {'capture': b'ERROR\n'},
                       {'sink': Mock(side_effect=OSError('journal'))}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.simulate(**kwargs)['accepted'])

    def test_raw_hash_mismatch(self):
        with patch.object(process.subprocess, 'Popen') as popen:
            with self.assertRaises(ValueError):
                process.AcceptanceProcess(E85+b' ', E93, authority())
            popen.assert_not_called()

    def test_wrong_serial_selector(self):
        backend = process.AcceptanceProcess(E85, E93, authority())
        with patch.object(process, '_Domain') as domain:
            result = backend.run_item('spi', 'H_TO_F')
            self.assertFalse(result['accepted'])
            domain.assert_not_called()

    def test_failed_capture_keeps_prefix_and_flags(self):
        result = self.simulate(capture=ValueError('OVERFLOW'))
        self.assertFalse(result['log_capture_complete'])
        self.assertGreater(result['logs']['stdout']['bytes'], 0)
        self.assertIsNotNone(result['logs']['stdout']['sha256'])
        self.assertFalse(result['logs']['stdout']['complete'])

    def test_direct_capture_reserves_budget_and_retains_prefix(self):
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {1: True}
        key = Mock(fd=1, data='stdout')
        selector.select.return_value = [(key, 1)]
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        with patch.object(process.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(process.os, 'set_blocking'), \
             patch.object(process.os, 'read', return_value=b'abc') as read, \
             patch.object(process, 'CAPTURE_LIMIT', 3):
            with self.assertRaisesRegex(ValueError, 'CAPTURE_BUDGET_EXHAUSTED'):
                process._capture(Mock(), Mock(), process.time.monotonic()+10, buffers)
        self.assertEqual(bytes(buffers['stdout']), b'abc')
        self.assertEqual(bytes(buffers['stderr']), b'')
        read.assert_called_once_with(1, 3)

    def test_durable_preflight_callback_rejects_before_spawn(self):
        sink = Mock(side_effect=OSError('fsync'))
        result = self.simulate(sink=sink)
        self.assertEqual(result['spawn_attempts'], 0)
        self.assertEqual(sink.call_args.args[0], 'PREFLIGHT')

    def test_separate_streams_cannot_hide_error_or_synthesize_marker(self):
        marker = b'E94_TRANSLATED_STATUS_ACCEPTANCE=PASS aes_core H_TO_M\n'
        self.assertFalse(self.simulate(capture=(marker, b'ERROR\n'))['accepted'])
        self.assertFalse(self.simulate(capture=(marker[:10], marker[10:]))['accepted'])

    def test_launched_ack_failure_stops_and_cleans(self):
        sink = Mock(side_effect=[{'seq': 1, 'sha256': 'a'*64}, OSError('journal')])
        result = self.simulate(sink=sink)
        self.assertFalse(result['accepted'])
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['tessent_calls'], 1)

    def test_cleanup_reaps_only_nonleader_target(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.membership = b'fixed'
        domain.pids = Mock(side_effect=[{100, 200, 201}, {100}])
        domain.own_children = Mock(side_effect=[{200, 201}, set()])
        domain.child_identity = Mock(return_value=(201, 5, 100, 'Z'))
        child = Mock(pid=200, returncode=7)
        with patch.object(process, '_identity', side_effect=lambda pid, _: (pid, 5, 200)), \
             patch.object(process.os, 'kill'), patch.object(process.os, 'killpg', create=True), \
             patch.object(process.os, 'WNOHANG', 1, create=True), \
             patch.object(process.signal, 'SIGKILL', 9, create=True), \
             patch.object(process.os, 'waitpid', return_value=(201, 0), create=True) as reap:
            self.assertTrue(domain.cleanup(child, (200, 5, 200), process.time.monotonic()+10))
            reap.assert_called_once_with(201, process.os.WNOHANG)
            child.poll.assert_called_once()
            self.assertEqual(child.returncode, 7)

    def test_adopted_zombie_absent_from_cgroup_is_reaped(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.membership = b'fixed'
        domain.pids = Mock(return_value={100})
        domain.own_children = Mock(side_effect=[{201}, set()])
        domain.child_identity = Mock(return_value=(201, 9, 100, 'Z'))
        with patch.object(process.os, 'waitpid', return_value=(201, 0), create=True) as reap, \
             patch.object(process.os, 'WNOHANG', 1, create=True), \
             patch.object(process.os, 'kill') as kill, \
             patch.object(process.os, 'killpg', create=True) as group:
            self.assertTrue(domain.cleanup(None, None, process.time.monotonic()+1))
        reap.assert_called_once_with(201, 1)
        kill.assert_not_called()
        group.assert_not_called()

    def test_live_adopted_child_blocks_success_without_broad_kill(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.pids = Mock(return_value={100})
        domain.own_children = Mock(return_value={201})
        domain.child_identity = Mock(return_value=(201, 9, 100, 'S'))
        with patch.object(process.time, 'monotonic', side_effect=[0, 2]), \
             patch.object(process.time, 'sleep'), \
             patch.object(process.os, 'waitpid', create=True) as reap:
            self.assertFalse(domain.cleanup(None, None, 1))
        reap.assert_not_called()

    def test_children_parser_is_bounded_and_strict(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        for raw in (b'0', b'-1', b'201 201', b'100', b'x', b'1 '*65):
            with patch.object(process, '_read', return_value=raw):
                with self.assertRaises(ValueError):
                    domain.own_children()

    def test_changed_child_identity_cannot_be_reaped_or_certified(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.pids = Mock(return_value={100})
        domain.own_children = Mock(return_value={201})
        domain.child_identity = Mock(side_effect=[(201, 9, 100, 'Z'),
                                                  (201, 10, 100, 'Z')])
        with patch.object(process.time, 'monotonic', side_effect=[0, 2]), \
             patch.object(process.time, 'sleep'), \
             patch.object(process.os, 'waitpid', create=True) as reap:
            self.assertFalse(domain.cleanup(None, None, 1))
        reap.assert_not_called()

    def test_fresh_child_at_final_gate_prevents_success(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        domain.pids = Mock(return_value={100})
        domain.own_children = Mock(side_effect=[set(), {202}])
        with patch.object(process.time, 'monotonic', side_effect=[0, 2]), \
             patch.object(process.time, 'sleep'):
            self.assertFalse(domain.cleanup(None, None, 1))

    def test_child_stat_handles_comm_and_requires_own_parent(self):
        domain = object.__new__(process._Domain)
        domain.self_pid = 100
        fields = ['Z', '100'] + ['0'] * 17 + ['999']
        raw = ('201 (name with ) space) ' + ' '.join(fields)).encode()
        with patch.object(process, '_read', return_value=raw):
            self.assertEqual(domain.child_identity(201), (201, 999, 100, 'Z'))
        with patch.object(process, '_read', return_value=raw.replace(b'Z 100 ', b'Z 99 ')):
            with self.assertRaises(ValueError):
                domain.child_identity(201)

    def test_unknown_spawn_cleanup_attempt_and_call_unknown(self):
        backend = process.AcceptanceProcess(E85, E93, authority(), event_sink=Mock(return_value={'seq': 1, 'sha256': 'a'*64}))
        domain = Mock(membership=b'fixed')
        domain.proof = dict(process_identity={'boot_id': 'boot'})
        with patch.object(process, '_Domain', return_value=domain), \
             patch('src.data.prospective_acceptance_materializer_v1.verify_materialized_item',
                   return_value={'verified': True}), \
             patch.object(process.subprocess, 'Popen', side_effect=OSError('ambiguous')), \
             patch.object(process, '_save_logs'):
            result = backend.run_item('aes_core', 'H_TO_M')
        domain.cleanup.assert_called_once()
        self.assertIsNone(domain.cleanup.call_args.args[0])
        self.assertIsNone(result['tessent_calls'])
        self.assertEqual(result['spawn_attempts'], 1)
        self.assertFalse(result['cleanup_verified'])
        self.assertIsNone(result['logs']['stdout']['sha256'])

    def test_domain_close_failure_releases_lock(self):
        backend = process.AcceptanceProcess(E85, E93, authority())
        domain = Mock()
        domain.close.side_effect = OSError('close')
        with patch.object(process, '_Domain', return_value=domain), \
             patch('src.data.prospective_acceptance_materializer_v1.verify_materialized_item',
                   side_effect=ValueError('pin')):
            result = backend.run_item('aes_core', 'H_TO_M')
        self.assertFalse(result['cleanup_verified'])
        self.assertTrue(process._WORKER.acquire(blocking=False))
        process._WORKER.release()

    def test_preflight_failure_no_spawn_consumes_attempt(self):
        backend = process.AcceptanceProcess(E85, E93, authority())
        with patch.object(process, '_Domain', side_effect=ValueError('E95')), \
             patch.object(process.subprocess, 'Popen') as popen:
            self.assertFalse(backend.run_item('aes_core', 'H_TO_M')['accepted'])
            self.assertEqual(backend.cursor, 1)
            self.assertFalse(backend.run_item('aes_core', 'H_TO_M')['accepted'])
            popen.assert_not_called()

    def test_four_serial_fixed_calls(self):
        backend = process.AcceptanceProcess(E85, E93, authority(), event_sink=Mock(return_value={'seq': 1, 'sha256': 'a'*64}))
        domain = Mock(membership=b'fixed')
        domain.proof = dict(process_identity={'boot_id': 'boot'},
                            actual_hard_caps={'memory_limit_bytes': 1024}, read_evidence={})
        domain.cleanup.return_value = True
        def child(*args, **kwargs):
            return Mock(pid=456, returncode=0, stdout=io.BytesIO(), stderr=io.BytesIO())
        with patch.object(process, '_Domain', return_value=domain), \
             patch('src.data.prospective_acceptance_materializer_v1.verify_materialized_item',
                   return_value={'verified': True}), \
             patch.object(process.subprocess, 'Popen', side_effect=child) as popen, \
             patch.object(process, '_save_logs'), \
             patch.object(process, '_identity', return_value=(456, 789, 456)), \
             patch.object(process, '_capture') as capture:
            for circuit, transition, _ in recipe.ROSTER:
                marker = ('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS %s %s\n' %
                          (circuit, transition)).encode()
                capture.side_effect = lambda proc, domain, deadline, buffers: buffers['stdout'].extend(marker)
                self.assertTrue(backend.run_item(circuit, transition)['accepted'])
            self.assertEqual(popen.call_count, 4)
            for call, item in zip(popen.call_args_list, backend.bundle['items']):
                self.assertEqual(call.args[0], item['argv'])
                self.assertFalse(call.kwargs['shell'])
                self.assertTrue(call.kwargs['start_new_session'])
            self.assertFalse(backend.run_item('aes_core', 'H_TO_M')['accepted'])
            self.assertEqual(popen.call_count, 4)


if __name__ == '__main__':
    unittest.main()
