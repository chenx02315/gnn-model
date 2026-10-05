import unittest
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from unittest.mock import Mock
from src.models import ranking_v4_memory_guard as guard


class MemoryGuardTests(unittest.TestCase):
    def _run_fake_exit_boundary(self, directory, polls, live, failure=None):
        process = Mock(pid=123, returncode=0)
        process.poll.side_effect = polls
        env = {key: '1' for key in guard.THREAD_KEYS}
        path = Path(directory) / 'boundary.log'
        with patch.object(guard.sys, 'platform', 'linux'), \
             patch.object(guard.subprocess, 'Popen', return_value=process), \
             patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)), \
             patch.object(guard, 'group_rss', side_effect=failure or guard.RSSExitBoundaryUnreadable(123, 'R')), \
             patch.object(guard, 'group_members', return_value=live), \
             patch.object(guard, 'terminate_group') as cleanup:
            if polls[-1] == 0 and not live and failure is None:
                result = guard.run_bounded(['fixture'], path, env)
                cleanup.assert_not_called()
                return result
            with self.assertRaises(RuntimeError):
                guard.run_bounded(['fixture'], path, env)
            cleanup.assert_called_once_with(process)
        return json.loads(Path(str(path) + '.memory.json').read_text())

    def test_exit_boundary_accepts_only_zero_exit_and_empty_whole_group(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run_fake_exit_boundary(directory, [None, 0], [])
            self.assertEqual('PASS_BOUNDED_WORKER', result['status'])
            self.assertEqual('EXIT_ZERO_NO_LIVE_GROUP', result['rss_exit_boundary_resolution'])
            self.assertEqual(0, result['sample_count'])
            self.assertEqual(0, result['exit_code'])
            self.assertEqual('R', result['rss_exit_boundary']['observed_stat_state'])

    def test_exit_boundary_live_leader_descendant_and_nonzero_refuse(self):
        for polls, live in (([None, None], [123]), ([None, None], []),
                            ([None, 0], [456]), ([None, 1], [])):
            with self.subTest(polls=polls, live=live), tempfile.TemporaryDirectory() as directory:
                result = self._run_fake_exit_boundary(directory, polls, live)
                self.assertEqual('STOPPED_NO_RETRY', result['status'])
                self.assertNotIn('rss_exit_boundary_resolution', result)
                self.assertEqual(live, result['rss_exit_boundary']['live_group_pids'])

    def test_unrelated_or_malformed_rss_error_cannot_use_exit_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run_fake_exit_boundary(directory, [None, 0], [], RuntimeError('MEMORY_RSS_UNREADABLE'))
            self.assertEqual('STOPPED_NO_RETRY', result['status'])
            self.assertNotIn('rss_exit_boundary', result)

    def test_exit_boundary_keeps_prior_real_sample_not_synthetic_zero(self):
        process = Mock(pid=123, returncode=0)
        process.poll.side_effect = [None, None, 0]
        env = {key: '1' for key in guard.THREAD_KEYS}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(guard.sys, 'platform', 'linux'), \
             patch.object(guard.subprocess, 'Popen', return_value=process), \
             patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)), \
             patch.object(guard, 'group_rss', side_effect=[100, guard.RSSExitBoundaryUnreadable(123, 'R')]), \
             patch.object(guard, 'rss', return_value=20), \
             patch.object(guard, 'group_members', return_value=[]), \
             patch.object(guard.time, 'sleep'), patch.object(guard, 'terminate_group') as cleanup:
            result = guard.run_bounded(['fixture'], Path(directory) / 'sample.log', env)
            cleanup.assert_not_called()
            self.assertEqual(1, result['sample_count'])
            self.assertEqual(100, result['peak_group_rss_bytes'])
            self.assertEqual(120, result['peak_combined_rss_bytes'])

    def test_parent_rss_failure_is_never_worker_exit_exception(self):
        process = Mock(pid=123, returncode=0)
        process.poll.side_effect = [None]
        env = {key: '1' for key in guard.THREAD_KEYS}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(guard.sys, 'platform', 'linux'), \
             patch.object(guard.subprocess, 'Popen', return_value=process), \
             patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)), \
             patch.object(guard, 'group_rss', return_value=100), \
             patch.object(guard, 'rss', side_effect=guard.RSSExitBoundaryUnreadable(999, 'R')), \
             patch.object(guard, 'group_members', return_value=[]), \
             patch.object(guard, 'terminate_group') as cleanup:
            path = Path(directory) / 'parent.log'
            with self.assertRaises(guard.RSSExitBoundaryUnreadable):
                guard.run_bounded(['fixture'], path, env)
            cleanup.assert_called_once_with(process)
            result = json.loads(Path(str(path) + '.memory.json').read_text())
            self.assertEqual('STOPPED_NO_RETRY', result['status'])
            self.assertNotIn('rss_exit_boundary_resolution', result)

    def test_missing_rss_requires_confirmed_exit(self):
        for state in ('Z', 'X'):
            with patch.object(Path, 'read_text', side_effect=['Name: worker\n', f'123 (worker) {state} 1 123 123']):
                self.assertEqual(0, guard.rss(123))
        with patch.object(Path, 'read_text', side_effect=['Name: worker\n', FileNotFoundError()]):
            self.assertEqual(0, guard.rss(123))
        for state in ('R', 'S', 'D', 'T'):
            with patch.object(Path, 'read_text', side_effect=['Name: worker\n', f'123 (worker) {state} 1 123 123']):
                with self.assertRaisesRegex(RuntimeError, 'MEMORY_RSS_UNREADABLE'):
                    guard.rss(123)
        with patch.object(Path, 'read_text', side_effect=['Name: worker\n', 'malformed']):
            with self.assertRaisesRegex(RuntimeError, 'MEMORY_RSS_UNREADABLE'):
                guard.rss(123)
        with patch.object(Path, 'read_text', side_effect=['Name: worker\n', '123 (worker) R bad bad']):
            with self.assertRaisesRegex(RuntimeError, 'MEMORY_RSS_UNREADABLE') as failure:
                guard.rss(123)
            self.assertNotIsInstance(failure.exception, guard.RSSExitBoundaryUnreadable)
        with patch.object(Path, 'read_text', side_effect=['Name: worker\n', PermissionError()]):
            with self.assertRaises(PermissionError):
                guard.rss(123)

    def test_reserve_and_caps_are_fixed(self):
        self.assertEqual(1, guard.policy()['max_concurrent_workers'])
        self.assertEqual(guard.GIB, guard.policy()['combined_rss_cap_bytes'])
        self.assertEqual(4 * guard.GIB, guard.check_available(16 * guard.GIB, 8 * guard.GIB))
        with self.assertRaisesRegex(RuntimeError, 'RESERVE'):
            guard.check_available(16 * guard.GIB, 4 * guard.GIB)
        with self.assertRaises(ValueError):
            guard.check_available(True, 10)

    def test_unavailable_platform_refuses_before_launch(self):
        with patch.object(guard.sys, 'platform', 'win32'), patch.object(guard.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, 'LINUX'):
                guard.run_bounded(['python'], 'unused', {})
            launch.assert_not_called()

    def test_thread_env_refuses_before_launch(self):
        with patch.object(guard.sys, 'platform', 'linux'), patch.object(guard.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'THREAD'):
                guard.run_bounded(['python'], 'unused', {})
            launch.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux resource execution required')
    def test_linux_child_success_and_sampled_stop(self):
        env = dict(os.environ, **{k: '1' for k in guard.THREAD_KEYS})
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)):
            success = guard.run_bounded([sys.executable, '-c', 'import time; time.sleep(.5)'], Path(directory) / 'ok.log', env)
            self.assertEqual(0, success['exit_code'])
            self.assertGreater(success['sample_count'], 0)
            # Tiny test cap intentionally triggers termination; never allocate a large buffer.
            with patch.object(guard, 'RSS_CAP', 1):
                with self.assertRaisesRegex(RuntimeError, 'PRESSURE'):
                    guard.run_bounded([sys.executable, '-c', 'import time; time.sleep(10)'], Path(directory) / 'stop.log', env)
            stopped = json.loads((Path(directory) / 'stop.log.memory.json').read_text())
            self.assertEqual('STOPPED_NO_RETRY', stopped['status'])
            self.assertIsNotNone(stopped['exit_code'])
            self.assertEqual([], guard.group_members(stopped['process_group']))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process-group execution required')
    def test_linux_dead_leader_descendant_is_stopped_and_timeout_cleans_group(self):
        env = dict(os.environ, **{k: '1' for k in guard.THREAD_KEYS})
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)):
            with self.assertRaisesRegex(RuntimeError, 'DESCENDANT'):
                guard.run_bounded(['/bin/sh', '-c', 'sleep 10 & exit 0'], Path(directory) / 'orphan.log', env)
            receipt = json.loads((Path(directory) / 'orphan.log.memory.json').read_text())
            self.assertEqual('STOPPED_NO_RETRY', receipt['status'])
            self.assertEqual([], guard.group_members(receipt['process_group']))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux hard-limit execution required')
    def test_linux_child_hard_limits_and_threads(self):
        env = dict(os.environ, **{k: '1' for k in guard.THREAD_KEYS})
        code = ('import resource,os,json; print(json.dumps({"address":resource.getrlimit(resource.RLIMIT_AS),'
                '"core":resource.getrlimit(resource.RLIMIT_CORE),"threads":'
                '[os.environ[k] for k in ("OMP_NUM_THREADS","MKL_NUM_THREADS","OPENBLAS_NUM_THREADS","NUMEXPR_NUM_THREADS")]}))')
        with tempfile.TemporaryDirectory() as directory, patch.object(guard, 'available_memory', return_value=(16 * guard.GIB, 12 * guard.GIB)):
            path = Path(directory) / 'limits.log'
            guard.run_bounded([sys.executable, '-c', code], path, env)
            result = json.loads(path.read_text())
            self.assertEqual([guard.ADDRESS_CAP, guard.ADDRESS_CAP], result['address'])
            self.assertEqual([0, 0], result['core'])
            self.assertEqual(['1'] * 4, result['threads'])
            with patch.object(guard, 'TIMEOUT_S', 0):
                with self.assertRaisesRegex(RuntimeError, 'TIMEOUT'):
                    guard.run_bounded([sys.executable, '-c', 'import time; time.sleep(10)'], Path(directory) / 'timeout.log', env)
            receipt = json.loads((Path(directory) / 'timeout.log.memory.json').read_text())
            self.assertEqual([], guard.group_members(receipt['process_group']))


if __name__ == '__main__':
    unittest.main()
