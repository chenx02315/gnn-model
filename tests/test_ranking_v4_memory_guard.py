import unittest
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from src.models import ranking_v4_memory_guard as guard


class MemoryGuardTests(unittest.TestCase):
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
