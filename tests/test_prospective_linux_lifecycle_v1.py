"""Parser/mock tests only. They never certify the Linux positive gate."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import verify_prospective_linux_lifecycle_v1 as gate


def stat(pgrp=2, ticks=100, state='S', pid=2):
    fields = [state, '1', str(pgrp)] + ['0'] * 16 + [str(ticks)]
    return str(pid)+' (name ) with spaces) ' + ' '.join(fields)


class LifecycleTests(unittest.TestCase):
    def test_stat_parser_with_parentheses(self):
        self.assertEqual(gate.parse_proc_stat(stat()), dict(pid=2, pgrp=2, start_ticks=100, state='S'))
        for text in ('bad', '2 (x) S', stat(pgrp=0), stat(ticks=0), stat(state='invalid')):
            with self.assertRaises((ValueError, IndexError)): gate.parse_proc_stat(text)

    def test_cgroup_path_no_escape(self):
        self.assertEqual(gate.parse_cgroup_path('0::/'), '/')
        self.assertEqual(gate.parse_cgroup_path('0::/safe/group'), '/safe/group')
        for value in ('1:memory:/x', '0::/../other', '0::/a/./b', '0::/\n0::/two', '', '0::relative'):
            with self.assertRaises(ValueError): gate.parse_cgroup_path(value)

    def test_non_linux_stops_before_io_and_launch(self):
        with patch.object(gate.sys, 'platform', 'win32'), patch.object(gate, 'small_read') as read, \
                patch.object(gate.subprocess, 'Popen') as popen, patch.object(gate.tempfile, 'TemporaryDirectory') as temp:
            with self.assertRaisesRegex(ValueError, 'LINUX_REQUIRED'): gate.run_gate()
            read.assert_not_called()
            popen.assert_not_called()
            temp.assert_not_called()

    def test_non_init_stops_before_kernel_reads(self):
        with patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.os, 'getpid', return_value=12), \
                patch.object(gate, 'small_read') as read:
            with self.assertRaisesRegex(ValueError, 'PID_NAMESPACE'): gate.preflight()
            read.assert_not_called()

    def preflight_reads(self, changed=None):
        values = {'/proc/self/cgroup': '0::/', '/proc/self/mountinfo':
                  '1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup ro\n2 0 0:2 / /proc rw - proc proc rw',
                  '/proc/self/stat': stat(pid=1, pgrp=1), '/proc/1/stat': stat(pid=1, pgrp=1),
                  '/sys/fs/cgroup/memory.max': str(gate.MEMORY_BYTES),
                  '/sys/fs/cgroup/memory.swap.max': '0', '/sys/fs/cgroup/memory.oom.group': '1',
                  '/sys/fs/cgroup/pids.max': str(gate.PIDS_MAX),
                  '/sys/fs/cgroup/pids.current': '1', '/sys/fs/cgroup/cgroup.procs': '1',
                  '/proc/sys/kernel/random/boot_id': 'synthetic-boot'}
        values.update(changed or {})
        return lambda path, *args: values[str(path).replace('\\', '/')]

    def test_preflight_fixture_observation_not_linux_execution(self):
        with patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.os, 'getpid', return_value=1), \
                patch.object(gate.os, 'uname', return_value=SimpleNamespace(release='synthetic-kernel', nodename='synthetic-host'), create=True), \
                patch.object(gate, 'small_read', side_effect=self.preflight_reads()), patch.object(Path, 'is_symlink', return_value=False):
            result = gate.preflight()
        self.assertEqual(result['memory_limit_bytes'], 128*1024*1024)
        self.assertFalse(result['active_oom_test'])
        self.assertFalse(result['production_atpg_limits_verified'])

    def test_preflight_bad_limits_and_shared_scope(self):
        cases = {'memory.max': 'max', 'memory.swap.max': '1', 'memory.oom.group': '0',
                 'pids.max': 'max', 'pids.current': '2', 'cgroup.procs': '1\n2'}
        for key, value in cases.items():
            with patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.os, 'getpid', return_value=1), \
                    patch.object(gate, 'small_read', side_effect=self.preflight_reads({'/sys/fs/cgroup/'+key: value})), \
                    patch.object(Path, 'is_symlink', return_value=False):
                with self.subTest(key=key), self.assertRaises(ValueError): gate.preflight()

    def test_only_fixed_profiles(self):
        for profile in ('success', 'failure', 'timeout_group'):
            code = gate.payload(profile, Path('fixed.child'))
            self.assertIsInstance(code, str)
        for profile in ('tessent', 'training', 'arbitrary-command', None):
            with self.assertRaises(ValueError): gate.payload(profile, Path('fixed.child'))

    def test_wrong_proc_namespace_rejected(self):
        for changed in ({'/proc/self/stat': stat(pid=400)},
                        {'/proc/1/stat': stat(pid=1, ticks=999)},
                        {'/proc/self/mountinfo': '1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup ro'}):
            with patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.os, 'getpid', return_value=1), \
                    patch.object(gate, 'small_read', side_effect=self.preflight_reads(changed)):
                with self.assertRaises(ValueError): gate.preflight()

    def test_main_non_linux_is_failed_gate_not_skip(self):
        output = io.StringIO()
        with patch.object(gate.sys, 'argv', ['gate']), patch.object(gate.sys, 'platform', 'win32'), \
                contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 78)
        self.assertIn('"gate_pass": false', output.getvalue())

    def test_mock_success_leader_has_new_session_and_cleanup(self):
        fake = SimpleNamespace(pid=2, returncode=0, wait=lambda **kw: 0)
        with patch.object(gate.subprocess, 'Popen', return_value=fake) as popen, \
                patch.object(gate, 'small_read', return_value=stat()), \
                patch.object(gate, 'group_members', return_value=[]), \
                patch.object(gate, 'reap_adopted'), \
                patch.object(gate.os, 'killpg', create=True) as kill, \
                patch.object(gate.signal, 'SIGKILL', 9, create=True):
            result = gate.run_profile('success', Path('synthetic'))
        self.assertEqual(result['leader_start_ticks'], 100)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertTrue(result['observed_group_empty'])
        kill.assert_called_once_with(2, 9)

    def test_mock_spawn_failure_never_moves_to_another_profile(self):
        with patch.object(gate, 'preflight', return_value={}), \
                patch.object(gate.ctypes, 'CDLL', return_value=SimpleNamespace(prctl=lambda *args: 0)), \
                patch.object(gate, 'run_profile', side_effect=OSError('synthetic launch failure')) as run:
            with self.assertRaises(OSError): gate.run_gate()
        self.assertEqual(run.call_count, 1)

    def test_subreaper_rejection_prevents_temp_or_launch(self):
        with patch.object(gate, 'preflight', return_value={}), \
                patch.object(gate.ctypes, 'CDLL', return_value=SimpleNamespace(prctl=lambda *args: -1)), \
                patch.object(gate.tempfile, 'TemporaryDirectory') as temp, \
                patch.object(gate.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(ValueError, 'SUBREAPER_REQUIRED'): gate.run_gate()
        temp.assert_not_called()
        popen.assert_not_called()

    def test_timeout_grandchild_cleanup_is_mandatory(self):
        from unittest.mock import Mock
        proc = SimpleNamespace(pid=2, returncode=-9,
            wait=Mock(side_effect=[gate.subprocess.TimeoutExpired('toy', 0.4), -9]))
        with patch.object(gate.subprocess, 'Popen', return_value=proc), \
                patch.object(gate, 'small_read', side_effect=[stat(), '3']), \
                patch.object(Path, 'exists', return_value=True), \
                patch.object(gate, 'group_members', side_effect=[[{'pid': 3}], [{'pid': 3}], []]), \
                patch.object(gate, 'reap_adopted') as reap, \
                patch.object(gate.time, 'sleep'), \
                patch.object(gate.os, 'killpg', create=True) as kill, \
                patch.object(gate.signal, 'SIGKILL', 9, create=True):
            result = gate.run_profile('timeout_group', Path('synthetic'))
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['grandchild_pid'], 3)
        self.assertGreaterEqual(reap.call_count, 2)
        kill.assert_called_once_with(2, 9)

    def test_identity_and_marker_failure_use_same_cleanup(self):
        for profile, source, marker_exists in (('success', stat(pgrp=7), True),
                                                ('timeout_group', stat(), False)):
            proc = SimpleNamespace(pid=2, returncode=-9, wait=lambda **kw: -9, poll=lambda: -9)
            with patch.object(gate.subprocess, 'Popen', return_value=proc), \
                    patch.object(gate, 'small_read', return_value=source), \
                    patch.object(Path, 'exists', return_value=marker_exists), \
                    patch.object(gate, 'group_members', return_value=[]), \
                    patch.object(gate, 'reap_adopted') as reap, \
                    patch.object(gate.os, 'killpg', create=True) as kill, \
                    patch.object(gate.signal, 'SIGKILL', 9, create=True):
                with self.assertRaises(ValueError): gate.run_profile(profile, Path('synthetic'))
            reap.assert_called_once_with(2)
            kill.assert_called_once_with(2, 9)

    def test_persistent_group_is_incomplete(self):
        proc = SimpleNamespace(pid=2, returncode=0, wait=lambda **kw: 0)
        with patch.object(gate.os, 'killpg', create=True), \
                patch.object(gate.signal, 'SIGKILL', 9, create=True), \
                patch.object(gate, 'reap_adopted'), \
                patch.object(gate, 'group_members', return_value=[{'pid': 3}]), \
                patch.object(gate.time, 'monotonic', side_effect=[0, 3]):
            with self.assertRaisesRegex(ValueError, 'INCOMPLETE_STOP_GROUP_NOT_EMPTY'):
                gate.cleanup_group(proc)

    def test_cleanup_error_even_with_empty_group_is_incomplete(self):
        proc = SimpleNamespace(pid=2, returncode=0, wait=lambda **kw: 0)
        with patch.object(gate.os, 'killpg', side_effect=PermissionError('toy'), create=True), \
                patch.object(gate.signal, 'SIGKILL', 9, create=True), \
                patch.object(gate, 'reap_adopted'), \
                patch.object(gate, 'group_members', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'INCOMPLETE_STOP_CLEANUP_UNVERIFIED'):
                gate.cleanup_group(proc)

    def test_adopted_wait_is_group_scoped(self):
        with patch.object(gate.os, 'waitpid', side_effect=[(3, 0), (0, 0)], create=True) as wait, \
                patch.object(gate.os, 'WNOHANG', 1, create=True):
            gate.reap_adopted(2)
        self.assertEqual(wait.call_count, 2)
        wait.assert_called_with(-2, 1)


if __name__ == '__main__':
    unittest.main()
