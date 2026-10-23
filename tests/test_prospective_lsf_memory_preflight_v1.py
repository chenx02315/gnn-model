"""Synthetic snapshots and fake I/O only; never call the real preflight."""
import ast
import errno
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import prospective_lsf_memory_preflight_v1 as m
from tests.test_prospective_acquisition_tree_inputs_e85 import FakeAnchoredIO

JOB = 12345
MEMBERSHIP = b'7:memory:/lsf/cluster/job.12345.800.999/tsk.12345.801/child.802\n'
MOUNTINFO = (b'31 20 0:27 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime '
             b'- cgroup cgroup rw,memory\n')
BOOT = b'11111111-2222-3333-4444-555555555555\n'


def proc_stat(pid=77, start=987654, cpu_ticks=1):
    # Fields after comm begin at field 3; starttime is field 22 / index 19.
    tail = ['S'] + ['1'] * 18 + [str(start)] + ['0'] * 10
    tail[11] = str(cpu_ticks)  # field 14: utime, not field 4: ppid.
    return ('%d (synthetic worker) %s\n' % (pid, ' '.join(tail))).encode('ascii')


def cgroup_result():
    row = limits()
    return dict(job_limits=row, chain_limits=[row, row, row],
                chain_components=['job.12345.800.999', 'tsk.12345.801',
                                  'child.802'],
                procs=b'77\n88\n', cgroup_bytes=80,
                root_directory={'dev': 1, 'ino': 1, 'uid': 0, 'gid': 0,
                                'mode': 0o755},
                job_directory={'dev': 1, 'ino': 2, 'uid': 0, 'gid': 0,
                               'mode': 0o755},
                current_directory={'dev': 1, 'ino': 3, 'uid': 0, 'gid': 0,
                                   'mode': 0o755},
                root_and_job_write_access_checks_clear=True)


def limits(memory=1024, memsw=2048, hierarchy=1):
    return {'memory.limit_in_bytes': ('%d\n' % memory).encode('ascii'),
            'memory.memsw.limit_in_bytes': ('%d\n' % memsw).encode('ascii'),
            'memory.use_hierarchy': ('%d\n' % hierarchy).encode('ascii')}


class LsfMemoryPreflightTests(unittest.TestCase):
    def test_documented_parallel_job_component_and_descendant(self):
        value = m._membership(MEMBERSHIP, JOB)
        self.assertEqual(value['job_component'], 'job.12345.800.999')
        self.assertEqual(value['job_path'], '/lsf/cluster/job.12345.800.999')
        self.assertEqual(value['descendant'], ['tsk.12345.801', 'child.802'])

    def test_membership_rejects_wrong_ambiguous_root_and_escape(self):
        cases = (
            (MEMBERSHIP.replace(b'job.12345', b'job.9'), 'EXACT_JOB_COMPONENT'),
            (b'7:memory:/job.12345.1.2\n', 'WORKER_MUST_BE_JOB_DESCENDANT'),
            (b'7:memory:/a/../job.12345.1.2/child.1\n', 'MEMBERSHIP_COMPONENTS'),
            (b'7:memory:/job.12345.1.2/job.12345.3.4/child.1\n',
             'EXACT_JOB_COMPONENT'),
            (b'7:memory:/a\\b/job.12345.1.2/child.1\n',
             'MEMBERSHIP_ABSOLUTE'),
        )
        for raw, code in cases:
            with self.assertRaisesRegex(m.PreflightError, code):
                m._membership(raw, JOB)
        too_deep = ('7:memory:/' + '/'.join(['a'] * 31 +
                    ['job.12345.1.2', 'child.1']) + '\n').encode('ascii')
        with self.assertRaisesRegex(m.PreflightError, 'MEMBERSHIP_COMPONENTS'):
            m._membership(too_deep, JOB)
        for task in (b'tsk.9.801', b'tsk.bad.801', b'tsk.12345.bad'):
            raw = MEMBERSHIP.replace(b'tsk.12345.801', task)
            with self.assertRaisesRegex(m.PreflightError,
                                        'TASK_COMPONENT_JOB_MISMATCH'):
                m._membership(raw, JOB)

    def test_mount_is_unique_memory_v1_at_fixed_root(self):
        m._mountinfo(MOUNTINFO)
        for raw in (
            MOUNTINFO.replace(b' - cgroup ', b' - cgroup2 '),
            MOUNTINFO.replace(b'0:27 / /sys', b'0:27 /nested /sys'),
            MOUNTINFO + MOUNTINFO,
            MOUNTINFO.replace(b'/sys/fs/cgroup/memory', b'/other'),
        ):
            with self.assertRaises(m.PreflightError):
                m._mountinfo(raw)
        self.assertEqual(m._mountinfo(MOUNTINFO), (0, 27))
        for extra in (b'40 20 0:40 / /sys/fs/cgroup/memory rw - tmpfs tmpfs rw\n',
                      b'40 20 0:40 / /sys/fs/cgroup/memory/lsf rw - tmpfs tmpfs rw\n'):
            with self.assertRaises(m.PreflightError):
                m._mountinfo(MOUNTINFO + extra)

    def test_forged_snapshot_is_never_os_authenticated_or_passed(self):
        value = m.evaluate_snapshot(
            {'membership': MEMBERSHIP, 'limits': limits()}, JOB, 4096)
        self.assertTrue(value['snapshot_consistent'])
        self.assertFalse(value['os_authenticated'])
        self.assertFalse(value['memory_preflight_passed'])
        self.assertEqual(value['actual_hard_caps']['memory_limit_bytes'], 1024)

    def test_hard_caps_are_finite_hierarchical_and_approved(self):
        membership = m._membership(MEMBERSHIP, JOB)
        self.assertEqual(m._evaluate_values(membership, limits(), JOB, 4096),
                         (1024, 2048, 1))
        inherited = limits(memory=m.CGROUP_V1_UNLIMITED_MIN,
                           memsw=m.CGROUP_V1_UNLIMITED_MIN)
        self.assertEqual(m._evaluate_values(membership, limits(), JOB, 4096,
            [limits(), inherited]), (1024, 2048, 1))
        for raw, cap, code in (
            (limits(memory=4097), 4096, 'APPROVED_HARD_CAP'),
            (limits(memsw=4097), 4096, 'APPROVED_HARD_CAP'),
            (limits(memory=2048, memsw=1024), 4096, 'APPROVED_HARD_CAP'),
            (limits(hierarchy=0), 4096, 'HIERARCHY_REQUIRED'),
            ({**limits(), 'memory.limit_in_bytes': b'max\n'}, 4096,
             'MEMORY_LIMIT'),
            ({**limits(), 'memory.limit_in_bytes': b'9223372036854771712\n'},
             m.MAX_INTEGER, 'MEMORY_LIMIT_NOT_FINITE'),
        ):
            with self.assertRaisesRegex(m.PreflightError, code):
                m._evaluate_values(membership, raw, JOB, cap)

    def test_jobid_cap_and_array_arguments_fail_closed(self):
        for job in (None, True, 0, -1, m.MAX_INTEGER + 1):
            with self.assertRaisesRegex(m.PreflightError, 'EXPECTED_JOB_ID'):
                m._arguments(job, 1)
        for cap in (None, True, 0, -1, m.MAX_INTEGER + 1):
            with self.assertRaisesRegex(m.PreflightError,
                                        'APPROVED_MEMORY_CAP_REQUIRED'):
                m._arguments(1, cap)
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': str(JOB),
                                             'LSB_JOBINDEX': '2'}, clear=True):
            with self.assertRaisesRegex(m.PreflightError,
                                        'LSB_JOB_ARRAY_UNSUPPORTED'):
                m.collect_preflight(JOB, 4096)
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': '9'}, clear=True):
            with self.assertRaisesRegex(m.PreflightError, 'LSB_JOBID_MISMATCH'):
                m.collect_preflight(JOB, 4096)

    def test_collect_with_fake_reads_returns_small_evidence_not_raw_bodies(self):
        fixed = {'/proc/self/cgroup': MEMBERSHIP,
                 '/proc/self/mountinfo': MOUNTINFO,
                 '/proc/self/stat': proc_stat(),
                 '/proc/sys/kernel/random/boot_id': BOOT}
        def reader(path, cap=m.MAX_FIXED):
            return fixed[path]
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': str(JOB)}, clear=True), \
             mock.patch.object(m, 'sys_platform_linux', return_value=True), \
             mock.patch.object(m.os, 'getpid', return_value=77), \
             mock.patch.object(m.socket, 'gethostname', return_value='worker-a'), \
             mock.patch.object(m, '_read_fixed', side_effect=reader), \
             mock.patch.object(m, '_cgroup_reads', return_value=cgroup_result()):
            value = m.collect_preflight(JOB, 4096)
        self.assertTrue(value['memory_preflight_passed'])
        self.assertEqual(value['process_identity'],
                         {'pid': 77, 'start_ticks': 987654,
                          'boot_id': BOOT.decode().strip(), 'hostname': 'worker-a'})
        self.assertEqual(value['actual_hard_caps']['memory_memsw_limit_bytes'],
                         2048)
        text = str(value)
        self.assertNotIn(MEMBERSHIP.decode().strip(), text)
        self.assertNotIn(proc_stat().decode().strip(), text)
        for forbidden in ('execution_ready', 'training_release',
                          'tessent_guard_verified', 'cleanup_verified',
                          'swap_disabled'):
            self.assertNotIn(forbidden, value)
        self.assertEqual(value['physical_io'],
                         'READ_ONLY_NO_SCAN_NO_WRITE_NO_PROCESS')
        self.assertTrue(value['root_and_job_write_access_checks_clear'])
        self.assertFalse(value['global_migration_or_limit_immutability_verified'])
        self.assertTrue(value['descendant_hierarchy_verified'])
        self.assertEqual(value['job_directory_identity']['uid'], 0)

    def test_collect_reread_change_fails_before_pass_snapshot(self):
        values = {'/proc/self/cgroup': [MEMBERSHIP, MEMBERSHIP + b' '],
                  '/proc/self/mountinfo': [MOUNTINFO, MOUNTINFO],
                  '/proc/self/stat': [proc_stat(), proc_stat()],
                  '/proc/sys/kernel/random/boot_id': [BOOT, BOOT]}
        def reader(path, cap=m.MAX_FIXED):
            return values[path].pop(0)
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': str(JOB)}, clear=True), \
             mock.patch.object(m, 'sys_platform_linux', return_value=True), \
             mock.patch.object(m.os, 'getpid', return_value=77), \
             mock.patch.object(m, '_read_fixed', side_effect=reader), \
             mock.patch.object(m, '_cgroup_reads', return_value=cgroup_result()):
            with self.assertRaisesRegex(m.PreflightError,
                                        'PROC_REREAD_CHANGED'):
                m.collect_preflight(JOB, 4096)

    def test_volatile_proc_cpu_fields_may_change_but_identity_must_not(self):
        changed_stat = proc_stat(cpu_ticks=9)
        values = {'/proc/self/cgroup': [MEMBERSHIP, MEMBERSHIP],
                  '/proc/self/mountinfo': [MOUNTINFO, MOUNTINFO],
                  '/proc/self/stat': [proc_stat(), changed_stat],
                  '/proc/sys/kernel/random/boot_id': [BOOT, BOOT]}
        def reader(path, cap=m.MAX_FIXED):
            return values[path].pop(0)
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': str(JOB)}, clear=True), \
             mock.patch.object(m, 'sys_platform_linux', return_value=True), \
             mock.patch.object(m.os, 'getpid', return_value=77), \
             mock.patch.object(m.socket, 'gethostname', return_value='worker-a'), \
             mock.patch.object(m, '_read_fixed', side_effect=reader), \
             mock.patch.object(m, '_cgroup_reads', return_value=cgroup_result()):
            value = m.collect_preflight(JOB, 4096)
        stat_evidence = value['read_evidence']['/proc/self/stat']
        self.assertNotEqual(stat_evidence['before_sha256'],
                            stat_evidence['after_sha256'])
        self.assertEqual(value['process_identity']['start_ticks'], 987654)

    def test_changed_process_start_ticks_is_rejected(self):
        stats = [proc_stat(), proc_stat(start=987655)]
        fixed = {'/proc/self/cgroup': MEMBERSHIP, '/proc/self/mountinfo': MOUNTINFO,
                 '/proc/sys/kernel/random/boot_id': BOOT}
        def reader(path, cap=m.MAX_FIXED):
            return stats.pop(0) if path == '/proc/self/stat' else fixed[path]
        with mock.patch.dict(m.os.environ, {'LSB_JOBID': str(JOB)}, clear=True), \
             mock.patch.object(m, 'sys_platform_linux', return_value=True), \
             mock.patch.object(m.os, 'getpid', return_value=77), \
             mock.patch.object(m, '_read_fixed', side_effect=reader), \
             mock.patch.object(m, '_cgroup_reads', return_value=cgroup_result()):
            with self.assertRaisesRegex(m.PreflightError, 'PROCESS_IDENTITY_CHANGED'):
                m.collect_preflight(JOB, 4096)

    def test_fixed_reader_scope_and_anchored_suffix_nofollow(self):
        with self.assertRaisesRegex(m.PreflightError, 'FIXED_READ_SCOPE'):
            m._read_fixed('/etc/passwd')
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / 'tree'
            tree.mkdir()
            target = tree / 'memory.limit_in_bytes'
            target.write_bytes(b'1024\n')
            io = FakeAnchoredIO(tree)
            with io.installed():
                root_fd = m.os.open('/tree', m.os.O_RDONLY | m.os.O_DIRECTORY)
                try:
                    self.assertEqual(m._read_at(root_fd,
                        'memory.limit_in_bytes', 4096, [0]), b'1024\n')
                finally:
                    m.os.close(root_fd)
            io = FakeAnchoredIO(tree)
            io.on_open = lambda path: io.links.add(path) if path == target else None
            with io.installed():
                root_fd = m.os.open('/tree', m.os.O_RDONLY | m.os.O_DIRECTORY)
                try:
                    with self.assertRaises(OSError):
                        m._read_at(root_fd, 'memory.limit_in_bytes', 4096, [0])
                finally:
                    m.os.close(root_fd)
            self.assertEqual(io.body_reads, 0)

    def test_current_pid_must_be_in_stable_worker_procs(self):
        self.assertEqual(m._parse_procs(b'77\n88\n', 77), [77, 88])
        with self.assertRaisesRegex(m.PreflightError,
                                    'CURRENT_PID_NOT_IN_WORKER_CGROUP'):
            m._parse_procs(b'88\n', 77)
        for raw in (b'', b'0\n', b'77\n77\n', b'77 x\n'):
            with self.assertRaises(m.PreflightError):
                m._parse_procs(raw, 77)

    def test_access_acl_fail_closed_and_effective_id_anchoring(self):
        with mock.patch.object(m.os, 'getxattr', return_value=b'ACL', create=True):
            with self.assertRaisesRegex(m.PreflightError, 'ACCESS_ACL_UNSUPPORTED'):
                m._reject_access_acl(5)
        for number in (errno.ENODATA, errno.ENOTSUP):
            with mock.patch.object(m.os, 'getxattr', side_effect=OSError(number, 'absent'), create=True):
                m._reject_access_acl(5)
        with mock.patch.object(m.os, 'getxattr', side_effect=OSError(errno.EACCES, 'denied'), create=True):
            with self.assertRaisesRegex(m.PreflightError, 'ACL_QUERY_FAILED'):
                m._reject_access_acl(5)
        with mock.patch.object(m.os, 'open', return_value=6), \
             mock.patch.object(m.os, 'close'), \
             mock.patch.object(m.os, 'O_NOFOLLOW', 0, create=True), \
             mock.patch.object(m, '_reject_access_acl'), \
             mock.patch.object(m.os, 'access', return_value=False) as access:
            self.assertFalse(m._write_access(5, 'tasks'))
            access.assert_called_once_with('tasks', os.W_OK, dir_fd=5,
                effective_ids=True, follow_symlinks=False)

    def test_strict_physical_read_budget_no_sentinel_byte(self):
        sizes = []
        def read(fd, size):
            sizes.append(size)
            return b'x' * size
        with mock.patch.object(m.os, 'read', side_effect=read):
            with self.assertRaisesRegex(m.PreflightError, 'READ_BYTE_BOUND'):
                m._read_fd(5, 10)
        self.assertEqual(sizes, [10])
        sizes[:] = []; budget = [m.MAX_CGROUP_TOTAL - 2]
        with mock.patch.object(m.os, 'read', side_effect=read):
            with self.assertRaisesRegex(m.PreflightError, 'READ_BYTE_BOUND'):
                m._read_fd(5, 4096, budget)
        self.assertEqual(sizes, [2])
        self.assertEqual(budget[0], m.MAX_CGROUP_TOTAL)

    def test_full_anchored_chain_reads_every_layer_and_permission_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / 'tree'
            tree.mkdir()
            base = Path(directory) / 'sys/fs/cgroup/memory/lsf/cluster'
            job = base / 'job.12345.800.999'
            task = job / 'tsk.12345.801'
            child = task / 'child.802'
            for layer in (job, task, child):
                layer.mkdir(parents=True, exist_ok=True)
                for name, raw in limits().items():
                    (layer / name).write_bytes(raw)
            (job / 'cgroup.procs').write_bytes(b'900\n')
            (job / 'tasks').write_bytes(b'900\n')
            mount = Path(directory) / 'sys/fs/cgroup/memory'
            for name, raw in dict(limits(), **{'cgroup.procs': b'900\n',
                                              'tasks': b'900\n'}).items():
                (mount / name).write_bytes(raw)
            (child / 'cgroup.procs').write_bytes(b'77\n88\n')
            membership = m._membership(MEMBERSHIP, JOB)
            io = FakeAnchoredIO(tree)
            identity = m._identity
            # Windows fixtures can report different ctime for name/fd views.
            fixture_identity = lambda value: identity(value)[:-1]
            with io.installed(), mock.patch.object(m, '_capability'), \
                 mock.patch.object(m.os, 'major', return_value=9, create=True), \
                 mock.patch.object(m.os, 'minor', return_value=9, create=True):
                with self.assertRaisesRegex(m.PreflightError, 'OPENED_MEMORY_MOUNT_DEVICE'):
                    m._open_mount((0, 27))
            self.assertEqual(io.handles, {})
            io = FakeAnchoredIO(tree)
            with io.installed(), mock.patch.object(m, '_capability'), \
                 mock.patch.object(m, '_identity', side_effect=fixture_identity), \
                 mock.patch.object(m, '_write_access', return_value=False), \
                 mock.patch.object(m.os, 'major', return_value=0, create=True), \
                 mock.patch.object(m.os, 'minor', return_value=27, create=True), \
                 mock.patch.object(m.os, 'geteuid', return_value=1000, create=True), \
                 mock.patch.object(m.os, 'getegid', return_value=1000, create=True), \
                 mock.patch.object(m.os, 'getgroups', return_value=[1000], create=True):
                value = m._cgroup_reads(membership, 77, (0, 27))
            self.assertEqual(value['chain_components'],
                ['job.12345.800.999', 'tsk.12345.801', 'child.802'])
            self.assertEqual(len(value['chain_limits']), 3)
            self.assertTrue(value['root_and_job_write_access_checks_clear'])
            io = FakeAnchoredIO(tree)
            with io.installed(), mock.patch.object(m, '_capability'), \
                 mock.patch.object(m, '_identity', side_effect=fixture_identity), \
                 mock.patch.object(m, '_write_access', return_value=True), \
                 mock.patch.object(m.os, 'major', return_value=0, create=True), \
                 mock.patch.object(m.os, 'minor', return_value=27, create=True), \
                 mock.patch.object(m.os, 'geteuid', return_value=1000, create=True), \
                 mock.patch.object(m.os, 'getegid', return_value=1000, create=True), \
                 mock.patch.object(m.os, 'getgroups', return_value=[1000], create=True):
                with self.assertRaisesRegex(m.PreflightError,
                                            'ROOT_OR_JOB_WRITE_ACCESS'):
                    m._cgroup_reads(membership, 77, (0, 27))

    def test_source_has_no_scan_write_process_or_limit_mutation(self):
        source = (Path(__file__).resolve().parents[1] /
                  'src/data/prospective_lsf_memory_preflight_v1.py').read_text()
        tree = ast.parse(source)
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'scandir', 'listdir', 'walk', 'write',
                                  'mkdir', 'makedirs', 'Popen', 'run'})
        self.assertNotIn('memory.max', source)
        self.assertNotIn('swap_disabled', source)


if __name__ == '__main__':
    unittest.main()
