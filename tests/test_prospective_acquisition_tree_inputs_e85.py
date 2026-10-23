"""E85 fake local trees/mocks only; never invoke the A-side helper main."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import ExitStack, contextmanager

from scripts import probe_acquisition_tree_inputs_e85 as m


class FakeAnchoredIO(object):
    """Exercise Linux fd-relative logic on Windows, with fail-closed NOFOLLOW."""
    def __init__(self, root):
        self.root = root
        self.handles = {}
        self.next_fd = 10000
        self.on_open = None
        self.links = set()
        self.body_reads = 0
        self.real_open = os.open
        self.real_read = os.read
        self.real_close = os.close
        self.real_dup = os.dup
        self.real_fstat = os.fstat
        self.real_stat = os.stat
        self.real_lstat = os.lstat
        self.real_scandir = os.scandir

    def path(self, name, dir_fd=None):
        if dir_fd is not None:
            return self.handles[dir_fd][0] / name
        if name == '/':
            return self.root.parent
        if name.startswith('/proc/self/fd/'):
            return self.handles[int(name.rsplit('/', 1)[1])][0]
        if name.startswith('/tree'):
            return self.root.parent / name.lstrip('/')
        raise AssertionError('unexpected path ' + str(name))

    def open(self, name, flags, dir_fd=None):
        path = self.path(name, dir_fd)
        if self.on_open:
            self.on_open(path)
        info = self.real_lstat(path)
        if path in self.links or stat.S_ISLNK(info.st_mode):
            raise OSError('O_NOFOLLOW rejected symlink')
        is_dir = bool(flags & m.os.O_DIRECTORY)
        if is_dir and not stat.S_ISDIR(info.st_mode):
            raise OSError('O_DIRECTORY rejected non-directory')
        if not is_dir and not stat.S_ISREG(info.st_mode):
            raise OSError('not regular')
        real_fd = None if is_dir else self.real_open(path, os.O_RDONLY)
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = (path, real_fd)
        return fd

    def dup(self, fd):
        path, real_fd = self.handles[fd]
        new_fd = self.next_fd
        self.next_fd += 1
        self.handles[new_fd] = (path, None if real_fd is None else self.real_dup(real_fd))
        return new_fd

    def close(self, fd):
        _, real_fd = self.handles.pop(fd)
        if real_fd is not None:
            self.real_close(real_fd)

    def fstat(self, fd):
        path, real_fd = self.handles[fd]
        return self.real_stat(path) if real_fd is None else self.real_fstat(real_fd)

    def stat(self, name, dir_fd=None, follow_symlinks=True):
        path = self.path(name, dir_fd)
        if path in self.links and not follow_symlinks:
            return SimpleNamespace(st_mode=stat.S_IFLNK, st_size=0)
        return self.real_stat(path) if follow_symlinks else self.real_lstat(path)

    def read(self, fd, size):
        self.body_reads += 1
        return self.real_read(self.handles[fd][1], size)

    def scandir(self, path):
        return self.real_scandir(self.path(path))

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, 'require_anchored_io'))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 0x100000, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 0x200000, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NONBLOCK', 0x400000, create=True))
            for key in ('open', 'dup', 'close', 'fstat', 'stat', 'read', 'scandir'):
                stack.enter_context(mock.patch.object(m.os, key, getattr(self, key)))
            yield self
        assert not self.handles, 'fd leak: %r' % self.handles


class TreeProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'tree'
        self.root.mkdir()

    def tree(self):
        io = FakeAnchoredIO(self.root)
        with io.installed():
            return m.inspect_tree('/tree', m.ReadBudget())

    def test_tree_hash_deterministic_and_membership_sensitive(self):
        (self.root / 'z').write_bytes(b'z')
        (self.root / 'a').mkdir()
        (self.root / 'a' / 'b').write_bytes(b'b')
        first = self.tree()
        second = self.tree()
        self.assertTrue(first['tree_complete'])
        self.assertEqual(first['tree_sha256'], second['tree_sha256'])
        self.assertEqual(first['regular_files_hashed'], 2)
        self.assertEqual(first['body_bytes'], 2)
        (self.root / 'c').write_bytes(b'b')
        self.assertNotEqual(self.tree()['tree_sha256'], first['tree_sha256'])

    def test_entry_and_depth_caps_are_partial_not_complete(self):
        (self.root / 'one').write_bytes(b'1')
        (self.root / 'two').write_bytes(b'2')
        with mock.patch.object(m, 'MAX_ENTRIES', 1):
            state = self.tree()
        self.assertFalse(state['tree_complete'])
        self.assertIsNone(state['tree_sha256'])
        self.assertIn('TREE_GLOBAL_ENTRY_BOUND', state['anomalies'][0]['code'])
        nested = self.root / 'nested'
        nested.mkdir()
        with mock.patch.object(m, 'MAX_DEPTH', 0):
            state = self.tree()
        self.assertFalse(state['tree_complete'])

    def test_symlink_or_special_entry_never_followed(self):
        child = self.root / 'apparent-link'
        child.write_bytes(b'secret-content')
        io = FakeAnchoredIO(self.root)
        io.links.add(child)
        with io.installed():
            state = m.inspect_tree('/tree', m.ReadBudget())
        self.assertFalse(state['tree_complete'])
        self.assertEqual(state['body_bytes'], 0)
        self.assertEqual(state['anomalies'][0]['code'],
                         'SYMLINK_OR_SPECIAL_NOT_FOLLOWED')

    def test_log_or_checkpoint_named_tree_entry_is_not_read(self):
        (self.root / 'solver.log').write_bytes(b'private log')
        (self.root / 'weights.ckpt').write_bytes(b'private checkpoint')
        io = FakeAnchoredIO(self.root)
        with io.installed(), mock.patch.object(m.ReadBudget, 'hash_regular_at') as body_read:
            state = m.inspect_tree('/tree', m.ReadBudget())
        body_read.assert_not_called()
        self.assertFalse(state['tree_complete'])
        self.assertEqual(state['anomaly_count'], 2)
        self.assertTrue(all(item['code'] == 'PROTECTED_TREE_ENTRY_NOT_READ'
                            for item in state['anomalies']))

    def test_hash_file_strict_per_file_and_total_caps(self):
        file_path = self.root / 'one'
        file_path.write_bytes(b'abcdef')
        budget = m.ReadBudget()
        io = FakeAnchoredIO(self.root)
        with io.installed():
            with self.assertRaisesRegex(m.ProbeError, 'BODY_BYTE_BOUND'):
                budget.hash_regular('/tree/one', per_file=5)
            self.assertEqual(budget.body_bytes, 0)
            self.assertEqual(budget.hash_regular('/tree/one')['sha256'],
                             hashlib.sha256(b'abcdef').hexdigest())
            with mock.patch.object(m, 'MAX_BODY', 11):
                with self.assertRaisesRegex(m.ProbeError, 'BODY_BYTE_BOUND'):
                    budget.hash_regular('/tree/one')
        self.assertEqual(budget.body_bytes, 6)

    def test_exact_reads_never_overread_small_file(self):
        file_path = self.root / 'small'
        file_path.write_bytes(b'xyz')
        sizes = []
        io = FakeAnchoredIO(self.root)
        original = io.read
        def checked(fd, length):
            sizes.append(length)
            return original(fd, length)
        with io.installed():
            with mock.patch.object(m.os, 'read', side_effect=checked):
                m.ReadBudget().hash_regular('/tree/small')
        self.assertEqual(sizes, [3])

    def test_file_swap_to_symlink_after_stat_never_reads_body(self):
        target = self.root / 'ordinary'
        target.write_bytes(b'ordinary')
        io = FakeAnchoredIO(self.root)
        def swap(path):
            if path == target:
                io.links.add(path)
        io.on_open = swap
        with io.installed():
            with self.assertRaises(OSError):
                m.ReadBudget().hash_regular('/tree/ordinary')
        self.assertEqual(io.body_reads, 0)

    def test_tree_child_directory_swap_to_symlink_never_descends(self):
        target = self.root / 'child'
        target.mkdir()
        (target / 'would_read').write_bytes(b'outside-like-content')
        io = FakeAnchoredIO(self.root)
        def swap(path):
            if path == target:
                io.links.add(path)
        io.on_open = swap
        with io.installed():
            state = m.inspect_tree('/tree', m.ReadBudget())
        self.assertFalse(state['tree_complete'])
        self.assertEqual(state['body_bytes'], 0)
        self.assertEqual(io.body_reads, 0)

    def test_unsupported_fd_api_fails_closed(self):
        with mock.patch.object(m.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(m.ProbeError, 'ANCHORED_IO_UNAVAILABLE'):
                m.ReadBudget().hash_regular('/tree/ordinary')

    def test_resolve_link_loop_and_protected_target(self):
        fake = SimpleNamespace(st_mode=stat.S_IFLNK)
        with mock.patch.object(m.os, 'lstat', return_value=fake):
            with mock.patch.object(m.os, 'readlink', return_value='/safe/a'):
                with self.assertRaisesRegex(m.ProbeError, 'SYMLINK_HOP_BOUND'):
                    m.resolve_links('/safe/a')
            with mock.patch.object(m.os, 'readlink', return_value='/etc/passwd'):
                with self.assertRaisesRegex(m.ProbeError, 'PROTECTED_PATH'):
                    m.resolve_links('/safe/a')

    def test_protected_names_and_normalized_parent_escape(self):
        for path in ('/proc/meminfo', '/safe/.ssh/id_rsa',
                     '/safe/credentials/key', '/safe/../etc/passwd',
                     '/safe/BLIND_TEST/file', '/safe/checkpoint/weights',
                     '/safe/outcomes.tsv', '/safe/graphs/graph.json',
                     '/safe/solver.log'):
            with self.assertRaises(m.ProbeError):
                m.safe_path(path)
        self.assertEqual(m.safe_path('/safe/./a'), '/safe/a')
        self.assertEqual(m.safe_path('/safe/logic_library/cells.tcelllib'),
                         '/safe/logic_library/cells.tcelllib')
        self.assertFalse(m.sensitive_tree_name('logic_model.v'))

    def test_path_probe_only_first_32_exact_candidates_no_version_launch(self):
        checked = []
        def seen(path, _budget, require_executable=False):
            checked.append(path)
            self.assertTrue(require_executable)
            return {'status': 'CURRENT_BODY_HASHED',
                    'resolved_path': '/safe/0/tessent',
                    'body_sha256': 'a'*64, 'bytes': 5, 'symlink_hops': 0}
        with mock.patch.object(m, 'inspect_link_file', side_effect=seen):
            state = m.probe_path_binary(m.ReadBudget(),
                                        ':'.join('/safe/'+str(i) for i in range(40)))
        self.assertEqual(checked, ['/safe/0/tessent'])
        self.assertFalse(state['version_verified'])
        self.assertFalse(state['program_launched'])
        self.assertEqual(state['components_inspected'], 1)

    def test_path_component_scope_and_output_bound(self):
        with mock.patch.object(m.os, 'lstat', side_effect=FileNotFoundError):
            value = m.probe_path_binary(m.ReadBudget(),
                                        ':'.join(['/bad']*32 + ['/safe/last']))
        self.assertEqual(value['components_inspected'], 32)
        self.assertIsNone(value['resolved_binary'])
        oversized = {'schema':'x','status':'PASS','tsdb_trees':[
            {'anomalies':[{'code':'x'*1000}], 'tree_complete':True,'status':'PASS'}]}
        with mock.patch.object(m, 'collect', return_value=oversized):
            with mock.patch.object(m, 'MAX_OUTPUT', 300):
                from io import StringIO
                stream = StringIO()
                with mock.patch.object(m.sys, 'stdout', stream):
                    m.main()
                self.assertLessEqual(len(stream.getvalue().encode('ascii')), 301)
                self.assertIn('PARTIAL_OUTPUT_BOUND', stream.getvalue())

    def test_host_guard_precedes_all_source_checks(self):
        with mock.patch.object(m.socket, 'gethostname', return_value='other-host'):
            with mock.patch.object(m, 'inspect_link_file') as library:
                with mock.patch.object(m, 'inspect_tree') as tree:
                    value = m.collect()
        self.assertEqual(value['status'], 'BLOCKED_HOST_OR_PLATFORM_BEFORE_SOURCE_CHECKS')
        library.assert_not_called()
        tree.assert_not_called()
        self.assertFalse(value['execution_ready'])

    def test_limit_failure_precedes_all_source_checks(self):
        with mock.patch.object(m.socket, 'gethostname', return_value=m.EXPECTED_HOST):
            with mock.patch.object(m.sys, 'platform', 'linux'):
                with mock.patch.object(m, 'enforce_self_limits',
                                       side_effect=ValueError('limit')):
                    with mock.patch.object(m, 'inspect_link_file') as library:
                        value = m.collect()
        self.assertEqual(value['status'],
                         'BLOCKED_HELPER_RESOURCE_LIMIT_BEFORE_SOURCE_CHECKS')
        library.assert_not_called()
        self.assertFalse(value['helper_self_limits_applied'])

    def test_fixed_scope_six_roots_and_library(self):
        self.assertEqual(len(m.ROOTS), 6)
        self.assertEqual(len(set(m.ROOTS)), 6)
        self.assertTrue(all(root.startswith(m.PHASE + '/10_circuits/')
                            for root in m.ROOTS))
        self.assertTrue(m.LIBRARY.endswith('scc28nhk_hsc31_lvt_scan.tcelllib'))

    def test_root_symlink_rejected_before_readlink_or_target_stat(self):
        (self.root / 'link').mkdir()
        io = FakeAnchoredIO(self.root)
        io.links.add(self.root / 'link')
        with io.installed(), mock.patch.object(m.os, 'readlink') as readlink:
            with self.assertRaises(OSError):
                m.direct_directory('/tree/link/child')
        readlink.assert_not_called()

    def test_global_entry_cap_shared_and_later_tree_never_traversed(self):
        for name in ('a', 'b', 'c'):
            (self.root / name).write_bytes(b'x')
        budget = m.ReadBudget()
        io = FakeAnchoredIO(self.root)
        with mock.patch.object(m, 'MAX_ENTRIES', 2), io.installed():
            first = m.inspect_tree('/tree', budget)
            with mock.patch.object(m.os, 'scandir') as scan, \
                 mock.patch.object(m, 'open_directory') as root_check:
                second = m.inspect_tree('/not-visited', budget)
        self.assertEqual(budget.tree_entries, 2)
        self.assertTrue(budget.tree_exhausted)
        self.assertFalse(first['tree_complete'])
        self.assertFalse(second['tree_complete'])
        scan.assert_not_called()
        root_check.assert_not_called()

    def test_limit_guard_installed_before_any_input_access(self):
        calls = []
        with mock.patch.object(m.socket, 'gethostname', return_value=m.EXPECTED_HOST), \
             mock.patch.object(m.sys, 'platform', 'linux'), \
             mock.patch.object(m, 'enforce_self_limits', side_effect=lambda: calls.append('limit')), \
             mock.patch.object(m, 'inspect_link_file', side_effect=lambda *a: (_ for _ in ()).throw(RuntimeError('stop'))) as inspect:
            with self.assertRaises(RuntimeError):
                m.collect()
        self.assertEqual(calls, ['limit'])
        inspect.assert_called_once()
