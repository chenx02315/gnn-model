"""Tiny virtual filesystem metadata only; never touch an A path or process."""
import ast
import copy
from contextlib import contextmanager
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from src.data import prospective_generation_storage_e118 as m


class FakeFS(object):
    def __init__(self):
        self.entries, self.handles, self.bodies, self.stat_calls = {}, {}, {}, {}
        self.next_fd, self.next_ino, self.scans = 100, 10, 0
        self.hook = None
        self.parent = m.ROOT.rsplit('/', 1)[0]
        self.add(self.parent, stat.S_IFDIR, 0)
        self.add(m.ROOT, stat.S_IFDIR, 0)
        self.add(m.SIDECAR, stat.S_IFREG, 17)

    def add(self, path, mode, size, **changes):
        info = SimpleNamespace(st_dev=1, st_ino=self.next_ino, st_mode=mode | 0o600,
            st_uid=1047, st_nlink=1, st_size=size, st_blocks=0, st_mtime_ns=100, st_ctime_ns=100)
        self.next_ino += 1
        for key, value in changes.items():
            setattr(info, key, value)
        self.entries[path] = info
        return info

    def directory(self, path):
        if path not in self.entries or not stat.S_ISDIR(self.entries[path].st_mode):
            raise OSError('nofollow-directory')
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = path
        return fd

    def fstat(self, fd):
        return copy.copy(self.entries[self.handles[fd]])

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        path = self.handles[dir_fd] + '/' + name
        self.stat_calls[path] = self.stat_calls.get(path, 0) + 1
        if self.hook:
            self.hook(path, self.stat_calls[path])
        return copy.copy(self.entries[path])

    def open(self, name, flags, dir_fd=None):
        return self.directory(self.handles[dir_fd] + '/' + name)

    def close(self, fd):
        self.handles.pop(fd)

    @contextmanager
    def scandir(self, path):
        self.scans += 1
        directory = self.handles[int(path.rsplit('/', 1)[1])]
        names = [p[len(directory) + 1:] for p in self.entries if p.startswith(directory + '/') and
                 '/' not in p[len(directory) + 1:]]
        yield iter(SimpleNamespace(name=name) for name in names)

    def publish(self, fd, name, raw):
        path = self.handles[fd] + '/' + name
        if path in self.entries:
            raise FileExistsError()
        self.add(path, stat.S_IFREG, len(raw))
        self.bodies[path] = raw

    def read(self, fd, name, budget, **kwargs):
        path = self.handles[fd] + '/' + name
        raw = self.bodies[path]
        return raw, len(raw), m.sha(raw)


class Tests(unittest.TestCase):
    def setUp(self):
        self.fs = FakeFS()
        self.clock = mock.Mock(return_value=m.END - 100)
        self.patchers = [
            mock.patch.object(m.io, '_directory', side_effect=self.fs.directory),
            mock.patch.object(m.os, 'fstat', side_effect=self.fs.fstat),
            mock.patch.object(m.os, 'stat', side_effect=self.fs.stat),
            mock.patch.object(m.os, 'scandir', side_effect=self.fs.scandir),
            mock.patch.object(m.os, 'open', side_effect=self.fs.open),
            mock.patch.object(m.os, 'close', side_effect=self.fs.close),
            mock.patch.object(m.os, 'getuid', return_value=1047, create=True),
            mock.patch.object(m.os, 'O_DIRECTORY', 65536, create=True),
            mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True),
            mock.patch.object(m.time, 'monotonic', self.clock)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.assert_no_handles)

    def assert_no_handles(self):
        self.assertEqual(self.fs.handles, {})

    def test_sidecar_and_root_aggregate_logical_allocated_accounting(self):
        self.fs.add(m.ROOT + '/data', stat.S_IFREG, 10, st_blocks=2)
        self.fs.entries[m.ROOT].st_size = 20
        result = m.DirectoryMonitor().sample()
        self.assertEqual(result['sampled_named_bytes'], 17 + 20 + 1024)
        self.assertEqual(result['entries'], 3)
        self.assertTrue(result['sidecar_accounted'])
        self.assertEqual(result['threshold_bytes'], 8589934592)
        self.assertFalse(result['sampling_is_disk_quota'])
        self.assertFalse(result['open_unlinked_or_outside_root_accounted'])

    def test_sidecar_alone_can_cross_directory_threshold(self):
        self.fs.entries[m.SIDECAR].st_size = m.LIMIT + 1
        with self.assertRaisesRegex(ValueError, 'STORAGE_BYTES_THRESHOLD'):
            m.DirectoryMonitor().sample()

    def test_live_file_growth_and_directory_mtime_change_are_allowed(self):
        path = m.ROOT + '/growing'
        self.fs.add(path, stat.S_IFREG, 10)
        def grow(name, call):
            if name == path and call == 2:
                self.fs.entries[path].st_size = 100
                self.fs.entries[path].st_mtime_ns += 1
                self.fs.entries[m.ROOT].st_mtime_ns += 1
        self.fs.hook = grow
        result = m.DirectoryMonitor().sample()
        self.assertEqual(result['sampled_named_bytes'], 117)

    def test_inode_replacement_during_scan_rejected(self):
        path = m.ROOT + '/replaced'
        self.fs.add(path, stat.S_IFREG, 10)
        def replace(name, call):
            if name == path and call == 2:
                self.fs.entries[path].st_ino += 1000
        self.fs.hook = replace
        with self.assertRaisesRegex(ValueError, 'STORAGE_ENTRY_REPLACED'):
            m.DirectoryMonitor().sample()

    def test_cache_age_expiry_and_fresh_root_sidecar_checks(self):
        monitor = m.DirectoryMonitor()
        first = monitor.sample()
        scans = self.fs.scans
        self.clock.return_value += .5
        cached = monitor.sample()
        self.assertTrue(cached['cached'])
        self.assertEqual(cached['cache_age_seconds'], .5)
        self.assertEqual(self.fs.scans, scans)
        self.clock.return_value += .6
        fresh = monitor.sample()
        self.assertFalse(fresh['cached'])
        self.assertGreater(self.fs.scans, scans)
        self.assertEqual(first['sampled_named_bytes'], fresh['sampled_named_bytes'])

    def test_cached_sample_cannot_hide_root_or_sidecar_replacement(self):
        for path, reason in ((m.ROOT, 'STORAGE_ROOT_REPLACED'), (m.SIDECAR, 'STORAGE_SIDECAR_REPLACED')):
            monitor = m.DirectoryMonitor()
            monitor.sample()
            self.fs.entries[path].st_ino += 1000
            with self.assertRaisesRegex(ValueError, reason):
                monitor.sample()

    def test_symlink_hardlink_crossdevice_wrongowner_and_fifo_rejected(self):
        path = m.ROOT + '/leaf'
        variants = [dict(mode=stat.S_IFLNK), dict(st_nlink=2), dict(st_dev=2),
                    dict(st_uid=999), dict(mode=stat.S_IFIFO)]
        for changes in variants:
            mode = changes.pop('mode', stat.S_IFREG)
            self.fs.add(path, mode, 1, **changes)
            with self.assertRaises(ValueError):
                m.DirectoryMonitor().sample()

    def test_only_exact_owned_pvm_socket_is_allowed_and_never_opened(self):
        socket = m.ROOT + '/pvmtmp.1047.123.bupt-vncs2.1'
        self.fs.add(socket, stat.S_IFSOCK, 0)
        with mock.patch.object(m.os, 'open') as opening:
            result = m.DirectoryMonitor().sample()
            opening.assert_not_called()
        self.assertEqual(result['sampled_named_bytes'], 17)
        del self.fs.entries[socket]
        self.fs.add(m.ROOT + '/arbitrary.sock', stat.S_IFSOCK, 0)
        with self.assertRaises(ValueError):
            m.DirectoryMonitor().sample()

    def test_cache_does_not_extend_original_deadline(self):
        monitor = m.DirectoryMonitor()
        monitor.sample()
        self.clock.return_value = m.END
        with self.assertRaisesRegex(ValueError, 'STORAGE_SAMPLE_DEADLINE'):
            monitor.sample()

    def test_cooperative_five_second_scan_bound(self):
        values = iter([m.END - 100, m.END - 100, m.END - 100, m.END - 94])
        self.clock.side_effect = lambda: next(values)
        with self.assertRaisesRegex(ValueError, 'STORAGE_SAMPLE_DEADLINE'):
            m.DirectoryMonitor().sample()

    def test_depth_bound(self):
        path = m.ROOT
        for index in range(34):
            path += '/d'
            self.fs.add(path, stat.S_IFDIR, 0)
        with self.assertRaisesRegex(ValueError, 'STORAGE_DEPTH_BOUND'):
            m.DirectoryMonitor().sample()

    def test_entry_bound_counts_root_and_sidecar(self):
        self.assertEqual(m.MAX_ENTRIES, 16384)
        self.fs.add(m.ROOT + '/one', stat.S_IFREG, 1)
        self.fs.add(m.ROOT + '/two', stat.S_IFREG, 1)
        with mock.patch.object(m, 'MAX_ENTRIES', 3):
            with self.assertRaisesRegex(ValueError, 'STORAGE_ENTRY_BOUND'):
                m.DirectoryMonitor().sample()

    def test_cache_does_not_hide_fresh_sidecar_link_or_owner_change(self):
        monitor = m.DirectoryMonitor()
        monitor.sample()
        self.fs.entries[m.SIDECAR].st_nlink = 2
        with self.assertRaisesRegex(ValueError, 'STORAGE_LEAF_DEVICE_OWNER_OR_LINKS'):
            monitor.sample()
        self.fs.entries[m.SIDECAR].st_nlink = 1
        self.fs.entries[m.SIDECAR].st_uid = 999
        with self.assertRaisesRegex(ValueError, 'STORAGE_LEAF_DEVICE_OWNER_OR_LINKS'):
            monitor.sample()

    def test_directory_device_and_owner_changes_rejected(self):
        directory = m.ROOT + '/dir'
        self.fs.add(directory, stat.S_IFDIR, 0, st_dev=2)
        with self.assertRaisesRegex(ValueError, 'STORAGE_DIRECTORY_OWNER_DEVICE_OR_TYPE'):
            m.DirectoryMonitor().sample()
        self.fs.entries[directory].st_dev = 1
        self.fs.entries[directory].st_uid = 999
        with self.assertRaisesRegex(ValueError, 'STORAGE_DIRECTORY_OWNER_DEVICE_OR_TYPE'):
            m.DirectoryMonitor().sample()

    def test_sidecar_publication_exclusive_readback_and_no_cleanup(self):
        del self.fs.entries[m.SIDECAR]
        with mock.patch.object(m.io, '_publish', side_effect=self.fs.publish), \
                mock.patch.object(m.io, '_read_at', side_effect=self.fs.read):
            receipt = m.persist_initial_intent(b'{"intent":true}')
            self.assertEqual(receipt, dict(path=m.SIDECAR, bytes=15, sha256=m.sha(b'{"intent":true}')))
            with self.assertRaises(FileExistsError):
                m.persist_initial_intent(b'changed')
        self.assertEqual(self.fs.bodies[m.SIDECAR], b'{"intent":true}')

    def test_failed_partial_sidecar_kept_and_collision_prevents_resume(self):
        del self.fs.entries[m.SIDECAR]
        def partial(fd, name, raw):
            self.fs.publish(fd, name, raw[:3])
            raise OSError('write failed')
        with mock.patch.object(m.io, '_publish', side_effect=partial):
            with self.assertRaises(OSError):
                m.persist_initial_intent(b'partial-intent')
        self.assertEqual(self.fs.bodies[m.SIDECAR], b'par')
        with mock.patch.object(m.io, '_publish', side_effect=self.fs.publish):
            with self.assertRaises(FileExistsError):
                m.persist_initial_intent(b'retry')

    def test_python36_ast(self):
        root = Path(__file__).resolve().parents[1]
        for path in ('src/data/prospective_generation_storage_e118.py',
                     'tests/test_prospective_generation_storage_e118.py'):
            ast.parse((root / path).read_text(), feature_version=(3, 6))
