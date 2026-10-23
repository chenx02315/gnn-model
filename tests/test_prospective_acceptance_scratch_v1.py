"""Metadata mocks only; never scans a real filesystem or Linux proc path."""
import ast
from contextlib import contextmanager, ExitStack
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.data import prospective_acceptance_scratch_v1 as m


def info(ino, size=0, blocks=0, mode=stat.S_IFREG | 0o600, links=1, dev=1):
    return SimpleNamespace(st_dev=dev, st_ino=ino, st_mode=mode,
        st_nlink=links, st_size=size, st_blocks=blocks,
        st_mtime_ns=1, st_ctime_ns=1)


class Stream:
    def __init__(self, names):
        self.names = names
    def __enter__(self):
        return (SimpleNamespace(name=x) for x in self.names)
    def __exit__(self, *args):
        return False


@contextmanager
def tree(files=None, nested=False):
    root = info(10, mode=stat.S_IFDIR | 0o700)
    child = info(20, mode=stat.S_IFDIR | 0o700)
    dirs = {10: dict(files or {}), 20: {'later': info(30, size=9)}}
    if nested:
        dirs[10]['old_tsdb'] = child
    with ExitStack() as stack:
        stack.enter_context(patch.object(m.os, 'fstat', side_effect=lambda fd: root if fd == 10 else child))
        stack.enter_context(patch.object(m.os, 'stat', side_effect=lambda name, dir_fd, follow_symlinks: dirs[dir_fd][name]))
        stack.enter_context(patch.object(m.os, 'scandir', side_effect=lambda path: Stream(dirs[int(path.rsplit('/', 1)[1])].keys())))
        opened = stack.enter_context(patch.object(m.os, 'open', return_value=20))
        stack.enter_context(patch.object(m.os, 'close'))
        stack.enter_context(patch.object(m.os, 'O_DIRECTORY', 0, create=True))
        stack.enter_context(patch.object(m.os, 'O_NOFOLLOW', 0, create=True))
        stack.enter_context(patch.object(m.time, 'monotonic', return_value=0))
        read = stack.enter_context(patch.object(m.os, 'read', side_effect=AssertionError('no bodies')))
        yield opened, read


class Tests(unittest.TestCase):
    def test_exact_threshold_and_plus_one(self):
        available = m.LIMIT - m.JOURNAL_RESERVE
        with tree({'file': info(11, size=available)}):
            result = m._sample(10, 10)
            self.assertEqual(result['accounted_bytes_with_journal_reserve'], m.LIMIT)
        with tree({'file': info(11, size=available+1)}):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_BYTES_THRESHOLD'):
                m._sample(10, 10)

    def test_prior_item_nested_files_included_without_body_reads(self):
        with tree({'current': info(11, size=3)}, nested=True) as (opened, read):
            result = m._sample(10, 10)
            self.assertEqual(result['named_bytes'], 12)
            self.assertEqual(result['entries'], 3)
            opened.assert_called_once()
            read.assert_not_called()

    def test_sparse_logical_and_allocated_max(self):
        with tree({'sparse': info(11, size=10000, blocks=1),
                   'allocated': info(12, size=1, blocks=8)}):
            self.assertEqual(m._sample(10, 10)['named_bytes'], 10000+4096)

    def test_links_specials_hardlinks_and_devices_rejected(self):
        cases = [info(11, mode=stat.S_IFLNK | 0o700),
                 info(11, mode=stat.S_IFIFO | 0o600),
                 info(11, links=2), info(11, dev=2)]
        for file_info in cases:
            with self.subTest(file_info=file_info), tree({'bad': file_info}):
                with self.assertRaises(ValueError):
                    m._sample(10, 10)

    def test_entry_depth_and_time_bounds(self):
        with tree({'a': info(11), 'b': info(12)}), patch.object(m, 'MAX_ENTRIES', 1):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_ENTRY_BOUND'):
                m._sample(10, 10)
        with tree(nested=True), patch.object(m, 'MAX_DEPTH', 0):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_DEPTH_BOUND'):
                m._sample(10, 10)
        with tree():
            with self.assertRaisesRegex(ValueError, 'SCRATCH_SAMPLE_TIMEOUT'):
                m._sample(10, 0)

    def test_changing_file_and_directory_rejected(self):
        with tree({'f': info(11)}), patch.object(m.os, 'stat',
                side_effect=[info(11), info(11, size=1)]):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_FILE_CHANGED'):
                m._sample(10, 10)
        with tree(nested=True), patch.object(m.os, 'fstat',
                side_effect=[info(10, mode=stat.S_IFDIR),
                             info(10, mode=stat.S_IFDIR),
                             info(99, mode=stat.S_IFDIR)]):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_DIRECTORY_REPLACED'):
                m._sample(10, 10)

    def test_inspection_error_propagates(self):
        with tree({'f': info(11)}), patch.object(m.os, 'stat', side_effect=OSError('inspection')):
            with self.assertRaises(OSError):
                m._sample(10, 10)

    def test_monitor_fixed_root_identity_and_bounded_summary(self):
        observed = dict(named_bytes=3, accounted_bytes_with_journal_reserve=3+m.JOURNAL_RESERVE,
                        entries=1, root_identity=[1, 10, stat.S_IFDIR])
        monitor = m.ScratchMonitor(10)
        with patch.object(m, '_directory', return_value=10) as directory, \
             patch.object(m, '_sample', return_value=observed), patch.object(m.os, 'close'):
            monitor.sample()
            directory.assert_called_once_with(m.recipe.ROOT)
            monitor.sample()
        summary = monitor.summary()
        self.assertEqual(summary['samples'], 2)
        self.assertFalse(summary['open_unlinked_or_outside_root_accounted'])
        with patch.object(m, '_directory', return_value=10), \
             patch.object(m, '_sample', return_value=dict(observed, root_identity=[1, 99, stat.S_IFDIR])), \
             patch.object(m.os, 'close'):
            with self.assertRaisesRegex(ValueError, 'SCRATCH_ROOT_REPLACED'):
                monitor.sample()

    def test_python36_syntax(self):
        for path in (Path(m.__file__), Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_root_open_error_is_retained_without_false_sample(self):
        monitor = m.ScratchMonitor(10)
        with patch.object(m, '_directory', side_effect=OSError('denied')):
            with self.assertRaises(OSError):
                monitor.sample()
        self.assertEqual(monitor.summary()['failure_code'], 'SCRATCH_INSPECTION_ERROR')
        self.assertEqual(monitor.summary()['samples'], 0)


if __name__ == '__main__':
    unittest.main()
