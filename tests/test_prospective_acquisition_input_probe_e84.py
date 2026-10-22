import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'scripts/probe_acquisition_inputs_e84.py'
SPEC = importlib.util.spec_from_file_location('e84_input_probe', SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def info(size, inode=1):
    return SimpleNamespace(st_size=size, st_mode=stat.S_IFREG | 0o444,
        st_nlink=1, st_dev=1, st_ino=inode, st_mtime_ns=10)


class InputProbeTests(unittest.TestCase):
    def test_exact_source_known_allowlist_excludes_outcomes(self):
        paths = probe.specs()
        self.assertEqual(len(paths), 20)
        self.assertEqual(sum(role == 'TSDB_DIRECTORY' for _, role in paths), 6)
        self.assertEqual(len(set(path for path, _ in paths)), 20)
        self.assertTrue(all('10_coverage95' not in path and 'checkpoint' not in path
                            and 'statistics' not in path for path, _ in paths))

    def test_growing_file_does_not_trigger_sentinel_overread(self):
        requests = []
        def read(fd, count):
            requests.append(count)
            return b'a' * count
        with patch.object(probe, 'specs', return_value=[('/input', 'COMMON_INPUT')]), \
             patch.object(probe, 'FILE_CAP', 4), patch.object(probe, 'TOTAL_CAP', 4), \
             patch.object(probe.os, 'lstat', return_value=info(4)), \
             patch.object(probe.os, 'open', return_value=7), \
             patch.object(probe.os, 'O_NOFOLLOW', 0, create=True), \
             patch.object(probe.os, 'O_NONBLOCK', 0, create=True), \
             patch.object(probe.os, 'fstat', side_effect=[info(4), info(5)]), \
             patch.object(probe.os, 'read', side_effect=read), \
             patch.object(probe.os, 'close') as close:
            result = probe.observe()
        self.assertEqual(requests, [4])
        self.assertEqual(result['bytes_read'], 4)
        self.assertEqual(result['paths'][0]['status'], 'INPUT_CHANGED')
        self.assertIsNone(result['paths'][0]['sha256'])
        close.assert_called_once_with(7)

    def test_whole_budget_skips_second_body_without_read(self):
        with patch.object(probe, 'specs', return_value=[('/one', 'CONFIG'), ('/two', 'CONFIG')]), \
             patch.object(probe, 'FILE_CAP', 4), patch.object(probe, 'TOTAL_CAP', 5), \
             patch.object(probe.os, 'lstat', return_value=info(3)), \
             patch.object(probe.os, 'open', return_value=7) as opened, \
             patch.object(probe.os, 'O_NOFOLLOW', 0, create=True), \
             patch.object(probe.os, 'O_NONBLOCK', 0, create=True), \
             patch.object(probe.os, 'fstat', return_value=info(3)), \
             patch.object(probe.os, 'read', return_value=b'abc') as read, \
             patch.object(probe.os, 'close'):
            result = probe.observe()
        self.assertEqual(result['bytes_read'], 3)
        self.assertEqual(result['paths'][1]['status'], 'BODY_HASH_CAP_SKIPPED')
        opened.assert_called_once()
        read.assert_called_once_with(7, 3)
        self.assertFalse(result['executable_path_discovery_performed'])
        self.assertIsNone(result['tessent_path_from_current_PATH'])

    def test_missing_input_record_retained(self):
        with patch.object(probe, 'specs', return_value=[('/missing', 'COMMON_INPUT')]), \
             patch.object(probe.os, 'lstat', side_effect=FileNotFoundError(2, 'absent')), \
             patch.object(probe.os, 'open') as opened:
            result = probe.observe()
        opened.assert_not_called()
        self.assertEqual(result['paths'][0]['status'], 'OS_ERROR')
        self.assertEqual(result['paths'][0]['errno'], 2)
        self.assertFalse(result['execution_ready'])


if __name__ == '__main__':
    unittest.main()
