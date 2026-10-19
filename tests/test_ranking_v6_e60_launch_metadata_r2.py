"""Synthetic compatibility tests; no SSH, project evidence or Linux claims."""
import errno
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from scripts import project_ranking_v6_e60_launch_metadata_r2 as p
from scripts import run_ranking_v6_e60_readonly_r2 as t
from tests import test_ranking_v6_e60_launch_metadata as legacy

OriginalFS = legacy.FakeFS


class CompatFS(OriginalFS):
    """Emulate a Linux API that rejects scandir(int), as Python 3.6 does."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aliases = []
        self.closed = []
        self.alias_checks = 0

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        if isinstance(name, str) and name.startswith('/proc/self/fd/'):
            assert follow_symlinks is True and dir_fd is None
            self.alias_checks += 1
            if self.options.get('proc_denied'):
                raise PermissionError(errno.EACCES, 'PRIVATE_ERROR')
            if self.options.get('proc_missing'):
                raise FileNotFoundError(errno.ENOENT, 'PRIVATE_ERROR')
            fd = int(name.rsplit('/', 1)[1])
            value = self.info(self.fds[fd])
            if self.alias_checks == self.options.get('mismatch_check'):
                value.st_ino += 1
            return value
        return super().stat(name, dir_fd, follow_symlinks)

    def scandir(self, alias):
        if type(alias) is not str:
            raise TypeError('FD_UNSUPPORTED')
        fd = int(alias.rsplit('/', 1)[1])
        assert alias == '/proc/self/fd/%d' % fd and fd in self.fds
        self.aliases.append(alias)
        return legacy.Entries(self.nodes[self.fds[fd]]['names'])

    def close(self, fd):
        assert fd not in self.closed
        self.closed.append(fd)
        return super().close(fd)


class PreservedScopeTests(legacy.LaunchMetadataTests):
    def setUp(self):
        for name, value in (('p', p), ('t', t), ('FakeFS', CompatFS)):
            item = patch.object(legacy, name, value)
            item.start()
            self.addCleanup(item.stop)

    def test_transport_fake_single_process_zero_retry_limits_and_mismatch(self):
        raw = json.dumps(legacy.result(CompatFS())).encode()
        process = legacy.FakeProcess(stdout=raw)
        output = Path(t.__file__).resolve().parents[2] / 'runtime_training_staging_20260928/v6_e60_launch_metadata_r2_synthetic'
        payload = t.SOURCE.read_bytes()
        self.assertLessEqual(len(payload), t.SOURCE_LIMIT)
        with patch.object(Path, 'mkdir', autospec=True), \
             patch.object(Path, 'write_text', autospec=True), \
             patch.object(Path, 'write_bytes', autospec=True), \
             patch.object(t.subprocess, 'Popen', return_value=process) as call, \
             patch('builtins.print'):
            self.assertEqual(t.run(hashlib.sha256(payload).hexdigest(), output), 0)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(t.LIMIT, 16384)
        self.assertEqual(t.SOURCE_LIMIT, 32768)
        self.assertEqual(t.TIMEOUT, 60)


class CompatibilityGuardTests(unittest.TestCase):
    def test_sibling_source_binding(self):
        self.assertEqual(t.SOURCE.name, 'project_ranking_v6_e60_launch_metadata_r2.py')
        self.assertEqual(t.SOURCE.resolve(), Path(p.__file__).resolve())

    def test_ascii_range_no_new_python_api(self):
        self.assertNotIn('.isascii(', t.SOURCE.read_text())
        for name in ('é', '\udcff', '../x', p.STEMS[0] + '.sh\n'):
            self.assertFalse(p.selected_name(name))
        self.assertTrue(p.selected_name(p.STEMS[0] + '.sh'))
        self.assertFalse(p.selected_name(types.SimpleNamespace()))

    def test_exact_alias_live_fd_and_closed_once(self):
        fs = CompatFS()
        value = p.scan(fs)
        self.assertEqual(value['status'], 'NO_MATCH_WITHIN_FIXED_SCOPE')
        self.assertEqual(len(fs.aliases), 2)
        self.assertEqual(fs.alias_checks, 4)
        self.assertEqual(fs.fds, {})
        self.assertEqual(len(fs.closed), len(set(fs.closed)))

    def test_proc_missing_or_denied_has_no_fallback(self):
        for options in ({'proc_missing': True}, {'proc_denied': True}):
            fs = CompatFS(**options)
            with self.assertRaises(OSError):
                p.scan(fs)
            self.assertEqual(fs.aliases, [])
            self.assertEqual(fs.read_paths, [])
            self.assertEqual(fs.fds, {})

    def test_pre_and_post_identity_mismatch_prevent_file_access(self):
        for count in (1, 2):
            fs = CompatFS({(p.ROOTS[0], p.STEMS[0] + '.sh'): b'code'}, mismatch_check=count)
            with self.assertRaisesRegex(p.AuditError, 'PROC_FD_IDENTITY'):
                p.scan(fs)
            self.assertEqual(fs.read_paths, [])
            self.assertEqual(fs.fds, {})

    def test_invalid_fd_no_proc_io(self):
        for fd in (-1, True, '5', None):
            fs = CompatFS()
            with self.assertRaisesRegex(p.AuditError, 'PROC_FD_NUMBER'):
                p.enumerate_names(fd, (), fs)
            self.assertEqual(fs.alias_checks, 0)

    def test_513_entries_do_not_stat_or_open_candidate(self):
        fs = CompatFS(extra={p.ROOTS[0]: ['unrelated_%d' % i for i in range(513)]})
        with self.assertRaisesRegex(p.AuditError, 'DIRECTORY_ENTRY_BOUND'):
            p.scan(fs)
        self.assertEqual(fs.read_paths, [])
        self.assertFalse(any('unrelated_' in item for item in fs.statted + fs.opened))
        self.assertEqual(fs.fds, {})

    def test_failure_projection_does_not_leak_exception(self):
        audit = dict(phase='PROC_PRECHECK', root_index=0, selected_index=None)
        for exc, expected in ((PermissionError(errno.EACCES, 'PRIVATE_PATH'), 'ACCESS_DENIED'),
                              (p.AuditError('PROC_FD_IDENTITY'), 'PROC_FD_IDENTITY'),
                              (ValueError('PRIVATE_LINE'), 'UNKNOWN_ACTUAL_GUARD')):
            value = p.failure_response(exc, audit)
            self.assertEqual(value['code'], expected)
            self.assertNotIn('PRIVATE', json.dumps(value))
            self.assertEqual(set(value), {'status', 'code', 'phase', 'root_index', 'selected_index'})


if __name__ == '__main__':
    unittest.main()
