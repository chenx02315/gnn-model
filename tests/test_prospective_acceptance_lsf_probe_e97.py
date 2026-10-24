"""E97 portable tests: fake metadata, environment, and I/O only."""
import ast
import errno
import importlib.util
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'probe_acceptance_lsf_e97.py'
spec = importlib.util.spec_from_file_location('e97_probe', str(SOURCE))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def info(mode=stat.S_IFREG | 0o755, size=10):
    return SimpleNamespace(st_mode=mode, st_dev=1, st_ino=2, st_uid=0,
                           st_gid=0, st_size=size, st_mtime_ns=3)


class ProbeTests(unittest.TestCase):
    def test_python36_ast_and_no_process_launch_imports(self):
        source = SOURCE.read_text(encoding='utf-8')
        ast.parse(source, feature_version=(3, 6))
        tree = ast.parse(source)
        imports = [n.name for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for n in node.names]
        self.assertFalse(set(imports) & {'subprocess', 'socket'})
        self.assertNotIn('os.system(', source)

    def test_parser_absence_duplicates_and_unsafe_tokens(self):
        result = m.parse_selected(b'# LSB_JOB_MEMLIMIT=y\nLSF_UNIT_FOR_LIMITS = MB # note\n'
                                  b'LSB_MEMLIMIT_ENFORCE=y\nLSB_MEMLIMIT_ENFORCE=y\n'
                                  b'LSF_PROCESS_TRACKING=$(secret)\n'
                                  b'LSF_LINUX_CGROUP_ACCT=' + b'x' * 65)
        self.assertEqual(result['LSF_UNIT_FOR_LIMITS']['raw_token'], 'MB')
        self.assertEqual(result['LSB_JOB_MEMLIMIT']['status'], 'absent')
        for key in ('LSB_MEMLIMIT_ENFORCE', 'LSF_PROCESS_TRACKING',
                    'LSF_LINUX_CGROUP_ACCT'):
            self.assertEqual(result[key]['status'], 'ambiguous')

    def test_read_config_bounded_nofollow_root_owned(self):
        raw = b'LSF_UNIT_FOR_LIMITS=MB\nUNRELATED=SECRET\n'
        with mock.patch.object(m.os, 'open', side_effect=[10, 11], create=True) as op, \
                mock.patch.object(m.os, 'close') as close, \
                mock.patch.object(m.os, 'fstat', return_value=info(size=len(raw))), \
                mock.patch.object(m.os, 'stat', return_value=info(size=len(raw))), \
                mock.patch.object(m.os, 'read', side_effect=[raw, b'']), \
                mock.patch.object(m.os, 'O_DIRECTORY', 65536, create=True), \
                mock.patch.object(m.os, 'O_NONBLOCK', 2048, create=True), \
                mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True):
            result = m.read_config('/lsf/etc')
            self.assertEqual(result['byte_count'], len(raw))
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertEqual(op.call_args_list[1].args[0], 'lsf.conf')
            self.assertEqual(op.call_args_list[1].kwargs['dir_fd'], 10)
            self.assertTrue(op.call_args_list[1].args[1] & 131072)
            self.assertEqual(close.call_count, 2)

    def test_reject_nonregular_and_oversized_before_read(self):
        for row in (info(stat.S_IFIFO | 0o600), info(size=m.CONFIG_CAP + 1)):
            with mock.patch.object(m.os, 'open', side_effect=[10, 11]), \
                    mock.patch.object(m.os, 'close'), \
                    mock.patch.object(m.os, 'fstat', return_value=row), \
                    mock.patch.object(m.os, 'read') as read, \
                    mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True), \
                    mock.patch.object(m.os, 'O_NONBLOCK', 4, create=True), \
                    mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True):
                with self.assertRaises(m.ProbeError):
                    m.read_config('/lsf/etc')
                read.assert_not_called()

    def test_collect_only_six_programs_and_no_config_when_env_absent(self):
        with mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m.platform, 'system', return_value='Linux'), \
                mock.patch.dict(m.os.environ, {'SECRET': 'not-exported'}, clear=True), \
                mock.patch.object(m.shutil, 'which', return_value=None) as which, \
                mock.patch.object(m, 'read_config') as read:
            result = m.collect()
            self.assertEqual([c.args[0] for c in which.call_args_list], list(m.EXECUTABLES))
            self.assertFalse(result['actual_job_memory_proof'])
            self.assertEqual(result['status'], 'PASS_BOUNDED_SETUP_METADATA_ONLY')
            for key, value in m.boundaries().items():
                self.assertEqual(result[key], value)
            self.assertNotIn('not-exported', json.dumps(result))
            read.assert_not_called()

    def test_invalid_host_stops_discovery(self):
        with mock.patch.object(m.platform, 'node', return_value='other'), \
                mock.patch.object(m.platform, 'system', return_value='Linux'), \
                mock.patch.object(m.shutil, 'which') as which:
            with self.assertRaisesRegex(m.ProbeError, 'E97_HOST_INVALID'):
                m.collect()
            which.assert_not_called()

    def test_executable_metadata_and_symlink_error_are_bounded(self):
        with mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m.platform, 'system', return_value='Linux'), \
                mock.patch.dict(m.os.environ, {'LSF_ENVDIR': '/lsf/etc'}, clear=True), \
                mock.patch.object(m, 'canonical_path', side_effect=lambda p: p), \
                mock.patch.object(m.os.path, 'realpath', side_effect=lambda p: p), \
                mock.patch.object(m.shutil, 'which', return_value='/lsf/bin/bsub'), \
                mock.patch.object(m.os, 'stat', return_value=info()), \
                mock.patch.object(m, 'read_config', side_effect=OSError(errno.ELOOP, 'SECRET')):
            result = m.collect()
            self.assertEqual(result['executables']['bsub']['metadata']['ino'], 2)
            self.assertEqual(result['errors'], ['E97_CONFIG_SYMLINK'])
            self.assertNotIn('SECRET', json.dumps(result))

    def test_resource_caps_are_applied_without_real_resource_calls(self):
        fake = SimpleNamespace(RLIMIT_AS=1, RLIMIT_CPU=2, RLIM_INFINITY=-1,
                               getrlimit=mock.Mock(return_value=(-1, -1)),
                               setrlimit=mock.Mock())
        with mock.patch.dict('sys.modules', {'resource': fake}):
            m.apply_caps()
        self.assertEqual(fake.setrlimit.call_args_list,
                         [mock.call(1, (268435456, 268435456)), mock.call(2, (20, 20))])

    def test_existing_lower_caps_are_preserved(self):
        fake = SimpleNamespace(RLIMIT_AS=1, RLIMIT_CPU=2, RLIM_INFINITY=-1,
                               getrlimit=mock.Mock(return_value=(10, 100)),
                               setrlimit=mock.Mock())
        with mock.patch.dict('sys.modules', {'resource': fake}):
            m.apply_caps()
        self.assertEqual(fake.setrlimit.call_args_list,
                         [mock.call(1, (10, 10)), mock.call(2, (10, 10))])

    def test_exact_read_short_read_growth_and_replacement(self):
        for scenario in ('exact', 'short', 'growth', 'replacement'):
            before = info(size=m.CONFIG_CAP)
            after = info(size=m.CONFIG_CAP + (scenario == 'growth'))
            named = info(size=m.CONFIG_CAP)
            if scenario == 'replacement':
                named.st_ino = 99
            chunks = ([b'x' * 8192] * 32 if scenario != 'short' else [b''])
            with mock.patch.object(m.os, 'open', side_effect=[10, 11]), \
                    mock.patch.object(m.os, 'close'), \
                    mock.patch.object(m.os, 'fstat', side_effect=[before, after]), \
                    mock.patch.object(m.os, 'stat', return_value=named), \
                    mock.patch.object(m.os, 'read', side_effect=chunks) as read, \
                    mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True), \
                    mock.patch.object(m.os, 'O_NONBLOCK', 4, create=True), \
                    mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True):
                if scenario == 'exact':
                    self.assertEqual(m.read_config('/lsf/etc')['byte_count'], m.CONFIG_CAP)
                else:
                    with self.assertRaises(m.ProbeError):
                        m.read_config('/lsf/etc')
                self.assertLessEqual(sum(c.args[1] for c in read.call_args_list), m.CONFIG_CAP)
                if scenario == 'exact':
                    self.assertEqual(read.call_count, 32)

    def test_main_caps_failure_and_output_cap_are_nonzero(self):
        for error, result in ((m.ProbeError('E97_CAPS_FAILED'), None),
                              (None, {'errors': [], 'large': 'x' * m.OUTPUT_CAP})):
            with mock.patch.object(m, 'apply_caps', side_effect=error), \
                    mock.patch.object(m, 'collect', return_value=result), \
                    mock.patch.object(m.sys, 'stdout', new_callable=io.StringIO) as out:
                self.assertEqual(m.main(), 1)
                self.assertLess(len(out.getvalue()), m.OUTPUT_CAP)
                self.assertIn('E97_', json.loads(out.getvalue())['errors'][0])
                result = json.loads(out.getvalue())
                self.assertEqual(result['status'], 'PARTIAL')
                for key, value in m.boundaries().items():
                    self.assertEqual(result[key], value)


if __name__ == '__main__':
    unittest.main()
