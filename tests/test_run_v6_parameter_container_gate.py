"""Linux protocol-only Docker gate tests; never import Torch or fit anything."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


@unittest.skipUnless(sys.platform == 'linux', 'LINUX_PROTOCOL_REQUIRED_NOT_A_PASS')
class RunnerProtocolTests(unittest.TestCase):
    def _protocol_fixture(self, root):
        (root / 'protocol_result.json').write_text(json.dumps({
            'source_manifest_sha256': 'a'*64, 'exit_code': 0,
            'gate': {'testsRun': 10, 'skipped': 0, 'failures': 0, 'errors': 0,
                     'torch_imported': False, 'status': 'PASS_NO_TORCH_LINUX_PROTOCOL'}}))
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        source = root / 'runner.py' if (root / 'runner.py').exists() else root.parent / 'scripts/run_v6_parameter_container_gate.py'
        spec = importlib.util.spec_from_file_location('v6_protocol_runner', source)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_ordinary_read(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'fixture'
            path.write_bytes(b'fixture')
            self.assertEqual(self.runner.read_small(path, 8), b'fixture')

    def test_final_symlink_rejected(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'fixture'
            path.write_bytes(b'fixture')
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                self.runner.read_small(link)

    def test_ancestor_symlink_rejected(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            (root / 'real').mkdir()
            (root / 'real/fixture').write_bytes(b'fixture')
            (root / 'link').symlink_to(root / 'real')
            with self.assertRaises(OSError):
                self.runner.read_small(root / 'link/fixture')

    def test_hardlink_rejected(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            (root / 'fixture').write_bytes(b'fixture')
            os.link(root / 'fixture', root / 'other')
            with self.assertRaisesRegex(ValueError, 'ORDINARY_FILE_BOUND'):
                self.runner.read_small(root / 'other')

    def test_size_bound(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'fixture'
            path.write_bytes(b'fixture')
            with self.assertRaisesRegex(ValueError, 'ORDINARY_FILE_BOUND'):
                self.runner.read_small(path, 3)

    def test_cleanup_timeout_still_kills_client(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(self.runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 10)):
            errors = self.runner.cleanup_owned(process, 'a'*64)
        self.assertIn('TimeoutExpired', errors)
        process.kill.assert_called_once()
        process.wait.assert_called_once()

    def test_cleanup_never_kills_foreign_label(self):
        process = Mock()
        process.poll.return_value = None
        observed = subprocess.CompletedProcess([], 0, stdout=b'foreign\n')
        with patch.object(self.runner.subprocess, 'run', return_value=observed) as run:
            errors = self.runner.cleanup_owned(process, 'a'*64)
        self.assertIn('OWN_CONTAINER_IDENTITY_UNCONFIRMED', errors)
        self.assertEqual(run.call_count, 1)
        process.kill.assert_called_once()

    def test_no_torch_import(self):
        self.assertNotIn('torch', sys.modules)

    def test_popen_failure_is_sealed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            self._protocol_fixture(root)
            calls = [subprocess.CompletedProcess([], 0, stdout=self.runner.IMAGE.encode()),
                     subprocess.CompletedProcess([], 1)]
            with patch.object(self.runner, 'HOST_ROOT', root), \
                    patch.object(self.runner, '__file__', str(root / 'runner.py')), \
                    patch.object(self.runner, 'preflight', return_value={'dependency_integrity_limit': 'synthetic'}), \
                    patch.object(self.runner.os, 'getuid', return_value=1000), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', side_effect=OSError('synthetic_start_failure')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner.parent('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_SYNTHETIC_PARAMETER_PROBE')
            self.assertEqual(result['failure'], 'synthetic_start_failure')
            self.assertTrue((root / 'actual.once.json').exists())
            self.assertEqual((root / 'actual.log').read_bytes(), b'')

    def test_bad_child_json_is_sealed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            self._protocol_fixture(root)
            process = Mock()
            process.returncode = 0
            process.stdout.fileno.return_value = 123
            selector = Mock()
            selector.get_map.side_effect = [True, True, False]
            key = Mock()
            key.fileobj = process.stdout
            selector.select.return_value = [(key, None)]
            calls = [subprocess.CompletedProcess([], 0, stdout=self.runner.IMAGE.encode()),
                     subprocess.CompletedProcess([], 1)]
            with patch.object(self.runner, 'HOST_ROOT', root), \
                    patch.object(self.runner, '__file__', str(root / 'runner.py')), \
                    patch.object(self.runner, 'preflight', return_value={'dependency_integrity_limit': 'synthetic'}), \
                    patch.object(self.runner.os, 'getuid', return_value=1000), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.os, 'read', side_effect=[b'not_json\n', b'']), \
                    patch.object(self.runner, 'read_small', return_value=(root / 'protocol_result.json').read_bytes()), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', return_value=process), \
                    patch.object(self.runner.selectors, 'DefaultSelector', return_value=selector), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner.parent('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_SYNTHETIC_PARAMETER_PROBE')
            self.assertEqual(result['failure'], 'CHILD_PARSE_JSONDecodeError')
            self.assertEqual((root / 'actual.log').read_bytes(), b'not_json\n')

    def test_unsafe_pass_result_rejected(self):
        result = {'status':'PASS_FIXED_PARAMETER_JOINT_PROBES_ONLY','parameters_restored':True,
                  'train_release':False,'synthetic_only':True,'real_data_access':False,
                  'all_committed_updates_safe':True,'numerical_guard_failures':0,
                  'optimizer_calls':0,'training_runs':0,'checkpoint_reads':0,'real_label_reads':0}
        self.assertTrue(self.runner.safe_result(result))
        for field in ('real_data_access','train_release','optimizer_calls','training_runs',
                      'checkpoint_reads','real_label_reads','numerical_guard_failures'):
            bad = dict(result); bad[field] = True if isinstance(result[field],bool) else 1
            self.assertFalse(self.runner.safe_result(bad), field)
        bad = dict(result); bad['parameters_restored'] = False
        self.assertFalse(self.runner.safe_result(bad))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerProtocolTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = (result.testsRun == 11 and not result.skipped and not result.failures and not result.errors)
    print(json.dumps({'status': 'PASS_NO_TORCH_LINUX_PROTOCOL' if passed else 'FAIL_PROTOCOL',
                      'testsRun': result.testsRun, 'skipped': len(result.skipped),
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'torch_imported': 'torch' in sys.modules}, sort_keys=True))
    raise SystemExit(0 if passed else 1)
