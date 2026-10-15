"""Linux protocol-only Docker gate tests; never import Torch or fit anything."""
import importlib.util
import ast
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
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent
        source = root / 'runner.py' if (root / 'runner.py').exists() else root.parent / 'scripts/run_v6_paired_cost_runtime_gate_v2.py'
        spec = importlib.util.spec_from_file_location('v6_protocol_runner', source)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)
        contract = root / '_contract.json' if (root / '_contract.json').exists() else root.parent / 'contracts/ranking_v6_paired_cost_runtime_gate_v2.json'
        cls.contract = json.loads(contract.read_text())

    @classmethod
    def valid_contract(cls):
        return dict(cls.contract)

    def test_parent_locked_without_subprocess_or_once(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            with patch.object(self.runner, 'HOST_ROOT', root), \
                    patch.object(self.runner, '__file__', str(root / 'runner.py')), \
                    patch.object(self.runner, 'preflight', return_value={'execution_authorized': False}), \
                    patch.object(self.runner.subprocess, 'run') as run, \
                    patch.object(self.runner.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(ValueError, 'E21_EXECUTION_LOCKED'):
                    self.runner.parent('a'*64)
            run.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_child_locked_before_resource_or_torch(self):
        with patch.object(self.runner, 'preflight', return_value={'execution_authorized': False}), \
                patch.object(self.runner.resource, 'setrlimit') as limits:
            with self.assertRaisesRegex(ValueError, 'E21_EXECUTION_LOCKED'):
                self.runner.child('a'*64)
        limits.assert_not_called()
        self.assertNotIn('torch', sys.modules)

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
        tree = ast.parse(Path(self.runner.__file__).read_text())
        for node in tree.body:
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name != 'torch' for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, 'torch')

    def test_popen_failure_is_sealed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            calls = [subprocess.CompletedProcess([], 0, stdout=self.runner.IMAGE.encode()),
                     subprocess.CompletedProcess([], 1)]
            with patch.object(self.runner, 'HOST_ROOT', root), \
                    patch.object(self.runner, '__file__', str(root / 'runner.py')), \
                    patch.object(self.runner, 'preflight', return_value=self.valid_contract()), \
                    patch.object(self.runner.os, 'getuid', return_value=1000), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', side_effect=OSError('synthetic_start_failure')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner._parent_after_gate('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_PAIRED_RUNTIME')
            self.assertEqual(result['failure'], 'synthetic_start_failure')
            self.assertTrue((root / 'actual.once.json').exists())
            self.assertEqual((root / 'actual.log').read_bytes(), b'')

    def test_bad_child_json_is_sealed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
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
                    patch.object(self.runner, 'preflight', return_value=self.valid_contract()), \
                    patch.object(self.runner.os, 'getuid', return_value=1000), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.os, 'read', side_effect=[b'not_json\n', b'']), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', return_value=process), \
                    patch.object(self.runner.selectors, 'DefaultSelector', return_value=selector), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner._parent_after_gate('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_PAIRED_RUNTIME')
            self.assertEqual(result['failure'], 'CHILD_PARSE_JSONDecodeError')
            self.assertEqual((root / 'actual.log').read_bytes(), b'not_json\n')

    def test_status_only_success_stub_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CHILD_RECEIPT'):
            self.runner.validate_child_receipt(
                {'status': 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY'}, 'a'*64, {})

    def test_malformed_authorization_cannot_open_public_entries(self):
        valid = self.valid_contract()
        mutations = {'authorization_id': 'foreign', 'status': 'DESIGN_LOCAL_TEST_ONLY_EXECUTION_LOCKED',
                     'formal_runs': True, 'planned_formal_runs': 2, 'planned_models': 7,
                     'planned_optimizer_steps_total': 145, 'workers': True, 'cpus': 2,
                     'memory_bytes': 2147483648, 'swap_extra_bytes': 1, 'automatic_retries': 1,
                     'scope': 'E20_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY'}
        for field, bad in mutations.items():
            with self.subTest(field=field), \
                    patch.object(self.runner, 'preflight', return_value=dict(valid, **{field: bad})), \
                    patch.object(self.runner, 'HOST_ROOT', Path('/tmp')), \
                    patch.object(self.runner, '__file__', '/tmp/runner.py'), \
                    patch.object(self.runner.subprocess, 'run') as run, \
                    patch.object(self.runner.subprocess, 'Popen') as popen, \
                    patch.object(self.runner.resource, 'setrlimit') as limits:
                for entry in (self.runner.parent, self.runner.child):
                    with self.assertRaisesRegex(ValueError, 'E21_EXECUTION_LOCKED'):
                        entry('a'*64)
                run.assert_not_called()
                popen.assert_not_called()
                limits.assert_not_called()


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerProtocolTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = (result.testsRun == 14 and not result.skipped and not result.failures and not result.errors)
    print(json.dumps({'status': 'PASS_NO_TORCH_LINUX_PROTOCOL' if passed else 'FAIL_PROTOCOL',
                      'testsRun': result.testsRun, 'skipped': len(result.skipped),
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'torch_imported': 'torch' in sys.modules}, sort_keys=True))
    raise SystemExit(0 if passed else 1)
