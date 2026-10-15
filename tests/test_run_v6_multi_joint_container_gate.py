"""Linux protocol-only Docker gate tests; never import Torch or fit anything."""
import importlib.util
import ast
import copy
import hashlib
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
        source = root / 'runner.py' if (root / 'runner.py').exists() else root.parent / 'scripts/run_v6_multi_joint_container_gate.py'
        spec = importlib.util.spec_from_file_location('v6_protocol_runner', source)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    @classmethod
    def valid_contract(cls):
        root = Path(__file__).resolve().parent
        source = root / '_contract.json' if (root / '_contract.json').exists() else root.parent / 'contracts/ranking_v6_multi_joint_container_gate_v1.json'
        return json.loads(source.read_bytes())

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
                    patch.object(self.runner, 'check_protocol_receipt', return_value={'status': 'test gate'}), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', side_effect=OSError('synthetic_start_failure')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner.parent('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_MULTI_POSITIVE_JOINT_VJP')
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
                    patch.object(self.runner, 'check_protocol_receipt', return_value={'status': 'test gate'}), \
                    patch.object(self.runner, 'open', side_effect=lambda p, *a, **kw: io.BytesIO(b'MemAvailable: 4194304 kB\n') if str(p) == '/proc/meminfo' else open(p, *a, **kw), create=True), \
                    patch.object(self.runner.os, 'read', side_effect=[b'not_json\n', b'']), \
                    patch.object(self.runner.subprocess, 'run', side_effect=calls), \
                    patch.object(self.runner.subprocess, 'Popen', return_value=process), \
                    patch.object(self.runner.selectors, 'DefaultSelector', return_value=selector), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.runner.parent('a'*64), 1)
            result = json.loads((root / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL_MULTI_POSITIVE_JOINT_VJP')
            self.assertEqual(result['failure'], 'CHILD_PARSE_JSONDecodeError')
            self.assertEqual((root / 'actual.log').read_bytes(), b'not_json\n')

    def test_runtime_version_exact_string_subclass_and_hostile_hooks(self):
        class TorchVersion(str):
            def __str__(self):
                raise AssertionError('untrusted string conversion')
            def __eq__(self, value):
                raise AssertionError('untrusted equality')
        value = self.runner.validate_torch_runtime_version(TorchVersion('2.5.1+cu124'))
        self.assertIs(type(value), str)
        self.assertEqual(value, '2.5.1+cu124')
        for bad in (None, True, '2.5.1', '2.5.1+cu121'):
            with self.assertRaises(ValueError):
                self.runner.validate_torch_runtime_version(bad)

    def test_contract_gate_rejects_modified_limits_and_authority(self):
        contract = self.valid_contract()
        self.runner.require_authorized(contract)
        for key, value in [('formal_runs', True), ('memory_bytes', 2**31), ('workers', 2),
                           ('scope', 'TRAIN'), ('real_training_release', True), ('log_limit_bytes', 1048576)]:
            bad = copy.deepcopy(contract); bad[key] = value
            with self.assertRaises(ValueError):
                self.runner.require_authorized(bad)
        bad = copy.deepcopy(contract); bad['fixture']['main_samples'] = 512
        with self.assertRaises(ValueError):
            self.runner.require_authorized(bad)

    def full_receipt(self):
        return dict(status='PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY',
                    scope='SYNTHETIC_MULTI_POSITIVE_JOINT_VJP_ONLY',
                    source_manifest_sha256='a'*64, python='3.11.2', image_id=self.runner.IMAGE,
                    torch='2.5.1+cu124', weights_unchanged=True, existing_grad_unchanged=True,
                    rng_preserved=True, threads_preserved=True, deterministic_vjp=True,
                    relu_masks_unchanged=True, full_nonlinear_exact_objectives_recomputed=True,
                    mc_finite_difference_is_frozen_linear_surrogate_only=True,
                    separate_phase_vjps=True, accepted_update=False, real_training_release=False,
                    mc_estimator_calls=1, parameter_count=1345, action_count=6, positive_count=2,
                    mc_nominal_work=9216, k=3, seed=11, dtype='float64', cpu_threads_during_probe=1,
                    fitting_performed=False, optimizer_implemented=False, blind_access=False,
                    held_corrupt_readback_loader_calls=0,
                    held_fixture_mirrors_fit_features_not_independent_population=True,
                    synthetic_held_freeze_proof=dict(held_outcome_release=True,
                        freeze_verified_before_loader_access=True, loader_calls=1, outcome_count=6,
                        synthetic_only=True, scope='generated_bounded_fixture_only',
                        actual_training=False, real_data_access=False, real_heldout_release=False,
                        fit_performed=False, generalization_claim=False,
                        freeze_sha256='b'*64, readback_sha256='b'*64),
                    lsf_tessent_calls=0, optimizer_calls=0, training_runs=0, checkpoint_reads=0,
                    real_label_reads=0, cgroup_limits={'memory.max':'1073741824',
                    'memory.swap.max':'0', 'pids.max':'64', 'cpu.max':'100000 100000'})

    def test_status_only_child_receipt_rejected(self):
        with self.assertRaises(ValueError):
            self.runner.validate_child_receipt({'status':'PASS_REAL_FACTORY_MULTI_POSITIVE_JOINT_VJP_ONLY'}, 'a'*64)
        self.runner.validate_child_receipt(self.full_receipt(), 'a'*64)

    def test_child_receipt_rejects_scope_counts_restoration_and_resources(self):
        for key, value in [('scope','TRAIN'), ('optimizer_calls',1), ('training_runs',1),
                           ('real_training_release',True), ('weights_unchanged',False),
                           ('mc_estimator_calls',2), ('parameter_count',1344),
                           ('torch','2.5.1'), ('source_manifest_sha256','b'*64)]:
            receipt = self.full_receipt(); receipt[key] = value
            with self.assertRaises(ValueError):
                self.runner.validate_child_receipt(receipt, 'a'*64)
        receipt = self.full_receipt(); receipt['cgroup_limits']['cpu.max'] = 'max 100000'
        with self.assertRaises(ValueError):
            self.runner.validate_child_receipt(receipt, 'a'*64)

    def test_protocol_receipt_binds_manifest_and_self_source(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory); (root/'_protocol_tests.py').write_bytes(b'fixture')
            receipt = dict(status='PASS_NO_TORCH_LINUX_PROTOCOL', testsRun=16, skipped=0,
                           failures=0, errors=0, torch_imported=False,
                           source_manifest_sha256='a'*64,
                           protocol_source_sha256=hashlib.sha256(b'fixture').hexdigest())
            (root/'protocol.receipt.json').write_text(json.dumps(receipt))
            self.assertEqual(self.runner.check_protocol_receipt(root, 'a'*64), receipt)
            for key, value in [('skipped',1), ('testsRun',0), ('failures',1), ('torch_imported',True),
                               ('protocol_source_sha256','0'*64), ('source_manifest_sha256','b'*64)]:
                bad = dict(receipt, **{key:value}); (root/'protocol.receipt.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    self.runner.check_protocol_receipt(root, 'a'*64)

    def test_protocol_failure_precedes_once_and_docker(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            with patch.object(self.runner, 'HOST_ROOT', root), \
                    patch.object(self.runner, '__file__', str(root/'runner.py')), \
                    patch.object(self.runner, 'preflight', return_value=self.valid_contract()), \
                    patch.object(self.runner, 'check_protocol_receipt', side_effect=ValueError('LINUX_PROTOCOL_RECEIPT')), \
                    patch.object(self.runner.subprocess, 'run') as run, \
                    patch.object(self.runner.subprocess, 'Popen') as popen:
                with self.assertRaises(ValueError):
                    self.runner.parent('a'*64)
                run.assert_not_called(); popen.assert_not_called()
            self.assertFalse((root/'actual.once.json').exists())


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerProtocolTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = (result.testsRun == 16 and not result.skipped and not result.failures and not result.errors
              and 'torch' not in sys.modules)
    receipt = {'status': 'PASS_NO_TORCH_LINUX_PROTOCOL' if passed else 'FAIL_PROTOCOL',
               'testsRun': result.testsRun, 'skipped': len(result.skipped),
               'failures': len(result.failures), 'errors': len(result.errors),
               'torch_imported': 'torch' in sys.modules}
    source = Path(__file__).resolve(); root = source.parent
    if passed and (root/'runner.py').exists() and (root/'_source_manifest.json').exists():
        manifest_bytes = RunnerProtocolTests.runner.read_small(root/'_source_manifest.json', 8192)
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        RunnerProtocolTests.runner.preflight(root, manifest_sha)
        receipt.update(source_manifest_sha256=manifest_sha,
                       protocol_source_sha256=hashlib.sha256(RunnerProtocolTests.runner.read_small(source)).hexdigest())
        fd = os.open(root/'protocol.receipt.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(receipt, stream, sort_keys=True)
            stream.flush(); os.fsync(stream.fileno())
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(0 if passed else 1)
