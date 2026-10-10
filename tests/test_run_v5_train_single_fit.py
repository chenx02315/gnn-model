"""Synthetic tempfile bootstrap and mocked context/worker: real ML/fits = zero."""
from contextlib import contextmanager, redirect_stderr
import copy
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('_unit_v5_train_cli',
    Path(__file__).parents[1]/'scripts/run_v5_train_single_fit.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class BootstrapRejectionTests(unittest.TestCase):
    def args(self):
        root = '/ssd/cjc/gnn_model_ranking_v5_train_20261008_r1'
        family = 'iwls_aes_core'; seed = 20260824
        return dict(source_root=root, output=f'{root}_{family}_{seed}',
            package_root=cli.PACKAGE_ROOT, family=family, seed=seed,
            trusted_envelope_sha256='a'*64)

    def test_wrong_platform_before_any_path_operation(self):
        with patch.object(cli.sys, 'platform', 'win32'), patch.object(cli, '_read') as read, \
                patch.object(Path, 'lstat') as stats, patch.object(cli, '_import') as imports, \
                self.assertRaisesRegex(ValueError, 'PLATFORM'):
            cli.execute_prelaunch(b'{}', **self.args())
        read.assert_not_called(); stats.assert_not_called(); imports.assert_not_called()

    def test_wrong_interpreter_python_cwd_no_path_io(self):
        for stage in ('interpreter', 'python', 'cwd'):
            with self.subTest(stage=stage), patch.object(cli.sys, 'platform', 'linux'), \
                    patch.object(cli.sys, 'executable', '/wrong' if stage == 'interpreter' else cli.INTERPRETER), \
                    patch.object(cli.sys, 'version_info', (3, 12, 0) if stage == 'python' else (3, 11, 2)), \
                    patch.object(cli.os, 'getcwd', return_value='/wrong' if stage == 'cwd' else cli.CWD), \
                    patch.object(Path, 'lstat') as stats, self.assertRaises(ValueError):
                cli.execute_prelaunch(b'{}', **self.args())
            stats.assert_not_called()

    def test_family_seed_roots_before_any_io_or_helper(self):
        cases = [('family', 'wrong'), ('seed', True), ('seed', 1),
                 ('source_root', '/ssd/cjc/multimode_ate_gnn_v1/a'),
                 ('source_root', '/ssd/cjc/gnn_model_ranking_v5_train_20261008_r1/../x'),
                 ('output', '/tmp/output'), ('package_root', '/tmp/package'),
                 ('source_root', '/SSD/CJC/MULTIMODE_ATE_GNN_V1/a')]
        for key, value in cases:
            args = self.args(); args[key] = value
            with self.subTest(key=key, value=value), patch.object(cli, '_runtime'), \
                    patch.object(cli, '_read') as read, patch.object(cli, '_helper') as helper, \
                    patch.object(Path, 'lstat') as stats, self.assertRaises(ValueError):
                cli.execute_prelaunch(b'{}', **args)
            read.assert_not_called(); helper.assert_not_called(); stats.assert_not_called()

    def test_bad_envelope_and_missing_external_sha_no_io(self):
        for raw, pin in ((b'{}', 'a'*64), (b'{}', None), (b'x'*(cli.JSON_CAP+1), 'a'*64)):
            args = self.args(); args['trusted_envelope_sha256'] = pin
            with patch.object(cli, '_runtime'), patch.object(cli, '_read') as read, \
                    self.assertRaisesRegex(ValueError, 'ENVELOPE_SHA'):
                cli.execute_prelaunch(raw, **args)
            read.assert_not_called()

    def test_duplicate_deep_nonfinite_integer_string_container_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                    b'{"x":'+b'['*70+b'0'+b']'*70+b'}', b'{"x":'+b'1'*400+b'}',
                    b'{"x":"'+b'a'*2049+b'"}', b'{"x":['+b'0,'*1024+b'0]}'):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError): cli._json(raw)

    def test_required_external_cli_options(self):
        with patch.object(cli, '_read') as read, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main([])
        read.assert_not_called()


class SyntheticBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'gnn_model_ranking_v5_train_20261008_r1'; self.root.mkdir()
        self.events = []
        self.enterContext(patch.object(cli, '_runtime', side_effect=lambda: self.events.append('runtime')))
        self.enterContext(patch.object(cli, 'ROOT_PATTERN', re.escape(self.root.as_posix())))
        self.source = {name: b'# SYNTHETIC BOOTSTRAP FIXTURE; NEVER EXECUTED\n' for name in cli.CORE_FILES}
        self.source['requirements/runtime_v2.lock.txt'] = b'torch==0.0.0\nnumpy==0.0.0\n'
        manifest = dict(schema='v5-caller-source-bytes-v1', formal_training_release=False,
                        sources={name: cli._sha(raw) for name, raw in self.source.items()})
        self.manifest_raw = encode(manifest)
        self.helper_raw = {name: b'# SYNTHETIC HELPER; MOCK CONTEXT ONLY\n' for name in cli.HELPERS}
        self.auth_raw = encode(dict(authorization_id=cli.AUTHORIZATION_ID, fixture_not_consent=True))
        self.release_raw = encode(dict(user_authorization_id=cli.AUTHORIZATION_ID, fixture_not_release=True))
        self.evidence = {'authorization.json': self.auth_raw, 'release.json': self.release_raw,
            'review.json': encode(dict(fixture_not_review=True)),
            'physical_gate.json': encode(dict(fixture_not_physical_gate=True)),
            'synthetic_linux_gate.json': encode(dict(fixture_not_linux_gate=True))}
        self.evidence.update({name: encode(dict(synthetic_gate_not_proof=True))
            for name in cli.EVIDENCE if name not in self.evidence})
        self.enterContext(patch.object(cli, 'SCOPE_AUTHORIZATION_SHA256',
            cli._sha(self.evidence['scope_authorization.json'])))
        self.gate_source = {name: (Path(cli.__file__).parents[1]/name).read_bytes() for name in cli.GATE_SOURCES}
        self.optimizer = self.enterContext(patch.object(cli, 'validate_optimizer_evidence',
            side_effect=lambda *a: self.events.append('optimizer')))
        self.enterContext(patch.object(cli, 'CORE_MANIFEST_SHA256', cli._sha(self.manifest_raw)))
        self.enterContext(patch.object(cli, 'AUTHORIZATION_SHA256', cli._sha(self.auth_raw)))
        self.enterContext(patch.object(cli, 'LOCK_SHA256', cli._sha(self.source['requirements/runtime_v2.lock.txt'])))
        self.enterContext(patch.object(cli, 'SYNTHETIC_LINUX_GATE_SHA256', cli._sha(self.evidence['synthetic_linux_gate.json'])))
        self.family = 'iwls_aes_core'; self.seed = 20260824
        self.output = self.root.as_posix()+f'_{self.family}_{self.seed}'
        self.envelope = dict(schema='v5-train-prelaunch-envelope-v1', source_root=self.root.as_posix(),
            output=self.output, package_root=cli.PACKAGE_ROOT, family=self.family, seed=self.seed,
            roles=['TRAIN'], parent_resource_guard_required=True,
            core_manifest_sha256=cli.CORE_MANIFEST_SHA256,
            helper_sha256={name: cli._sha(raw) for name, raw in self.helper_raw.items()},
            gate_source_sha256=cli.optimizer_source_pins(),
            authorization_id=cli.AUTHORIZATION_ID,
            **{field: cli._sha(self.evidence[name]) for name, field in cli.EVIDENCE.items()})
        for name, raw in {**self.source, **self.helper_raw, **self.gate_source, **self.evidence,
                          cli.MANIFEST_NAME: self.manifest_raw}.items():
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        self.result = dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
            formal_training_authorized_by_this_function=False, new_formal_18_fit_release=False)
        self.binder = Mock(); self.approval = Mock(); self.resource = Mock(); self.worker = Mock()
        self.binder.validate_source_bytes.side_effect = lambda *a, **k: self.events.append('binder')
        self.approval.validate_approval_integrity.side_effect = lambda *a, **k: self.events.append('approval')
        self.resource.check_current_process.side_effect = lambda: self.events.append('resource')
        self.worker.execute_single_fit.side_effect = lambda *a, **k: self.events.append('fit') or self.result
        self.torch = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False))
        self.numpy = object()
        @contextmanager
        def context(sources, pins, **kwargs):
            self.events.append('fresh_metadata_and_context')
            self.assertEqual(len(sources), 25)
            self.assertEqual(set(sources), set(pins))
            self.assertEqual(kwargs['lock_raw'], self.source['requirements/runtime_v2.lock.txt'])
            yield {'status': 'MOCK_CONTEXT_NOT_RESOURCE_PROOF'}
            self.events.append('context_exit')
        self.runtime = SimpleNamespace(controlled_imports=context)
        self.helper = self.enterContext(patch.object(cli, '_helper', side_effect=[object(), object(), self.runtime]))
        modules = {'src.models.ranking_v5_caller_source_binding': self.binder,
            'src.models.ranking_v5_approval_binding': self.approval,
            'src.models.ranking_v5_parent_guard_receipt': object(),
            'src.models.ranking_v5_worker_resource_context': self.resource,
            'src.models.ranking_v5_single_fit_worker': self.worker, 'torch': self.torch, 'numpy': self.numpy}
        def import_module(name):
            self.events.append('import:'+name)
            return modules[name]
        self.imports = self.enterContext(patch.object(cli, '_import', side_effect=import_module))

    def execute(self, envelope=None):
        raw = encode(self.envelope if envelope is None else envelope)
        return cli.execute_prelaunch(raw, trusted_envelope_sha256=cli._sha(raw),
            source_root=self.root.as_posix(), output=self.output, package_root=cli.PACKAGE_ROOT,
            family=self.family, seed=self.seed)

    def test_synthetic_positive_exact_order_no_output_created(self):
        self.assertIs(self.execute(), self.result)
        for before, after in (('fresh_metadata_and_context', 'binder'), ('binder', 'approval'),
                              ('approval', 'optimizer'), ('optimizer', 'resource'), ('resource', 'import:torch'),
                              ('import:numpy', 'fit'), ('fit', 'context_exit')):
            self.assertLess(self.events.index(before), self.events.index(after))
        self.assertEqual(self.worker.execute_single_fit.call_count, 1)
        args, kwargs = self.worker.execute_single_fit.call_args
        self.assertEqual(args[:3], (cli.PACKAGE_ROOT, self.family, self.seed))
        self.assertEqual(set(args[4]), cli.RELEASE_SOURCE_FILES)
        self.assertEqual(kwargs['output'], self.output)
        self.assertIs(kwargs['torch'], self.torch)
        self.assertFalse(Path(self.output).exists())

    def test_envelope_wrong_bindings_seals_schema_before_source_io(self):
        for key, value in [('seed', True), ('family', 'iwls_spi'), ('roles', ['TEST']),
                           ('parent_resource_guard_required', False), ('authorization_id', 'fake'),
                           ('core_manifest_sha256', '0'*64), ('unknown', 1),
                           ('helper_sha256', {})]:
            altered = copy.deepcopy(self.envelope); altered[key] = value
            with self.subTest(key=key), patch.object(cli, '_read') as read, self.assertRaises(ValueError):
                self.execute(altered)
            read.assert_not_called()
        self.helper.assert_not_called(); self.imports.assert_not_called()

    def test_manifest_source_helper_lock_evidence_drift_before_exec_or_ml(self):
        names = [cli.MANIFEST_NAME, next(iter(cli.CORE_FILES)), cli.HELPERS[0],
                 'requirements/runtime_v2.lock.txt', *cli.EVIDENCE]
        for name in names:
            path = self.root/name; original = path.read_bytes(); path.write_bytes(original+b' ')
            with self.subTest(name=name), self.assertRaises(ValueError): self.execute()
            path.write_bytes(original)
        self.helper.assert_not_called(); self.imports.assert_not_called(); self.worker.execute_single_fit.assert_not_called()

    def test_oversize_source_and_evidence_before_exec(self):
        for name, limit in [(cli.HELPERS[0], cli.SOURCE_CAP), ('authorization.json', cli.JSON_CAP)]:
            path = self.root/name; original = path.read_bytes(); path.write_bytes(b'x'*(limit+1))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'FILE_BOUND'): self.execute()
            path.write_bytes(original)
        self.helper.assert_not_called(); self.imports.assert_not_called()

    def test_total_source_cap_before_helper_exec(self):
        with patch.object(cli, 'TOTAL_SOURCE_CAP', 1), self.assertRaisesRegex(ValueError, 'SOURCE_TOTAL_BOUND'):
            self.execute()
        self.helper.assert_not_called()

    def test_approval_failure_before_resource_ml_worker(self):
        self.approval.validate_approval_integrity.side_effect = ValueError('approval-closed')
        with self.assertRaisesRegex(ValueError, 'approval-closed'): self.execute()
        self.resource.check_current_process.assert_not_called()
        self.worker.execute_single_fit.assert_not_called()
        self.assertNotIn('import:torch', self.events); self.assertNotIn('import:numpy', self.events)

    def test_optimizer_failure_before_resource_ml_worker(self):
        self.optimizer.side_effect = ValueError('optimizer-closed')
        with self.assertRaisesRegex(ValueError, 'optimizer-closed'): self.execute()
        self.resource.check_current_process.assert_not_called()
        self.worker.execute_single_fit.assert_not_called()
        self.assertNotIn('import:torch', self.events)

    def test_context_or_binder_failure_before_approval_ml_worker(self):
        self.binder.validate_source_bytes.side_effect = ValueError('binder-closed')
        with self.assertRaisesRegex(ValueError, 'binder-closed'): self.execute()
        self.approval.validate_approval_integrity.assert_not_called()
        self.worker.execute_single_fit.assert_not_called()
        self.assertNotIn('import:torch', self.events)

    def test_external_module_bootstrap_does_not_publish_src_package(self):
        # _helper is mocked for the positive integration; exercise its original
        # function through a separate script instance without importing src.
        spec2 = importlib.util.spec_from_file_location('_unit_v5_cli_bootstrap', Path(cli.__file__))
        original = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(original)
        module = original._helper(b'value = 7\n', '_external_synthetic_helper')
        self.assertEqual(module.value, 7)
        self.assertEqual(module.__name__, '_external_synthetic_helper')
        self.assertNotIn('_external_synthetic_helper', original.sys.modules)

    def test_main_derives_one_fixed_perfit_envelope_name(self):
        raw = encode(self.envelope)
        expected_name = f'prelaunch_{self.family}_{self.seed}.json'
        with patch.object(cli, '_read', return_value=raw) as read, \
                patch.object(cli, 'execute_prelaunch', return_value=self.result) as execute, \
                patch('builtins.print'):
            result = cli.main(['--source-root', self.root.as_posix(), '--output', self.output,
                '--package-root', cli.PACKAGE_ROOT, '--envelope-sha256', cli._sha(raw),
                '--family', self.family, '--seed', str(self.seed)])
        self.assertEqual(result, 0)
        read.assert_called_once_with(self.root.as_posix(), expected_name, cli.JSON_CAP)
        self.assertEqual(execute.call_count, 1)

    def test_resource_failure_before_ml_package_output(self):
        self.resource.check_current_process.side_effect = ValueError('resource-closed')
        with self.assertRaisesRegex(ValueError, 'resource-closed'): self.execute()
        self.worker.execute_single_fit.assert_not_called()
        self.assertNotIn('import:torch', self.events); self.assertFalse(Path(self.output).exists())

    def test_fixed_names_and_symlink_reparse_before_open(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_FILE'): cli._read(self.root.as_posix(), '../bad', 100)
        for info in (SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0),
                     SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)):
            with patch.object(Path, 'lstat', return_value=info), patch.object(os, 'open') as opened, \
                    self.assertRaisesRegex(ValueError, 'SYMLINK'):
                self.execute()
            opened.assert_not_called()

    def test_worker_failure_no_retry(self):
        self.worker.execute_single_fit.side_effect = RuntimeError('synthetic fit failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic fit failure'): self.execute()
        self.assertEqual(self.worker.execute_single_fit.call_count, 1)


if __name__ == '__main__':
    unittest.main()
