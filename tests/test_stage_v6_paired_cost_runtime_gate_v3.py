"""Local E22 bundle scope tests: fake sources, mocked transport, no Torch."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_stage():
    spec = importlib.util.spec_from_file_location(
        'e22_stage', ROOT / 'scripts/stage_v6_paired_cost_runtime_gate_v3.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StageScopeTests(unittest.TestCase):
    def test_locked_before_local_creation_or_transport(self):
        stage = load_stage()
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / 'must_not_exist'
            with patch.object(stage, 'LOCAL', local), patch.object(stage.subprocess, 'run') as transport:
                with patch.object(stage.json, 'loads', return_value={'execution_authorized': False}):
                    with self.assertRaisesRegex(ValueError, 'E22_EXECUTION_LOCKED'):
                        stage.stage()
            self.assertFalse(local.exists())
            transport.assert_not_called()

    def test_fixed_scope_and_count(self):
        stage = load_stage()
        self.assertEqual(len(stage.MAPPING), 15)
        self.assertEqual(stage.REMOTE, '/ssd/cjc/gnn_model_v6_paired_cost_runtime_20261015_r3')
        self.assertEqual(stage.LOCAL.name, 'v6_paired_cost_runtime_20261015_r3')
        self.assertIn('src/models/ranking_v6_complete_first_hit_reference.py', stage.MAPPING)
        self.assertIn('src/models/ranking_v6_complete_cost_paired_runtime_v3.py', stage.MAPPING)
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        self.assertEqual(contract['source_count'], len(stage.MAPPING))
        self.assertEqual(contract['bundle_entries'], len(stage.MAPPING) + 1)
        self.assertEqual(contract['root'], stage.REMOTE)
        self.assertEqual(contract['expected_child_status'], 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY')
        self.assertEqual(contract['scope'], 'E22_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY')
        self.assertEqual(contract['formal_runs'], 1)
        self.assertEqual(contract['automatic_retries'], 0)

    def test_local_bundle_with_mocked_transport(self):
        stage = load_stage()
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'repo'
            fixture.mkdir()
            local = Path(directory) / 'staged'
            for relative in stage.MAPPING.values():
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'fixture only; no imported model\n')
            (fixture / stage.MAPPING['_contract.json']).write_text(json.dumps(json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())))
            captured = []

            def transport(command, **kwargs):
                captured.append((command, kwargs))
                if 'input' in kwargs:
                    manifest = (local / 'source_manifest.json').read_bytes()
                    receipt = {'status': 'PASS_BOUNDED_STAGING_ONLY', 'entries': stage.ENTRY_COUNT,
                               'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
                               'archive_sha256': hashlib.sha256((local / 'payload.tar.gz').read_bytes()).hexdigest()}
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(receipt))
                return subprocess.CompletedProcess(command, 0)

            with patch.object(stage, 'REPO', fixture), patch.object(stage, 'LOCAL', local), \
                    patch.object(stage.subprocess, 'run', side_effect=transport), \
                    contextlib.redirect_stdout(io.StringIO()):
                stage.stage()
            self.assertEqual(len(captured), 3)
            extraction = captured[-1][1]['input']
            compile(extraction, '<mocked-remote-extraction>', 'exec')
            self.assertIn(f'len(members)!={stage.ENTRY_COUNT}', extraction)
            self.assertIn(f"'entries':{stage.ENTRY_COUNT}", extraction)
            with tarfile.open(local / 'payload.tar.gz', 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), set(stage.MAPPING) | {'_source_manifest.json'})
                self.assertEqual(len(bundle.getmembers()), stage.ENTRY_COUNT)
                self.assertLessEqual(sum(m.size for m in bundle.getmembers()), 262144)
                manifest = json.load(bundle.extractfile('_source_manifest.json'))
                self.assertEqual(set(manifest['sources']), set(stage.MAPPING))
                for name, pin in manifest['sources'].items():
                    self.assertEqual(hashlib.sha256(bundle.extractfile(name).read()).hexdigest(), pin)

    def test_runner_and_stage_allowlists_match_without_importing_linux_runner(self):
        stage = load_stage()
        tree = ast.parse((ROOT / stage.MAPPING['runner.py']).read_text())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'NAMES' for t in n.targets))
        self.assertEqual(set(ast.literal_eval(assignment.value)), set(stage.MAPPING))

    def test_pinned_limits_and_probe_call(self):
        stage = load_stage()
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        expected = {'python': '3.11.2', 'torch': '2.5.1', 'numpy': '2.1.3', 'sympy': '1.13.1',
                    'memory_bytes': 1073741824, 'swap_extra_bytes': 0, 'workers': 1,
                    'cpus': 1, 'timeout_seconds': 120, 'log_limit_bytes': 524288,
                    'network': 'none', 'root_filesystem': 'read_only'}
        for name, value in expected.items():
            self.assertEqual(contract[name], value)
        text = (ROOT / stage.MAPPING['runner.py']).read_text()
        self.assertIn('probe.run(torch, release=contract)', text)
        self.assertIn("child_result.get('status') == 'COMPLETE_PAIRED_SYNTHETIC_FIT_DIAGNOSTIC_ONLY'", text)
        for switch in ('--pull=never', '--read-only', 'no-new-privileges'):
            self.assertIn(switch, text)

    def test_current_source_sizes_and_dependency_closure(self):
        stage = load_stage()
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        self.assertEqual(contract['archive_limit_bytes'], stage.ARCHIVE_LIMIT)
        self.assertEqual(contract['unpacked_limit_bytes'], stage.UNPACKED_LIMIT)
        self.assertEqual(contract['file_limit_bytes'], stage.FILE_LIMIT)
        sources = {}
        for name, relative in stage.MAPPING.items():
            data = (ROOT / relative).read_bytes()
            self.assertLessEqual(len(data), stage.FILE_LIMIT)
            sources[name] = hashlib.sha256(data).hexdigest()
            if name.startswith('src/models/'):
                tree = ast.parse(data)
                nodes = list(tree.body)
                # The fixed MLP factory is reachable; the graph factory is not.
                for item in tree.body:
                    if isinstance(item, (ast.FunctionDef, ast.ClassDef)) and item.name != 'make_graph_ranker':
                        nodes.extend(ast.walk(item))
                for node in nodes:
                    if not isinstance(node, ast.ImportFrom):
                        continue
                    if node.module and node.module.startswith('src.models.'):
                        required = node.module.replace('.', '/') + '.py'
                        self.assertIn(required, stage.MAPPING)
                    elif node.module == 'src.models' or (node.level == 1 and not node.module):
                        for alias in node.names:
                            self.assertIn('src/models/' + alias.name + '.py', stage.MAPPING)
                    elif node.level == 1 and node.module:
                        self.assertIn('src/models/' + node.module + '.py', stage.MAPPING)
        total = sum((ROOT / relative).stat().st_size for relative in stage.MAPPING.values())
        manifest_size = len(json.dumps({'sources': sources}, sort_keys=True, separators=(',', ':')).encode()) + 1
        # Tar headers and padding are covered separately from file contents.
        padded = sum(512 + ((ROOT / relative).stat().st_size + 511) // 512 * 512
                     for relative in stage.MAPPING.values())
        padded += 512 + (manifest_size + 511) // 512 * 512 + 1024
        padded = (padded + 10239) // 10240 * 10240
        self.assertLessEqual(total + manifest_size, stage.UNPACKED_LIMIT)
        self.assertLessEqual(padded, stage.UNPACKED_LIMIT)

    def test_lock_precedes_parent_side_effects_and_child_torch(self):
        stage = load_stage()
        tree = ast.parse((ROOT / stage.MAPPING['runner.py']).read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        for name, forbidden in [('_parent_after_gate', ('subprocess.run', 'os.open')),
                                ('_child_after_gate', ('resource.setrlimit',))]:
            calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(functions[name])
                     if isinstance(node, ast.Call)]
            lock_line = next(line for line, call in calls if call == 'require_authorized')
            for line, call in calls:
                if call in forbidden:
                    self.assertLess(lock_line, line)
        torch_line = next(node.lineno for node in ast.walk(functions['_child_after_gate'])
                          if isinstance(node, ast.Import) and any(a.name == 'torch' for a in node.names))
        lock_line = next(node.lineno for node in ast.walk(functions['_child_after_gate'])
                         if isinstance(node, ast.Call) and ast.unparse(node.func) == 'require_authorized')
        self.assertLess(lock_line, torch_line)
        for name in ('parent', 'child'):
            self.assertIsInstance(functions[name].body[0], ast.Return)

    def test_exact_torch_runtime_build_pin_without_importing_runner_or_torch(self):
        stage = load_stage()
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        self.assertEqual(contract['torch'], '2.5.1')
        self.assertEqual(contract['torch_runtime_version'], '2.5.1+cu124')
        tree = ast.parse((ROOT / stage.MAPPING['runner.py']).read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'validate_torch_runtime_version')
        namespace = {'TORCH_RUNTIME_VERSION': contract['torch_runtime_version']}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), '<pure-runtime-version-check>', 'exec'), namespace)
        check = namespace['validate_torch_runtime_version']
        self.assertEqual(check('2.5.1+cu124', contract), '2.5.1+cu124')
        reviewed = ast.parse((ROOT / 'src/models/ranking_v6_torch_version_gate_v3.py').read_text())
        reviewed_helper = next(node for node in reviewed.body if isinstance(node, ast.FunctionDef)
                               and node.name == 'validate_torch_runtime_version')
        self.assertEqual(ast.dump(helper), ast.dump(reviewed_helper))

        class TorchVersionLike(str):
            pass

        actual = TorchVersionLike('2.5.1+cu124')
        self.assertIsNot(type(actual), str)  # The old strict-type helper rejected this.
        old_tree = ast.parse((ROOT / 'scripts/run_v6_paired_cost_runtime_gate_v2.py').read_text())
        old_helper = next(node for node in old_tree.body if isinstance(node, ast.FunctionDef)
                          and node.name == 'validate_torch_runtime_version')
        old_namespace = {'TORCH_RUNTIME_VERSION': contract['torch_runtime_version']}
        exec(compile(ast.Module(body=[old_helper], type_ignores=[]), '<old-version-check>', 'exec'), old_namespace)
        with self.assertRaisesRegex(ValueError, 'TORCH_RUNTIME_VERSION'):
            old_namespace['validate_torch_runtime_version'](actual, contract)
        canonical = check(actual, contract)
        self.assertIs(type(canonical), str)
        self.assertEqual(canonical, '2.5.1+cu124')

        class HostileVersion(str):
            def __eq__(self, other):
                return True

            def __str__(self):
                return '2.5.1+cu124'

        with self.assertRaisesRegex(ValueError, 'TORCH_RUNTIME_VERSION'):
            check(HostileVersion('2.5.1+cpu'), contract)
        for wrong in ('2.5.1', '2.5.1+cpu', '2.5.1+cu121', '2.5.1+cu124.extra', None):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'TORCH_RUNTIME_VERSION'):
                check(wrong, contract)
        with self.assertRaisesRegex(ValueError, 'TORCH_RUNTIME_VERSION'):
            check('2.5.1+cpu', {'torch_runtime_version': '2.5.1+cpu'})

    def test_private_authorization_rejects_bool_budget_before_effects(self):
        stage = load_stage()
        tree = ast.parse((ROOT / stage.MAPPING['runner.py']).read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'require_authorized')
        namespace = {}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), '<pure-authorization-check>', 'exec'), namespace)
        check = namespace['require_authorized']
        valid = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        check(valid)
        mutations = {'authorization_id': 'foreign', 'status': 'DESIGN_LOCAL_TEST_ONLY_EXECUTION_LOCKED',
                     'planned_formal_runs': 2, 'planned_models': 7,
                     'planned_optimizer_steps_total': 145, 'workers': True, 'cpus': 2,
                     'memory_bytes': 2147483648, 'swap_extra_bytes': 1, 'automatic_retries': 1,
                     'scope': 'E20_PAIRED_COST_RUNTIME_DIAGNOSTIC_ONLY', 'protocol_sha256': 'a'*64}
        for field, bad in mutations.items():
            invalid = dict(valid, **{field: bad})
            with self.subTest(field=field), patch.object(stage.json, 'loads', return_value=invalid), \
                    patch.object(stage.Path, 'read_text', return_value='{}'), \
                    patch.object(stage.Path, 'mkdir') as mkdir, \
                    patch.object(stage.subprocess, 'run') as transport:
                with self.assertRaisesRegex(ValueError, 'E22_EXECUTION_LOCKED'):
                    stage.stage()
                mkdir.assert_not_called()
                transport.assert_not_called()
        for bad in (True, False, 1.0, '1', 0, None):
            contract = dict(valid, formal_runs=bad)
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'E22_EXECUTION_LOCKED'):
                check(contract)
            with patch.object(stage.json, 'loads', return_value=contract), \
                    patch.object(stage.Path, 'read_text', return_value='{}'), \
                    patch.object(stage.Path, 'mkdir') as mkdir, \
                    patch.object(stage.subprocess, 'run') as transport:
                with self.assertRaisesRegex(ValueError, 'E22_EXECUTION_LOCKED'):
                    stage._stage_after_gate()
            mkdir.assert_not_called()
            transport.assert_not_called()


if __name__ == '__main__':
    unittest.main()
