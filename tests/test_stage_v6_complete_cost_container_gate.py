"""Local E17 bundle scope tests: fake sources, mocked transport, no Torch."""
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
        'e17_stage', ROOT / 'scripts/stage_v6_complete_cost_container_gate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StageScopeTests(unittest.TestCase):
    def test_fixed_scope_and_count(self):
        stage = load_stage()
        self.assertEqual(len(stage.MAPPING), 9)
        self.assertEqual(stage.REMOTE, '/ssd/cjc/gnn_model_v6_complete_cost_synthetic_20261014_r1')
        self.assertEqual(stage.LOCAL.name, 'v6_complete_cost_container_20261014_r1')
        self.assertIn('src/models/ranking_v6_complete_first_hit_reference.py', stage.MAPPING)
        self.assertIn('src/models/ranking_v6_complete_cost_scorer_probe.py', stage.MAPPING)
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        self.assertEqual(contract['source_count'], len(stage.MAPPING))
        self.assertEqual(contract['bundle_entries'], len(stage.MAPPING) + 1)
        self.assertEqual(contract['root'], stage.REMOTE)
        self.assertEqual(contract['expected_child_status'], 'PASS_REAL_FACTORY_COMPLETE_COST_VJP_ONLY')
        self.assertEqual(contract['scope'], 'SYNTHETIC_COMPLETE_COST_SCORER_VJP_ONLY')
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
            captured = []

            def transport(command, **kwargs):
                captured.append((command, kwargs))
                if 'input' in kwargs:
                    manifest = (local / 'source_manifest.json').read_bytes()
                    receipt = {'status': 'PASS_BOUNDED_STAGING_ONLY', 'entries': 10,
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
            self.assertIn('len(members)!=10', extraction)
            self.assertIn("'entries':10", extraction)
            with tarfile.open(local / 'payload.tar.gz', 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), set(stage.MAPPING) | {'_source_manifest.json'})
                self.assertEqual(len(bundle.getmembers()), 10)
                self.assertLessEqual(sum(m.size for m in bundle.getmembers()), 131072)
                manifest = json.load(bundle.extractfile('_source_manifest.json'))
                self.assertEqual(set(manifest['sources']), set(stage.MAPPING))
                for name, pin in manifest['sources'].items():
                    self.assertEqual(hashlib.sha256(bundle.extractfile(name).read()).hexdigest(), pin)

    def test_runner_and_stage_allowlists_match_without_importing_linux_runner(self):
        stage = load_stage()
        tree = ast.parse((ROOT / stage.MAPPING['runner.py']).read_text())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'NAMES' for t in n.targets))
        self.assertEqual(ast.literal_eval(assignment.value), set(stage.MAPPING))

    def test_pinned_limits_and_probe_call(self):
        stage = load_stage()
        contract = json.loads((ROOT / stage.MAPPING['_contract.json']).read_text())
        expected = {'python': '3.11.2', 'torch': '2.5.1', 'numpy': '2.1.3', 'sympy': '1.13.1',
                    'memory_bytes': 1073741824, 'swap_extra_bytes': 0, 'workers': 1,
                    'cpus': 1, 'timeout_seconds': 120, 'log_limit_bytes': 65536,
                    'network': 'none', 'root_filesystem': 'read_only'}
        for name, value in expected.items():
            self.assertEqual(contract[name], value)
        text = (ROOT / stage.MAPPING['runner.py']).read_text()
        self.assertIn('probe.verify(torch, scope=probe.SCOPE)', text)
        self.assertIn("child_result.get('status') == 'PASS_REAL_FACTORY_COMPLETE_COST_VJP_ONLY'", text)
        for switch in ('--pull=never', '--read-only', 'no-new-privileges'):
            self.assertIn(switch, text)


if __name__ == '__main__':
    unittest.main()
