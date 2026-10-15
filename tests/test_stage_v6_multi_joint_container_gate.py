"""E29 local package tests, transport mocked; no Torch or formal staging."""
import ast
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load_stage():
    spec = importlib.util.spec_from_file_location('e29_stage', ROOT / 'scripts/stage_v6_multi_joint_container_gate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StageScopeTests(unittest.TestCase):
    def setUp(self):
        self.stage = load_stage()
        self.contract = json.loads((ROOT / self.stage.MAPPING['_contract.json']).read_bytes())

    def fixture(self, directory):
        repo = Path(directory) / 'repo'; repo.mkdir()
        for name, relative in self.stage.MAPPING.items():
            p = repo / relative; p.parent.mkdir(parents=True, exist_ok=True)
            if name == '_contract.json': p.write_text(json.dumps(self.contract), encoding='utf-8')
            elif name == 'src/models/runtime_ranking_v3.py': p.write_bytes((ROOT / relative).read_bytes())
            else: p.write_bytes(b'fixture only; not imported\n')
        return repo, Path(directory) / 'staged'

    def test_exact_scope_mapping_and_limits(self):
        s = self.stage
        self.assertEqual(len(s.MAPPING), 12); self.assertEqual(s.ENTRY_COUNT, 13)
        self.assertEqual(s.REMOTE, self.contract['root'])
        self.assertEqual(s.LOCAL.name, 'v6_multi_positive_joint_container_20261015_r1')
        self.assertEqual((s.ARCHIVE_LIMIT, s.UNPACKED_LIMIT, s.FILE_LIMIT), (65536, 196608, 65536))
        tree = ast.parse((ROOT / s.MAPPING['runner.py']).read_text())
        names = next(n for n in tree.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'NAMES' for t in n.targets))
        self.assertEqual(set(ast.literal_eval(names.value)), set(s.MAPPING))
        self.assertIn('src/models/ranking_v6_multi_positive_joint_caller.py', s.MAPPING)
        self.assertNotIn('src/models/ranking_v6_complete_cost_paired_runtime_v3.py', s.MAPPING)

    def test_local_build_only_and_mocked_transfer(self):
        s = self.stage
        with tempfile.TemporaryDirectory() as directory:
            repo, local = self.fixture(directory); calls = []
            def transport(command, **kw):
                calls.append((command, kw))
                if 'input' in kw:
                    receipt = {'status': 'PASS_BOUNDED_STAGING_ONLY', 'entries': 13,
                               'manifest_sha256': hashlib.sha256((local/'source_manifest.json').read_bytes()).hexdigest(),
                               'archive_sha256': hashlib.sha256((local/'payload.tar.gz').read_bytes()).hexdigest()}
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(receipt))
                return subprocess.CompletedProcess(command, 0)
            with patch.object(s, 'REPO', repo), patch.object(s, 'LOCAL', local), \
                    patch.object(s.subprocess, 'run', side_effect=transport), \
                    contextlib.redirect_stdout(io.StringIO()):
                bundle = s.build(); self.assertEqual(calls, [])
                s.transfer(bundle)
            self.assertEqual(len(calls), 3)
            extraction = calls[-1][1]['input']
            for guard in ('len(members)!=13', 'compressed.read(196609)', 'O_NOFOLLOW',
                          'O_EXCL', 'READBACK_SHA', 'st_nlink!=1', 'ENTRY_ALLOWLIST'):
                self.assertIn(guard, extraction)
            self.assertLessEqual((local/'payload.tar.gz').stat().st_size, 65536)
            self.assertLessEqual(len(gzip.decompress((local/'payload.tar.gz').read_bytes())), 196608)
            with tarfile.open(local/'payload.tar.gz', 'r:gz') as archive:
                self.assertEqual(set(archive.getnames()), set(s.MAPPING) | {'_source_manifest.json'})
                manifest = json.load(archive.extractfile('_source_manifest.json'))
                for name, pin in manifest['sources'].items():
                    self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), pin)

    def test_contract_gate_rejects_widening_before_any_creation_or_transport(self):
        s = self.stage
        for key, value in [('formal_runs', True), ('memory_bytes', 2**31), ('workers', 2),
                           ('root', '/ssd/cjc/other'), ('real_training_release', True),
                           ('source_count', 13), ('log_limit_bytes', 1048576)]:
            c = copy.deepcopy(self.contract); c[key] = value
            with self.assertRaises(ValueError): s.require_authorized(c)
        with patch.object(s.subprocess, 'run') as run, patch.object(s, 'build') as build:
            with self.assertRaises(ValueError): s.stage()
            with self.assertRaises(ValueError): s.stage(execute=1)
            run.assert_not_called(); build.assert_not_called()

    def test_oversize_factory_change_and_collision_stop_before_transport(self):
        s = self.stage
        for mode in ('oversize', 'factory', 'collision'):
            with tempfile.TemporaryDirectory() as directory:
                repo, local = self.fixture(directory)
                if mode == 'oversize': (repo / s.MAPPING['runner.py']).write_bytes(b'x'*65537)
                elif mode == 'factory': (repo / s.MAPPING['src/models/runtime_ranking_v3.py']).write_bytes(b'changed')
                else: local.mkdir()
                with patch.object(s, 'REPO', repo), patch.object(s, 'LOCAL', local), \
                        patch.object(s.subprocess, 'run') as run:
                    with self.assertRaises((ValueError, FileExistsError)): s.stage(execute=True)
                    run.assert_not_called()

    def test_cli_requires_execute_and_disallows_overrides(self):
        s = self.stage
        with patch.object(s, 'stage') as stage:
            for args in ([], ['--execute', '--root', '/other']):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): s.main(args)
            stage.assert_not_called()
            s.main(['--execute']); stage.assert_called_once_with(execute=True)

    def test_runner_uses_safe_limits_and_probe_only(self):
        text = (ROOT / self.stage.MAPPING['runner.py']).read_text()
        for value in ('probe.verify(torch, scope=probe.SCOPE)', '--pull=never', '--read-only',
                      'no-new-privileges', "'--memory', '1g', '--memory-swap', '1g'",
                      'len(output) + len(data) > 524288', "'protocol.receipt.json'"):
            self.assertIn(value, text)
        self.assertNotIn('torch.optim', text)

    def test_pure_runner_receipt_gates_cross_platform_not_linux_proof(self):
        spec = importlib.util.spec_from_file_location('e29_pure_runner', ROOT / self.stage.MAPPING['runner.py'])
        runner = importlib.util.module_from_spec(spec)
        # Only pure validation functions are called; this does not simulate Linux.
        with patch.dict(sys.modules, {'resource': SimpleNamespace()}):
            spec.loader.exec_module(runner)
        spec = importlib.util.spec_from_file_location('e29_receipt_fixture', ROOT / self.stage.MAPPING['_protocol_tests.py'])
        protocol = importlib.util.module_from_spec(spec); spec.loader.exec_module(protocol)
        probe = protocol.RunnerProtocolTests('test_status_only_child_receipt_rejected')
        probe.runner = runner
        runner.require_authorized(self.contract)
        receipt = probe.full_receipt(); runner.validate_child_receipt(receipt, 'a'*64)
        for key, bad in [('optimizer_calls', 1), ('weights_unchanged', False), ('torch', '2.5.1'),
                         ('mc_estimator_calls', 2), ('real_training_release', True)]:
            with self.assertRaises(ValueError): runner.validate_child_receipt(dict(receipt, **{key: bad}), 'a'*64)
        bad = copy.deepcopy(receipt); bad['synthetic_held_freeze_proof']['loader_calls'] = 2
        with self.assertRaises(ValueError): runner.validate_child_receipt(bad, 'a'*64)


if __name__ == '__main__':
    unittest.main()
