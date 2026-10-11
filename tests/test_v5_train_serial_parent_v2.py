"""Local synthetic tests only; no ML, deployment, formal package or TRAIN."""
import os
import json
from pathlib import Path
import stat
import tempfile
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_v5_train_serial_parent_v2 as parent
from scripts import run_v5_train_single_fit_v2 as cli
from src.models import ranking_v4_memory_guard as guard
from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_caller_source_binding as binder
from src.models import ranking_v5_bound_input_reader as inputs
from tests import test_ranking_v5_serial_matrix as matrix_tests
from src.models import ranking_v5_serial_matrix as matrix


class ParentV2Tests(unittest.TestCase):
    def test_all18_exact_task_environments_ignore_inherited_temp(self):
        paths = parent.jit_roots(parent.ROOT)
        self.assertEqual(len(paths), 18)
        self.assertEqual(len(set(paths)), 18)
        with patch.dict(os.environ, {'TMPDIR': '/untrusted', 'TMP': '/untrusted',
                                    'TEMP': '/untrusted', 'PYTHONPATH': '/untrusted'}):
            for path in paths:
                env = parent.child_environment(path)
                self.assertEqual(env['TMPDIR'], path)
                self.assertNotIn('TMP', env); self.assertNotIn('TEMP', env)
                self.assertNotIn('PYTHONPATH', env)
                self.assertEqual(env['SETUPTOOLS_USE_DISTUTILS'], 'stdlib')
                self.assertEqual(env['CUDA_VISIBLE_DEVICES'], '')

    def test_protected_bad_root_missing_trust_zero_io(self):
        with patch.object(parent, 'read') as read, patch.object(parent.Path, 'lstat') as lstat:
            for root in ('/ssd/cjc/multimode_ate_gnn_v1', parent.ROOT+'_other', parent.ROOT):
                with self.assertRaises(ValueError):
                    parent.load_packet(root, 'a'*64)
            read.assert_not_called(); lstat.assert_not_called()
        with patch.object(parent.Path, 'mkdir') as mkdir:
            with self.assertRaises(ValueError):
                parent.prepare_jit_roots('/ssd/cjc/multimode_ate_gnn_v1', matrix.FAMILIES, matrix.SEEDS)
            mkdir.assert_not_called()
        with patch.object(parent.Path, 'lstat') as lstat:
            denied = ('/ssd/cjc/multimode_ate_gnn_v1/trust.json',
                '/ssd/cjc/x/../multimode_ate_gnn_v1/a', '/ssd//cjc/multimode_ate_gnn_v1/a',
                '/SSD/CJC/MULTIMODE_ATE_GNN_V1/a', '\\ssd\\cjc\\multimode_ate_gnn_v1\\a',
                'trust.json', '../multimode_ate_gnn_v1/a', '/ssd/cjc/./multimode_ate_gnn_v1/a')
            for path in denied:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    parent.read(path,parent.JSON_CAP)
            lstat.assert_not_called()

    def test_bootstrap_fixed5_paths_isolated_flags_and_new_cli(self):
        for program in (parent.CLI, parent.PROGRAM):
            code = parent.bootstrap(parent.ROOT, program, 'a'*64)
            self.assertIn('sys.flags.no_site==1 and sys.flags.isolated==1', code)
            self.assertIn(repr(list(parent.SEARCH_PATHS)), code)
            self.assertIn(parent.ROOT+'/'+program, code)
            self.assertNotIn('jit_tmp', code)
        self.assertEqual(len(parent.SEARCH_PATHS), 5)
        with self.assertRaises(ValueError):
            parent.bootstrap(parent.ROOT, 'scripts/run_v5_train_single_fit.py', 'a'*64)

    def test_all18_child_commands_bind_exact_external_maps_and_guard_policy(self):
        packet = dict(source_sha256={p:'a'*64 for p in {*cli.HELPERS,parent.CLI}},
                      evidence_sha256={p:'b'*64 for p in cli.EVIDENCE},
                      prelaunch_sha256={f'prelaunch_{f}_{s}.json':'c'*64
                                        for f in cli.FAMILIES for s in cli.SEEDS})
        for task in matrix.build_train_matrix(parent.ROOT):
            command = parent.child_command(parent.ROOT,task,packet,cli)
            self.assertEqual(command[:4],[parent.INTERPRETER,'-I','-S','-B'])
            supplement = json.loads(command[command.index('--trusted-supplement-sha256-json')+1])
            evidence = json.loads(command[command.index('--trusted-evidence-sha256-json')+1])
            self.assertEqual(supplement,{p:'a'*64 for p in cli.HELPERS})
            self.assertEqual(evidence,packet['evidence_sha256'])
            self.assertEqual(command[command.index('--output')+1],task.output)
        policy = guard.policy()
        self.assertEqual(policy['max_concurrent_workers'],1)
        self.assertEqual(policy['retries'],0)
        self.assertEqual(policy['combined_rss_cap_bytes'],1024**3)
        self.assertEqual(policy['child_address_space_cap_bytes'],8*1024**3)

    @unittest.skipIf(os.name == 'nt', 'POSIX 0700 directory mode assertion')
    def test_exclusive_private_temp_roots_no_worker_output_or_reuse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'source'; root.mkdir()
            with patch.object(parent, 'ROOT', root.as_posix()):
                paths = parent.prepare_jit_roots(root.as_posix(), matrix.FAMILIES, matrix.SEEDS)
                for path in paths:
                    self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o700)
                    self.assertFalse(Path(root.as_posix()+'_'+Path(path).name).exists())
                with self.assertRaises(ValueError):
                    parent.prepare_jit_roots(root.as_posix(), matrix.FAMILIES, matrix.SEEDS)

    def test_summary_and_once_marker_never_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'once.json'
            parent.write_once(path, {'marker': True})
            raw = path.read_bytes()
            with self.assertRaises(ValueError): parent.write_once(path, {'marker': False})
            self.assertEqual(path.read_bytes(), raw)

    def test_serial_first_failure_stops_without_retry(self):
        tasks = matrix.build_train_matrix(parent.ROOT)
        calls = []
        def execute(task):
            calls.append(task)
            raise ValueError('synthetic failure')
        def review(task):
            self.fail('failed child must not be reviewed')
        controller = matrix.SerialTrainMatrix(parent.ROOT, tasks)
        state = controller.run(execute_once=execute, review_independently=review)
        self.assertEqual(state.failed_index, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(state.remaining), 17)
        with self.assertRaisesRegex(RuntimeError, 'NO_RETRY'):
            controller.run(execute_once=execute, review_independently=review)

    def test_parent_missing_sidecar_stops_before_artifact_acceptance(self):
        packet = dict(source_sha256={p:'a'*64 for p in
            cli.CORE_FILES|{parent.CLI,*cli.HELPERS,*cli.RELEASE_SOURCE_FILES}},
            evidence_sha256={p:'b'*64 for p in cli.EVIDENCE},
            prelaunch_sha256={f'prelaunch_{f}_{s}.json':'c'*64 for f in cli.FAMILIES for s in cli.SEEDS})
        source={p:b'x' for p in cli.CORE_FILES|{parent.FENCE,parent.CPU_PROGRAM,*parent.EXTRA}}
        receipt=matrix_tests.parent_receipt()
        evidence={p:b'{}' for p in cli.EVIDENCE}
        evidence.update({'cpu_gate.child.json':b'{}',
            'cpu_gate.memory.json':json.dumps(receipt).encode(),
            'cpu_gate.launch.json':json.dumps(dict(parent_guard_receipt=receipt,
                child_receipt_sha256=parent.CPU_EVIDENCE['cpu_gate.child.json'],child_receipt={})).encode()})
        binding=SimpleNamespace(build_independent_fit_context=lambda *a,**k:object())
        collector=SimpleNamespace(collect_parent_artifact_candidate=unittest.mock.Mock())
        def external(name,raw):
            if name=='_v5_serial_fence': return SimpleNamespace(sealed_imports=lambda *a:nullcontext())
            return SimpleNamespace(validate_child=lambda *a:None,typed_equal=lambda *a:True)
        def read(path,cap):
            if str(path).endswith('.stdout.log.memory.json'): return json.dumps(receipt).encode()
            raise FileNotFoundError('synthetic missing successful admission sidecar')
        with patch.object(parent,'runtime'),patch.object(parent,'load_packet',return_value=(cli,packet,source,evidence,b'{}')),\
             patch.object(parent,'external',side_effect=external),patch.object(parent,'global_worker_lock',return_value=nullcontext()),\
             patch.object(parent,'supplemental_aliases',return_value=nullcontext((None,binding,matrix,collector))),\
             patch.object(parent,'absent'),patch.object(parent,'write_once'),patch.object(parent,'prepare_jit_roots'),\
             patch.object(parent,'read',side_effect=read),patch.object(binder,'validate_source_bytes'),\
             patch.object(approval,'validate_approval_integrity'),patch.object(cli,'validate_optimizer_evidence'),\
             patch.object(inputs,'load_bound_fold_request',return_value=dict(request={},input_identity={})),\
             patch.object(guard,'run_bounded',return_value=receipt) as bounded:
            final=parent.run(parent.ROOT,'d'*64)
        self.assertEqual(final['status'],'STOPPED_NO_RETRY')
        self.assertEqual(final['failed_index'],0)
        self.assertEqual(final['completed_count'],0)
        self.assertEqual(final['remaining_count'],17)
        bounded.assert_called_once()
        collector.collect_parent_artifact_candidate.assert_not_called()


if __name__ == '__main__': unittest.main()
