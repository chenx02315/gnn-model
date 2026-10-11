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

from scripts import run_v5_train_serial_parent_v3 as parent
from scripts import run_v5_train_single_fit_v3 as cli
from src.models import ranking_v4_memory_guard as guard
from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_caller_source_binding as binder
from src.models import ranking_v5_bound_input_reader as inputs
from tests import test_ranking_v5_serial_matrix as matrix_tests
from src.models import ranking_v5_serial_matrix as matrix


class ParentV3Tests(unittest.TestCase):
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
        packet = dict(source_sha256={p:'a'*64 for p in {*cli.HELPERS,*parent.FREEZE_SOURCES,parent.CLI}},
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
            freeze = json.loads(command[command.index('--trusted-freeze-supplement-sha256-json')+1])
            self.assertEqual(freeze,{p:'a'*64 for p in parent.FREEZE_SOURCES})
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
            cli.CORE_FILES|{parent.CLI,*cli.HELPERS,*parent.EXTRA,*cli.RELEASE_SOURCE_FILES}},
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
            if hasattr(self, 'synthetic_sidecar'):
                return self.synthetic_sidecar
            raise FileNotFoundError('synthetic missing successful admission sidecar')
        events = []
        def marker(path, payload):
            events.append(('write', str(path), payload))
        def package(*args):
            events.append(('package', args))
            return dict(request={},input_identity={})
        with patch.object(parent,'runtime'),patch.object(parent,'load_packet',return_value=(cli,packet,source,evidence,b'{}')),\
             patch.object(parent,'external',side_effect=external),patch.object(parent,'global_worker_lock',return_value=nullcontext()),\
             patch.object(parent,'supplemental_aliases',return_value=nullcontext((None,binding,matrix,collector))),\
             patch.object(parent,'absent') as absent,patch.object(parent,'write_once',side_effect=marker),patch.object(parent,'prepare_jit_roots'),\
             patch.object(parent,'read',side_effect=read),patch.object(binder,'validate_source_bytes'),\
             patch.object(approval,'validate_approval_integrity'),patch.object(cli,'validate_optimizer_evidence'),\
             patch.object(inputs,'load_bound_fold_request',side_effect=package),\
             patch.object(guard,'run_bounded',return_value=receipt) as bounded:
            final=parent.run(parent.ROOT,'d'*64)
        self.assertEqual(final['status'],'STOPPED_NO_RETRY')
        self.assertEqual(final['failed_index'],0)
        self.assertEqual(final['completed_count'],0)
        self.assertEqual(final['remaining_count'],17)
        bounded.assert_called_once()
        collector.collect_parent_artifact_candidate.assert_not_called()
        once = [event for event in events if event[0] == 'write' and event[1].endswith('.once.json')]
        self.assertEqual(len(once), 1)
        self.assertEqual(once[0][1], parent.TRAIN_ONCE_PREFIX+cli.RUN_AUTHORIZATION_SHA256+'.once.json')
        record = once[0][2]
        self.assertEqual(set(record), {'schema','source_root','run_authorization_sha256',
            'run_authorization_id','source_binding_sha256','packet_sha256','planned_fits','automatic_retries'})
        self.assertEqual(record['schema'], 'v5-fresh-train-one-use-authorization-v1')
        self.assertEqual(record['run_authorization_id'], cli.RUN_AUTHORIZATION_ID)
        self.assertEqual(record['source_binding_sha256'], parent.mapping_digest(packet['source_sha256']))
        self.assertLess(events.index(once[0]), next(i for i, e in enumerate(events) if e[0] == 'package'))
        checked = [str(call.args[0]) for call in absent.call_args_list]
        new_marker = parent.TRAIN_ONCE_PREFIX+cli.RUN_AUTHORIZATION_SHA256+'.once.json'
        self.assertEqual(checked.count(new_marker), 2)  # before and inside lock
        self.assertNotIn(parent.TRAIN_ONCE_PREFIX+cli.AUTHORIZATION_SHA256+'.once.json', checked)

    def test_invalid_sidecar_receives_external_bindings_and_never_reaches_collector(self):
        self.synthetic_sidecar = b'{}'
        with patch.object(cli, 'validate_fit_admission_receipt',
                          side_effect=ValueError('synthetic binding rejection')) as validate:
            self.test_parent_missing_sidecar_stops_before_artifact_acceptance()
        validate.assert_called_once()
        self.assertEqual(validate.call_args.args, (b'{}',))
        kwargs = validate.call_args.kwargs
        source = {p: 'a'*64 for p in cli.CORE_FILES | {
            parent.CLI, *cli.HELPERS, *parent.EXTRA, *cli.RELEASE_SOURCE_FILES}}
        evidence = {p: 'b'*64 for p in cli.EVIDENCE if p != 'run_binding_review.json'}
        self.assertEqual(kwargs['source_binding_sha256'], parent.mapping_digest(source))
        self.assertEqual(kwargs['legacy_evidence_binding_sha256'], parent.mapping_digest(evidence))
        self.assertEqual(kwargs['run_binding_review_sha256'], 'b'*64)
        self.assertEqual(kwargs['trusted_freeze_supplement_sha256'],
                         {p: 'a'*64 for p in parent.FREEZE_SOURCES})
        self.assertEqual(kwargs['trusted_supplement_sha256'],
                         {p: 'a'*64 for p in cli.HELPERS})

    @unittest.skipIf(os.name == 'nt', 'POSIX 0600 mode assertion')
    def test_once_is_private_even_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'once.json'
            previous = os.umask(0)
            try:
                parent.write_once(path, {'marker': True})
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            raw = path.read_bytes()
            with self.assertRaises(ValueError):
                parent.write_once(path, {'marker': False})
            self.assertEqual(path.read_bytes(), raw)

    def test_new_supplement_authentication_before_any_compilation(self):
        sources = {path: b'value = 1\\n' for path in parent.EXTRA}
        pins = {path: parent.sha(raw) for path, raw in sources.items()}
        for path in parent.EXTRA:
            changed = dict(pins); changed[path] = '0'*64
            with patch('builtins.compile') as compiler, patch.object(parent.importlib, 'import_module') as importer:
                with self.assertRaisesRegex(ValueError, 'EXTRA_SOURCE_BYTES'):
                    with parent.supplemental_aliases(sources, cli, changed):
                        self.fail('entered')
            compiler.assert_not_called(); importer.assert_not_called()

    def test_new_chain_loads_with_old_core_identity_and_cleans_all(self):
        from types import ModuleType
        from src.models import ranking_v5_frozen_import_fence as fence
        repo = Path(__file__).resolve().parents[1]
        core = {path: (repo/path).read_bytes() for path in fence.FILES}
        sources = {path: (repo/path).read_bytes() for path in parent.EXTRA}
        pins = {path: parent.sha(raw) for path, raw in sources.items()}
        fresh_cli = ModuleType('_new_cli_fixture')
        fresh_cli.__dict__.update(cli.__dict__)
        # Full test discovery may preload ML dependencies. Isolate only this
        # synthetic registry view; production fence remains unchanged.
        import sys
        saved = {name: module for name, module in sys.modules.items()
                 if name == 'src' or name.startswith('src.') or name == 'scripts' or name.startswith('scripts.')
                 or name.partition('.')[0] in fence.HEAVY_ROOTS}
        try:
            for name in saved: del sys.modules[name]
            with fence.sealed_imports(core, {p: parent.sha(raw) for p, raw in core.items()}):
                old = parent.importlib.import_module('src.models.ranking_v5_real_artifact_store')
                with parent.supplemental_aliases(sources, fresh_cli, pins) as (reader, context, matrix_module, collector):
                    self.assertEqual(reader.LIMITS['freeze.json'], 16*1024**2)
                    self.assertIs(context.readback, reader)
                    self.assertIs(collector.reader, reader)
                    self.assertIs(collector.fit_context, context)
                    self.assertIs(sys.modules['src.models.ranking_v5_real_artifact_store'], old)
                    self.assertEqual(old.FREEZE_MAX_BYTES, 20480)
                    self.assertEqual(len(matrix_module.build_train_matrix(parent.ROOT)), 18)
                self.assertTrue(all(p[:-3].replace('/', '.') not in sys.modules for p in parent.EXTRA))
        finally:
            for name in list(sys.modules):
                if name == 'src' or name.startswith('src.') or name == 'scripts' or name.startswith('scripts.') \
                        or name.partition('.')[0] in fence.HEAVY_ROOTS:
                    del sys.modules[name]
            sys.modules.update(saved)
            restored = {name: module for name, module in sys.modules.items()
                        if name == 'src' or name.startswith('src.') or name == 'scripts' or name.startswith('scripts.')
                        or name.partition('.')[0] in fence.HEAVY_ROOTS}
            self.assertEqual(set(restored), set(saved))
            self.assertTrue(all(restored[name] is module for name, module in saved.items()))

    def test_synthetic_heavy_cache_is_restored_after_core_loader_test(self):
        import sys
        from types import ModuleType
        name = 'numpy._v3_non_ml_identity_fixture'
        fake = ModuleType(name)
        with patch.dict(sys.modules, {name: fake}):
            self.test_new_chain_loads_with_old_core_identity_and_cleans_all()
            self.assertIs(sys.modules[name], fake)


if __name__ == '__main__': unittest.main()
