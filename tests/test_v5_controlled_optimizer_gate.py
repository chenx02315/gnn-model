import builtins
from contextlib import contextmanager
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import run_v5_controlled_optimizer_gate as gate
from scripts import run_v5_controlled_runtime_gate as transport
from src.models import ranking_v5_training_kernel as kernel
from src.models import runtime_ranking_v3 as runtime


class OptimizerGateTests(unittest.TestCase):
    root = '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1'

    def pins(self):
        return {name: 'a'*64 for name in (gate.PROGRAM, gate.TRANSPORT, gate.OBS, gate.CONTEXT, gate.AUTH)}

    def records(self):
        request = gate.request_for(runtime, kernel)
        prepared, recipe = kernel.prepare(request)
        scores = {uid: 0.0 for uid in prepared['fit_uids']}
        return [kernel.log_record(scores, recipe, prepared['pairs'], epoch=epoch,
                    phase=phase, request_sha256=runtime.digest(request))
                for epoch, phase in [(0, 'INITIAL')] + [(i, 'EPOCH') for i in range(1, 121)] + [(120, 'FINAL')]]

    def worker(self):
        site = gate.SEARCH_PATHS[-1] + '/'
        return dict(status=gate.CHILD_STATUS, supplemental_sha256=self.pins(), core_manifest_sha256=gate.CORE_SHA,
            authorization_raw_sha256='a'*64, authentic_user_consent_proven=False,
            torch_version='2.5.1+cu124', numpy_version='2.1.3', torch_origin=site+'torch/__init__.py',
            numpy_origin=site+'numpy/__init__.py', threads=1, interop_threads=1, cuda_available=False,
            child_prerequisites=dict(status='PASS_CHILD_PREREQUISITES_ONLY', address_space_limits=[8*1024**3]*2,
                core_limits=[0, 0], threads=1, parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False),
            synthetic_optimizer_fits=1, optimizer_steps=120, fitting_log_records=122, actual_formal_fits=0,
            production_package_reads=0, held_label_reads=0, formal_training_release=False, automatic_retries=0,
            request_sha256=gate.SYNTHETIC_REQUEST_SHA, model_sha256='b'*64, fitting_log_sha256='b'*64,
            model_bytes=100, fitting_log_bytes=1000, initial_head_loss=1., final_head_loss=.1,
            initial_pair_reference=1., final_pair_reference=.1)

    @contextmanager
    def controlled(self, *args, **kwargs):
        yield

    def test_minimal_synthetic_request_has_no_held_labels(self):
        request = gate.request_for(runtime, kernel)
        prepared, recipe = kernel.prepare(request)
        self.assertEqual(len(request['rows']), 72)
        self.assertEqual(len(prepared['fit_uids']), 60)
        self.assertEqual(len(recipe['families']), 5)
        self.assertEqual(request['scope'], kernel.SCOPE)
        held = {r['action_uid'] for r in request['rows'] if r['family'] == request['family']}
        self.assertFalse(held & request['fit_cycles'].keys())

    def test_logs_exact_120_steps_and_finite(self):
        rows = self.records()
        request_sha = runtime.digest(gate.request_for(runtime, kernel))
        self.assertEqual(gate.expected_bindings(runtime, kernel), (gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA))
        self.assertEqual(len(gate.log_bytes(rows, request_sha, gate.SYNTHETIC_RECIPE_SHA).splitlines()), 122)
        for kind in ('missing', 'epoch_bool', 'nonfinite', 'bad_request', 'wrong_phase'):
            changed = copy.deepcopy(rows)
            if kind == 'missing': changed.pop()
            if kind == 'epoch_bool': changed[1]['epoch'] = True
            if kind == 'nonfinite': changed[2]['families'][0]['head_softplus'] = float('inf')
            if kind == 'bad_request': changed[1]['canonical_request_sha256'] = 'c'*64
            if kind == 'wrong_phase': changed[1]['phase'] = 'FINAL'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.log_bytes(changed, request_sha, gate.SYNTHETIC_RECIPE_SHA)

    def test_strict_worker_receipt(self):
        gate.validate_child(self.worker(), self.pins())
        changes = [('optimizer_steps', True), ('fitting_log_records', 121), ('model_bytes', True),
            ('final_head_loss', float('nan')), ('final_pair_reference', float('inf')),
            ('held_label_reads', 1), ('actual_formal_fits', 1), ('authentic_user_consent_proven', True),
            ('authorization_raw_sha256', 'b'*64), ('request_sha256', 'b'*64),
            ('formal_training_release', True), ('extra', False)]
        for key, value in changes:
            worker = self.worker(); worker[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate_child(worker, self.pins())
        worker = self.worker(); worker['child_prerequisites']['core_limits'] = [False, False]
        with self.assertRaises(ValueError): gate.validate_child(worker, self.pins())

    def test_coherently_rebound_log_request_and_recipe_refuse(self):
        for key, value in [('canonical_request_sha256', 'c'*64), ('recipe_sha256', 'd'*64)]:
            rows = self.records()
            for row in rows: row[key] = value
            for expected_request, expected_recipe in ((gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA),
                    (value if key == 'canonical_request_sha256' else gate.SYNTHETIC_REQUEST_SHA,
                     value if key == 'recipe_sha256' else gate.SYNTHETIC_RECIPE_SHA)):
                with self.subTest(key=key, caller_rebound=expected_request+expected_recipe), self.assertRaises(ValueError):
                    gate.log_bytes(rows, expected_request, expected_recipe)
        with self.assertRaises(TypeError): gate.log_bytes(self.records(), gate.SYNTHETIC_REQUEST_SHA)
        rows = self.records(); rows[60]['recipe_sha256'] = 'd'*64
        with self.assertRaises(ValueError):
            gate.log_bytes(rows, gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA)

    def test_independent_fixture_rebuild_refuses_changed_request_without_ml(self):
        request = gate.request_for(runtime, kernel)
        request['fit_cycles'][next(iter(request['fit_cycles']))] += 1
        with mock.patch.object(gate, 'request_for', return_value=request):
            with self.assertRaisesRegex(ValueError, 'FIXTURE_BINDING'):
                gate.expected_bindings(runtime, kernel)

    def test_family_exact_fields_strict_types_and_derived_metrics(self):
        base = self.records()
        family = base[45]['families'][0]
        for key in family:
            rows = copy.deepcopy(base); del rows[45]['families'][0][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                gate.log_bytes(rows, gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA)
        for key, value in [('extra', 1), ('first_positive_rank', True), ('hit_at_10', False),
                ('negatives_before_first_positive', 2), ('first_positive_rank', 0),
                ('top10_cycle_regret', -1.), ('top10_cycle_regret', 1.),
                ('head_gap', None), ('head_softplus', -1.), ('head_softplus', 100.),
                ('pair_softplus_reference', -1.), ('pair_softplus_reference', 1),
                ('guaranteed_hit_by_size', True), ('strict_score_hit_certificate', True),
                ('tie_at_boundary', False)]:
            rows = copy.deepcopy(base); rows[45]['families'][0][key] = value
            with self.subTest(corrupt=key), self.assertRaises(ValueError):
                gate.log_bytes(rows, gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA)
        for key in ('macro_head_loss', 'macro_pair_softplus_reference'):
            rows = copy.deepcopy(base); rows[45][key] += 1.
            with self.subTest(macro=key), self.assertRaises(ValueError):
                gate.log_bytes(rows, gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA)
        rows = copy.deepcopy(base)
        rows[45]['families'][0] = {k: family[k] for k in ('family', 'actions', 'positive_count', 'negative_count')}
        with self.assertRaises(ValueError):
            gate.log_bytes(rows, gate.SYNTHETIC_REQUEST_SHA, gate.SYNTHETIC_RECIPE_SHA)

    def test_bootstrap_isolated_new_root_only(self):
        code = gate.bootstrap(self.root, 'a'*64)
        compile(code, '<test>', 'exec')
        self.assertIn(repr(list(gate.SEARCH_PATHS)), code)
        self.assertIn('sys.flags.no_site==1 and sys.flags.isolated==1', code)
        for root in ('/ssd/cjc/gnn_model_ranking_v5_runtime_gate_20261010_r1', self.root+'/../x', '/tmp/x'):
            with self.assertRaises(ValueError): gate.bootstrap(root, 'a'*64)

    def test_runtime_refuses_before_any_io(self):
        with mock.patch.object(gate.sys, 'platform', 'win32'), mock.patch.object(gate, 'read') as read:
            with self.assertRaises(ValueError): gate.load(self.root, self.pins())
            read.assert_not_called()
        with mock.patch.object(gate.sys, 'platform', 'win32'), mock.patch.object(gate, 'global_worker_lock') as lock:
            with self.assertRaises(ValueError): gate.parent(self.root, self.pins())
            lock.assert_not_called()

    def test_parent_holds_common_lock_for_entire_workflow(self):
        events = []
        @contextmanager
        def locked():
            events.append('lock')
            yield
            events.append('unlock')
        with mock.patch.object(gate, 'preconditions', side_effect=lambda *a: events.append('preconditions')), \
                mock.patch.object(gate, 'global_worker_lock', side_effect=locked), \
                mock.patch.object(gate, 'parent_locked', side_effect=lambda *a: events.append('workflow')):
            gate.parent(self.root, self.pins())
        self.assertEqual(events, ['preconditions', 'lock', 'workflow', 'unlock'])
        self.assertEqual(gate.GLOBAL_LOCK, '/ssd/cjc/gnn_model_ranking_v5_serial_parent.lock')

    def test_transport_sha_refuses_before_compile(self):
        with mock.patch.object(gate, 'preconditions'), mock.patch.object(gate, 'read', return_value=b'pass'), \
                mock.patch.object(gate, 'external') as external:
            with self.assertRaisesRegex(ValueError, 'TRANSPORT_SHA'): gate.load(self.root, self.pins())
            external.assert_not_called()

    def test_bounded_model_buffer_and_create_once_readback(self):
        buffer = gate.BoundedBuffer()
        buffer.write(b'x'*gate.MODEL_CAP)
        with self.assertRaises(ValueError): buffer.write(b'x')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'model.pt'
            self.assertEqual(gate.persist(path, b'model', gate.MODEL_CAP), gate.sha(b'model'))
            with self.assertRaises(FileExistsError): gate.persist(path, b'model', gate.MODEL_CAP)

    def test_global_one_use_preserved_after_second_attempt(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(gate, 'ONCE_PREFIX', str(Path(tmp)/'authorization_')):
            gate.claim_once(tmp, self.pins(), transport)
            gate.verify_started(tmp, self.pins(), transport)
            with self.assertRaises(FileExistsError): gate.claim_once(tmp, self.pins(), transport)
            self.assertTrue((Path(tmp)/gate.STARTED).exists())
            changed = self.pins(); changed[gate.AUTH] = 'b'*64
            with self.assertRaises((ValueError, FileNotFoundError)): gate.verify_started(tmp, changed, transport)

    def test_child_resource_gate_precedes_ml(self):
        from src.models import ranking_v5_worker_resource_context as resource
        events = []
        original = builtins.__import__
        def watched(name, *args, **kwargs):
            if name in ('torch', 'numpy'): events.append(name)
            return original(name, *args, **kwargs)
        loaded = (transport, (object(), {gate.OBS: b'pass', gate.CONTEXT: b'pass'},
                  {'requirements/runtime_v2.lock.txt': b'lock'}, {}, {}))
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(gate, 'verify_started'), \
                mock.patch.object(transport, 'write'), \
                mock.patch.object(gate, 'external', side_effect=[object(), SimpleNamespace(controlled_imports=self.controlled)]), \
                mock.patch.object(resource, 'check_current_process', side_effect=ValueError('resource')), \
                mock.patch.object(builtins, '__import__', side_effect=watched):
            with self.assertRaises(ValueError): gate.child(self.root, self.pins())
        self.assertEqual(events, [])

    def test_parent_failure_keeps_marker_no_success_receipt(self):
        from src.models import ranking_v4_memory_guard as guard
        loaded = (transport, (SimpleNamespace(sealed_imports=self.controlled), {}, {}, {}, {}))
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(Path, 'exists', return_value=False), \
                mock.patch.object(Path, 'is_symlink', return_value=False), mock.patch.object(gate, 'claim_once') as claim, \
                mock.patch.object(guard, 'run_bounded', side_effect=RuntimeError('STOP')), \
                mock.patch.object(gate, 'read') as read, mock.patch.object(transport, 'write') as write:
            with self.assertRaises(RuntimeError): gate.parent_locked(self.root, self.pins())
            claim.assert_called_once(); read.assert_not_called(); write.assert_not_called()

    def test_child_mocked_kernel_fit_save_readback(self):
        from src.models import ranking_v5_worker_resource_context as resource
        rows = self.records()
        loaded = (transport, (object(), {gate.OBS: b'pass', gate.CONTEXT: b'pass'},
                    {'requirements/runtime_v2.lock.txt': b'lock'}, {}, {}))
        torch = SimpleNamespace(__version__='2.5.1+cu124', __file__=self.worker()['torch_origin'],
            set_num_threads=lambda n: None, set_num_interop_threads=lambda n: None,
            get_num_threads=lambda: 1, get_num_interop_threads=lambda: 1,
            cuda=SimpleNamespace(is_available=lambda: False),
            save=lambda state, buffer: buffer.write(b'model'))
        numpy = SimpleNamespace(__version__='2.1.3', __file__=self.worker()['numpy_origin'])
        def fit(actual_torch, actual_numpy, request, emit):
            self.assertIs(actual_torch, torch); self.assertIs(actual_numpy, numpy)
            self.assertEqual(request, gate.request_for(runtime, kernel))
            for row in rows: emit(row)
            return SimpleNamespace(state_dict=lambda: {'synthetic': True})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(gate, 'load', return_value=loaded), \
                mock.patch.object(gate, 'verify_started'), \
                mock.patch.object(gate, 'external', side_effect=[object(), SimpleNamespace(controlled_imports=self.controlled)]), \
                mock.patch.object(resource, 'check_current_process', return_value=self.worker()['child_prerequisites']), \
                mock.patch.dict('sys.modules', {'torch': torch, 'numpy': numpy}), \
                mock.patch.object(kernel, 'fit_synthetic', side_effect=fit) as fitted:
            result = gate.child(tmp, self.pins())
            fitted.assert_called_once()
            self.assertEqual(result['optimizer_steps'], 120)
            self.assertEqual(result['fitting_log_records'], 122)
            self.assertEqual(result['model_sha256'], gate.sha((Path(tmp)/gate.MODEL).read_bytes()))
            self.assertEqual(len((Path(tmp)/gate.FITTING).read_bytes().splitlines()), 122)
            self.assertTrue((Path(tmp)/gate.CHILD).exists())
            with self.assertRaises(FileExistsError): gate.child(tmp, self.pins())
            fitted.assert_called_once()  # replay refuses before optimizer

    def test_parent_success_validates_reread_and_distutils_env(self):
        from src.models import ranking_v4_memory_guard as guard
        from src.models import ranking_v5_parent_guard_receipt as receipt
        worker = self.worker()
        rows = self.records()
        worker['request_sha256'] = runtime.digest(gate.request_for(runtime, kernel))
        fitting = gate.log_bytes(rows, worker['request_sha256'], gate.SYNTHETIC_RECIPE_SHA)
        worker.update(model_sha256=gate.sha(b'model'), model_bytes=5,
            fitting_log_sha256=gate.sha(fitting), fitting_log_bytes=len(fitting),
            initial_head_loss=rows[0]['macro_head_loss'], final_head_loss=rows[-1]['macro_head_loss'],
            initial_pair_reference=rows[0]['macro_pair_softplus_reference'],
            final_pair_reference=rows[-1]['macro_pair_softplus_reference'])
        memory = dict(status='PASS_BOUNDED_WORKER', memory_policy=guard.policy(),
            initial_available_bytes=60*1024**3, effective_total_bytes=64*1024**3,
            reserve_bytes=6871947674, sample_count=1, peak_group_rss_bytes=123,
            peak_combined_rss_bytes=456, exit_code=0, process_group=9, elapsed_seconds=.5)
        def bounded(argv, log_path, env):
            self.assertEqual(env['SETUPTOOLS_USE_DISTUTILS'], 'stdlib')
            self.assertEqual(argv[:5], [gate.INTERPRETER, '-I', '-S', '-B', '-c'])
            return memory
        data = {gate.LOG+'.memory.json': json.dumps(memory).encode(),
                gate.CHILD: json.dumps(worker, sort_keys=True, allow_nan=False).encode(),
                gate.MODEL: b'model', gate.FITTING: fitting}
        loaded = (transport, (SimpleNamespace(sealed_imports=self.controlled), {}, {}, {}, {}))
        with mock.patch.object(gate, 'load', return_value=loaded), mock.patch.object(Path, 'exists', return_value=False), \
                mock.patch.object(Path, 'is_symlink', return_value=False), mock.patch.object(gate, 'claim_once'), \
                mock.patch.object(guard, 'run_bounded', side_effect=bounded), \
                mock.patch.object(gate, 'read', side_effect=lambda p, cap: data[Path(p).name]), \
                mock.patch.object(transport, 'write') as write:
            result = gate.parent_locked(self.root, self.pins())
            for key in ('canonical_request_sha256', 'recipe_sha256'):
                forged_rows = copy.deepcopy(rows)
                for row in forged_rows: row[key] = 'd'*64
                forged_fitting = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':'),
                    allow_nan=False)+'\n').encode() for row in forged_rows)
                forged_worker = copy.deepcopy(worker)
                forged_worker.update(fitting_log_sha256=gate.sha(forged_fitting), fitting_log_bytes=len(forged_fitting))
                if key == 'canonical_request_sha256': forged_worker['request_sha256'] = 'd'*64
                data[gate.FITTING] = forged_fitting
                data[gate.CHILD] = json.dumps(forged_worker, sort_keys=True, allow_nan=False).encode()
                with self.subTest(forged=key), self.assertRaises(ValueError):
                    gate.parent_locked(self.root, self.pins())
        self.assertEqual(result['status'], gate.FINAL_STATUS)
        write.assert_called_once()
        gate.validate_final(result, self.pins(), transport, receipt)
        for key, value in [('worker_count', True), ('automatic_retries', False), ('actual_linux_resource_proof', 1),
                            ('child_receipt_sha256', 'c'*64), ('formal_training_release', True), ('extra', False)]:
            changed = copy.deepcopy(result); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate_final(changed, self.pins(), transport, receipt)
        changed = copy.deepcopy(result)
        changed['child_receipt']['request_sha256'] = 'd'*64
        changed['child_receipt_sha256'] = gate.sha(json.dumps(changed['child_receipt'], sort_keys=True, allow_nan=False).encode())
        with self.assertRaisesRegex(ValueError, 'CHILD_REQUEST_BINDING'):
            gate.validate_final(changed, self.pins(), transport, receipt)


if __name__ == '__main__':
    unittest.main()
