"""Generated fixtures and mocked CPU APIs only: genuine approvals/Torch fits=0."""
import copy
import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.models import ranking_v5_single_fit_worker as worker
from src.models import ranking_v5_training_kernel as kernel
from src.models.ranking_v5_physical_worker import synthetic_request, _test_release
from src.models.runtime_ranking_v3 import digest


def fixture():
    sources = {name: 'a' * 64 for name in worker.boundary.REQUIRED_SOURCE_BINDINGS}
    release = _test_release(sources)
    release['user_authorization_id'] = 'opaque-unit-fixture-not-genuine-consent'
    auth = dict(schema='v5-explicit-authorization-evidence-v1',
                authorization_id=release['user_authorization_id'], scope=worker.approval.SCOPE,
                roles=['TRAIN'], planned_fits=18, seeds=list(worker.boundary.SEEDS),
                source_sha256=worker.boundary.SOURCE_SHA256,
                package_receipt_sha256=worker.boundary.PACKAGE_SHA256, retry_count=0)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    auth_raw = encode(auth)
    auth_sha = hashlib.sha256(auth_raw).hexdigest()
    release['user_authorization_sha256'] = auth_sha
    review = dict(schema='v5-independent-release-binding-review-v1',
                  status='PASS_V5_RELEASE_BINDING_REVIEW', scope=worker.approval.SCOPE,
                  authorization_sha256=auth_sha,
                  release_sha256=worker.approval.review_subject(release),
                  source_binding_sha256=digest(sources), physical_gate_sha256='b' * 64)
    review_raw = encode(review)
    review_sha = hashlib.sha256(review_raw).hexdigest()
    release['independent_review_receipt_sha256'] = review_sha
    request = synthetic_request()
    loaded = dict(status=worker.inputs.STATUS, request=request,
                  input_identity=dict(package_receipt_sha256=worker.boundary.PACKAGE_SHA256,
                                      source_sha256=worker.boundary.SOURCE_SHA256,
                                      fold_manifest_sha256='c' * 64,
                                      family=request['family'], seed=request['seed']))
    root = next(iter(worker.package_binding.PACKAGE_ROOT_ALLOWLIST))
    args = [root, request['family'], request['seed'], release, sources, auth_raw, review_raw]
    kwargs = dict(trusted_authorization_sha256=auth_sha, trusted_review_sha256=review_sha,
                  trusted_physical_gate_sha256='b' * 64)
    return args, kwargs, loaded


class Values:
    def __init__(self, values): self.values = values
    def detach(self): return self
    def cpu(self): return self
    def tolist(self): return self.values
    def __len__(self): return len(self.values)


class Model:
    def __call__(self, features): return Values([float(i) for i in range(len(features))])
    def state_dict(self): return {'unit': 1}
    def parameters(self): return []
    def train(self): pass
    def eval(self): pass


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = (Path(self.temp.name) / 'gnn_model_ranking_v5_train_unit').as_posix()
        self.args, self.kwargs, self.loaded = fixture()
        self.events = []
        self.torch = SimpleNamespace(float32='float32', no_grad=nullcontext,
            tensor=lambda features, **kwargs: features,
            set_num_threads=lambda value: None, get_num_threads=lambda: 1,
            set_num_interop_threads=lambda value: None, get_num_interop_threads=lambda: 1,
            save=lambda state, stream: stream.write(b'UNIT_FIXTURE_NOT_TORCH_CHECKPOINT'))
        self.kwargs.update(output=self.output, torch=self.torch, np=object())
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(worker.artifacts, 'PRODUCTION_PREFIX',
            (Path(self.temp.name) / 'gnn_model_ranking_v5_train_').as_posix()))
        self.check = stack.enter_context(patch.object(worker.resource_context, 'check_current_process',
            return_value=dict(status='UNIT_MOCK_NOT_LINUX_PROOF',
                              parent_sampled_rss_enforcement_proven=False)))
        self.load = stack.enter_context(patch.object(worker.inputs, 'load_bound_fold_request',
                                                   return_value=self.loaded))
        self.fit_original = worker.physical.fit_prepared
        self.fit = stack.enter_context(patch.object(worker.physical, 'fit_prepared', side_effect=self.fake_fit))
        self.held = stack.enter_context(patch.object(worker.held, 'load_frozen_held_outcomes',
                                                    side_effect=self.outcomes))

    def fake_fit(self, torch, np, prepared, recipe, seed, emit, request_sha):
        self.events.append('fit')
        self.assertIs(torch, self.torch)
        self.assertEqual(seed, self.args[2])
        held_uids = worker.boundary.prepare_request(self.loaded['request'])[0].heldout
        self.assertFalse(set(prepared['fit_uids']) & set(held_uids))
        self.assertNotIn('rows', prepared)
        scores = {uid: float(i) for i, uid in enumerate(prepared['fit_uids'])}
        for index in range(122):
            record = kernel.log_record(scores, recipe, prepared['pairs'], epoch=min(index, 120),
                phase='INITIAL' if index == 0 else ('FINAL' if index == 121 else 'EPOCH'),
                request_sha256=request_sha)
            emit(record)
        return Model()

    def outcomes(self, root, identity, fold, uids, sha, readback):
        self.events.append('held')
        self.assertEqual(readback, self.active_store.read_freeze(sha))
        self.assertTrue((Path(self.output) / 'model.pt').exists())
        return {uid: dict(execution_status='SUCCESS', is_d95_feasible=1,
                         total_cycles=100, policy_charged_runtime_s=2) for uid in uids}

    def run_worker(self):
        original = worker.artifacts.RealArtifactStore
        def create(output):
            self.active_store = original(output)
            return self.active_store
        with patch.object(worker.artifacts, 'RealArtifactStore', side_effect=create):
            return worker.execute_single_fit(*self.args, **self.kwargs)

    def test_complete_bounded_artifacts_and_no_authority_promotion(self):
        # Capture readback explicitly: do not rely on outcomes' mocked class reference.
        self.held.side_effect = lambda root, identity, fold, uids, sha, readback: {
            uid: dict(execution_status='SUCCESS', is_d95_feasible=1,
                      total_cycles=100, policy_charged_runtime_s=2) for uid in uids}
        result = self.run_worker()
        self.load.assert_called_once_with(*self.args[:3])
        self.assertEqual(self.fit.call_count, 1)
        self.assertEqual(self.check.call_count, 2)
        self.assertEqual(set(p.name for p in Path(self.output).iterdir()), worker.artifacts.ARTIFACTS)
        lines = (Path(self.output) / 'fitting.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), 122)
        self.assertTrue(all(json.loads(line)['canonical_request_sha256'] == digest(self.loaded['request']) for line in lines))
        self.assertFalse(any(row['action_uid'] in '\n'.join(lines) for row in self.loaded['request']['rows']))
        for key in ('authentic_user_consent_proven', 'full_source_file_binding_verified',
                    'parent_sampled_rss_enforcement_proven', 'physical_worker_limits_verified',
                    'formal_training_authorized_by_this_function', 'new_formal_18_fit_release'):
            self.assertIs(result[key], False)
        self.assertTrue(result['boundary_receipt']['held_labels_replayed'])
        stored = json.loads((Path(self.output) / 'worker_receipt.json').read_text())
        self.assertEqual(stored, result)

    def test_pre_io_rejections(self):
        for mode in ('test', 'synthetic', 'pin', 'root', 'family', 'seed', 'bool_seed', 'output'):
            args, kwargs, loaded = fixture()
            kwargs.update(output=self.output, torch=self.torch, np=object())
            if mode in ('test', 'synthetic'): args[3]['user_authorization_id'] = mode.upper() + '_ONLY'
            elif mode == 'pin': kwargs['trusted_review_sha256'] = 'e' * 64
            elif mode == 'root': args[0] = '/not-allowed'
            elif mode == 'family': args[1] = 'wrong'
            elif mode == 'seed': args[2] += 9
            elif mode == 'bool_seed': args[2] = True
            else: kwargs['output'] = '/ssd/cjc/multimode_ate_gnn_v1/no-write'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                worker.execute_single_fit(*args, **kwargs)
        self.load.assert_not_called(); self.fit.assert_not_called(); self.held.assert_not_called()
        self.assertFalse(Path(self.output).exists())

    def test_process_check_before_loader(self):
        self.check.side_effect = ValueError('not-guarded')
        with self.assertRaisesRegex(ValueError, 'not-guarded'): self.run_worker()
        self.load.assert_not_called(); self.fit.assert_not_called()
        self.assertFalse(Path(self.output).exists())

    def test_second_process_check_before_output_and_fit(self):
        self.check.side_effect = [{}, ValueError('changed-process')]
        with self.assertRaisesRegex(ValueError, 'changed-process'): self.run_worker()
        self.load.assert_called_once(); self.fit.assert_not_called(); self.held.assert_not_called()
        self.assertFalse(Path(self.output).exists())

    def test_torch_threads_fail_before_output_or_fit(self):
        self.torch.get_num_threads = lambda: 2
        with self.assertRaisesRegex(ValueError, 'TORCH_THREADS'): self.run_worker()
        self.fit.assert_not_called(); self.held.assert_not_called()
        self.assertFalse(Path(self.output).exists())

    def test_reuses_actual_fixed_loop_with_only_mock_tensors(self):
        # Execute existing physical.fit_prepared, not real Torch or real labels.
        optimizer_calls, seed_calls = [], []
        class Optimizer:
            def zero_grad(self): optimizer_calls.append('zero')
            def step(self): optimizer_calls.append('step')
        self.torch.optim = SimpleNamespace(Adam=lambda params, **kwargs: Optimizer())
        model = Model()
        self.fit.side_effect = None
        from src.models import runtime_training_v2
        physical_fit = self.fit_original
        self.fit.side_effect = physical_fit
        with patch.object(worker.physical, 'make_candidate_ranker', return_value=model), \
             patch.object(runtime_training_v2, 'seed_everything',
                          side_effect=lambda seed, torch, np: seed_calls.append(seed)), \
             patch.object(kernel, 'torch_loss', return_value=SimpleNamespace(backward=lambda: None)):
            result = self.run_worker()
        self.assertEqual(optimizer_calls.count('step'), 120)
        self.assertEqual(optimizer_calls.count('zero'), 120)
        self.assertEqual(seed_calls, [self.args[2]])
        self.assertEqual(len((Path(self.output) / 'fitting.jsonl').read_text().splitlines()), 122)
        self.assertFalse(result['new_formal_18_fit_release'])

    def test_input_identity_and_invalid_request_before_output(self):
        for field, value in [('source_sha256', 'e' * 64), ('family', 'wrong'), ('seed', 1.0),
                             ('fold_manifest_sha256', 'invalid')]:
            loaded = copy.deepcopy(self.loaded); loaded['input_identity'][field] = value
            self.load.return_value = loaded
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'INPUT_IDENTITY'):
                self.run_worker()
        self.load.return_value = copy.deepcopy(self.loaded)
        self.load.return_value['request']['fit_cycles'] = {}
        with self.assertRaises(ValueError): self.run_worker()
        self.fit.assert_not_called(); self.held.assert_not_called()
        self.assertFalse(Path(self.output).exists())

    def test_fit_failure_preserves_directory_and_refuses_retry(self):
        self.fit.side_effect = RuntimeError('fit-failed')
        with self.assertRaisesRegex(RuntimeError, 'fit-failed'): self.run_worker()
        self.assertTrue(Path(self.output).is_dir()); self.held.assert_not_called()
        self.fit.side_effect = self.fake_fit
        with self.assertRaises(FileExistsError): self.run_worker()
        self.assertEqual(self.fit.call_count, 1)

    def test_model_serialization_bound_preserves_logs_no_held(self):
        self.torch.save = lambda state, stream: stream.seek(worker.artifacts.MODEL_MAX_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'MODEL_BOUND'): self.run_worker()
        self.assertTrue((Path(self.output) / 'fitting.jsonl').is_file())
        self.assertFalse((Path(self.output) / 'model.pt').exists()); self.held.assert_not_called()

    def test_total_log_cap_before_model_or_held(self):
        with patch.object(worker.artifacts, 'LOG_MAX_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'LOG_BOUND'): self.run_worker()
        self.assertEqual(list(Path(self.output).iterdir()), [])
        self.held.assert_not_called()

    def test_model_ack_failure_preserves_partial_and_blocks_held(self):
        with patch.object(worker.artifacts.RealArtifactStore, 'ack_model', return_value='e' * 64):
            with self.assertRaisesRegex(ValueError, 'MODEL_ACK'): self.run_worker()
        self.assertEqual(set(p.name for p in Path(self.output).iterdir()), {'model.pt', 'fitting.jsonl'})
        self.held.assert_not_called()

    def test_freeze_failure_preserves_model_logs_blocks_held(self):
        with patch.object(worker.artifacts.RealArtifactStore, 'persist_freeze', side_effect=ValueError('freeze-fail')):
            with self.assertRaisesRegex(ValueError, 'freeze-fail'): self.run_worker()
        self.assertEqual(set(p.name for p in Path(self.output).iterdir()), {'model.pt', 'fitting.jsonl'})
        self.held.assert_not_called()

    def test_external_mutation_during_fit_does_not_change_bound_snapshot(self):
        expected_identity = copy.deepcopy(self.loaded['input_identity'])
        expected_sha = digest(self.loaded['request'])
        def mutated_fit(*args):
            result = self.fake_fit(*args)
            self.args[3]['user_authorization_id'] = 'mutated'
            self.args[4].clear()
            self.loaded['input_identity']['fold_manifest_sha256'] = 'e' * 64
            self.loaded['request']['fit_cycles'].clear()
            return result
        self.fit.side_effect = mutated_fit
        result = self.run_worker()
        self.assertEqual(result['input_identity'], expected_identity)
        self.assertEqual(result['boundary_receipt']['canonical_request_sha256'], expected_sha)
        self.assertEqual(self.held.call_args.args[1], expected_identity)

    def test_log_caps_and_injected_uid_rejected(self):
        for mode in ('record', 'uid', 'count', 'short', 'sha', 'stage'):
            self.kwargs['output'] = self.output + '_' + mode
            def bad(torch, np, prepared, recipe, seed, emit, sha):
                scores = {uid: 0. for uid in prepared['fit_uids']}
                record = kernel.log_record(scores, recipe, prepared['pairs'], epoch=0,
                                           phase='INITIAL', request_sha256=sha)
                if mode == 'record': record['extra'] = 'x' * 2049
                if mode == 'uid': record['action_uid'] = prepared['fit_uids'][0]
                if mode == 'sha': record['canonical_request_sha256'] = 'e' * 64
                if mode == 'stage': record['epoch'] = 1
                if mode == 'count':
                    for index in range(123):
                        emit(kernel.log_record(scores, recipe, prepared['pairs'], epoch=min(index, 120),
                            phase='INITIAL' if index == 0 else ('FINAL' if index >= 121 else 'EPOCH'),
                            request_sha256=sha))
                else: emit(record)
                return Model()
            self.fit.side_effect = bad
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.run_worker()
        self.held.assert_not_called()

    def test_freeze_reread_before_held_and_bad_reread_blocks(self):
        original = worker.artifacts.RealArtifactStore.read_freeze
        events = []
        def reread(store, sha):
            events.append('reread')
            return original(store, sha)
        def held(root, identity, fold, uids, sha, proof):
            events.append('held')
            self.assertEqual(proof, original(self.active_store, sha))
            return {uid: dict(execution_status='SUCCESS', is_d95_feasible=1,
                             total_cycles=100, policy_charged_runtime_s=2) for uid in uids}
        self.held.side_effect = held
        with patch.object(worker.artifacts.RealArtifactStore, 'read_freeze', reread): self.run_worker()
        self.assertEqual(events, ['reread', 'reread', 'held'])
        self.kwargs['output'] = self.output + '_bad'
        self.held.reset_mock()
        calls = []
        def changed(store, sha):
            calls.append(sha)
            return original(store, sha) if len(calls) == 1 else ({'changed': True}, sha)
        with patch.object(worker.artifacts.RealArtifactStore, 'read_freeze', changed):
            with self.assertRaisesRegex(ValueError, 'FREEZE_REREAD'): self.run_worker()
        self.held.assert_not_called()

    def test_serialization_and_prediction_failures_block_held(self):
        for mode in ('empty', 'predict'):
            self.kwargs['output'] = self.output + '_' + mode
            if mode == 'empty': self.torch.save = lambda state, stream: None
            else:
                self.torch.save = lambda state, stream: stream.write(b'unit')
                self.torch.tensor = lambda *args, **kwargs: []
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.run_worker()
        self.held.assert_not_called()


class BufferTests(unittest.TestCase):
    def test_initial_data_restore_and_writelines_cannot_bypass_cap(self):
        with self.assertRaises(TypeError):
            worker.BoundedModelBuffer(b'x' * (worker.artifacts.MODEL_MAX_BYTES + 1))
        with worker.BoundedModelBuffer() as buffer:
            with self.assertRaisesRegex(ValueError, 'MODEL_RESTORE_UNSUPPORTED'):
                buffer.__setstate__((b'x', 0, {}))
            self.assertEqual(buffer.getvalue(), b'')
            with self.assertRaisesRegex(ValueError, 'MODEL_BOUND'):
                buffer.writelines([b'unit', b'x' * worker.artifacts.MODEL_MAX_BYTES])
            self.assertEqual(buffer.getvalue(), b'unit')

    def test_write_seek_truncate_fail_before_growth(self):
        cap = worker.artifacts.MODEL_MAX_BYTES
        with worker.BoundedModelBuffer() as buffer:
            for action in (lambda: buffer.write(b'x' * (cap + 1)),
                           lambda: buffer.seek(cap + 1), lambda: buffer.seek(cap + 1, 1),
                           lambda: buffer.seek(cap + 1, 2), lambda: buffer.truncate(cap + 1)):
                with self.assertRaisesRegex(ValueError, 'MODEL_BOUND'): action()
                self.assertEqual(buffer.getvalue(), b'')
            buffer.seek(cap); buffer.write(b'')
            with self.assertRaisesRegex(ValueError, 'MODEL_BOUND'): buffer.write(b'x')
            self.assertEqual(buffer.getvalue(), b'')
            buffer.seek(0); buffer.write(b'unit'); buffer.seek(-2, 2); buffer.write(b'OK')
            self.assertEqual(buffer.getvalue(), b'unOK')


if __name__ == '__main__': unittest.main()
