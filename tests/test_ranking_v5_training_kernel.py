import copy
import json
import unittest
from unittest.mock import patch

from src.models import ranking_v5_training_kernel as kernel
from src.models.runtime_ranking_v3 import plan_folds
from tests.test_runtime_ranking_v3 import fixture
from tests.test_ranking_v4_training_worker import request_for


class KernelTests(unittest.TestCase):
    def setUp(self):
        rows, outcomes = fixture()
        self.fold = plan_folds(rows)[0]
        self.request = request_for(rows, outcomes, self.fold)
        self.request['scope'] = kernel.SCOPE

    def test_scope_rejected_before_tensor_or_fit(self):
        for scope in ('RANKING_V4_SYNTHETIC_ONLY', 'REAL', None):
            with self.assertRaises(ValueError):
                kernel.fit_synthetic(None, None, dict(self.request, scope=scope), print)

    def test_exact_fitting_join_and_held_feature_invariance(self):
        prepared, recipe = kernel.prepare(self.request)
        changed = copy.deepcopy(self.request)
        for row in changed['rows']:
            if row['action_uid'] in self.fold.heldout:
                row['scheme_hf'] = 999.
        self.assertEqual((prepared, recipe), kernel.prepare(changed))
        self.assertEqual(set(self.fold.fitting), set(prepared['fit_uids']))
        self.assertNotIn(self.fold.family, recipe['families'])
        changed['fit_cycles'][self.fold.heldout[0]] = 100
        with self.assertRaises(ValueError): kernel.prepare(changed)

    def test_reject_extra_labels_and_invalid_cycle(self):
        for bad in (dict(self.request, held_cycles={}),
                    dict(self.request, fit_cycles=dict(self.request['fit_cycles'],
                         **{self.fold.fitting[0]: True}))):
            with self.assertRaises(ValueError): kernel.prepare(bad)

    def test_aggregate_log_pair_reference_and_no_raw_vectors(self):
        prepared, recipe = kernel.prepare(self.request)
        scores = {uid: 0. for uid in prepared['fit_uids']}
        record = kernel.log_record(scores, recipe, prepared['pairs'], epoch=0,
                                   phase='INITIAL', request_sha256='a'*64)
        import math
        self.assertAlmostEqual(math.log(2), record['macro_pair_softplus_reference'])
        self.assertEqual(0., record['macro_head_loss'])
        payload = json.dumps(record, allow_nan=False)
        for uid in scores: self.assertNotIn(uid, payload)
        self.assertLess(len(payload), 20000)
        self.assertEqual(record, kernel.log_record(scores, recipe, prepared['pairs'],
                         epoch=0, phase='INITIAL', request_sha256='a'*64))

    def test_stage_and_pair_tampering_fail_closed(self):
        prepared, recipe = kernel.prepare(self.request)
        scores = {uid: 0. for uid in prepared['fit_uids']}
        for epoch, phase in ((1,'INITIAL'), (0,'EPOCH'), (121,'EPOCH'), (119,'FINAL')):
            with self.assertRaises(ValueError):
                kernel.log_record(scores, recipe, prepared['pairs'], epoch=epoch,
                                  phase=phase, request_sha256='a'*64)
        pairs = copy.deepcopy(prepared['pairs'])
        family = next(iter(pairs)); pairs[family] = pairs[family][1:]
        with self.assertRaises(ValueError):
            kernel.log_record(scores, recipe, pairs, epoch=0, phase='INITIAL', request_sha256='a'*64)

    def test_mock_loop_has_fixed_optimizer_epochs_and_fitting_only_logs(self):
        from contextlib import nullcontext
        prepared, _ = kernel.prepare(self.request)
        calls = {'step': 0, 'backward': 0, 'forward': 0}
        class Scores:
            def detach(self): return self
            def cpu(self): return self
            def tolist(self): return [0.] * len(prepared['fit_uids'])
        class Model:
            def train(self): pass
            def eval(self): pass
            def parameters(self): return ('parameters',)
            def __call__(self, matrix):
                self_outer.assertEqual(prepared['fit_features'], matrix)
                calls['forward'] += 1
                return Scores()
        class Optimizer:
            def zero_grad(self): pass
            def step(self): calls['step'] += 1
        class Loss:
            def backward(self): calls['backward'] += 1
        class Torch:
            float32 = 'float32'
            def tensor(self, matrix, **kwargs):
                self_outer.assertEqual({'dtype': 'float32', 'device': 'cpu'}, kwargs)
                return matrix
            def no_grad(self): return nullcontext()
        self_outer = self
        torch = Torch()
        from types import SimpleNamespace
        adam_calls = []
        def adam(parameters, **kwargs):
            adam_calls.append((parameters, kwargs)); return Optimizer()
        torch.optim = SimpleNamespace(Adam=adam)
        logs = []
        with patch('src.models.runtime_training_v2.seed_everything') as seed, \
             patch.object(kernel, 'make_candidate_ranker', return_value=Model()), \
             patch.object(kernel, 'torch_loss', return_value=Loss()) as head:
            kernel.fit_synthetic(torch, None, self.request, logs.append)
        seed.assert_called_once_with(20260824, torch, None)
        self.assertEqual(120, head.call_count)
        self.assertEqual(120, calls['step']); self.assertEqual(120, calls['backward'])
        self.assertEqual([( ('parameters',), {'lr': .001, 'weight_decay': .0001})], adam_calls)
        self.assertEqual(122, len(logs))
        self.assertEqual(('INITIAL', 0), (logs[0]['phase'], logs[0]['epoch']))
        self.assertEqual(list(range(1,121)), [row['epoch'] for row in logs[1:-1]])
        self.assertEqual(('FINAL',120), (logs[-1]['phase'], logs[-1]['epoch']))
        self.assertEqual(1, len({row['canonical_request_sha256'] for row in logs}))


if __name__ == '__main__': unittest.main()
