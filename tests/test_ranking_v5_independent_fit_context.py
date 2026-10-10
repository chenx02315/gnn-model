"""Entirely generated candidate evidence: no real package, files or ML fit."""
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.test_ranking_v5_single_fit_worker import fixture
from src.models import ranking_v5_independent_fit_context as binding
from src.models import ranking_v5_train_artifact_readback as reader
from src.models.ranking_v5_training_kernel import log_record
from src.models.runtime_ranking_v3 import digest, freeze_ranking


def encode(value):
    return reader._canonical(value)+b'\n'


class IndependentFitContextTests(unittest.TestCase):
    def setUp(self):
        self.args, self.kwargs, self.loaded = fixture()
        self.context = self.build()
        request = self.loaded['request']
        fold, prepared, _, recipe = binding.boundary.prepare_request(request)
        payload, sha = freeze_ranking({uid: float(i) for i, uid in enumerate(fold.heldout)}, fold)
        self.freeze = dict(payload=payload, sha256=sha)
        scores = {uid: float(i) for i, uid in enumerate(prepared['fit_uids'])}
        self.logs = [log_record(scores, recipe, prepared['pairs'], epoch=min(i, 120),
            phase='INITIAL' if i == 0 else 'FINAL' if i == 121 else 'EPOCH',
            request_sha256=digest(request)) for i in range(122)]
        self.model_raw = b'PURE_SYNTHETIC_NOT_CHECKPOINT'
        model_sha = hashlib.sha256(self.model_raw).hexdigest()
        self.receipt = dict(status='PASS_SINGLE_FIT_CALLBACK_ADAPTER_ONLY',
            caller_must_use_existing_resource_guard=True,
            input_identity=deepcopy(self.loaded['input_identity']),
            approval_integrity=binding.approval.validate_approval_integrity(
                self.args[3], self.args[4], self.args[5], self.args[6], **self.kwargs),
            observed_process_preconditions=dict(status='PASS_CHILD_PREREQUISITES_ONLY',
                address_space_limits=[8*1024**3]*2, core_limits=[0, 0], threads=1,
                parent_sampled_rss_enforcement_proven=False, authentic_user_consent_proven=False),
            boundary_receipt=dict(scope=binding.boundary.SCOPE, family=fold.family, seed=request['seed'],
                model='candidate_mlp', model_ack_sha256=model_sha, expected_model_sha256=model_sha,
                freeze_sha256=sha, canonical_request_sha256=self.context.canonical_request_sha256,
                release_sha256=self.context.release_sha256,
                source_binding_sha256=self.context.source_binding_sha256,
                head_recipe_sha256=self.context.head_recipe_sha256,
                held_labels_replayed=True, metrics=dict(hit_at_10=1, hit_found=True,
                    attempt_count=1, charged_runtime_s=2., best_cycle_regret_at_10=0., freeze_sha256=sha)),
            **{field: False for field in reader.FALSE_FIELDS})
        self.refresh()

    def build(self):
        return binding.build_independent_fit_context(self.loaded['request'], self.args[3],
            self.args[4], self.loaded['input_identity'], self.args[5], self.args[6],
            family=self.args[1], seed=self.args[2], **self.kwargs)

    def refresh(self):
        log_raw = b''.join(encode(record) for record in self.logs)
        self.receipt['fitting_log_sha256'] = hashlib.sha256(log_raw).hexdigest()
        self.receipt['worker_receipt_sha256'] = digest({key: value for key, value in self.receipt.items()
                                                       if key != 'worker_receipt_sha256'})
        self.pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in {
            'model.pt': self.model_raw, 'fitting.jsonl': log_raw,
            'freeze.json': encode(self.freeze), 'worker_receipt.json': encode(self.receipt)}.items()}

    def verify(self):
        return binding.verify_candidate_fit_artifacts(self.context, self.receipt,
                                                      self.freeze, self.logs, self.pins)

    def test_complete_synthetic_identity_only_no_numerical_or_authority_promotion(self):
        result = self.verify()
        self.assertEqual(result['status'], 'PASS_FIT_CONTEXT_BINDING_ONLY')
        self.assertEqual((self.context.fitting_count, self.context.heldout_count), (60, 12))
        for field in ('numerical_model_predictions_verified', 'numerical_held_metrics_verified',
                      'callback_provenance_authenticated', 'authentic_user_consent_proven',
                      'formal_training_authorized_by_this_function', 'new_formal_18_fit_release'):
            self.assertIs(result[field], False)

    def test_context_snapshot_immutable_without_shared_dict(self):
        old = self.context
        self.loaded['request']['rows'][0]['action_uid'] = 'modified after build'
        self.loaded['input_identity']['fold_manifest_sha256'] = '0'*64
        self.args[3]['source_binding'].clear()
        self.assertEqual(old, self.context)
        self.assertEqual(old.fold_manifest_sha256, 'c'*64)
        self.assertFalse(hasattr(old, '__dict__'))
        with self.assertRaises(AttributeError):
            old.seed = 0
        self.verify()

    def test_bad_build_identity_approval_and_unbounded_graph(self):
        for field, value in (('seed', True), ('family', 'unknown'), ('fold_manifest_sha256', 'bad'),
                             ('source_sha256', '0'*64), ('extra', None)):
            original = deepcopy(self.loaded['input_identity'])
            self.loaded['input_identity'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.build()
            self.loaded['input_identity'] = original
        original = self.kwargs['trusted_review_sha256']
        self.kwargs['trusted_review_sha256'] = '0'*64
        with self.assertRaises(ValueError): self.build()
        self.kwargs['trusted_review_sha256'] = original
        self.loaded['request']['seed'] = 20260825
        with self.assertRaises(ValueError): self.build()
        self.loaded['request']['seed'] = self.args[2]
        cycle = []; cycle.append(cycle)
        self.loaded['request']['extra'] = cycle
        with self.assertRaisesRegex(ValueError, 'GRAPH_BOUND'): self.build()

    def test_coherent_repin_wrong_request_recipe_release_source_and_seed_rejected(self):
        baseline = deepcopy(self.receipt)
        baseline_logs = deepcopy(self.logs)
        for field in ('canonical_request_sha256', 'head_recipe_sha256', 'release_sha256',
                      'source_binding_sha256', 'seed', 'family'):
            self.receipt = deepcopy(baseline); self.logs = deepcopy(baseline_logs)
            changed = (20260825 if field == 'seed' else 'iwls_spi' if field == 'family' else '0'*64)
            self.receipt['boundary_receipt'][field] = changed
            if field in ('seed', 'family'):
                self.receipt['input_identity'][field] = changed
            if field == 'release_sha256':
                self.receipt['approval_integrity'][field] = changed
            if field in ('canonical_request_sha256', 'head_recipe_sha256'):
                log_field = 'recipe_sha256' if field == 'head_recipe_sha256' else field
                for record in self.logs: record[log_field] = changed
            self.refresh()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'BOUNDARY_IDENTITY'):
                self.verify()

    def test_coherent_repin_wrong_foldmanifest_and_approval_anchor_rejected(self):
        baseline = deepcopy(self.receipt)
        self.receipt['input_identity']['fold_manifest_sha256'] = '0'*64
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'INPUT_IDENTITY_BINDING'): self.verify()
        self.receipt = deepcopy(baseline)
        self.receipt['approval_integrity']['review_sha256'] = '0'*64
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'APPROVAL_IDENTITY'): self.verify()

    def test_coherent_repin_wrong_uidset_or_uidhash_rejected(self):
        original = deepcopy(self.freeze)
        for mode in ('extra_uid', 'missing_uid', 'wrong_uid', 'fitting_hash', 'held_hash', 'order'):
            self.freeze = deepcopy(original)
            payload = self.freeze['payload']
            first = next(iter(payload['scores']))
            if mode == 'extra_uid': payload['scores']['extra'] = 0.
            elif mode == 'missing_uid': del payload['scores'][first]
            elif mode == 'wrong_uid': payload['scores']['wrong'] = payload['scores'].pop(first)
            elif mode == 'fitting_hash': payload['fitting_uids_sha256'] = '0'*64
            elif mode == 'held_hash': payload['heldout_uids_sha256'] = '0'*64
            else: payload['order'].reverse()
            if mode in ('extra_uid', 'missing_uid', 'wrong_uid'):
                payload['order'] = sorted(payload['scores'], key=lambda uid: (-payload['scores'][uid], uid))
            self.freeze['sha256'] = digest(payload)
            self.receipt['boundary_receipt']['freeze_sha256'] = self.freeze['sha256']
            self.receipt['boundary_receipt']['metrics']['freeze_sha256'] = self.freeze['sha256']
            self.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.verify()

    def test_held_false_or_missing_metrics_cannot_pass_after_repin(self):
        for replay, metrics in ((False, None), (1, self.receipt['boundary_receipt']['metrics']), (True, None)):
            self.receipt['boundary_receipt']['held_labels_replayed'] = replay
            self.receipt['boundary_receipt']['metrics'] = metrics
            self.refresh()
            with self.assertRaisesRegex(ValueError, 'HELD_REPLAY_REQUIRED'): self.verify()

    def test_log_class_counts_independent_even_when_current_reader_accepts(self):
        row = self.logs[0]['families'][0]
        row.update(positive_count=2, negative_count=10, first_positive_rank=11,
                   negatives_before_first_positive=10, hit_at_10=0)
        self.refresh()
        # Existing self-consistency schema passes; independent recipe joins fail.
        reader._logs(b''.join(encode(r) for r in self.logs), self.receipt['boundary_receipt'])
        with self.assertRaisesRegex(ValueError, 'LOG_INDEPENDENT_CLASS_COUNTS'): self.verify()

    def test_measured_model_ack_log_freeze_and_receipt_pins_are_not_authority(self):
        original = deepcopy(self.pins)
        for name in self.pins:
            self.pins = deepcopy(original); self.pins[name] = '0'*64
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify()
        self.pins = original
        self.receipt['boundary_receipt']['model_ack_sha256'] = '0'*64
        self.refresh()
        with self.assertRaises(ValueError): self.verify()

    def test_inputs_not_mutated_and_never_reads_or_decodes_files(self):
        before = deepcopy((self.receipt, self.freeze, self.logs, self.pins, self.loaded))
        with patch('builtins.open', side_effect=AssertionError('I/O forbidden')), \
             patch('os.open', side_effect=AssertionError('I/O forbidden')), \
             patch.object(Path, 'lstat', side_effect=AssertionError('I/O forbidden')), \
             patch.object(reader, '_read', side_effect=AssertionError('I/O forbidden')):
            self.build()
            self.verify()
            self.receipt['input_identity']['fold_manifest_sha256'] = '0'*64
            with self.assertRaises(ValueError): self.verify()
            self.receipt['input_identity']['fold_manifest_sha256'] = 'c'*64
        self.assertEqual(before, (self.receipt, self.freeze, self.logs, self.pins, self.loaded))

    def test_context_malformed_primitive_and_uidhash_types_refused(self):
        for context in (replace(self.context, seed=True),
                        replace(self.context, fitting_uids_sha256='0'*64),
                        replace(self.context, heldout_uids=list(self.context.heldout_uids)),
                        replace(self.context, recipe_class_counts=())):
            with self.assertRaises(ValueError):
                binding.verify_candidate_fit_artifacts(context, self.receipt, self.freeze, self.logs, self.pins)


if __name__ == '__main__':
    unittest.main()
