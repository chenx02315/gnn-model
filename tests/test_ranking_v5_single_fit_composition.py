import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.models import ranking_v5_approval_binding as approval
from src.models import ranking_v5_execution_boundary as boundary
from src.models import ranking_v5_single_fit_composition as composition
from src.models.ranking_v5_physical_worker import _test_release, synthetic_request
from src.models.runtime_ranking_v3 import digest
from src.data import ranking_v3_real_fold_package as v3
from src.models.ranking_v5_v3_fold_adapter import adapt_v3_fold
from src.models import ranking_v5_real_artifact_store as store_module


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    sources = {name: 'a' * 64 for name in boundary.REQUIRED_SOURCE_BINDINGS}
    release = _test_release(sources)
    # Artificial opaque ID is not genuine authority; no physical callback runs.
    release['user_authorization_id'] = 'opaque-unit-fixture-id'
    auth = dict(schema='v5-explicit-authorization-evidence-v1',
                authorization_id=release['user_authorization_id'], scope=approval.SCOPE,
                roles=['TRAIN'], planned_fits=18, seeds=list(boundary.SEEDS),
                source_sha256=boundary.SOURCE_SHA256,
                package_receipt_sha256=boundary.PACKAGE_SHA256, retry_count=0)
    auth_raw = raw(auth)
    auth_sha = hashlib.sha256(auth_raw).hexdigest()
    release['user_authorization_sha256'] = auth_sha
    gate_sha = 'b' * 64
    review = dict(schema='v5-independent-release-binding-review-v1',
                  status='PASS_V5_RELEASE_BINDING_REVIEW', scope=approval.SCOPE,
                  authorization_sha256=auth_sha,
                  release_sha256=approval.review_subject(release),
                  source_binding_sha256=digest(sources), physical_gate_sha256=gate_sha)
    review_raw = raw(review)
    review_sha = hashlib.sha256(review_raw).hexdigest()
    release['independent_review_receipt_sha256'] = review_sha
    request = synthetic_request()
    loaded = dict(status=composition.inputs.STATUS, request=request,
                  input_identity=dict(package_receipt_sha256=boundary.PACKAGE_SHA256,
                                      source_sha256=boundary.SOURCE_SHA256,
                                      fold_manifest_sha256='c' * 64,
                                      family=request['family'], seed=request['seed']))
    events, frozen = [], {}
    def fit(prepared, recipe, seed):
        events.append('fit')
        assert all(uid not in prepared['fit_uids'] for uid in boundary.prepare_request(request)[0].heldout)
        return object()
    def persist_model(model, sha):
        events.append('model_ack')
        return sha
    def predict(model, uids, features):
        events.append('predict')
        return {uid: float(i) for i, uid in enumerate(uids)}
    def persist_freeze(payload, sha):
        events.append('freeze_ack')
        frozen['value'] = (copy.deepcopy(payload), sha)
        return sha
    def reread(sha):
        events.append('reread')
        return frozen['value']
    def outcomes(root, identity, fold, uids, sha, readback):
        events.append('held')
        assert readback == frozen['value']
        return {uid: dict(execution_status='SUCCESS', is_d95_feasible=1,
                         total_cycles=100, policy_charged_runtime_s=2) for uid in uids}
    args = ('/ssd/cjc/not-read-unit-fixture', request['family'], request['seed'],
            release, sources, auth_raw, review_raw)
    kwargs = dict(trusted_authorization_sha256=auth_sha, trusted_review_sha256=review_sha,
                  trusted_physical_gate_sha256=gate_sha, fit=fit, predict=predict,
                  model_sha256=lambda model: 'd' * 64, persist_model=persist_model,
                  persist_freeze=persist_freeze, read_frozen=reread)
    return args, kwargs, loaded, events, outcomes


class CompositionTests(unittest.TestCase):
    def test_generated_package_to_frozen_replay_without_mocking_held_reader(self):
        args, kwargs, loaded, events, _ = fixture()
        request = loaded['request']
        fold = boundary.prepare_request(request)[0]
        outcomes = {row['action_uid']: dict(execution_status='SUCCESS', is_d95_feasible=1,
                    total_cycles=100 if row['action_uid'].endswith('00') else 200,
                    policy_charged_runtime_s=2) for row in request['rows']}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'train_folds'
            root.mkdir()
            folder = root / ('fold_' + fold.family)
            sha = v3.export_real_fold(folder, request['rows'], outcomes, fold,
                     release=dict(status=v3.RELEASE_STATUS, source_sha256=boundary.SOURCE_SHA256,
                                  independent_review_pass=True, roles=['TRAIN']),
                     source_sha256=boundary.SOURCE_SHA256)
            loaded['request'] = adapt_v3_fold(folder.as_posix(), sha, fold.family, request['seed'])
            loaded['input_identity']['fold_manifest_sha256'] = sha
            args = (root.as_posix(), *args[1:])
            with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded), \
                 patch.object(composition.held.package_binding, 'PACKAGE_ROOT_ALLOWLIST',
                              frozenset((root.as_posix(),))), \
                 patch.object(store_module, 'PRODUCTION_PREFIX',
                              (Path(directory) / 'gnn_model_ranking_v5_train_').as_posix()):
                store = store_module.RealArtifactStore(
                    (Path(directory) / 'gnn_model_ranking_v5_train_unit').as_posix())
                model_raw = b'UNIT_FIXTURE_NOT_TORCH_CHECKPOINT'
                kwargs['model_sha256'] = lambda model: hashlib.sha256(model_raw).hexdigest()
                def save_model(model, expected):
                    events.append('model_ack')
                    return store.persist_model_bytes(model_raw, expected)
                def save_freeze(payload, expected):
                    events.append('freeze_ack')
                    return store.persist_freeze(payload, expected)
                def read_freeze(expected):
                    events.append('reread')
                    return store.read_freeze(expected)
                kwargs.update(persist_model=save_model, persist_freeze=save_freeze,
                              read_frozen=read_freeze)
                result = composition.compose_single_fit(*args, **kwargs)
            self.assertTrue(result['boundary_receipt']['held_labels_replayed'])
            self.assertEqual(events, ['fit', 'model_ack', 'predict', 'freeze_ack', 'reread'])

    def test_callbacks_order_and_no_permission_promotion(self):
        args, kwargs, loaded, events, outcomes = fixture()
        with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded), \
             patch.object(composition.held, 'load_frozen_held_outcomes', side_effect=outcomes):
            result = composition.compose_single_fit(*args, **kwargs)
        self.assertEqual(events, ['fit', 'model_ack', 'predict', 'freeze_ack', 'reread', 'held'])
        self.assertEqual(result['status'], 'PASS_CALLBACK_COMPOSITION_ONLY')
        self.assertFalse(result['authentic_user_consent_proven'])
        self.assertFalse(result['physical_worker_limits_verified'])
        self.assertFalse(result['formal_training_authorized_by_this_function'])
        self.assertEqual(result['boundary_receipt']['metrics']['charged_runtime_s'], 2)

    def test_test_only_or_bad_integrity_rejected_before_input_io(self):
        for mode in ('test', 'synthetic', 'pin', 'callback'):
            args, kwargs, loaded, _, _ = fixture()
            if mode == 'test': args[3]['user_authorization_id'] = 'TEST_ONLY_AUTHORITY_NOT_FORMAL'
            elif mode == 'synthetic': args[3]['user_authorization_id'] = 'synthetic-fixture'
            elif mode == 'pin': kwargs['trusted_review_sha256'] = 'e' * 64
            else: kwargs['fit'] = None
            with patch.object(composition.inputs, 'load_bound_fold_request') as read:
                with self.assertRaises(ValueError): composition.compose_single_fit(*args, **kwargs)
                read.assert_not_called()

    def test_identity_drift_refused_before_fit(self):
        for field, value in [('package_receipt_sha256', 'e'*64), ('source_sha256', 'e'*64),
                             ('fold_manifest_sha256', 'bad'), ('family', 'wrong'), ('seed', 20260824.0)]:
            args, kwargs, loaded, events, _ = fixture()
            loaded['input_identity'][field] = value
            with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded):
                with self.assertRaisesRegex(ValueError, 'INPUT_IDENTITY'):
                    composition.compose_single_fit(*args, **kwargs)
            self.assertEqual(events, [])

    def test_failures_never_call_held_reader(self):
        for phase in ('fit', 'model_ack', 'predict', 'freeze_ack', 'reread'):
            args, kwargs, loaded, _, _ = fixture()
            callback = dict(fit='fit', model_ack='persist_model', predict='predict',
                            freeze_ack='persist_freeze', reread='read_frozen')[phase]
            def fail(*unused): raise ValueError('injected_failure')
            kwargs[callback] = fail
            with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded), \
                 patch.object(composition.held, 'load_frozen_held_outcomes') as held:
                with self.assertRaises(ValueError): composition.compose_single_fit(*args, **kwargs)
                held.assert_not_called()

    def test_invalid_ack_and_changed_reread_never_call_held(self):
        for callback, value in [('persist_model', 'e'*64), ('persist_freeze', 'e'*64),
                                ('read_frozen', ({'scores': {}}, 'e'*64))]:
            args, kwargs, loaded, _, _ = fixture()
            kwargs[callback] = lambda *unused, value=value: value
            with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded), \
                 patch.object(composition.held, 'load_frozen_held_outcomes') as held:
                with self.assertRaises(ValueError): composition.compose_single_fit(*args, **kwargs)
                held.assert_not_called()

    def test_external_mutation_during_fit_does_not_change_snapshots(self):
        args, kwargs, loaded, events, outcomes = fixture()
        original = kwargs['fit']
        expected_identity = copy.deepcopy(loaded['input_identity'])
        def mutate(*fit_args):
            model = original(*fit_args)
            args[3]['user_authorization_id'] = 'mutated'
            args[4].clear()
            loaded['input_identity']['fold_manifest_sha256'] = 'e'*64
            loaded['request']['fit_cycles'].clear()
            return model
        kwargs['fit'] = mutate
        with patch.object(composition.inputs, 'load_bound_fold_request', return_value=loaded), \
             patch.object(composition.held, 'load_frozen_held_outcomes', side_effect=outcomes):
            result = composition.compose_single_fit(*args, **kwargs)
        self.assertEqual(result['input_identity'], expected_identity)
        self.assertEqual(events[-1], 'held')


if __name__ == '__main__': unittest.main()
