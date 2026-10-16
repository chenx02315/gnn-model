"""E31->E32 fabricated integration, opaque sentinels not model weights/labels."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.models import ranking_v6_materialized_freeze_store as disk
from src.models.ranking_v6_materialized_fold import prepare_fold
from tests.test_ranking_v6_materialized_fold import fabricated


def snapshot():
    features, outcomes = fabricated()
    held = 'iwls_spi'
    fit = {r['action_uid']: outcomes[r['action_uid']] for r in features if r['family'] != held}
    fold = prepare_fold(features, fit, held_family=held, seed=20260824, implementation_only=True)
    model = b'opaque-generated-sentinel-not-checkpoint'
    normalizer = json.dumps(fold['normalizer'], sort_keys=True, separators=(',', ':')).encode('ascii')
    uids_bytes = json.dumps(fold['fit_uids'], separators=(',', ':')).encode('ascii')
    freeze = disk.make_freeze(model_bytes=model, normalizer_bytes=normalizer,
                              feature_snapshot_sha256=fold['feature_snapshot_sha256'],
                              fitting_uids_sha256=hashlib.sha256(uids_bytes).hexdigest(),
                              held_family=held, seed=fold['seed'],
                              scores={uid: 0. for uid in fold['held_uids']}, implementation_only=True)
    return fold, model, normalizer, freeze


class MaterializedFreezeIntegrationTests(unittest.TestCase):
    def test_actual_temp_files_bind_fold_metadata_before_one_fixture_callback(self):
        fold, model, normalizer, freeze = snapshot()
        parsed = json.loads(freeze)
        self.assertEqual(parsed['feature_snapshot_sha256'], fold['feature_snapshot_sha256'])
        self.assertEqual(parsed['normalizer_sha256'], fold['normalizer_sha256'])
        self.assertEqual(parsed['ranking'], sorted(fold['held_uids']))
        with tempfile.TemporaryDirectory(prefix='gnn_v6_parent_test_') as parent:
            with patch.dict(os.environ, {'TEMP': parent, 'TMP': parent, 'TMPDIR': parent}):
                root = os.path.join(parent, 'gnn_v6_freeze_fixture_integration')
                store = disk.Store(root, implementation_only=True)
                ack = store.persist(model, normalizer, freeze)
                self.assertTrue(ack['ordinary_files_verified'])
                self.assertEqual(set(os.listdir(root)), {'model.bin', 'normalizer.json', 'freeze.json'})
                callback = Mock(return_value={'generated_probe': True})
                with self.assertRaises(ValueError):
                    store.release(model, b'wrong-normalizer', freeze, callback)
                callback.assert_not_called()
                released = store.release(model, normalizer, freeze, callback)
                callback.assert_called_once_with()
                self.assertEqual(released['outcome'], {'generated_probe': True})
                self.assertFalse(released['receipt']['real_held_release'])
                self.assertFalse(released['receipt']['model_ready'])

    def test_tampered_generated_model_blocks_callback(self):
        _, model, normalizer, freeze = snapshot()
        with tempfile.TemporaryDirectory(prefix='gnn_v6_parent_test_') as parent:
            with patch.dict(os.environ, {'TEMP': parent, 'TMP': parent, 'TMPDIR': parent}):
                root = os.path.join(parent, 'gnn_v6_freeze_fixture_tampered')
                store = disk.Store(root, implementation_only=True)
                store.persist(model, normalizer, freeze)
                (Path(root)/'model.bin').write_bytes(b'altered-generated-sentinel')
                callback = Mock(side_effect=AssertionError('fixture callback accessed'))
                with self.assertRaises(ValueError):
                    store.release(model, normalizer, freeze, callback)
                callback.assert_not_called()

    def test_contract_caps_and_no_production_or_training_release(self):
        root = Path(__file__).resolve().parents[1]
        contract = json.loads((root/'contracts/ranking_v6_materialized_freeze_store_v1.json').read_text())
        self.assertEqual(contract['files']['model.bin']['max_bytes'], disk.MODEL_CAP)
        self.assertEqual(contract['files']['normalizer.json']['max_bytes'], disk.NORMALIZER_CAP)
        self.assertEqual(contract['files']['freeze.json']['max_bytes'], disk.FREEZE_CAP)
        for flag in ('real_data_access', 'real_heldout_release', 'real_training_release',
                     'model_ready', 'trainer_implemented', 'cross_process_resume_supported'):
            self.assertFalse(contract[flag])
        self.assertTrue(contract['release_requires_same_instance_complete_persist_ack'])
        self.assertFalse(contract['root']['production_root_supported'])


if __name__ == '__main__':
    unittest.main()
