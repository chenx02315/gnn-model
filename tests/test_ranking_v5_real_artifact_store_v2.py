"""Synthetic local storage tests; never read real package/model data."""
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from src.models import ranking_v5_real_artifact_store as legacy
from src.models import ranking_v5_real_artifact_store_v2 as new
from src.models.runtime_ranking_v3 import Fold, freeze_ranking


class StoreV2Tests(unittest.TestCase):
    def make(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        # Bypass only production-directory creation in this synthetic fixture;
        # no legacy global is changed and the real protected constructor is tested.
        store=new.RealArtifactStore.__new__(new.RealArtifactStore)
        store.output=Path(temporary.name)
        return store.output,store

    def payload(self,count=1706):
        uids=tuple('held_'+str(i).zfill(4)+'_'+'x'*64 for i in range(count))
        return freeze_ranking({uid:float(i%9) for i,uid in enumerate(uids)},Fold('iwls_spi',('fitting',),uids))

    def test_large_freeze_full_persist_hash_ack_and_exact_reread(self):
        output,store=self.make();payload,sha=self.payload()
        self.assertEqual(store.persist_freeze(payload,sha),sha)
        self.assertEqual(store.read_freeze(sha),(payload,sha))
        raw=(output/'freeze.json').read_bytes()
        self.assertGreater(len(raw),legacy.FREEZE_MAX_BYTES)
        self.assertEqual(new.codec.decode(raw,sha),(payload,sha))
        with self.assertRaises(FileExistsError):store.persist_freeze(payload,sha)

    def test_bad_payload_or_sha_before_path_io_or_encoder(self):
        _,store=self.make();payload,sha=self.payload(3)
        with patch.object(store,'_write',side_effect=AssertionError('IO')):
            with self.assertRaises(ValueError):store.persist_freeze(payload,'0'*64)
            payload['order'].reverse()
            with self.assertRaises(ValueError):store.persist_freeze(payload,sha)

    def test_tamper_truncate_and_wrong_expected_sha(self):
        output,store=self.make();payload,sha=self.payload(3)
        store.persist_freeze(payload,sha)
        with self.assertRaises(ValueError):store.read_freeze('0'*64)
        raw=(output/'freeze.json').read_bytes()
        for changed in (raw[:-1],raw.replace(b'0.01',b'0.02'),b'{}\n'):
            (output/'freeze.json').write_bytes(changed)
            with self.assertRaises(ValueError):store.read_freeze(sha)

    def test_protected_and_noncanonical_output_zero_io(self):
        with patch.object(legacy,'_check_existing_ancestors',side_effect=AssertionError('IO')):
            for output in ('/ssd/cjc/multimode_ate_gnn_v1/child','/tmp/unapproved',
                           '/ssd/cjc/gnn_model_ranking_v5_train_x/../child'):
                with self.subTest(output=output),self.assertRaises(ValueError):new.RealArtifactStore(output)

    def test_model_log_receipt_methods_and_limits_inherited_unchanged(self):
        for name in ('__init__','_path','_write','_read','persist_model_bytes','ack_model','persist_logs',
                     'ack_logs','persist_receipt'):
            self.assertIs(getattr(new.RealArtifactStore,name),getattr(legacy.RealArtifactStore,name))
        for name in ('MODEL_MAX_BYTES','LOG_MAX_BYTES','LOG_RECORD_MAX_BYTES','LOG_RECORD_COUNT',
                     'RECEIPT_MAX_BYTES','JSON_MAX_DEPTH','JSON_MAX_NODES','JSON_MAX_CONTAINER_ITEMS',
                     'JSON_MAX_STRING_CHARS','JSON_MAX_INT_BITS','ARTIFACTS','_canonical'):
            self.assertEqual(getattr(new,name),getattr(legacy,name))
        _,store=self.make();model=b'synthetic model'
        sha=hashlib.sha256(model).hexdigest()
        self.assertEqual(store.persist_model_bytes(model,sha),sha)
        self.assertTrue(store.persist_logs([{'epoch':i} for i in range(122)]))
        self.assertTrue(store.persist_receipt({'status':'SYNTHETIC_ONLY'}))
        _,store2=self.make()
        with self.assertRaisesRegex(ValueError,'RECEIPT_BOUND'):store2.persist_receipt({'x':'x'*20481})

    def test_legacy_store_still_refuses_large_full_freeze(self):
        _,store=self.make();payload,sha=self.payload(1025)
        old=legacy.RealArtifactStore.__new__(legacy.RealArtifactStore);old.output=store.output
        with self.assertRaises(ValueError):old.persist_freeze(payload,sha)
        self.assertFalse((store.output/'freeze.json').exists())


if __name__=='__main__':unittest.main()
