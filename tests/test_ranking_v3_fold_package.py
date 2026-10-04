import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tests.test_runtime_ranking_v3 import fixture
from src.models.runtime_ranking_v3 import plan_folds,freeze_ranking
from src.data.ranking_v3_fold_package import export_fixture_fold,FoldReader,SCOPE
from src.models.ranking_v3_freeze_io import persist_freeze
from src.models.run_runtime_ranking_v3 import run_fold,aggregate_three_seeds,SEEDS

class FoldPackageTests(unittest.TestCase):
    def test_disk_pipeline_all_eighteen_receipts(self):
        rows,outcomes=fixture(); receipts=[]
        with tempfile.TemporaryDirectory() as directory:
            for i,fold in enumerate(plan_folds(rows)):
                root=Path(directory)/str(i)
                seal=export_fixture_fold(root,rows,outcomes,fold,scope=SCOPE)
                reader=FoldReader(root,seal,fold)
                for seed in SEEDS:
                    freeze_path=root/('freeze_%d.json'%seed)
                    receipts.append(run_fold(reader.feature_rows(),fold,seed,
                        load_fitting=reader.fitting,
                        fit=lambda prep,seed: None,
                        predict=lambda model,uids,x:{u:0 for u in uids},
                        persist_freeze=lambda p,s:persist_freeze(freeze_path,p,s),
                        load_heldout=lambda uids,sha:reader.heldout(uids,freeze_path,sha),
                        mode='synthetic',fixture_attestation=SCOPE))
            self.assertEqual(aggregate_three_seeds(receipts)['receipt_count'],18)
            self.assertTrue(all(r['scope']=='SYNTHETIC_ONLY_NO_FORMAL_TRAINING' for r in receipts))

    def test_split_fit_access_and_hold_access_order(self):
        rows,outcomes=fixture(); fold=plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'fold'
            seal=export_fixture_fold(root,rows,outcomes,fold,scope=SCOPE)
            reader=FoldReader(root,seal,fold)
            names=[]; original=Path.read_bytes
            def spy(path): names.append(path.name); return original(path)
            with patch.object(Path,'read_bytes',spy):
                self.assertEqual(set(reader.fitting(fold.fitting)),set(fold.fitting))
                reader.feature_rows()
                with self.assertRaises(FileNotFoundError): reader.heldout(fold.heldout,root/'missing.json','0'*64)
            self.assertNotIn('heldout_outcomes.json',names)
            payload,sha=freeze_ranking({u:0 for u in fold.heldout},fold)
            persist_freeze(root/'freeze.json',payload,sha)
            self.assertEqual(set(reader.heldout(fold.heldout,root/'freeze.json',sha)),set(fold.heldout))
    def test_real_export_and_bad_manifest_refuse(self):
        rows,outcomes=fixture(); fold=plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'fold'
            with self.assertRaises(ValueError): export_fixture_fold(root,rows,outcomes,fold)
            self.assertFalse(root.exists())
            seal=export_fixture_fold(root,rows,outcomes,fold,scope=SCOPE)
            with self.assertRaises(ValueError): FoldReader(root,'0'*64,fold)
            with self.assertRaises(FileExistsError): export_fixture_fold(root,rows,outcomes,fold,scope=SCOPE)
    def test_file_tamper_refuses(self):
        rows,outcomes=fixture(); fold=plan_folds(rows)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'fold'
            seal=export_fixture_fold(root,rows,outcomes,fold,scope=SCOPE)
            reader=FoldReader(root,seal,fold)
            with (root/'fit_outcomes.json').open('ab') as stream: stream.write(b' ')
            with self.assertRaises(ValueError): reader.fitting(fold.fitting)

if __name__=='__main__': unittest.main()
