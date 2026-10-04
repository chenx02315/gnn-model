import copy
import hashlib
import json
from pathlib import Path
import unittest
from scripts.collect_ranking_v3_results import validate, validate_persisted_freezes

class ResultCollectionTests(unittest.TestCase):
    def setUp(self):
        self.payload=json.loads(Path('data/manifests/ranking_v3_train_results_20261005.json').read_bytes())
        self.payload['schema_version']=2
        self.payload['persisted_freeze_files']={}
        for key,record in self.payload['records'].items():
            if key.endswith('/evaluation.json'):
                r=record['data']
                raw=(json.dumps({'payload':r['freeze'],'sha256':r['freeze_sha256']},sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
                self.payload['persisted_freeze_files'][key.replace('evaluation.json','freeze.json')]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    def test_valid_and_rounding(self):
        validate(self.payload)
    def test_missing_freeze(self):
        self.payload['persisted_freeze_files'].pop(next(iter(self.payload['persisted_freeze_files'])))
        with self.assertRaisesRegex(ValueError,'INVENTORY'): validate_persisted_freezes(self.payload)
    def test_tampered_freeze(self):
        self.payload['persisted_freeze_files'][next(iter(self.payload['persisted_freeze_files']))]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'FREEZE_SHA'): validate(self.payload)
    def test_bad_exit_or_anchor(self):
        original=copy.deepcopy(self.payload)
        self.payload['records']['exit_receipt.json']['data']['exit_code']=1
        with self.assertRaisesRegex(ValueError,'PROCESS_EXIT'): validate(self.payload)
        original['records']['execution_release.json']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'EXTERNAL_ANCHORS'): validate(original)
    def test_macro_mismatch(self):
        self.payload['records']['experiment/summary.json']['data']['xgboost']['family_seed_macro']['charged_runtime_s']+=1
        with self.assertRaisesRegex(ValueError,'SUMMARY_MISMATCH'): validate(self.payload)
