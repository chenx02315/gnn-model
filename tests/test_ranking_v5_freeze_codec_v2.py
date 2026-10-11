"""Pure metadata/codec tests, no real data, fit or release."""
import hashlib
import json
import unittest
from unittest.mock import patch

from src.models import ranking_v5_freeze_codec_v2 as codec
from src.models import ranking_v5_real_artifact_store as legacy
from src.models.runtime_ranking_v3 import Fold, digest, freeze_ranking


def fixture(count=3, width=8):
    uids=tuple('u'+str(i).zfill(4)+'_'+'x'*width for i in range(count))
    fold=Fold('iwls_aes_core',('fitting',),uids)
    scores={uid:float(i%7) for i,uid in enumerate(uids)}
    payload,sha=freeze_ranking(scores,fold)
    return fold,payload,sha


class CodecTests(unittest.TestCase):
    def test_canonical_original_bytes_and_sha_unchanged(self):
        fold,payload,sha=fixture()
        metadata=codec.preflight(fold)
        self.assertEqual(metadata['fitting_uids_sha256'],digest(fold.fitting))
        self.assertEqual(metadata['heldout_uids_sha256'],digest(fold.heldout))
        expected=json.dumps({'payload':payload,'sha256':sha},sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
        self.assertEqual(codec.encode(payload,sha),expected)
        self.assertEqual(codec.payload_bytes(payload),json.dumps(payload,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
        self.assertEqual(codec.decode(expected,sha),(payload,sha))
        self.assertEqual(codec.decode(expected),(payload,sha))

    def test_full_1025_and_1706_candidates_above_old_cap(self):
        for count in (1025,1706):
            fold,payload,sha=fixture(count,64)
            meta=codec.preflight(fold)
            raw=codec.encode(payload,sha)
            self.assertGreater(len(raw),legacy.FREEZE_MAX_BYTES)
            self.assertEqual(meta['candidate_count'],count)
            self.assertLessEqual(len(raw),meta['freeze_upper_bound_bytes'])
            reread,_=codec.decode(raw,sha)
            self.assertEqual(len(reread['scores']),count)
            self.assertEqual(len(reread['order']),count)
            self.assertEqual(reread,payload)
            with self.assertRaises(ValueError):legacy._canonical(payload,legacy.FREEZE_MAX_BYTES)

    def test_encoder_exact_cap_and_off_by_one(self):
        _,payload,sha=fixture()
        raw=codec.encode(payload,sha)
        self.assertEqual(codec.encode(payload,sha,limit=len(raw)),raw)
        with self.assertRaisesRegex(ValueError,'BYTES'):codec.encode(payload,sha,limit=len(raw)-1)
        with self.assertRaisesRegex(ValueError,'LIMIT'):codec.encode(payload,sha,limit=codec.FREEZE_MAX_BYTES+1)

    def test_candidate_uid_and_score_reject_before_full_encoder(self):
        _,payload,sha=fixture()
        for change in ('count','uid','empty','int','nan','infinity','family','fields','topk','epsilon'):
            item=dict(payload);item['scores']=dict(payload['scores']);item['order']=list(payload['order'])
            if change=='count':item['scores']={str(i):1. for i in range(1707)}
            if change=='uid':item['scores']={'x'*2049:1.}
            if change=='empty':item['scores']={'':1.}
            if change in ('int','nan','infinity'):item['scores'][item['order'][0]]={'int':1,'nan':float('nan'),'infinity':float('inf')}[change]
            if change=='family':item['family']='unknown'
            if change=='fields':item['extra']='unknown'
            if change=='topk':item['top_k']=True
            if change=='epsilon':item['epsilon']=1
            with self.subTest(change=change),patch.object(codec,'_stream_json',side_effect=AssertionError('encoder')),self.assertRaises(ValueError):codec.encode(item,sha)

    def test_order_duplicate_mismatch_and_tie_order(self):
        _,payload,_=fixture(4)
        for change in ('duplicate','missing','reverse'):
            item=dict(payload);item['order']=list(payload['order'])
            if change=='duplicate':item['order'][0]=item['order'][1]
            if change=='missing':item['order'].pop()
            if change=='reverse':item['order'].reverse()
            with self.subTest(change=change),self.assertRaises(ValueError):codec.validate_payload(item)
        fold=Fold('iwls_spi',('fit',),('b','a'))
        tied,sha=freeze_ranking({'b':0.,'a':-0.},fold)
        self.assertEqual(tied['order'],['a','b'])
        self.assertEqual(codec.decode(codec.encode(tied,sha)),(tied,sha))

    def test_preflight_metadata_uniqueness_disjoint_and_total_bound(self):
        valid,_,_=fixture()
        bad=[Fold('unknown',valid.fitting,valid.heldout),Fold(valid.family,['f'],valid.heldout),
             Fold(valid.family,('f','f'),valid.heldout),Fold(valid.family,('f',),('f',)),
             Fold(valid.family,('f',),('x','x')),Fold(valid.family,('f',),tuple(str(i) for i in range(1707))),
             Fold(valid.family,tuple('f'+str(i) for i in range(20000)),('held',))]
        for fold in bad:
            with self.subTest(family=fold.family),patch.object(codec,'_uid_hash',side_effect=AssertionError('hash')),self.assertRaises(ValueError):codec.preflight(fold)

    def test_escaped_uid_budget_refuses_before_hash_and_not_all_max_uids_fit(self):
        uids=tuple(str(i).zfill(4)+'\U0001f600'*2044 for i in range(1706))
        with patch.object(codec,'_uid_hash',side_effect=AssertionError('hash')),self.assertRaisesRegex(ValueError,'CAPACITY'):codec.preflight(Fold('iwls_spi',('fit',),uids))
        # Exactly 2048 decoded chars despite 4096 surrogate-code-unit escapes.
        uid='\U0001f600'*2048
        fold=Fold('iwls_spi',('fit',),(uid,))
        payload,sha=freeze_ranking({uid:1.},fold)
        self.assertEqual(codec.decode(codec.encode(payload,sha)),(payload,sha))

    def test_predecoder_nodes_depth_string_and_number_budgets(self):
        cases=[(b'{"payload":['+b'0,'*6000+b'0],"sha256":"x"}\n','NODES'),
               (b'[[[[[[0]]]]]]\n','DEPTH'),
               (b'"'+b'x'*2049+b'"\n','UID_CHARS'),
               (b'1'+b'0'*32+b'\n','NUMBER_CHARS')]
        for raw,code in cases:
            with self.subTest(code=code),patch.object(codec.json,'loads',side_effect=AssertionError('decoder')),self.assertRaisesRegex(ValueError,code):codec.decode(raw)

    def test_sha_duplicate_keys_tamper_and_noncanonical(self):
        _,payload,sha=fixture()
        raw=codec.encode(payload,sha)
        for item in (raw[:-1],b' '+raw,raw.replace(b'"payload":',b'"payload":{},"payload":'),
                     raw.replace(sha.encode(),b'0'*64),raw.replace(b'0.01',b'0.02')):
            with self.subTest(length=len(item)),self.assertRaises(ValueError):codec.decode(item,sha)
        with self.assertRaises(ValueError):codec.decode(raw,'0'*64)
        with self.assertRaisesRegex(ValueError,'PAYLOAD_SHA'):codec.encode(payload,'0'*64)

    def test_diagnostics_never_contain_uid_content(self):
        _,payload,sha=fixture();payload['scores']={'SECRET_UID'*300:1.}
        with self.assertRaises(ValueError) as caught:codec.encode(payload,sha)
        self.assertNotIn('SECRET',str(caught.exception))
        self.assertLess(len(str(caught.exception)),120)

    def test_legacy_generic_bounds_unchanged(self):
        self.assertEqual(legacy.FREEZE_MAX_BYTES,20480)
        self.assertEqual(legacy.JSON_MAX_CONTAINER_ITEMS,1024)
        self.assertEqual(legacy.JSON_MAX_NODES,4096)
        self.assertEqual(legacy.JSON_MAX_DEPTH,64)
        with self.assertRaises(ValueError):legacy._canonical({'scores':{str(i):1. for i in range(1025)}},legacy.RECEIPT_MAX_BYTES)


if __name__=='__main__':unittest.main()
