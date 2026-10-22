"""Pure E80 request-feature checks: no checkpoint, graph, labels, or processes."""
import copy
import math
import unittest

from src.data import prospective_request_features_v1 as m


GRAPH='a'*64
ROWS=[dict(action_uid='z-hmf',scheme='HMF',h_request=20,m_request=8),
      dict(action_uid='a-hf',scheme='HF',h_request=2,m_request=None),
      dict(action_uid='m-hmf',scheme='HMF',h_request=5,m_request=3)]


class RequestFeaturesTests(unittest.TestCase):
    def freeze(self, rows=None, count=71216, graph=GRAPH):
        return m.freeze_requests('aes_core',ROWS if rows is None else rows,count,graph)

    def test_canonical_order_and_digest_bind_graph_count_request(self):
        frozen=self.freeze()
        reordered=self.freeze(list(reversed(ROWS)))
        self.assertEqual(frozen,reordered)
        self.assertEqual([x['action_uid'] for x in frozen['requested_roster']],
                         ['a-hf','m-hmf','z-hmf'])
        self.assertEqual(frozen['requested_max_h'],20)
        self.assertEqual(frozen['requested_max_m'],8)
        self.assertNotEqual(frozen['freeze_sha256'],self.freeze(count=71217)['freeze_sha256'])
        self.assertNotEqual(frozen['freeze_sha256'],self.freeze(graph='b'*64)['freeze_sha256'])
        changed=copy.deepcopy(ROWS);changed[0]['h_request']=21
        self.assertNotEqual(frozen['freeze_sha256'],self.freeze(changed)['freeze_sha256'])
        self.assertFalse(frozen['supplied_roster_external_completeness_verified'])
        self.assertFalse(frozen['graph_bytes_authenticated'])

    def test_subset_uses_whole_roster_maxima_and_stable_order(self):
        frozen=self.freeze()
        left=m.build_features(frozen,['m-hmf','a-hf'])
        right=m.build_features(frozen,['a-hf','m-hmf'])
        self.assertEqual(left,right)
        self.assertEqual(left['selected_action_uids'],['a-hf','m-hmf'])
        self.assertEqual(left['freeze_sha256'],frozen['freeze_sha256'])
        self.assertEqual(left['vectors'][0]['values'][4],2/20)
        self.assertEqual(left['vectors'][1]['values'][4],5/20)
        self.assertEqual(left['vectors'][1]['values'][5],3/8)
        self.assertEqual(len(left['feature_columns']),7)
        self.assertTrue(all(math.isfinite(x) for row in left['vectors'] for x in row['values']))

    def test_hf_has_no_m_stage_and_zero_feature_sentinel(self):
        frozen=self.freeze()
        hf=next(c for c in frozen['requested_controls'] if c['action_uid']=='a-hf')
        self.assertEqual(hf['stages'],[{'mode':'H','pattern_limit':2}])
        bundle=m.build_features(frozen,['a-hf'])
        values=bundle['vectors'][0]['values']
        self.assertEqual(values[0:2],[1.0,0.0])
        self.assertEqual(values[3],0.0)
        self.assertEqual(values[5],0.0)
        self.assertFalse(bundle['legacy_model_compatible'])
        self.assertFalse(bundle['future_unknown_actions_d95_preverified'])
        self.assertFalse(bundle['execution_ready'])
        self.assertFalse(bundle['training_release'])
        self.assertFalse(bundle['inference_release'])

    def test_outcome_or_realized_fields_and_aliases_rejected(self):
        for key,value in [('h_patterns',2),('m_patterns',3),('f_patterns',4),
                          ('detected_faults',10),('d95',95),('cycles',10),('runtime_ns',100)]:
            rows=copy.deepcopy(ROWS);rows[0][key]=value
            with self.assertRaises(ValueError):
                self.freeze(rows)
        rows=copy.deepcopy(ROWS);rows.append(dict(rows[0],action_uid='alias'))
        with self.assertRaisesRegex(ValueError,'COLLAPSE_ALIASES'):
            self.freeze(rows)
        rows=copy.deepcopy(ROWS);rows.append(dict(rows[0]))
        with self.assertRaises(ValueError):
            self.freeze(rows)
        with self.assertRaises(ValueError):
            self.freeze(ROWS*155)  # >462 entries, not a roster permission

    def test_tampered_freeze_hash_max_graph_count_schema_rejected(self):
        frozen=self.freeze()
        changes=[('freeze_sha256','0'*64),('requested_max_h',2),
                 ('requested_max_m',3),('graph_sha256','b'*64),
                 ('common_fault_count',71217),('feature_schema_id','LEGACY_V2'),
                 ('roster_sha256','0'*64)]
        for key,value in changes:
            altered=copy.deepcopy(frozen);altered[key]=value
            with self.assertRaises(ValueError):
                m.build_features(altered)
        altered=copy.deepcopy(frozen);altered['requested_roster'][0]['h_request']=100
        with self.assertRaises(ValueError):
            m.build_features(altered)
        # Python's bool/int and float/int equality must not alias canonical bytes.
        for mutation in (
            lambda x:x.__setitem__('requested_max_h',20.0),
            lambda x:x.__setitem__('execution_ready',0),
            lambda x:x['requested_controls'][0]['stages'][0].__setitem__('pattern_limit',2.0)):
            altered=copy.deepcopy(frozen)
            mutation(altered)
            with self.assertRaisesRegex(ValueError,'FREEZE_CHANGED_OR_SCHEMA_MISMATCH'):
                m.build_features(altered)
        hf_only=self.freeze([ROWS[1]])
        altered=copy.deepcopy(hf_only);altered['requested_max_m']=False
        with self.assertRaisesRegex(ValueError,'FREEZE_CHANGED_OR_SCHEMA_MISMATCH'):
            m.build_features(altered)
        with self.assertRaises(ValueError):
            self.freeze(count=True)
        with self.assertRaises(ValueError):
            self.freeze(graph='A'*64)
        with self.assertRaises(ValueError):
            self.freeze(graph='not-a-sha')

    def test_subset_duplicate_unknown_and_empty_rejected(self):
        frozen=self.freeze()
        for selected in ([],['a-hf','a-hf'],['missing'],[1],('a-hf',)):
            with self.assertRaises(ValueError):
                m.build_features(frozen,selected)
        self.assertEqual(len(m.build_features(frozen)['vectors']),3)

    def test_checkpoint_id_only_never_authenticates_weights_or_releases(self):
        exact=m.assess_checkpoint_schema('REQUESTED_COUNT_V1')
        self.assertTrue(exact['schema_id_compatible'])
        self.assertFalse(exact['checkpoint_authenticated'])
        self.assertFalse(exact['weights_authenticated'])
        self.assertFalse(exact['model_inference_performed'])
        self.assertFalse(exact['execution_ready'])
        self.assertFalse(exact['training_release'])
        self.assertFalse(exact['inference_release'])
        for schema in ('LEGACY_V2','runtime_training_v2','UNKNOWN',None,1):
            with self.assertRaisesRegex(ValueError,'CHECKPOINT_FEATURE_SCHEMA_MISMATCH'):
                m.assess_checkpoint_schema(schema)


if __name__=='__main__':
    unittest.main()
