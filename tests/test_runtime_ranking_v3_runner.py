import copy
import unittest
from tests.test_runtime_ranking_v3 import fixture
from src.models.runtime_ranking_v3 import plan_folds,prepare_fold,fit_normalizer,feature_matrix
from src.models.run_runtime_ranking_v3 import run_fold,run_six_folds,aggregate_three_seeds,SEEDS
from src.models.xgboost_ranking_v3 import pack_groups,make_ranker

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.rows,self.outcomes=fixture(); self.events=[]
        self.callbacks=dict(load_fitting=self.load_fit,fit=self.fit,predict=self.predict,
                            persist_freeze=self.persist,load_heldout=self.load_held,
                            mode='synthetic',fixture_attestation='GENERATED_SYNTHETIC_NO_EXTERNAL_DATA')
    def load_fit(self,uids):
        self.events.append('fit_labels'); return {u:self.outcomes[u] for u in uids}
    def fit(self,prep,seed):
        self.events.append('fit'); self.assertEqual(len(prep['fit_uids']),15)
        return prep
    def predict(self,model,uids,x):
        self.events.append('predict'); return {u:-float(u.split(':')[-1]) for u in uids}
    def persist(self,payload,sha):
        self.events.append('freeze'); return sha
    def load_held(self,uids,sha):
        self.assertEqual(self.events[-1],'freeze'); self.events.append('held_labels')
        return {u:self.outcomes[u] for u in uids}
    def test_order_and_determinism(self):
        fold=plan_folds(self.rows)[0]
        first=run_fold(self.rows,fold,SEEDS[0],**self.callbacks)
        self.assertEqual(self.events,['fit_labels','fit','predict','freeze','held_labels'])
        self.events=[]
        self.assertEqual(first,run_fold(self.rows,fold,SEEDS[0],**self.callbacks))
    def test_formal_rejected_before_io(self):
        callbacks=dict(self.callbacks,mode='formal')
        with self.assertRaises(ValueError): run_fold(self.rows,plan_folds(self.rows)[0],SEEDS[0],**callbacks)
        self.assertEqual(self.events,[])
    def test_failed_persistence_never_reads_held_labels(self):
        callbacks=dict(self.callbacks,persist_freeze=lambda p,s: 'wrong')
        with self.assertRaises(ValueError): run_fold(self.rows,plan_folds(self.rows)[0],SEEDS[0],**callbacks)
        self.assertNotIn('held_labels',self.events)
    def test_mutated_freeze_never_reads_held_labels(self):
        def mutate(payload,sha):
            payload['epsilon']=.05
            return sha
        callbacks=dict(self.callbacks,persist_freeze=mutate)
        with self.assertRaises(ValueError): run_fold(self.rows,plan_folds(self.rows)[0],SEEDS[0],**callbacks)
        self.assertNotIn('held_labels',self.events)
    def test_all_folds_all_seeds_and_no_selection(self):
        receipts=[]
        for seed in SEEDS: receipts.extend(run_six_folds(self.rows,seed,**self.callbacks))
        result=aggregate_three_seeds(receipts)
        self.assertEqual(result['receipt_count'],18)
        self.assertEqual(result['family_seed_macro']['hit_at_10'],1)
        with self.assertRaises(ValueError): aggregate_three_seeds(receipts[:-1])
        with self.assertRaises(ValueError): aggregate_three_seeds(receipts[:-1]+[receipts[0]])
        changed=copy.deepcopy(receipts); changed[0]['freeze']['epsilon']=.05
        with self.assertRaises(ValueError): aggregate_three_seeds(changed)
    def test_xgb_groups_and_relevance(self):
        fold=plan_folds(self.rows)[0]
        prep=prepare_fold(self.rows,{u:self.outcomes[u] for u in fold.fitting},fold,SEEDS[0])
        rows=[r for r in self.rows if r['action_uid'] in fold.fitting]
        packed=pack_groups(rows,prep['targets'],prep['normalizer'])
        self.assertEqual(packed['group'],[3]*5)
        self.assertEqual(packed['sample_weight'],[1]*5)
        self.assertEqual(packed['y'],[2,1,0]*5)
        self.assertEqual(len(packed['x'][0]),7)
        self.assertEqual(packed,pack_groups(list(reversed(rows)),prep['targets'],prep['normalizer']))
    def test_xgb_constructor_exact_protocol(self):
        class Fake:
            @staticmethod
            def XGBRanker(**args): return args
        cfg=make_ranker(Fake,SEEDS[0])
        self.assertEqual(cfg['objective'],'rank:pairwise')
        self.assertEqual(cfg['n_jobs'],1)
        self.assertEqual(cfg['random_state'],SEEDS[0])

    def test_xgb_fit_has_no_eval_set_or_row_weights(self):
        from src.models.xgboost_ranking_v3 import fit_ranker
        class NP:
            @staticmethod
            def asarray(value,dtype=None): return value
        calls=[]
        class Model:
            def fit(self,x,y,**kwargs): calls.append((x,y,kwargs))
        class Fake:
            @staticmethod
            def XGBRanker(**args): return Model()
        fold=plan_folds(self.rows)[0]
        prep=prepare_fold(self.rows,{u:self.outcomes[u] for u in fold.fitting},fold,SEEDS[0])
        packed=pack_groups([r for r in self.rows if r['action_uid'] in fold.fitting],prep['targets'],prep['normalizer'])
        fit_ranker(Fake,NP,packed,SEEDS[0])
        self.assertNotIn('eval_set',calls[0][2])
        self.assertEqual(len(calls[0][2]['sample_weight']),5)

    def test_real_xgb_repeatability(self):
        try:
            import numpy as np
            import xgboost as xgb
        except ImportError:
            self.skipTest('XGBoost absent; real fitting/determinism remains NOT_VERIFIED')
        from src.models.xgboost_ranking_v3 import fit_ranker
        fold=plan_folds(self.rows)[0]
        prep=prepare_fold(self.rows,{u:self.outcomes[u] for u in fold.fitting},fold,SEEDS[0])
        packed=pack_groups([r for r in self.rows if r['action_uid'] in fold.fitting],prep['targets'],prep['normalizer'])
        first=fit_ranker(xgb,np,packed,SEEDS[0]).predict(np.asarray(packed['x']))
        second=fit_ranker(xgb,np,packed,SEEDS[0]).predict(np.asarray(packed['x']))
        np.testing.assert_array_equal(first,second)

if __name__=='__main__': unittest.main()
