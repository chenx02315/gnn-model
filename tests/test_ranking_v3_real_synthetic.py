"""Actual model fitting, exclusively on in-memory generated toy circuits."""
import unittest
from tests.test_runtime_ranking_v3 import fixture
from src.models.runtime_ranking_v3 import plan_folds,prepare_fold,feature_matrix,transform
from src.models.neural_ranking_v3 import fit_neural,predict_neural
from src.models.xgboost_ranking_v3 import pack_groups,fit_ranker
from src.models.run_runtime_ranking_v3 import SEEDS

class RealSyntheticTests(unittest.TestCase):
    def test_full_six_fold_three_seed_real_model_pipeline(self):
        try:
            import torch
            import numpy as np
            import xgboost as xgb
        except ImportError:
            self.skipTest('ML dependencies absent: full real synthetic grid NOT_VERIFIED')
        from src.models.run_runtime_ranking_v3 import run_six_folds,aggregate_three_seeds
        rows,outcomes=fixture()
        graphs={r['circuit']:(torch.zeros(2,81),torch.tensor([[0,1],[1,0]],dtype=torch.long)) for r in rows}
        circuit={r['action_uid']:r['circuit'] for r in rows}
        for kind in ('candidate_mlp','graphsage','xgboost'):
            receipts=[]
            def fit(prep,seed):
                if kind=='xgboost':
                    fit_rows=[r for r in rows if r['action_uid'] in prep['fit_uids']]
                    return fit_ranker(xgb,np,pack_groups(fit_rows,prep['targets'],prep['normalizer']),seed)
                kwargs=dict(graphs=graphs,uid_graph_keys={u:circuit[u] for u in prep['fit_uids']}) if kind=='graphsage' else {}
                return fit_neural(torch,np,prep,seed,**kwargs)
            def predict(model,uids,x):
                if kind=='xgboost':
                    return dict(zip(uids,map(float,model.predict(np.asarray(x)))))
                kwargs=dict(graphs=graphs,uid_graph_keys={u:circuit[u] for u in uids}) if kind=='graphsage' else {}
                return predict_neural(torch,model,uids,x,**kwargs)
            for seed in SEEDS:
                receipts.extend(run_six_folds(rows,seed,
                    load_fitting=lambda uids:{u:outcomes[u] for u in uids},
                    fit=fit,predict=predict,persist_freeze=lambda payload,sha:sha,
                    load_heldout=lambda uids,sha:{u:outcomes[u] for u in uids},
                    mode='synthetic',fixture_attestation='GENERATED_SYNTHETIC_NO_EXTERNAL_DATA'))
            self.assertEqual(aggregate_three_seeds(receipts)['receipt_count'],18)

    def test_all_seeds_neural_fitting_and_repeatability(self):
        try:
            import torch
            import numpy as np
        except ImportError:
            self.skipTest('PyTorch absent: no model execution PASS')
        rows,outcomes=fixture(); fold=plan_folds(rows)[0]
        for seed in SEEDS:
            prep=prepare_fold(rows,{u:outcomes[u] for u in fold.fitting},fold,seed)
            held=sorted((r for r in rows if r['action_uid'] in fold.heldout),key=lambda r:r['action_uid'])
            uids=tuple(r['action_uid'] for r in held)
            x=transform(feature_matrix(held),prep['normalizer'])
            graphs={r['circuit']:(torch.zeros(2,81),torch.tensor([[0,1],[1,0]],dtype=torch.long)) for r in rows}
            fit_keys={r['action_uid']:r['circuit'] for r in rows if r['action_uid'] in fold.fitting}
            held_keys={r['action_uid']:r['circuit'] for r in held}
            for graph in (False,True):
                kwargs=dict(graphs=graphs,uid_graph_keys=fit_keys) if graph else {}
                predict_kwargs=dict(graphs=graphs,uid_graph_keys=held_keys) if graph else {}
                first=fit_neural(torch,np,prep,seed,**kwargs)
                a=predict_neural(torch,first,uids,x,**predict_kwargs)
                second=fit_neural(torch,np,prep,seed,**kwargs)
                b=predict_neural(torch,second,uids,x,**predict_kwargs)
                self.assertEqual(a,b)
                for key,value in first.state_dict().items():
                    self.assertTrue(torch.equal(value,second.state_dict()[key]))
                self.assertTrue(all(p.device.type=='cpu' for p in first.parameters()))

    def test_all_seeds_xgboost_fitting_and_repeatability(self):
        try:
            import numpy as np
            import xgboost as xgb
        except ImportError:
            self.skipTest('XGBoost absent: no model execution PASS')
        rows,outcomes=fixture(); fold=plan_folds(rows)[0]
        fit_rows=[r for r in rows if r['action_uid'] in fold.fitting]
        for seed in SEEDS:
            prep=prepare_fold(rows,{u:outcomes[u] for u in fold.fitting},fold,seed)
            packed=pack_groups(fit_rows,prep['targets'],prep['normalizer'])
            first=fit_ranker(xgb,np,packed,seed)
            second=fit_ranker(xgb,np,packed,seed)
            np.testing.assert_array_equal(first.predict(np.asarray(packed['x'])),second.predict(np.asarray(packed['x'])))
            self.assertEqual(first.get_booster().save_raw(),second.get_booster().save_raw())

if __name__=='__main__': unittest.main()
