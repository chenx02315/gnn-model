import copy
import json
import math
import unittest
from pathlib import Path
from src.models.runtime_ranking_v3 import (
    FAMILIES,FEATURES,Fold,plan_folds,feature_matrix,prepare_fold,bounded_pairs,
    pairwise_loss,freeze_ranking,replay_frozen)

def fixture():
    rows=[]; outcomes={}
    for circuit,family in FAMILIES.items():
        for i in range(3):
            uid=circuit+':'+str(i)
            rows.append(dict(action_uid=uid,circuit=circuit,family=family,role='TRAIN',
                             **{f:float(i) for f in FEATURES}))
            outcomes[uid]={'total_cycles':100+i*10,'policy_charged_runtime_s':2+i,
                           'execution_status':'SUCCESS','is_d95_feasible':1}
    return rows,outcomes

class RankingTests(unittest.TestCase):
    def setUp(self):
        self.rows,self.outcomes=fixture()
        self.fold=plan_folds(self.rows)[0]
        self.fit={u:self.outcomes[u] for u in self.fold.fitting}

    def test_contract_keeps_execution_closed(self):
        path=Path(__file__).resolve().parents[1]/'contracts/runtime_ranking_v3.json'
        contract=json.loads(path.read_text())
        self.assertEqual(contract['scope']['families'],FAMILIES)
        self.assertEqual(tuple(contract['features']['candidate']),FEATURES)
        self.assertEqual(contract['scope']['epsilon'],.01)
        self.assertEqual(contract['scope']['top_k'],10)
        self.assertFalse(contract['execution']['training_allowed'])
        self.assertFalse(contract['execution']['remote_access_allowed'])
        self.assertFalse(contract['execution']['blind_allowed'])
        self.assertFalse(contract['execution']['lsf_tessent_allowed'])

    def test_six_disjoint_folds_and_exact_coverage(self):
        folds=plan_folds(self.rows)
        self.assertEqual(len(folds),6)
        self.assertEqual(set(u for f in folds for u in f.heldout),set(self.outcomes))
        for f in folds:
            self.assertFalse(set(f.fitting)&set(f.heldout))
            self.assertEqual(len(f.fitting),15)

    def test_forbidden_roles_duplicate_and_family_drift(self):
        for role in ('VALIDATION','BLIND_TEST','PILOT'):
            rows=copy.deepcopy(self.rows); rows[0]['role']=role
            with self.assertRaises(ValueError): plan_folds(rows)
        with self.assertRaises(ValueError): plan_folds(self.rows+[self.rows[0]])
        rows=copy.deepcopy(self.rows); rows[0]['family']='wrong'
        with self.assertRaises(ValueError): plan_folds(rows)

    def test_only_fitting_outcomes_and_no_forged_fold(self):
        with self.assertRaises(ValueError): prepare_fold(self.rows,self.outcomes,self.fold,20260824)
        with self.assertRaises(ValueError): prepare_fold(self.rows,self.fit,Fold('wrong',self.fold.fitting,self.fold.heldout),20260824)

    def test_heldout_features_cannot_change_fit_normalizer_or_pairs(self):
        first=prepare_fold(self.rows,self.fit,self.fold,20260824)
        rows=copy.deepcopy(self.rows)
        for r in rows:
            if r['action_uid'] in self.fold.heldout:
                for f in FEATURES: r[f]=1e9
        second=prepare_fold(rows,self.fit,self.fold,20260824)
        self.assertEqual(first,second)

    def test_identifiers_oracle_runtime_predictions_never_features(self):
        x=feature_matrix(self.rows)
        rows=copy.deepcopy(self.rows)
        for r in rows: r.update(total_cycles=1e9,epsilon_hit=1,oracle=1,predicted_cycles=123,runtime=456)
        self.assertEqual(x,feature_matrix(rows))

    def test_within_circuit_pairs_orientation_determinism(self):
        prep=prepare_fold(self.rows,self.fit,self.fold,20260824)
        self.assertEqual(prep,prepare_fold(list(reversed(self.rows)),self.fit,self.fold,20260824))
        pairs=prep['pairs']
        again=bounded_pairs(list(reversed(self.rows)),prep['targets'],20260824)
        self.assertEqual(pairs,again)
        for family,group in pairs.items():
            self.assertLessEqual(len(group),4096)
            for b,w in group:
                self.assertEqual(b.split(':')[0],w.split(':')[0])
                self.assertLess(prep['targets'][b],prep['targets'][w])

    def test_family_macro_loss_and_preferred_scores(self):
        pairs={'a':(('x','y'),),'b':(('z','w'),)*10}
        good={'x':2,'y':0,'z':2,'w':0}
        self.assertAlmostEqual(pairwise_loss(good,pairs),math.log1p(math.exp(-2)))
        self.assertLess(pairwise_loss(good,pairs),pairwise_loss({k:-v for k,v in good.items()},pairs))

    def test_freeze_ties_tamper_and_no_hit_cost(self):
        scores={u:0 for u in self.fold.heldout}
        payload,sha=freeze_ranking(scores,self.fold)
        self.assertEqual(payload['order'],sorted(scores))
        outcomes={u:self.outcomes[u] for u in self.fold.heldout}
        result=replay_frozen(payload,sha,self.fold,outcomes)
        self.assertTrue(result['hit_found']); self.assertEqual(result['charged_runtime_s'],2)
        tamper=copy.deepcopy(payload); tamper['order'].reverse()
        with self.assertRaises(ValueError): replay_frozen(tamper,sha,self.fold,outcomes)
        with self.assertRaises(ValueError): replay_frozen(payload,'0'*64,self.fold,outcomes)

    def test_nonfinite_unsafe_and_fixed_seed(self):
        fit=copy.deepcopy(self.fit); fit[next(iter(fit))]['total_cycles']=float('nan')
        with self.assertRaises(ValueError): prepare_fold(self.rows,fit,self.fold,20260824)
        fit=copy.deepcopy(self.fit); fit[next(iter(fit))]['is_d95_feasible']=0
        with self.assertRaises(ValueError): prepare_fold(self.rows,fit,self.fold,20260824)
        with self.assertRaises(ValueError): prepare_fold(self.rows,self.fit,self.fold,0)

    def test_pair_cap_and_ties(self):
        rows=[dict(action_uid='spi:'+str(i),circuit='spi',family=FAMILIES['spi'],role='TRAIN') for i in range(100)]
        targets={r['action_uid']:float(i) for i,r in enumerate(rows)}
        pairs=bounded_pairs(rows,targets,20260824)
        self.assertEqual(len(pairs[FAMILIES['spi']]),4096)
        self.assertEqual(pairs,bounded_pairs(list(reversed(rows)),targets,20260824))
        with self.assertRaises(ValueError): bounded_pairs(rows,{u:0 for u in targets},20260824)

    def test_no_hit_budget_and_stop_at_first_hit(self):
        rows=[]
        for circuit,family in FAMILIES.items():
            for i in range(12):
                rows.append(dict(action_uid=circuit+':%02d'%i,circuit=circuit,family=family,role='TRAIN'))
        fold=plan_folds(rows)[0]
        scores={u:0 for u in fold.heldout}
        payload,sha=freeze_ranking(scores,fold)
        outcomes={u:dict(total_cycles=200,policy_charged_runtime_s=3,
                         execution_status='SUCCESS',is_d95_feasible=1) for u in fold.heldout}
        outcomes[payload['order'][-1]]['total_cycles']=100
        result=replay_frozen(payload,sha,fold,outcomes)
        self.assertFalse(result['hit_found']); self.assertEqual(result['attempt_count'],10)
        self.assertEqual(result['charged_runtime_s'],30)
        outcomes[payload['order'][2]]['total_cycles']=100
        result=replay_frozen(payload,sha,fold,outcomes)
        self.assertTrue(result['hit_found']); self.assertEqual(result['attempt_count'],3)
        self.assertEqual(result['charged_runtime_s'],9)

    def test_torch_loss_models_and_gradients(self):
        try:
            import torch
        except ImportError:
            self.skipTest('PyTorch absent; ML execution gate remains NOT_VERIFIED')
        from src.models.runtime_ranking_v3 import make_candidate_ranker,make_graph_ranker,torch_pairwise_loss
        torch.manual_seed(20260824)
        scores=torch.tensor([2.,0.,1.,0.],requires_grad=True)
        pairs={'a':(('x','y'),),'b':(('z','w'),)*10}; index={'x':0,'y':1,'z':2,'w':3}
        loss=torch_pairwise_loss(scores,index,pairs,torch)
        self.assertAlmostEqual(loss.item(),pairwise_loss(dict(zip(index,[2,0,1,0])),pairs),places=6)
        loss.backward(); self.assertTrue(torch.isfinite(scores.grad).all())
        x=torch.zeros(3,len(FEATURES))
        for model,output in [(make_candidate_ranker(torch),None),(make_graph_ranker(torch),None)]:
            if hasattr(model,'quality'):
                graph=(torch.zeros(2,81),torch.tensor([[0],[1]],dtype=torch.long))
                output=model({'g':graph},['g']*3,x)
            else: output=model(x)
            self.assertEqual(tuple(output.shape),(3,))
            output.sum().backward()
            self.assertTrue(all(torch.isfinite(p.grad).all() for p in model.parameters() if p.grad is not None))

if __name__=='__main__': unittest.main()
