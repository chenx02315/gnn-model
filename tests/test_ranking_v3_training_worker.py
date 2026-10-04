import json
from pathlib import Path
import tempfile
import unittest
from tests.test_runtime_ranking_v3 import fixture
from src.models.runtime_ranking_v3 import plan_folds, replay_frozen
from src.models.ranking_v3_training_worker import execute
from src.models.ranking_v3_freeze_io import read_freeze
from src.models.run_runtime_ranking_v3 import SEEDS

def request_for(rows, outcomes, fold, seed, model):
    rows = [dict(r, graph_key=r['circuit'], action_scheme='HMF', h_limit=i, m_limit=0) for i,r in enumerate(rows)]
    return {'scope':'TRAIN_ONLY_WORKER_NO_HELD_LABELS', 'source_sha256':'a'*64,
            'family':fold.family, 'seed':seed, 'model':model, 'rows':rows,
            'fit_outcomes':{u:outcomes[u] for u in fold.fitting}, 'graphs':[],
            'graph_contract':{'features':{'node_type_buckets':16,'cell_type_hash_buckets':64}}}

class WorkerTests(unittest.TestCase):
    def test_schema_rejects_held_labels_and_fixed_freeze(self):
        rows, outcomes = fixture(); fold = plan_folds(rows)[0]
        request = request_for(rows, outcomes, fold, SEEDS[0], 'fixed_heuristic')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'worker'
            bad = dict(request, heldout_outcomes={u:outcomes[u] for u in fold.heldout})
            with self.assertRaisesRegex(ValueError, 'SCHEMA'):
                execute(bad, output, None, None, None)
            self.assertFalse(output.exists())
            result = execute(request, output, None, None, None)
            self.assertFalse(result['held_labels_supplied'])
            freeze = read_freeze(output/'freeze.json', result['freeze_sha256'])
            self.assertEqual(set(freeze['scores']), set(fold.heldout))

    def test_real_adapters_full_toy_grid_fixed_worker(self):
        try:
            import torch
            import numpy as np
            import xgboost as xgb
        except ImportError:
            self.skipTest('ML dependencies absent; real worker execution not verified locally')
        rows, outcomes = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); graphs=[]
            import hashlib
            for circuit in sorted({r['circuit'] for r in rows}):
                path = root/(circuit+'.json')
                path.write_text(json.dumps({'schema_version':'runtime-graph-v1', 'circuit':circuit,
                    'nodes':[{'node_type':'cell','cell_type':'NAND','sequential_flag':False}], 'edge_index':[]}))
                graphs.append(dict(graph_key=circuit, path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            count = 0
            for fold in plan_folds(rows):
                for seed in SEEDS:
                    for model in ('candidate_mlp','graphsage','xgboost','fixed_heuristic'):
                        request = request_for(rows, outcomes, fold, seed, model); request['graphs']=graphs
                        worker = execute(request, root/(fold.family+str(seed)+model), torch, np, xgb)
                        freeze = read_freeze(root/(fold.family+str(seed)+model)/'freeze.json', worker['freeze_sha256'])
                        result = replay_frozen(freeze, worker['freeze_sha256'], fold, {u:outcomes[u] for u in fold.heldout})
                        self.assertIn(result['hit_at_10'], (0,1)); count += 1
            self.assertEqual(count, 72)

if __name__ == '__main__':
    unittest.main()
