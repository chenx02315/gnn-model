import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import collect_ranking_v4_r3_results as collector
from src.models.runtime_ranking_v3 import FAMILIES
from src.models.run_runtime_ranking_v3 import SEEDS


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')


def fixture(root):
    write(root / 'exit_receipt.json', {'exit_code': 0, 'retries': 0})
    for name in ('execution_release.json', 'independent_review.json', 'launch_receipt.json'):
        write(root / name, {'name': name})
    write(root / 'experiment/summary.json', {'receipt_count': 18})
    for family in FAMILIES.values():
        for seed in SEEDS:
            token = family + '_' + str(seed) + '_candidate_mlp'; folder = root / 'experiment' / token
            common = {'family': family, 'seed': seed, 'model': 'candidate_mlp', 'source_sha256': 'a' * 64,
                      'freeze_sha256': 'b' * 64, 'pair_recipe_sha256': 'c' * 64}
            write(folder / 'worker_receipt.json', dict(common, held_labels_supplied=False))
            write(root / 'experiment' / (token + '.log.memory.json'), {'status': 'PASS_BOUNDED_WORKER', 'exit_code': 0})
            write(folder / 'evaluation.json', dict(common, scope='TRAIN_ONLY_REAL_SIX_FOLD_V4',
                                                    metrics={'hit_at_10': 1}, memory_guard={'status': 'PASS_BOUNDED_WORKER'},
                                                    freeze={'scores': {'must_not_export': 0}}))


class R3CollectionTests(unittest.TestCase):
    def collect_root(self, root):
        with patch.object(collector, 'ROOT', root): return collector.collect()

    def test_small_projected_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); receipt = self.collect_root(root)
            result = json.loads((root / collector.OUTPUT_NAME).read_text())
            self.assertEqual(59, receipt['entry_count']); self.assertEqual(59, result['entry_count'])
            evaluation = next(value for key, value in result['records'].items() if key.endswith('/evaluation.json'))
            self.assertEqual(set(collector.EVALUATION_FIELDS), set(evaluation['data']))
            self.assertNotIn('freeze', evaluation['data'])
            self.assertEqual({'hit_at_10'}, set(evaluation['data']['metrics']))
            with self.assertRaises(FileExistsError): self.collect_root(root)

    def test_nested_leakage_fields_are_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            worker = next((root / 'experiment').glob('*/worker_receipt.json'))
            value = json.loads(worker.read_text()); value['held_cycles'] = {'uid': 7}; value['request'] = {'rows': ['uid']}; write(worker, value)
            evaluation = next((root / 'experiment').glob('*/evaluation.json'))
            value = json.loads(evaluation.read_text()); value['source_labels'] = {'uid': 1}; value['metrics']['candidate_uids'] = ['uid']; write(evaluation, value)
            receipt = self.collect_root(root); result = json.loads((root / collector.OUTPUT_NAME).read_text())
            worker_data = next(data['data'] for key, data in result['records'].items() if key.endswith('/worker_receipt.json'))
            eval_data = next(data['data'] for key, data in result['records'].items() if key.endswith('/evaluation.json'))
            self.assertNotIn('held_cycles', worker_data); self.assertNotIn('request', worker_data)
            self.assertNotIn('source_labels', eval_data); self.assertNotIn('candidate_uids', eval_data['metrics'])
            self.assertEqual(59, receipt['entry_count'])

    def test_exit_incomplete_duplicate_and_memory_fail_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            write(root / 'exit_receipt.json', {'exit_code': 1, 'retries': 0})
            with self.assertRaises(ValueError): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            next((root / 'experiment').glob('*/evaluation.json')).unlink()
            with self.assertRaises(ValueError): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            memory = next((root / 'experiment').glob('*.memory.json')); write(memory, {'status': 'STOPPED_NO_RETRY', 'exit_code': 1})
            with self.assertRaises(ValueError): self.collect_root(root)

    def test_duplicate_grid_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            evaluation = next((root / 'experiment').glob('*/evaluation.json'))
            value = json.loads(evaluation.read_text()); value['family'] = next(iter(FAMILIES.values())); value['seed'] = next(iter(SEEDS))
            write(evaluation, value)
            with self.assertRaises(ValueError): self.collect_root(root)


if __name__ == '__main__': unittest.main()
