import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import collect_ranking_v4_r4_results as collector
from src.models.runtime_ranking_v3 import FAMILIES
from src.models.run_runtime_ranking_v3 import SEEDS
from src.models.ranking_v4_real_worker import MODEL, PACKAGE_SHA256, SCOPE as WORKER_SCOPE, SOURCE_SHA256
from scripts.run_ranking_v4_real_experiment import SCOPE as RUNNER_SCOPE


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')


def fixture(root):
    write(root / 'independent_review.json', {'name': 'review', 'request': {'must_not_export': True}})
    review_sha = collector._sha((root / 'independent_review.json').read_bytes())
    release = {'status': 'PASS_V4_TRAIN_ONLY_EXECUTION', 'source_sha256': SOURCE_SHA256,
               'package_receipt_sha256': PACKAGE_SHA256, 'roles': ['TRAIN'], 'seeds': list(SEEDS), 'model': MODEL,
               'training_release': True, 'independent_review_sha256': review_sha}
    write(root / 'execution_release.json', release); release_sha = collector._sha((root / 'execution_release.json').read_bytes())
    write(root / 'launch_receipt.json', {'release_sha256': release_sha,
          'package': '/ssd/cjc/gnn_model_ranking_v3_train_0ca7dbf_20261004_r1/train_folds',
          'package_sha256': PACKAGE_SHA256, 'output': str(root / 'experiment'), 'code_root': '/sealed/code',
          'launcher_sha256': 'd' * 64, 'expected_evaluations': 18, 'max_concurrent_workers': 1, 'retries': 0,
          'started_unix': 1, 'pid': 2})
    write(root / 'exit_receipt.json', {'exit_code': 0, 'retries': 0, 'release_sha256': release_sha})
    write(root / 'experiment/summary.json', {'scope': RUNNER_SCOPE, 'model': MODEL,
          'receipt_count': 18, 'nonexhaustive_count': 15})
    for family in FAMILIES.values():
        for seed in SEEDS:
            token = family + '_' + str(seed) + '_candidate_mlp'; folder = root / 'experiment' / token
            common = {'family': family, 'seed': seed, 'model': MODEL, 'source_sha256': SOURCE_SHA256,
                      'freeze_sha256': 'b' * 64, 'pair_recipe_sha256': 'c' * 64}
            write(folder / 'worker_receipt.json', dict(common, scope=WORKER_SCOPE, held_labels_supplied=False,
                  request={'rows': ['never']}, held_cycles={'uid': 7}))
            write(root / 'experiment' / (token + '.log.memory.json'),
                  {'status': 'PASS_BOUNDED_WORKER', 'exit_code': 0, 'source_labels': {'never': 1}})
            write(folder / 'evaluation.json', dict(common, scope=RUNNER_SCOPE,
                  metrics={'hit_at_10': 1, 'candidate_uids': ['never']}, memory_guard={'status': 'PASS_BOUNDED_WORKER'},
                  freeze={'scores': {'must_not_export': 0}}, source_labels={'never': 1}))


class R4CollectionTests(unittest.TestCase):
    def collect_root(self, root):
        with patch.object(collector, 'ROOT', root): return collector.collect()

    def test_small_projected_export_and_create_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); receipt = self.collect_root(root)
            result = json.loads((root / collector.OUTPUT_NAME).read_text())
            self.assertEqual(59, receipt['entry_count']); self.assertEqual(59, result['entry_count'])
            evaluation = next(value for key, value in result['records'].items() if key.endswith('/evaluation.json'))['data']
            worker = next(value for key, value in result['records'].items() if key.endswith('/worker_receipt.json'))['data']
            self.assertEqual(set(collector.EVALUATION_FIELDS), set(evaluation)); self.assertNotIn('freeze', evaluation)
            self.assertNotIn('candidate_uids', evaluation['metrics']); self.assertNotIn('request', worker)
            self.assertNotIn('held_cycles', worker)
            with self.assertRaises(FileExistsError): self.collect_root(root)

    def test_exit_incomplete_and_memory_failure_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); write(root / 'exit_receipt.json', {'exit_code': 1, 'retries': 0})
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_EXIT'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); next((root / 'experiment').glob('*/evaluation.json')).unlink()
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_GRID'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            write(next((root / 'experiment').glob('*.memory.json')), {'status': 'STOPPED_NO_RETRY', 'exit_code': 1})
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_BINDING'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); worker = next((root / 'experiment').glob('*/worker_receipt.json'))
            value = json.loads(worker.read_text()); value['held_labels_supplied'] = True; write(worker, value)
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_BINDING'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); launch = root / 'launch_receipt.json'
            value = json.loads(launch.read_text()); value['release_sha256'] = '0' * 64; write(launch, value)
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_RELEASE_BINDING'): self.collect_root(root)

    def test_duplicate_grid_and_worker_binding_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); evaluation = next((root / 'experiment').glob('*/evaluation.json'))
            value = json.loads(evaluation.read_text()); value['family'] = next(iter(FAMILIES.values())); value['seed'] = next(iter(SEEDS)); write(evaluation, value)
            worker = evaluation.parent / 'worker_receipt.json'; value = json.loads(worker.read_text())
            value['family'] = next(iter(FAMILIES.values())); value['seed'] = next(iter(SEEDS)); write(worker, value)
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_GRID'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); worker = next((root / 'experiment').glob('*/worker_receipt.json'))
            value = json.loads(worker.read_text()); value['freeze_sha256'] = 'd' * 64; write(worker, value)
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_BINDING'): self.collect_root(root)

    def test_bounds_refuse_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            (root / 'launch_receipt.json').write_bytes(b'x' * (collector.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_BOUND'): self.collect_root(root)
            self.assertFalse((root / collector.OUTPUT_NAME).exists())

    def test_extra_grid_and_nested_evaluation_metadata_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            source = next((root / 'experiment').glob('*/evaluation.json'))
            extra = root / 'experiment' / 'extra_candidate_mlp' / 'evaluation.json'; extra.parent.mkdir()
            extra.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_GRID'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); evaluation = next((root / 'experiment').glob('*/evaluation.json'))
            value = json.loads(evaluation.read_text()); value['family'] = {'graph': 'forbidden'}; write(evaluation, value)
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_EVALUATION_METADATA'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            write(root / 'experiment' / 'extra.log.memory.json', {'status': 'PASS_BOUNDED_WORKER', 'exit_code': 0})
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_GRID'): self.collect_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root); write(root / 'old_exit_receipt.json', {'exit_code': 0})
            with self.assertRaisesRegex(ValueError, 'V4_R4_COLLECTION_GRID'): self.collect_root(root)


if __name__ == '__main__': unittest.main()
