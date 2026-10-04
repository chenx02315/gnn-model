import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.export_ranking_v3_real_inputs import (
    FEATURE_FIELDS, GRAPH_FIELDS, OUTCOME_FIELDS, export_real_inputs,
)
from src.models.runtime_ranking_v3 import FAMILIES, digest


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_tsv(path, fields, rows):
    with Path(path).open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n')
        writer.writeheader(); writer.writerows(rows)


class ExportRankingRealInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.graphs = self.root / 'source_graphs'; (self.graphs / 'graphs').mkdir(parents=True)
        features, outcomes, graph_rows = [], [], []
        for index, (circuit, family) in enumerate(sorted(FAMILIES.items())):
            graph = self.graphs / 'graphs' / (circuit + '.json')
            graph.write_text(json.dumps({'schema_version': 'runtime-graph-v1', 'circuit': circuit,
                                         'nodes': [{'node_type': 'cell', 'cell_type': 'NAND', 'sequential_flag': False}],
                                         'edge_index': []}), encoding='utf-8')
            graph_rows.append({'graph_key': circuit, 'circuit': circuit, 'graph_path': 'graphs/' + graph.name,
                               'graph_sha256': sha(graph)})
            for limit in (1, 2):
                uid = '%s:%d' % (circuit, limit)
                features.append({'action_uid': uid, 'circuit': circuit, 'family': family, 'role': 'TRAIN',
                                 'graph_key': circuit, 'action_scheme': 'HF' if limit == 1 else 'HMF',
                                 'h_limit': str(limit), 'm_limit': '0', 'common_fault_count': '10'})
                outcomes.append({'action_uid': uid, 'execution_status': 'SUCCESS', 'is_d95_feasible': '1',
                                 'total_cycles': str(100 + index + limit), 'policy_charged_runtime_s': '1.5',
                                 'epsilon_hit': '1'})
        # Source may carry non-TRAIN rows; they are not projected or graph-copied.
        features.append({'action_uid': 'validation:1', 'circuit': 'validation', 'family': 'v_family', 'role': 'VALIDATION',
                         'graph_key': 'validation', 'action_scheme': 'HF', 'h_limit': '1', 'm_limit': '0', 'common_fault_count': '10'})
        validation_graph = self.graphs / 'graphs' / 'validation.json'
        validation_graph.write_text(json.dumps({'schema_version': 'runtime-graph-v1', 'circuit': 'validation',
                                                'nodes': [], 'edge_index': []}), encoding='utf-8')
        graph_rows.append({'graph_key': 'validation', 'circuit': 'validation', 'graph_path': 'graphs/validation.json',
                           'graph_sha256': sha(validation_graph)})
        self.features = self.root / 'features.tsv'; self.outcomes = self.root / 'train_outcomes.tsv'; self.manifest = self.root / 'graph_manifest.tsv'
        write_tsv(self.features, FEATURE_FIELDS, features); write_tsv(self.outcomes, OUTCOME_FIELDS, outcomes); write_tsv(self.manifest, GRAPH_FIELDS, graph_rows)
        self.expected = {'features.tsv': sha(self.features), 'train_outcomes.tsv': sha(self.outcomes), 'graph_manifest.tsv': sha(self.manifest)}
        self.release = {'status': 'PASS_TRAIN_ONLY_SOURCE_EXPORT_RELEASE', 'code_review_sha256': 'b' * 64, 'user_authorization': True}
        self.release_sha = digest(self.release)

    def tearDown(self): self.temp.cleanup()

    def call(self, output, **overrides):
        args = dict(release=self.release, expected_release_sha256=self.release_sha,
                    expected=self.expected, expected_train_count=12)
        args.update(overrides)
        return export_real_inputs(output, self.features, self.outcomes, self.manifest, self.graphs, **args)

    def test_release_refuses_before_any_source_io(self):
        with patch('scripts.export_ranking_v3_real_inputs._read_tsv_once') as read:
            with self.assertRaises(ValueError): self.call(self.root / 'no', release={})
        read.assert_not_called()

    def test_feature_schema_matches_existing_builder_order(self):
        self.assertEqual(('role', 'family', 'circuit', 'action_uid', 'action_scheme',
                          'h_limit', 'm_limit', 'common_fault_count', 'graph_key'), FEATURE_FIELDS)

    def test_exports_train_only_six_folds(self):
        receipt = self.call(self.root / 'output')
        self.assertEqual(12, receipt['train_action_count']); self.assertEqual(6, receipt['graph_count'])
        self.assertEqual(6, len(receipt['fold_manifest_sha256']))
        self.assertTrue((self.root / 'output' / 'graphs' / 'aes_core.json').is_file())
        self.assertFalse((self.root / 'output' / 'graphs' / 'validation.json').exists())
        self.assertEqual(self.expected, receipt['source_input_sha256'])
        self.assertEqual({circuit: sha(self.root / 'output' / 'graphs' / (circuit + '.json'))
                          for circuit in sorted(FAMILIES)}, receipt['graph_sha256'])
        self.assertEqual(sha(self.root / 'output' / 'family_metadata.json'), receipt['family_metadata_sha256'])
        self.assertEqual(digest({'source_input_sha256': receipt['source_input_sha256'],
                                 'graph_sha256': receipt['graph_sha256']}), receipt['source_sha256'])

    def test_hash_mismatch_role_drift_and_graph_escape_refuse(self):
        with self.assertRaises(ValueError):
            self.call(self.root / 'bad_hash', expected=dict(self.expected, **{'features.tsv': '0' * 64}))
        with self.features.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream, delimiter='\t'))
        rows[0]['family'] = 'wrong'
        write_tsv(self.features, FEATURE_FIELDS, rows); changed = dict(self.expected, **{'features.tsv': sha(self.features)})
        with self.assertRaises(ValueError): self.call(self.root / 'bad_role', expected=changed)
        # Restore source then bind the malformed manifest, so path validation is reached.
        rows[0]['family'] = FAMILIES[rows[0]['circuit']]; write_tsv(self.features, FEATURE_FIELDS, rows)
        with self.manifest.open(encoding='utf-8', newline='') as stream:
            graphs = list(csv.DictReader(stream, delimiter='\t'))
        graphs[0]['graph_path'] = '../escape.json'
        write_tsv(self.manifest, GRAPH_FIELDS, graphs)
        expected = dict(self.expected, **{'features.tsv': sha(self.features), 'graph_manifest.tsv': sha(self.manifest)})
        with self.assertRaises(ValueError): self.call(self.root / 'bad_graph', expected=expected)


if __name__ == '__main__': unittest.main()
