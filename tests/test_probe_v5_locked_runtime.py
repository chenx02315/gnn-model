import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import probe_v5_locked_runtime as probe
from src.models.ranking_v5_caller_source_binding import parse_lock_bytes


class RuntimeMetadataTests(unittest.TestCase):
    def test_wrong_host_context_refuses_before_distribution_or_spec_lookup(self):
        with patch.object(probe.sys,'platform','win32'), \
             patch.object(probe.metadata,'distribution') as dist, \
             patch.object(probe.importlib.util,'find_spec') as spec:
            with self.assertRaisesRegex(ValueError,'FIXED_RUNTIME'): probe.probe()
            dist.assert_not_called(); spec.assert_not_called()

    def test_recorded_remote_metadata_matches_full_lock_not_training_proof(self):
        root = Path(__file__).resolve().parents[1]
        receipt = json.loads((root/'data/manifests/ranking_v5_b_runtime_metadata_20261008.json').read_bytes())
        expected = parse_lock_bytes((root/'requirements/runtime_v2.lock.txt').read_bytes())
        normalize = lambda name: name.lower().replace('_','-')
        self.assertEqual({normalize(n):v for n,v in receipt['versions'].items()}, expected)
        self.assertEqual(len(expected),31)
        self.assertEqual(receipt['interpreter'],probe.INTERPRETER)
        self.assertEqual(receipt['python'],'3.11.2')
        self.assertFalse(receipt['ml_imported'])
        self.assertFalse(receipt['formal_release'])
        self.assertFalse(receipt['actual_linux_resource_proof'])
        shared = '/ssd/cjc/gnn_model_runtime_v2_98efbd4f_20261002T235119/venv/lib/python3.11/site-packages'
        self.assertEqual(set(receipt['distribution_roots'].values()),{shared})
        for name in ('torch','numpy'):
            self.assertEqual(receipt['top_level_origins'][name], shared+'/'+name+'/__init__.py')


if __name__ == '__main__': unittest.main()
