"""Frozen local inputs only; policy checks are not a live simulation result."""
import hashlib
import json
from pathlib import Path
import unittest

from src.data import hf_detection_credit_e134 as audit


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]
        cls.spec = json.loads((cls.repo / 'contracts/physical_f_replay_measurement_spec_e135_v1.json').read_bytes())

    def test_frozen_baseline_DI_count_and_canonical_set_hash(self):
        folder = self.repo.parent / 'runtime_training_staging_20260928/v6_e133_eq_group_readback_20261027_r1/files'
        bodies = {k:(folder / audit.groups.PINS[k][1]).read_bytes() for k in ('F_basic','mapping','manifest')}
        for role, raw in bodies.items():
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), audit.groups.PINS[role])
        manifest = json.loads(bodies['manifest'])
        lookup, keys = audit.extension.mapping_lookup(bodies['mapping'], 71216, manifest['f_flat_instance_offset'], 'F', 'H')
        labels = audit._basic_classes(bodies['F_basic'], 71216, set(lookup))
        self.assertNotIn('DS', labels.values())
        detected = {lookup[k] for k,label in labels.items() if audit.extension.detected(label)}
        baseline = self.spec['baseline_before_any_external_pattern']
        self.assertEqual(len(keys), self.spec['common_universe']['count'])
        self.assertEqual(len(detected), baseline['allowed_detected_count'])
        self.assertEqual(audit._set_hash(detected), baseline['allowed_canonical_detected_set_sha256'])

    def test_three_distinct_snapshots_and_no_preload_waiver(self):
        snapshots = self.spec['required_snapshot_stages']
        self.assertEqual(len(snapshots), 3)
        self.assertIn('before read_patterns', snapshots[0])
        self.assertIn('before simulate_patterns', snapshots[1])
        self.assertTrue(self.spec['post_import_pre_simulation_policy']['same_baseline_DI_only_set_required'])
        self.assertEqual(self.spec['detection_credit']['PT_PD_credit'], 0)
        self.assertEqual(self.spec['detection_credit']['D95_requires_independent_actual_union_count_at_least'], 67656)

    def test_spec_not_new_authority_or_budget_expansion(self):
        proposal_path = self.repo / 'contracts/physical_f_pattern_replay_proposal_e135_v1.json'
        raw = proposal_path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.spec['proposal_sha256'])
        proposal = json.loads(raw)
        for key in ('result_body_bytes_total_max','result_response_bytes_max'):
            self.assertEqual(self.spec['within_existing_proposal_limits'][key], proposal['scope_if_granted'][key])
        for key in ('execution_ready','physical_HF_D95_verified','training_release'):
            self.assertIs(self.spec[key], False)
        self.assertIs(proposal['user_authorization_received'], False)


if __name__ == '__main__':
    unittest.main()
