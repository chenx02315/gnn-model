"""Generated in-memory HELDOUT fixtures only; no formal probes or data readers."""
import copy
import json
import unittest
from unittest.mock import patch

from src.models import ranking_v6_multi_positive_joint_caller as caller
from src.models import ranking_v6_synthetic_joint_freeze as gate


class PoisonLoader:
    def __init__(self, outcomes):
        self.calls = 0
        self.outcomes = outcomes

    def __len__(self):
        raise AssertionError('LOADER_LEN')

    def __iter__(self):
        raise AssertionError('LOADER_ITER')

    def __call__(self):
        self.calls += 1
        return self.outcomes


class SyntheticJointFreezeTests(unittest.TestCase):
    def setUp(self):
        self.features, self.outcomes = caller.generated_fixture()
        for row in self.features:
            row['role'] = 'HELDOUT'
        self.scores = {row['action_uid']: .1 * (i // 2) for i, row in enumerate(self.features)}
        self.options = dict(normalizer_bytes=gate.identity_normalizer_bytes(),
                            model_sha256='a' * 64, synthetic_only=True)
        self.frozen = gate.freeze_snapshot(self.features, self.scores, **self.options)
        self.loader = PoisonLoader(self.outcomes)

    def release(self, frozen=None, readback=None, **changes):
        return gate.release_outcomes(self.frozen if frozen is None else frozen,
                                     self.frozen if readback is None else readback,
                                     self.features, self.scores, outcome_loader=self.loader,
                                     **dict(self.options, **changes))

    def test_canonical_permutation_tie_ranking_and_identity(self):
        before = copy.deepcopy((self.features, self.scores))
        shuffled = gate.freeze_snapshot(list(reversed(self.features)),
                                       dict(reversed(list(self.scores.items()))), **self.options)
        self.assertEqual(self.frozen, shuffled)
        payload = json.loads(self.frozen)['snapshot']
        self.assertEqual(payload['ranking'], ['u004', 'u005', 'u002', 'u003', 'u000', 'u001'])
        self.assertEqual(payload['action_uids'], sorted(self.scores))
        self.assertEqual(json.loads(self.options['normalizer_bytes']),
                         dict(type='identity_generated_bounded_v1', fit_only=True,
                              feature_names=list(gate.FEATURES)))
        self.assertEqual(before, (self.features, self.scores))

    def test_exact_readback_then_one_call(self):
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('random.Random', side_effect=AssertionError('RNG')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')):
            result = self.release()
        self.assertEqual(self.loader.calls, 1)
        self.assertEqual(result['outcome_count'], 6)
        self.assertEqual(result['freeze_sha256'], result['readback_sha256'])
        self.assertTrue(result['held_outcome_release'])
        self.assertTrue(result['freeze_verified_before_loader_access'])
        for flag in ('fit_performed', 'actual_training', 'normalizer_fitted', 'real_data_access',
                     'real_heldout_release', 'generalization_claim'):
            self.assertFalse(result[flag])

    def test_stale_or_corrupt_freeze_and_readback_no_loader_inspection(self):
        for frozen, readback in ((b'{}', self.frozen), (self.frozen, b'{}'),
                                 (self.frozen + b' ', self.frozen),
                                 (b'', self.frozen), ('{}', self.frozen),
                                 (b'x' * (gate.MAX_BYTES + 1), self.frozen)):
            with self.subTest(kind=type(frozen)), self.assertRaises(ValueError):
                self.release(frozen=frozen, readback=readback)
        self.assertEqual(self.loader.calls, 0)
        # Exact-current-byte mismatch is checked before even callable(loader).
        with patch('builtins.callable', side_effect=AssertionError('CALLABLE')):
            with self.assertRaisesRegex(ValueError, 'MISMATCH'):
                self.release(readback=b'{}')

    def test_stale_scores_uid_features_norm_model_and_schema_zero_calls(self):
        changes = [dict(normalizer_bytes=b'{}'), dict(model_sha256='b'*64),
                   dict(model_sha256='A'*64), dict(synthetic_only=False),
                   dict(synthetic_only=1)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.release(**change)
        for mutator in (lambda: self.scores.update(u000=.9),
                        lambda: self.scores.pop('u000'),
                        lambda: self.features[0].update(log1p_h_limit=.9),
                        lambda: self.features[0].update(action_uid='different'),
                        lambda: self.features[0].update(role='FIT'),
                        lambda: self.features[0].update(extra=0)):
            old_features, old_scores = copy.deepcopy(self.features), dict(self.scores)
            mutator()
            with self.assertRaises(ValueError):
                self.release()
            self.features, self.scores = old_features, old_scores
        self.assertEqual(self.loader.calls, 0)

    def test_normalizer_and_snapshot_bytecap_before_parsing(self):
        with patch.object(gate.json, 'loads', side_effect=AssertionError('JSON_READ')):
            with self.assertRaises(ValueError):
                self.release(readback=b'x'*(gate.MAX_BYTES+1))
            with self.assertRaises(ValueError):
                self.release(normalizer_bytes=b'x'*(gate.MAX_BYTES+1))
            self.release()
        self.assertEqual(self.loader.calls, 1)

    def test_feature_domains_score_types_and_heldout_only(self):
        for field, value in (('scheme_hf', True), ('scheme_hmf', 2),
                             ('log1p_h_limit', -1), ('log1p_m_limit', 2.1),
                             ('h_limit_fraction_of_circuit_max', 1.1),
                             ('log1p_common_fault_count', float('nan')),
                             ('role', 'TRAIN'), ('circuit', 'other')):
            old = self.features[0][field]
            self.features[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.release()
            self.features[0][field] = old
        for value in (True, 21, float('inf'), 10**1000):
            self.scores['u000'] = value
            with self.assertRaises(ValueError):
                self.release()
        self.assertEqual(self.loader.calls, 0)

    def test_postrelease_invalid_outcomes_one_call_reject_no_filter(self):
        for mutation in (lambda rows: rows[0].update(execution_status='FAIL'),
                         lambda rows: rows[0].update(is_d95_feasible=0),
                         lambda rows: rows[0].update(total_cycles=True),
                         lambda rows: rows[0].update(policy_charged_runtime_s=0),
                         lambda rows: rows[0].update(extra=1),
                         lambda rows: rows[0].update(action_uid='other'),
                         lambda rows: rows.pop(), lambda rows: rows.append(dict(rows[0]))):
            rows = copy.deepcopy(self.outcomes)
            mutation(rows)
            self.loader = PoisonLoader(rows)
            with self.assertRaises(ValueError):
                self.release()
            self.assertEqual(self.loader.calls, 1)

    def test_noncallable_only_checked_after_barrier_and_no_outcome_mutation(self):
        self.loader = object()
        with self.assertRaisesRegex(ValueError, 'MISMATCH'):
            self.release(readback=b'{}')
        with self.assertRaisesRegex(ValueError, 'OUTCOME_LOADER'):
            self.release()
        original = copy.deepcopy(self.outcomes)
        self.loader = PoisonLoader(tuple(reversed(self.outcomes)))
        first = self.release()
        self.loader = PoisonLoader(self.outcomes)
        second = self.release()
        self.assertEqual(first['outcome_sha256'], second['outcome_sha256'])
        self.assertEqual(original, self.outcomes)


if __name__ == '__main__':
    unittest.main()
