"""Six-family fabricated integration; never opens outcomes or remote evidence."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.models.ranking_v6_materialized_fold import FAMILIES, FEATURES
from src.models.ranking_v6_accounted_fold import prepare_accounted_fold
from src.replay import ranking_v6_attempt_charges as charges


def fabricated(held='iwls_spi'):
    features, actions, attempts = [], [], []
    for c, (circuit, family) in enumerate(FAMILIES.items()):
        for i in range(2):
            uid = f'{circuit}.{i}'
            features.append(dict(zip(FEATURES, (1-i, i, c+i*.2, .1*c, .2*i, .4, 3.+c)),
                                 action_uid=uid, circuit=circuit, family=family, role='TRAIN'))
            if family == held:
                continue
            scheme = 'HF' if i == 0 else 'HMF'
            actions.append(dict(action_uid=uid, circuit=circuit, family=family,
                                role='TRAIN', action_scheme=scheme, execution_status='SUCCESS',
                                is_d95_feasible=1, total_cycles=100+i,
                                measurement_sha256='b'*64, environment_cohort='cohort1'))
            stages = ('H', 'F') if scheme == 'HF' else ('H', 'M', 'F')
            for stage in stages:
                attempts.append(dict(attempt_id=f'{uid}.{stage}.0', action_uid=uid,
                                     stage=stage, retry_order=0, execution_status='SUCCESS',
                                     wall_s=2., environment_cohort='cohort1', source_sha256='a'*64))
            # Charge failed/time-limited attempts before the successful H retry.
            h = next(a for a in attempts if a['attempt_id'] == f'{uid}.H.0')
            h['execution_status'] = 'FAILED'
            h['wall_s'] = 3.
            attempts.append(dict(h, attempt_id=f'{uid}.H.1', retry_order=1,
                                 execution_status='TIMEOUT', wall_s=5.))
            attempts.append(dict(h, attempt_id=f'{uid}.H.2', retry_order=2,
                                 execution_status='SUCCESS', wall_s=2.))
    return features, actions, attempts


class AccountedFoldTests(unittest.TestCase):
    def call(self, features, actions, attempts, held='iwls_spi'):
        return prepare_accounted_fold(features, actions, attempts, held_family=held,
                                      seed=20260824, implementation_only=True)

    def test_all_six_folds_preserve_every_retry_charge_and_macro_task(self):
        for held in FAMILIES.values():
            rows, actions, attempts = fabricated(held)
            original = copy.deepcopy((rows, actions, attempts))
            result = self.call(rows, actions, attempts, held)
            self.assertEqual(len(result['fold']['fit_tasks']), 5)
            self.assertEqual(len(result['fold']['held_uids']), 2)
            for task in result['fold']['fit_tasks']:
                self.assertTrue(task['all_positive'])
                self.assertEqual(sorted(task['costs'].values()), [12., 14.])
                self.assertEqual(task['cost_normalization_B'], 28.)
            self.assertFalse(result['real_training_release'])
            self.assertFalse(result['source_provenance_verified'])
            self.assertEqual(original, (rows, actions, attempts))

    def test_feature_barrier_precedes_action_and_attempt_inspection(self):
        rows, _, _ = fabricated()
        rows[-1]['role'] = 'BLIND_TEST'
        with self.assertRaisesRegex(ValueError, 'TRAIN_ONLY'):
            self.call(rows, object(), object())

    def test_held_or_duplicate_uid_rejected_before_attempts(self):
        rows, actions, _ = fabricated()
        actions[-1] = dict(actions[-1], action_uid='spi.0', total_cycles=object())
        with self.assertRaisesRegex(ValueError, 'FIT_ONLY_UNIQUE_UID_JOIN'):
            self.call(rows, actions, object())
        actions[-1] = dict(actions[0])
        with self.assertRaisesRegex(ValueError, 'FIT_ONLY_UNIQUE_UID_JOIN'):
            self.call(rows, actions, object())

    def test_feature_action_metadata_and_scheme_join(self):
        for field, value in (('family', 'iwls_spi'), ('circuit', 'spi'),
                             ('role', 'VALIDATION'), ('action_scheme', 'HMF')):
            rows, actions, _ = fabricated()
            actions[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'JOIN'):
                self.call(rows, actions, object())

    def test_terminal_failed_fit_is_explicit_rejection_not_filter(self):
        rows, actions, attempts = fabricated()
        uid = actions[0]['action_uid']
        actions[0].update(execution_status='FAILED', total_cycles=None)
        for a in attempts:
            if a['action_uid'] == uid and a['stage'] == 'F':
                a['execution_status'] = 'FAILED'
        with self.assertRaisesRegex(ValueError, 'SUCCESS_REQUIRED'):
            self.call(rows, actions, attempts)

    def test_mixed_candidate_cohorts_rejected_before_fold(self):
        rows, actions, attempts = fabricated()
        uid = actions[0]['action_uid']
        actions[0]['environment_cohort'] = 'cohort2'
        for a in attempts:
            if a['action_uid'] == uid:
                a['environment_cohort'] = 'cohort2'
        with self.assertRaisesRegex(ValueError, 'CIRCUIT_ENVIRONMENT_COHORT_JOIN'):
            self.call(rows, actions, attempts)

    def test_fees_are_not_features_and_no_io_or_sampling(self):
        rows, actions, attempts = fabricated()
        with patch('builtins.open', side_effect=AssertionError('IO')), \
                patch('socket.socket', side_effect=AssertionError('NETWORK')), \
                patch('random.Random', side_effect=AssertionError('MC')):
            first = self.call(rows, actions, attempts)
            attempts[0]['wall_s'] += 100
            second = self.call(rows, actions, attempts)
        self.assertEqual(first['fold']['fit_features'], second['fold']['fit_features'])
        self.assertEqual(first['fold']['feature_snapshot_sha256'],
                         second['fold']['feature_snapshot_sha256'])
        self.assertNotEqual(first['fold']['fit_tasks'], second['fold']['fit_tasks'])

    def test_optin_rejects_before_any_input_access(self):
        for flag in (False, 1, None):
            with self.assertRaisesRegex(ValueError, 'IMPLEMENTATION_OPT_IN'):
                prepare_accounted_fold(object(), object(), object(), held_family='none',
                                        seed=0, implementation_only=flag)

    def test_contract_matches_interfaces_without_changing_parent_release(self):
        root = Path(__file__).resolve().parents[1]
        contract = json.loads((root/'contracts/ranking_v6_materialized_accounting_v1.json').read_text())
        self.assertEqual(set(contract['canonical_accounting']['action_fields']), charges.ACTION_FIELDS)
        self.assertEqual(set(contract['canonical_accounting']['attempt_fields']), charges.ATTEMPT_FIELDS)
        self.assertEqual(contract['feature_split']['feature_names'], list(FEATURES))
        self.assertEqual(set(contract['feature_split']['families']), set(FAMILIES.values()))
        self.assertEqual(contract['replay']['K'], 10)
        self.assertFalse(contract['real_training_release'])
        self.assertFalse(contract['actual_d95_action_attempt_join_verified'])
        parent = (root/contract['parent_plan']).read_bytes()
        self.assertEqual(hashlib.sha256(parent).hexdigest(), contract['parent_plan_sha256'])
        self.assertFalse(json.loads(parent)['real_training_release'])


if __name__ == '__main__':
    unittest.main()
