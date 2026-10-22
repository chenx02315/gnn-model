"""Synthetic dictionaries only: no process, checkpoint, label or file access."""
import copy
import hashlib
import unittest

from src.data import prospective_request_features_v1 as features
from src.data import prospective_stage_observation_v1 as observation


def frozen():
    return features.freeze_requests('aes_core', [
        dict(action_uid='hf', scheme='HF', h_request=4, m_request=None),
        dict(action_uid='hmf', scheme='HMF', h_request=8, m_request=3)], 100, 'a'*64)


def pin(uid):
    return hashlib.sha256(uid.encode('ascii')).hexdigest()


def pair(freeze, uid, stage, index, aid='hf', parent=None, pid=7, control=None):
    row = next(r for r in freeze['requested_roster'] if r['action_uid'] == aid)
    if control is None:
        control = dict(kind='FULL', value=None) if stage == 'F' else dict(
            kind='PATTERN_LIMIT', value=row['h_request'] if stage == 'H' else row['m_request'])
    request = dict(run_uid='run-1', action_uid=aid, attempt_uid=uid, stage=stage,
        stage_index=index, freeze_sha256=freeze['freeze_sha256'], control=control,
        parent_attempt_uid=parent['attempt_uid'] if parent else None,
        parent_result_sha256=parent['result_sha256'] if parent else None)
    result = dict(run_uid='run-1', action_uid=aid, attempt_uid=uid, stage=stage,
        stage_index=index, request_sha256=observation.digest(request),
        process_identity=dict(host='synthetic-host', boot_id='11111111-2222-3333-4444-555555555555',
            pid=pid, start_ticks=100+pid), status='SUCCESS', returncode=0,
        generated_patterns=2, detected_common_faults=95 if stage == 'F' else 50,
        cycles=100, elapsed_ns=10, result_sha256=pin(uid), termination_verified=True)
    return request, result


def hf_fixture():
    freeze = frozen()
    h, hr = pair(freeze, 'h1', 'H', 1)
    f, fr = pair(freeze, 'f1', 'F', 1, parent=hr, pid=8)
    return freeze, [h, f], [hr, fr]


class ObservationTests(unittest.TestCase):
    def test_different_requested_and_generated_are_joined_without_substitution(self):
        freeze, requests, results = hf_fixture()
        before = features.build_features(freeze)
        value = observation.join_stage_observations(freeze, 'run-1', requests, results)
        self.assertFalse(value['observations'][0]['requested_equals_generated'])
        self.assertEqual(value['observations'][0]['requested_control']['value'], 4)
        self.assertEqual(value['observations'][0]['generated_patterns'], 2)
        self.assertTrue(value['observations'][1]['meets_declared_d95_threshold'])
        self.assertFalse(value['observations'][1]['acceptance_authenticated'])
        self.assertEqual(value['asserted_elapsed_ns_sum'], 20)
        self.assertEqual(before, features.build_features(freeze))
        self.assertFalse(value['legacy_checkpoint_compatible'])

    def test_outcome_changes_never_change_feature_bundle(self):
        freeze, requests, results = hf_fixture()
        first = observation.join_stage_observations(freeze, 'run-1', requests, results)
        results[-1].update(generated_patterns=40, cycles=10000, detected_common_faults=94)
        second = observation.join_stage_observations(freeze, 'run-1', requests, results)
        self.assertEqual(first['feature_bundle_sha256'], second['feature_bundle_sha256'])
        self.assertFalse(second['observations'][-1]['meets_declared_d95_threshold'])

    def test_hmf_exact_h_then_m_then_f_and_fresh_rebuild(self):
        freeze = frozen()
        requests, results = [], []
        for index in (1, 2):
            h, hr = pair(freeze, 'h%d'%index, 'H', index, 'hmf', pid=3*index+4)
            m, mr = pair(freeze, 'm%d'%index, 'M', index, 'hmf', hr, pid=3*index+5)
            f, fr = pair(freeze, 'f%d'%index, 'F', index, 'hmf', mr, pid=3*index+6)
            requests.extend([h, m, f]); results.extend([hr, mr, fr])
        value = observation.join_stage_observations(freeze, 'run-1', requests, results)
        self.assertEqual(value['observation_count'], 6)
        self.assertFalse(value['execution_ready'])

    def test_reused_prefix_and_stale_m_rejected(self):
        freeze, requests, results = hf_fixture()
        f2, fr2 = pair(freeze, 'f2', 'F', 2, parent=results[0], pid=9)
        with self.assertRaisesRegex(ValueError, 'EXACT_FRESH_SUCCESSFUL_PARENT'):
            observation.join_stage_observations(freeze, 'run-1', requests+[f2], results+[fr2])
        h, hr = pair(freeze, 'h1', 'H', 1, 'hmf')
        m, mr = pair(freeze, 'm1', 'M', 1, 'hmf', hr, pid=8)
        h2, hr2 = pair(freeze, 'h2', 'H', 2, 'hmf', pid=9)
        f, fr = pair(freeze, 'f1', 'F', 1, 'hmf', mr, pid=10)
        with self.assertRaisesRegex(ValueError, 'STALE_M_PREFIX'):
            observation.join_stage_observations(freeze, 'run-1', [h,m,h2,f], [hr,mr,hr2,fr])

    def test_join_hash_action_parent_and_stage_order_rejected(self):
        freeze, requests, results = hf_fixture()
        for key, bad in [('attempt_uid','foreign'), ('request_sha256','0'*64),
                         ('action_uid','hmf'), ('stage_index',True)]:
            changed = copy.deepcopy(results); changed[-1][key] = bad
            with self.assertRaises(ValueError):
                observation.join_stage_observations(freeze, 'run-1', requests, changed)
        changed = copy.deepcopy(requests); changed[-1]['parent_result_sha256'] = 'b'*64
        with self.assertRaises(ValueError):
            observation.join_stage_observations(freeze, 'run-1', changed, results)
        with self.assertRaises(ValueError):
            observation.join_stage_observations(freeze, 'run-1', requests[::-1], results[::-1])

    def test_failed_parent_and_unknown_elapsed_do_not_gain_admission(self):
        freeze, requests, results = hf_fixture()
        failed = copy.deepcopy(results)
        failed[0].update(status='FAILED', returncode=7, generated_patterns=None,
            detected_common_faults=None, cycles=None, result_sha256=None)
        with self.assertRaises(ValueError):
            observation.join_stage_observations(freeze, 'run-1', requests, failed)
        unknown = copy.deepcopy(results)
        unknown[0].update(status='UNKNOWN', returncode=None, elapsed_ns=None,
            termination_verified=False, generated_patterns=None, detected_common_faults=None,
            cycles=None, result_sha256=None)
        value = observation.join_stage_observations(freeze, 'run-1', requests[:1], unknown[:1])
        self.assertIsNone(value['asserted_elapsed_ns_sum'])
        with self.assertRaisesRegex(ValueError, 'UNRESOLVED_PRIOR_ATTEMPT'):
            observation.join_stage_observations(freeze, 'run-1', requests, unknown)

    def test_process_duplicates_or_host_boot_drift_rejected(self):
        freeze, requests, results = hf_fixture()
        for key, bad in [('host','other-host'), ('boot_id','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')]:
            changed = copy.deepcopy(results); changed[-1]['process_identity'][key] = bad
            with self.assertRaisesRegex(ValueError, 'HOST_BOOT_MISMATCH'):
                observation.join_stage_observations(freeze, 'run-1', requests, changed)
        changed = copy.deepcopy(results)
        changed[-1]['process_identity'] = dict(changed[0]['process_identity'])
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_PROCESS_OBSERVATION'):
            observation.join_stage_observations(freeze, 'run-1', requests, changed)

    def test_control_schema_and_outcome_fields_not_accepted_as_requests(self):
        freeze, requests, results = hf_fixture()
        for control in (dict(kind='COVERAGE_PERCENT',value='nan'),
                        dict(kind='COVERAGE_PERCENT',value=95),
                        dict(kind='PATTERN_LIMIT',value=True)):
            changed = copy.deepcopy(requests); changed[-1]['control'] = control
            with self.assertRaises(ValueError):
                observation.join_stage_observations(freeze, 'run-1', changed, results)
        changed = copy.deepcopy(requests); changed[0]['cycles'] = 100
        with self.assertRaisesRegex(ValueError, 'REQUEST_SCHEMA'):
            observation.join_stage_observations(freeze, 'run-1', changed, results)
        changed = copy.deepcopy(results); changed[0]['generated_patterns'] = True
        with self.assertRaisesRegex(ValueError, 'OBSERVED_COUNT'):
            observation.join_stage_observations(freeze, 'run-1', requests, changed)

    def test_success_with_unknown_elapsed_or_termination_stops_next(self):
        freeze, requests, results = hf_fixture()
        for key, value in [('elapsed_ns', None), ('termination_verified', False)]:
            changed = copy.deepcopy(results); changed[0][key] = value
            first = observation.join_stage_observations(freeze, 'run-1', requests[:1], changed[:1])
            self.assertIsNone(first['asserted_elapsed_ns_sum'])
            with self.assertRaisesRegex(ValueError, 'UNRESOLVED_PRIOR_ATTEMPT'):
                observation.join_stage_observations(freeze, 'run-1', requests, changed)

    def test_explicit_f_pattern_and_coverage_controls(self):
        for control in (dict(kind='PATTERN_LIMIT', value=3),
                        dict(kind='COVERAGE_PERCENT', value='95.125000')):
            freeze, requests, results = hf_fixture()
            requests[-1]['control'] = control
            results[-1]['request_sha256'] = observation.digest(requests[-1])
            value = observation.join_stage_observations(freeze, 'run-1', requests, results)
            self.assertEqual(value['observations'][-1]['requested_control'], control)

    def test_known_failure_charged_before_other_action_not_retried(self):
        freeze, requests, results = hf_fixture()
        failed = copy.deepcopy(results[0])
        failed.update(status='FAILED', returncode=7, generated_patterns=None,
                      detected_common_faults=None, cycles=None, result_sha256=None)
        other, other_result = pair(freeze, 'other', 'H', 1, 'hmf', pid=10)
        value = observation.join_stage_observations(freeze, 'run-1',
            [requests[0], other], [failed, other_result])
        self.assertEqual(value['asserted_elapsed_ns_sum'], 20)
        self.assertFalse(value['observations'][0]['meets_declared_d95_threshold'])
        retry, retry_result = pair(freeze, 'retry', 'H', 2, pid=10)
        with self.assertRaisesRegex(ValueError, 'ACTION_OR_ATTEMPT_ID'):
            observation.join_stage_observations(freeze, 'run-1',
                [requests[0], retry], [failed, retry_result])


if __name__ == '__main__':
    unittest.main()
