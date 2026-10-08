import copy
import json
import unittest
from unittest.mock import patch

from src.models import ranking_v5_parent_guard_receipt as receipt


def payload():
    return dict(status='PASS_BOUNDED_WORKER', memory_policy=receipt.guard.policy(),
                initial_available_bytes=12 * receipt.guard.GIB,
                effective_total_bytes=16 * receipt.guard.GIB,
                reserve_bytes=4 * receipt.guard.GIB, sample_count=2,
                peak_group_rss_bytes=100, peak_combined_rss_bytes=200,
                exit_code=0, process_group=123, elapsed_seconds=0.5)


def with_boundary():
    result = payload()
    result.update(rss_exit_boundary_resolution='EXIT_ZERO_NO_LIVE_GROUP',
                  rss_exit_boundary=dict(unreadable_pid=123, observed_stat_state='R',
                                         leader_exit_code=0, live_group_member_count=0,
                                         live_group_pids=[], pids_truncated=False))
    return result


class ParentGuardReceiptTests(unittest.TestCase):
    def validate(self, value):
        return receipt.validate_parent_guard_receipt(value, json.loads(json.dumps(value)))

    def reject(self, value):
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_valid_receipt_is_implementation_only_and_nonmutating(self):
        value = payload()
        original = copy.deepcopy(value)
        result = self.validate(value)
        self.assertEqual(result['status'], 'PASS_PARENT_GUARD_RECEIPT_IMPLEMENTATION_ONLY')
        self.assertTrue(result['bounded_worker_receipt_validated'])
        for key in ('receipt_provenance_proven', 'actual_training_proven',
                    'release_authorization_proven', 'authentic_user_consent_proven'):
            self.assertFalse(result[key])
        self.assertEqual(value, original)

    def test_strict_integer_fields(self):
        fields = ('initial_available_bytes', 'effective_total_bytes', 'reserve_bytes',
                  'sample_count', 'peak_group_rss_bytes', 'peak_combined_rss_bytes',
                  'exit_code', 'process_group')
        for field in fields:
            for bad in (True, False, 0.0, -1, '0', None):
                with self.subTest(field=field, bad=bad):
                    value = payload(); value[field] = bad
                    self.reject(value)
        for field in ('sample_count', 'process_group', 'effective_total_bytes'):
            value = payload(); value[field] = 0
            self.reject(value)

    def test_elapsed_is_finite_positive_float_with_strict_timeout(self):
        for bad in (True, 1, 0.0, -1.0, float('nan'), float('inf'),
                    float('-inf'), 1800.0001, '1', None):
            value = payload(); value['elapsed_seconds'] = bad
            self.reject(value)
        value = payload(); value['elapsed_seconds'] = 1800.0
        self.validate(value)

    def test_status_schema_and_failure_leftovers(self):
        for bad in ('STARTING', 'STOPPED_NO_RETRY', 'PASS', '', None, True):
            value = payload(); value['status'] = bad
            self.reject(value)
        for field in ('error', 'live_group_members_after_cleanup', 'cleanup', 'unknown'):
            value = payload(); value[field] = 0
            self.reject(value)
        for field in payload():
            value = payload(); del value[field]
            self.reject(value)
        self.reject([])
        value = payload(); value['exit_code'] = 1
        self.reject(value)

    def test_policy_exact_types_keys_and_values(self):
        for key, original in receipt.guard.policy().items():
            alternatives = ([True, float(original)] if type(original) is int
                            else [0, float('nan'), float('inf')] if type(original) is float
                            else [None, 'changed'])
            for bad in alternatives:
                value = payload(); value['memory_policy'][key] = bad
                self.reject(value)
            value = payload(); del value['memory_policy'][key]
            self.reject(value)
        value = payload(); value['memory_policy']['unknown'] = 0
        self.reject(value)

    def test_memory_and_peak_consistency(self):
        for updates in (
                dict(initial_available_bytes=17 * receipt.guard.GIB),
                dict(initial_available_bytes=5 * receipt.guard.GIB - 1),
                dict(reserve_bytes=4 * receipt.guard.GIB + 1),
                dict(effective_total_bytes=4 * receipt.guard.GIB,
                     initial_available_bytes=4 * receipt.guard.GIB),
                dict(peak_group_rss_bytes=201),
                dict(peak_combined_rss_bytes=receipt.guard.GIB + 1)):
            value = payload(); value.update(updates)
            self.reject(value)
        value = payload(); value.update(effective_total_bytes=100 * receipt.guard.GIB,
                                       initial_available_bytes=20 * receipt.guard.GIB)
        value['reserve_bytes'] = receipt.guard.check_available(
            value['effective_total_bytes'], value['initial_available_bytes'])
        self.validate(value)
        value = payload(); value.update(peak_group_rss_bytes=0, peak_combined_rss_bytes=1)
        self.validate(value)
        for value in (payload(), with_boundary()):
            value.update(peak_group_rss_bytes=0, peak_combined_rss_bytes=0)
            self.reject(value)

    def test_independent_payload_must_match(self):
        for field, replacement in (('sample_count', 3), ('process_group', 124),
                                   ('elapsed_seconds', 0.6), ('peak_group_rss_bytes', 99)):
            value = payload(); reread = copy.deepcopy(value); reread[field] = replacement
            with self.assertRaisesRegex(ValueError, 'MISMATCH'):
                receipt.validate_parent_guard_receipt(value, reread)
        value = payload(); reread = copy.deepcopy(value); reread['exit_code'] = False
        with self.assertRaises(ValueError):
            receipt.validate_parent_guard_receipt(value, reread)

    def test_optional_exit_boundary_cannot_bypass_real_samples_or_live_group(self):
        self.validate(with_boundary())
        value = with_boundary(); value['sample_count'] = 0
        self.reject(value)
        for key, bad in (('unreadable_pid', True), ('unreadable_pid', 0),
                         ('observed_stat_state', 'Z'), ('observed_stat_state', 'unknown'),
                         ('leader_exit_code', None), ('leader_exit_code', False),
                         ('leader_exit_code', 1), ('live_group_member_count', False),
                         ('live_group_member_count', 1), ('live_group_pids', [123]),
                         ('live_group_pids', ()), ('pids_truncated', 0),
                         ('pids_truncated', True)):
            value = with_boundary(); value['rss_exit_boundary'][key] = bad
            # Direct call preserves tuple rather than JSON normalizing it.
            with self.assertRaises(ValueError):
                receipt.validate_parent_guard_receipt(value, copy.deepcopy(value))
        for key in ('rss_exit_boundary', 'rss_exit_boundary_resolution'):
            value = with_boundary(); del value[key]
            self.reject(value)
        value = with_boundary(); value['rss_exit_boundary_resolution'] = 'ZERO_RSS'
        self.reject(value)
        value = with_boundary(); value['rss_exit_boundary']['fabricated_samples'] = 0
        self.reject(value)
        for key in with_boundary()['rss_exit_boundary']:
            value = with_boundary(); del value['rss_exit_boundary'][key]
            self.reject(value)

    def test_validation_does_not_observe_or_execute(self):
        with patch.object(receipt.guard, 'available_memory', side_effect=AssertionError), \
             patch.object(receipt.guard, 'run_bounded', side_effect=AssertionError), \
             patch.object(receipt.guard, 'group_members', side_effect=AssertionError):
            self.validate(payload())


if __name__ == '__main__':
    unittest.main()
