"""Caller-supplied synthetic snapshots only; no operating-system experiments."""
import copy
import unittest

from src.data import prospective_linux_resource_gate_v1 as m


def fixture():
    return dict(platform='linux', cgroup_version=2,
                memory_max_bytes=m.MAX_SYNTHETIC_GUARD_MEMORY_BYTES,
                memory_swap_max_bytes=0, memory_current_bytes=0,
                memory_oom_group=1, pids_max=64, cgroup_empty=True,
                scope_is_dedicated=True, guard_installed_before_launch=True,
                expected_memory_limit_bytes=m.MAX_SYNTHETIC_GUARD_MEMORY_BYTES)


class ResourceGateTests(unittest.TestCase):
    def reject(self, field, value):
        snapshot = fixture()
        snapshot[field] = value
        with self.assertRaises(ValueError):
            m.evaluate_snapshot(snapshot)

    def test_valid_snapshot_never_authenticates_or_releases(self):
        result = m.evaluate_snapshot(fixture())
        self.assertIs(result['snapshot_consistent'], True)
        self.assertIs(result['synthetic_guard_design_only'], True)
        for key in ('os_state_authenticated', 'execution_ready', 'training_release'):
            self.assertIs(result[key], False)
        self.assertEqual(result['actual_processes_executed'], 0)

    def test_constants_and_synthetic_scope(self):
        self.assertEqual(m.MAX_SYNTHETIC_GUARD_MEMORY_BYTES, 536870912)
        self.assertEqual(m.MAX_PIDS, 64)
        self.assertEqual(m.MAX_INTEGER, 2**63 - 1)
        result = m.evaluate_snapshot(fixture())
        self.assertEqual(result['synthetic_guard_memory_limit_bytes'], 536870912)
        self.assertEqual(result['max_synthetic_guard_memory_bytes'], 536870912)
        self.assertIn('memory.max_not_rss_polling_or_rlimit_as', result['guard_design'])

    def test_missing_every_field_fails_closed(self):
        for key in fixture():
            snapshot = fixture()
            del snapshot[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.evaluate_snapshot(snapshot)

    def test_unknown_fields_rejected(self):
        for key in ('extra', 'rss_bytes', 'rlimit_as', 'execution_ready',
                    'os_state_authenticated', 'training_release', 'atpg_budget_bytes'):
            self.reject(key, True)

    def test_same_length_unknown_key_rejected(self):
        snapshot = fixture()
        snapshot['unrecognized'] = snapshot.pop('cgroup_empty')
        with self.assertRaises(ValueError):
            m.evaluate_snapshot(snapshot)

    def test_non_builtin_dict_rejected(self):
        class DictSubclass(dict):
            pass
        for value in (None, [], (), 'snapshot', DictSubclass(fixture())):
            with self.subTest(value=type(value)), self.assertRaises(ValueError):
                m.evaluate_snapshot(value)

    def test_linux_required(self):
        for value in ('Linux', 'win32', 'darwin', '', None, True, 1):
            self.reject('platform', value)

    def test_cgroup_v2_required(self):
        for value in (0, 1, 3, '2', 2.0, True, None):
            self.reject('cgroup_version', value)

    def test_unlimited_max_string_rejected(self):
        for key in ('memory_max_bytes', 'memory_swap_max_bytes', 'pids_max',
                    'expected_memory_limit_bytes'):
            self.reject(key, 'max')

    def test_all_integer_fields_exclude_bool_and_coercion(self):
        for key in ('cgroup_version', 'memory_max_bytes', 'memory_swap_max_bytes',
                    'memory_current_bytes', 'memory_oom_group', 'pids_max',
                    'expected_memory_limit_bytes'):
            for bad in (True, False, 0.0, 1.0, '0', None):
                with self.subTest(key=key, bad=bad):
                    self.reject(key, bad)

    def test_integer_subclass_rejected(self):
        class IntegerSubclass(int):
            pass
        self.reject('memory_current_bytes', IntegerSubclass(0))

    def test_integer_overflow_rejected(self):
        for key in ('cgroup_version', 'memory_max_bytes', 'memory_swap_max_bytes',
                    'memory_current_bytes', 'memory_oom_group', 'pids_max',
                    'expected_memory_limit_bytes'):
            for bad in (2**63, -(2**63)-1, 2**100):
                self.reject(key, bad)

    def test_memory_limit_positive(self):
        for key in ('memory_max_bytes', 'expected_memory_limit_bytes'):
            for bad in (0, -1):
                self.reject(key, bad)

    def test_fixed_synthetic_cap(self):
        snapshot = fixture()
        snapshot['memory_max_bytes'] += 1
        snapshot['expected_memory_limit_bytes'] += 1
        with self.assertRaises(ValueError):
            m.evaluate_snapshot(snapshot)

    def test_expected_limit_must_match(self):
        self.reject('expected_memory_limit_bytes', 1)
        self.reject('memory_max_bytes', 1)

    def test_smallest_limit_and_pid_boundaries(self):
        for pid in (1, 64):
            snapshot = fixture()
            snapshot.update(memory_max_bytes=1, expected_memory_limit_bytes=1,
                            pids_max=pid)
            self.assertTrue(m.evaluate_snapshot(snapshot)['snapshot_consistent'])

    def test_swap_disabled_exactly(self):
        for bad in (-1, 1, m.MAX_INTEGER):
            self.reject('memory_swap_max_bytes', bad)

    def test_current_memory_boundaries(self):
        for value in (0, m.MAX_SYNTHETIC_GUARD_MEMORY_BYTES):
            snapshot = fixture()
            snapshot['memory_current_bytes'] = value
            self.assertTrue(m.evaluate_snapshot(snapshot)['snapshot_consistent'])
        for bad in (-1, m.MAX_SYNTHETIC_GUARD_MEMORY_BYTES + 1, m.MAX_INTEGER):
            self.reject('memory_current_bytes', bad)

    def test_oom_group_required(self):
        for bad in (-1, 0, 2):
            self.reject('memory_oom_group', bad)

    def test_pids_cap(self):
        for bad in (-1, 0, 65, m.MAX_INTEGER):
            self.reject('pids_max', bad)

    def test_all_prelaunch_flags_exactly_true(self):
        for key in ('cgroup_empty', 'scope_is_dedicated', 'guard_installed_before_launch'):
            for bad in (False, 0, 1, 'true', None, [], {}):
                with self.subTest(key=key, bad=bad):
                    self.reject(key, bad)

    def test_forged_consistent_flags_are_not_os_evidence(self):
        # These literal claims are made up, not obtained from a kernel.
        forged = fixture()
        result = m.evaluate_snapshot(forged)
        self.assertTrue(result['snapshot_consistent'])
        self.assertFalse(result['os_state_authenticated'])
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['training_release'])

    def test_input_and_output_detached(self):
        snapshot = fixture()
        before = copy.deepcopy(snapshot)
        result = m.evaluate_snapshot(snapshot)
        self.assertEqual(snapshot, before)
        result['synthetic_guard_memory_limit_bytes'] = 9
        self.assertEqual(snapshot, before)
        snapshot['pids_max'] = 1
        self.assertEqual(result['pids_max'], 64)


if __name__ == '__main__':
    unittest.main()
