"""No files, processes, remote access, or empirical ATPG labels in these tests."""
import unittest

from src.data import prospective_pilot_budget_v1 as budget


def declared(**changes):
    value=dict(f_full_pattern_bound=4,candidate_count_upper=2,sessions=3,
               endpoint_calls_per_session_upper=5,extra_calls_per_session_upper=7,
               prefix_rebuild_per_f_call=False,attempt_timeout_s=10,
               cleanup_timeout_s=2)
    value.update(changes)
    return value


def simulated_search_calls(upper, first_limit, first_passing):
    """Counting-only adversarial shape; includes worst coverage and fallback."""
    count=2
    limit=first_limit
    while limit<=upper:
        count+=1
        if limit>=first_passing:
            break
        limit+=1
    if limit>upper:
        return count
    low,high=0,limit
    while high-low>1:
        midpoint=(low+high)//2
        count+=1
        if midpoint>=first_passing:
            high=midpoint
        else:
            low=midpoint
    return count


class BudgetTests(unittest.TestCase):
    def test_f_search_exhaustive_small_bound_and_f_one_not_double_counted(self):
        for upper in range(1,40):
            for first_limit in range(1,upper+1):
                for passing in range(1,upper+2):
                    self.assertLessEqual(simulated_search_calls(upper,first_limit,passing),
                                         budget.f_search_upper(upper))
        self.assertEqual(budget.f_search_upper(1),3)  # coverage+fallback+F1; F0 incoming
        self.assertEqual(budget.f_search_upper(2),5)
        self.assertEqual(budget.f_search_upper(2**31-1),
                         2+(2**31-1)+31)

    def test_complete_conditional_without_prefix_rebuild(self):
        result=budget.calculate_budget(declared())
        self.assertEqual(result['status'],'CONDITIONAL_DECLARED_CAPS_ONLY')
        self.assertEqual(result['f_probe_calls_per_action_upper'],8)
        self.assertEqual(result['physical_calls_per_action_upper'],10)
        self.assertEqual(result['physical_calls_per_session_upper'],32)
        self.assertEqual(result['total_physical_calls_upper'],96)
        self.assertEqual(result['summed_attempt_envelope_seconds_upper'],1152)
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['training_release'])
        self.assertEqual(result['actual_atpg_calls'],0)
        self.assertIn('NOT_END_TO_END_WALL',result['time_scope'])

    def test_prefix_rebuild_is_per_f_probe_not_cross_action_cache(self):
        result=budget.calculate_budget(declared(prefix_rebuild_per_f_call=True))
        self.assertEqual(result['physical_calls_per_action_upper'],26)
        self.assertEqual(result['physical_calls_per_session_upper'],64)
        self.assertEqual(result['total_physical_calls_upper'],192)
        self.assertFalse(result['cross_candidate_cache_assumed'])
        self.assertFalse(result['cross_method_cache_assumed'])
        self.assertFalse(result['cross_session_cache_assumed'])

    def test_endpoints_extras_and_sessions_all_multiplied_and_zero_allowed(self):
        result=budget.calculate_budget(declared(sessions=2,candidate_count_upper=1,
                    endpoint_calls_per_session_upper=0,extra_calls_per_session_upper=0))
        self.assertEqual(result['physical_calls_per_session_upper'],10)
        self.assertEqual(result['total_physical_calls_upper'],20)
        result=budget.calculate_budget(declared(sessions=2,candidate_count_upper=1,
                    endpoint_calls_per_session_upper=3,extra_calls_per_session_upper=4))
        self.assertEqual(result['total_physical_calls_upper'],34)

    def test_missing_numeric_values_keep_every_bound_null(self):
        for field in budget.NUMERIC_CAPS:
            result=budget.calculate_budget(declared(**{field:None}))
            self.assertEqual(result['status'],'INCOMPLETE_DESIGN')
            self.assertEqual(result['missing_fields'],[field])
            for key in ('f_probe_calls_per_action_upper','hmf_base_calls_per_action_upper',
                        'physical_calls_per_action_upper','physical_calls_per_session_upper',
                        'total_physical_calls_upper','summed_attempt_envelope_seconds_upper'):
                self.assertIsNone(result[key])
        for field in budget.NUMERIC_CAPS:
            with self.assertRaises(ValueError):
                budget.calculate_budget(declared(**{field:'unknown'}))

    def test_exact_keys_bool_as_int_and_large_values_rejected(self):
        with self.assertRaises(ValueError):
            budget.calculate_budget({})
        with self.assertRaises(ValueError):
            budget.calculate_budget(dict(declared(),candidate_roster='not-proof'))
        for field in budget.NUMERIC_CAPS:
            with self.assertRaises(ValueError):
                budget.calculate_budget(declared(**{field:True}))
            with self.assertRaises(ValueError):
                budget.calculate_budget(declared(**{field:budget.NUMERIC_CAPS[field]+1}))
            if field not in budget.ZERO_ALLOWED:
                with self.assertRaises(ValueError):
                    budget.calculate_budget(declared(**{field:0}))
        for value in (None,0,1,'false'):
            with self.assertRaises(ValueError):
                budget.calculate_budget(declared(prefix_rebuild_per_f_call=value))
        with self.assertRaises(ValueError):
            budget.f_search_upper(True)
        with self.assertRaises(ValueError):
            budget.f_search_upper(None)

    def test_candidate_alias_count_is_only_declared_upper_not_roster_proof(self):
        result=budget.calculate_budget(declared(candidate_count_upper=462))
        self.assertEqual(result['declared']['candidate_count_upper'],462)
        self.assertEqual(result['status'],'CONDITIONAL_DECLARED_CAPS_ONLY')
        self.assertFalse(result['execution_ready'])
        self.assertNotIn('roster_sha256',result)
        self.assertIn('DECLARED_STAGE_CALLS_ONLY',result['call_scope'])


if __name__=='__main__':
    unittest.main()
