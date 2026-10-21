import copy
import unittest

from src.data import prospective_input_binding_v1 as binding


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(action_uid='spi:HF:h3', scheme='HF', h_request=3, m_request=None),
                     dict(action_uid='spi:HMF:h2:m5', scheme='HMF', h_request=2, m_request=5)]
        self.pins = {key: None for key in binding.IDENTITIES}

    def test_requested_caps_and_conditional_prefix(self):
        result = binding.bind_requests('spi', self.rows, self.pins)
        self.assertEqual(result['payload']['requested_max_h'], 3)
        self.assertEqual(result['payload']['requested_max_m'], 5)
        self.assertEqual(result['controls'][1]['stages'][1],
                         dict(mode='M', pattern_limit=5, conditional_h_request=2))
        self.assertIsNone(result['model_feature_vector'])
        self.assertFalse(result['legacy_model_compatible'])
        self.assertFalse(result['execution_ready'])

    def test_pins_never_authenticate_bytes_or_unlock(self):
        result = binding.bind_requests('spi', self.rows, {key: 'a'*64 for key in binding.IDENTITIES})
        self.assertEqual(result['missing_identity_names'], [])
        for key in ('supplied_identity_bytes_authenticated', 'requested_vs_realized_equivalence_verified',
                    'future_unknown_actions_d95_preverified', 'execution_ready', 'training_release'):
            self.assertFalse(result[key])

    def test_outcome_fields_rejected(self):
        for key in ('h_patterns', 'm_patterns', 'cycles', 'runtime', 'epsilon_hit', 'd95', 'f_patterns'):
            rows = copy.deepcopy(self.rows)
            rows[0][key] = 1
            with self.assertRaisesRegex(ValueError, 'REQUEST_ONLY_SCHEMA'):
                binding.bind_requests('spi', rows, self.pins)

    def test_strict_numeric_and_scope(self):
        for bad in (True, False, 0, -1, 1.0, 2**31, '3', None):
            rows = copy.deepcopy(self.rows)
            rows[0]['h_request'] = bad
            with self.assertRaises(ValueError): binding.bind_requests('spi', rows, self.pins)
        for circuit in ('wb_dma', 's9234', None, [], True):
            with self.assertRaises(ValueError): binding.bind_requests(circuit, self.rows, self.pins)

    def test_m_scheme_and_aliases(self):
        for idx, value in ((0, 1), (1, None), (1, True), (1, 0)):
            rows = copy.deepcopy(self.rows)
            rows[idx]['m_request'] = value
            with self.assertRaises(ValueError): binding.bind_requests('spi', rows, self.pins)
        for new_uid in (self.rows[0]['action_uid'], 'alias'):
            rows = copy.deepcopy(self.rows)
            row = dict(rows[0], action_uid=new_uid)
            with self.assertRaises(ValueError): binding.bind_requests('spi', rows+[row], self.pins)

    def test_determinism_no_mutation_and_full_roster_binding(self):
        before = copy.deepcopy((self.rows, self.pins))
        full = binding.bind_requests('spi', self.rows, self.pins)
        reversed_result = binding.bind_requests('spi', self.rows[::-1], self.pins)
        self.assertEqual(full, reversed_result)
        partial = binding.bind_requests('spi', self.rows[1:], self.pins)
        self.assertNotEqual(full['roster_sha256'], partial['roster_sha256'])
        self.assertEqual((self.rows, self.pins), before)

    def test_identity_and_container_bounds(self):
        for value in ('A'*64, 'z'*64, 'a'*63, True, 3, {}):
            pins = dict(self.pins, config=value)
            with self.assertRaises(ValueError): binding.bind_requests('spi', self.rows, pins)
        for rows in ([], self.rows*232, tuple(self.rows)):
            with self.assertRaises(ValueError): binding.bind_requests('spi', rows, self.pins)
        with self.assertRaises(ValueError): binding.bind_requests('spi', self.rows, {})


if __name__ == '__main__':
    unittest.main()
