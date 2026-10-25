import ast
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

from src.data import direct_observation_journal_e102 as m


class Tests(unittest.TestCase):
    def observed(self):
        return dict(returncode=-9, cleaned=True, failure='CASE_TIMEOUT',
                    output=b'Warning: unknown\n', sampled_peak_rss_swap_bytes=123,
                    launch_attempted=True, readiness=None, streams_combined=True,
                    stderr_separately_validated=False)

    def test_sealed_before_monitor_failure_and_input_unchanged(self):
        value = self.observed()
        before = dict(value)
        events = []
        def sample():
            events.append('sample')
            raise ValueError('SCRATCH_TEST_FAILURE')
        def receipt(name, raw):
            events.append('receipt')
            row = json.loads(raw)
            self.assertEqual(row['returncode'], -9)
            self.assertEqual(row['sampled_peak_rss_swap_bytes'], 123)
            self.assertEqual(row['log_sha256'], hashlib.sha256(value['output']).hexdigest())
            self.assertFalse(row['acceptance_evaluated'])
            self.assertFalse(row['final_scratch_sample_evaluated'])
            self.assertFalse(row['independent_os_termination_attested'])
            self.assertEqual(row['warning_inventory']['warnings'][0]['category'], 'UNKNOWN')
        with self.assertRaisesRegex(ValueError, 'SCRATCH_TEST_FAILURE'):
            m.seal_observation(value, 'aes_core', 'H_TO_M', 1.5, receipt,
                               lambda name, raw: events.append('log'), sample)
        self.assertEqual(events, ['receipt', 'log', 'sample'])
        self.assertEqual(value, before)

    def test_publication_failure_not_retried_or_certified(self):
        receipt = Mock(side_effect=OSError('disk'))
        log, sample = Mock(), Mock()
        with self.assertRaises(OSError):
            m.seal_observation(self.observed(), 'spi', 'H_TO_F', 0,
                               receipt, log, sample)
        receipt.assert_called_once()
        log.assert_not_called()
        sample.assert_not_called()

    def test_invalid_observation_rejected_before_callbacks(self):
        for key, bad in [('cleaned', False), ('sampled_peak_rss_swap_bytes', True),
                         ('returncode', False), ('readiness', {}), ('output', 'text')]:
            value = self.observed()
            value[key] = bad
            callback = Mock()
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.seal_observation(value, 'spi', 'H_TO_F', 0,
                                   callback, callback, callback)
            callback.assert_not_called()

    def test_success_is_only_observation_not_case_pass(self):
        row = m.seal_observation(self.observed(), 'spi', 'H_TO_F', 2,
                                 Mock(), Mock(), Mock())
        self.assertNotIn('passed', row)
        self.assertFalse(row['acceptance_evaluated'])

    def test_log_failure_leaves_receipt_but_no_sample(self):
        receipt = Mock()
        log = Mock(side_effect=OSError('log publication'))
        sample = Mock()
        with self.assertRaises(OSError):
            m.seal_observation(self.observed(), 'spi', 'H_TO_F', 0,
                               receipt, log, sample)
        receipt.assert_called_once()
        log.assert_called_once()
        sample.assert_not_called()

    def test_scope_and_elapsed_rejected_before_publication(self):
        for circuit, transition, elapsed in [('other', 'H_TO_F', 0),
                ('spi', 'other', 0), ('spi', 'H_TO_F', float('nan')),
                ('spi', 'H_TO_F', -1), ('spi', 'H_TO_F', True)]:
            callback = Mock()
            with self.subTest(circuit=circuit, transition=transition, elapsed=elapsed), \
                    self.assertRaises(ValueError):
                m.seal_observation(self.observed(), circuit, transition, elapsed,
                                   callback, callback, callback)
            callback.assert_not_called()

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_warning_parse_bound_does_not_erase_returned_evidence(self):
        value = self.observed()
        value['output'] = b'Warning: unknown\n' * 129
        receipt = Mock()
        row = m.seal_observation(value, 'spi', 'H_TO_F', 0,
                                 receipt, Mock(), Mock())
        receipt.assert_called_once()
        self.assertTrue(row['warning_inventory']['inventory_failed'])
        self.assertFalse(row['acceptance_evaluated'])
        self.assertEqual(row['returncode'], -9)


if __name__ == '__main__':
    unittest.main()
