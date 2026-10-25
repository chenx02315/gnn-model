"""Composition mocks only: no launch, remote filesystem, or real consent."""
import ast
from contextlib import ExitStack
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from src.data import direct_tessent_acceptance_e102 as m
from tests import test_direct_tessent_acceptance_e101 as prior


class Tests(unittest.TestCase):
    def authority(self):
        value = prior.Tests().authority()
        value.update(schema='direct-tessent-repair-authorization-e102-v1',
                     root=m.ROOT, predecessor_log_sha256=m.PREDECESSOR_LOG_SHA,
                     package_repair_versions_max=2,
                     package_additional_launch_attempts_total_max=8,
                     package_version_index=1, stop_on_first_failure=True,
                     unchanged_code_retries_allowed=False,
                     warnings_require_individual_review=True,
                     blanket_warning_ignore_allowed=False)
        value.pop('predecessor_execution_response_sha256')
        return json.dumps(value).encode('ascii')

    def test_old_consumed_authority_and_proposal_rejected_before_execution(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('direct_tessent_repair_authorization_e101_20261025.json',
                     'direct_tessent_runtime_repair_e102_proposal_v1.json'):
            with self.subTest(name=name), patch.object(m, '_execute') as run:
                with self.assertRaises(ValueError):
                    m.execute(b'', b'', (root / 'contracts' / name).read_bytes())
                run.assert_not_called()

    def test_missing_source_binding_rejected_before_execution(self):
        with patch.object(m, '_execute') as run:
            with self.assertRaisesRegex(ValueError, 'SOURCE_BINDING'):
                m.execute(b'', b'', self.authority())
            run.assert_not_called()

    def test_single_execution_and_restoration_after_failure(self):
        before = (m.base.ROOT, m.base.validate_authority, m.recipe.ROOT, m.material.RECIPE_SHA256)
        with ExitStack() as stack:
            for module, pin in m.SOURCE_PINS:
                stack.enter_context(patch.object(module, '__source_sha256__', pin, create=True))
            run = stack.enter_context(patch.object(m, '_execute', side_effect=RuntimeError('test')))
            with self.assertRaises(RuntimeError):
                m.execute(b'', b'', self.authority())
            run.assert_called_once()
        self.assertEqual(before, (m.base.ROOT, m.base.validate_authority,
                                 m.recipe.ROOT, m.material.RECIPE_SHA256))

    def flow(self, log, sample_failure=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        maker = Mock(root_fd=10)
        maker.initialize_bundle.return_value = dict(items=[
            dict(circuit=c, transition=t, target_mode=mode)
            for c, t, mode in m.recipe.ROSTER])
        maker.materialize_item.return_value = dict(cwd=m.ROOT + '/scratch/aes_core_M',
                                                 argv=['fixed-test-command'],tcl_bytes=b'read_faults {one}\nread_faults {two} -merge\n')
        stack.enter_context(patch.object(m, 'DirectMaterializer', return_value=maker))
        stack.enter_context(patch.object(m.sys, 'platform', 'linux'))
        stack.enter_context(patch.object(m.platform, 'node', return_value='bupt-vncs2'))
        stack.enter_context(patch.object(m.time, 'monotonic', return_value=1))
        stack.enter_context(patch.object(m, 'Descendants'))
        stack.enter_context(patch.object(m, 'synthetic_gate', return_value=[]))
        monitor = Mock()
        monitor.sample.side_effect = sample_failure
        stack.enter_context(patch.object(m, 'ScratchMonitor', return_value=monitor))
        observed = dict(returncode=0, cleaned=True, failure=None, output=log,
                        sampled_peak_rss_swap_bytes=123, launch_attempted=True,
                        readiness=None, streams_combined=True,
                        stderr_separately_validated=False)
        run = stack.enter_context(patch.object(m, 'supervise', return_value=observed))
        stack.enter_context(patch.object(m.material, '_directory', return_value=20))
        stack.enter_context(patch.object(m.os, 'close'))
        writes = []
        stack.enter_context(patch.object(m.material, '_publish',
            side_effect=lambda fd, name, raw: writes.append((name, raw))))
        return maker, run, writes, monitor

    def test_monitor_failure_preserves_observation_and_stops_remaining_cases(self):
        maker, run, writes, monitor = self.flow(b'log', ValueError('SCRATCH_TEST'))
        with self.assertRaisesRegex(ValueError, 'SCRATCH_TEST'):
            m._execute(b'', b'', self.authority())
        names = [name for name, raw in writes]
        self.assertLess(names.index('observation_aes_core_H_TO_M.json'),
                        names.index('direct_tessent.log'))
        self.assertLess(names.index('direct_tessent.log'), names.index('failure.json'))
        row = json.loads(dict(writes)['observation_aes_core_H_TO_M.json'])
        self.assertEqual(row['sampled_peak_rss_swap_bytes'], 123)
        self.assertFalse(row['acceptance_evaluated'])
        run.assert_called_once()
        maker.materialize_item.assert_called_once()
        maker.close.assert_called_once()

    def test_warning_still_fails_and_no_second_case_is_launched(self):
        marker = b'E94_TRANSLATED_STATUS_ACCEPTANCE=PASS aes_core H_TO_M\n'
        maker, run, writes, monitor = self.flow(marker + b'Warning: Rule FN1 violation occurs 6 times\n')
        result = m._execute(b'', b'', self.authority())
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['cases']), 1)
        self.assertEqual(result['tessent_launch_attempts'], 1)
        run.assert_called_once()
        self.assertTrue(any(name == 'observation_aes_core_H_TO_M.json' for name, raw in writes))

    def test_log_directory_open_failure_still_preserves_returned_observation(self):
        maker, run, writes, monitor = self.flow(b'log')
        with patch.object(m.material, '_directory', side_effect=OSError('directory lost')):
            with self.assertRaises(OSError):
                m._execute(b'', b'', self.authority())
        names = [name for name, raw in writes]
        self.assertIn('observation_aes_core_H_TO_M.json', names)
        self.assertNotIn('direct_tessent.log', names)
        self.assertIn('failure.json', names)
        run.assert_called_once()
        monitor.sample.assert_not_called()
        maker.close.assert_called_once()

    def test_bad_budgets_and_scope_not_relaxed(self):
        for key, bad in [('workers', True), ('lsf_allowed', True),
                         ('additional_launch_attempts_max', 8), ('training_allowed', True)]:
            value = json.loads(self.authority())
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_authority(json.dumps(value).encode('ascii'))

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
