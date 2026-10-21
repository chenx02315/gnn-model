"""Synthetic event fixtures only; never launch child processes."""
import copy
import unittest

from src.data import prospective_process_observation_v1 as m


def fixture(aid='a1', index=1, status='success', role='endpoint', start=10, end=25):
    identity = dict(boot_id='synthetic-boot', host='synthetic-host', pid=index,
                    start_ticks=index * 100)
    return [dict(event='PLANNED', attempt_id=aid, circuit='aes_core',
                 command_sha256=format(index, '064x'), input_binding_sha256='b' * 64,
                 cost_role=role),
            dict(event='LAUNCHED', attempt_id=aid, monotonic_ns=start, **identity),
            dict(event='REAPED', attempt_id=aid, monotonic_ns=end, returncode=(
                0 if status == 'success' else -15), termination_verified=True,
                 status=status, **identity)]


class ProcessObservationTests(unittest.TestCase):
    def test_all_statuses_and_roles_charged(self):
        events = []
        for i, status in enumerate(('success', 'failed', 'timeout', 'cancelled'), 1):
            events.extend(fixture('a' + str(i), i, status,
                                  ('endpoint', 'probe', 'search', 'endpoint')[i-1],
                                  start=i*100, end=i*100+15))
        before = copy.deepcopy(events)
        result = m.summarize_observations(events)
        self.assertEqual(events, before)
        self.assertTrue(result['cost_complete'])
        self.assertEqual(result['raw_observed_interval_ns_sum'], 60)
        self.assertEqual(result['actual_processes_executed'], 0)
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['training_release'])
        result['attempts'][0]['circuit'] = 'changed'
        self.assertEqual(events, before)

    def test_incomplete_and_unverified_never_impute(self):
        for events in (fixture()[:1], fixture()[:2], fixture()):
            if len(events) == 3:
                events[-1]['termination_verified'] = False
            result = m.summarize_observations(events)
            self.assertFalse(result['cost_complete'])
            self.assertIsNone(result['raw_observed_interval_ns_sum'])
            self.assertIsNone(result['attempts'][0]['observed_interval_ns'])
        events = fixture() + fixture('a2', 2, start=30, end=40)[:1]
        self.assertIsNone(m.summarize_observations(events)['raw_observed_interval_ns_sum'])

    def test_unknown_and_labels_rejected_at_every_stage(self):
        for stage in range(3):
            for key in ('quality', 'd95', 'ate_cycles', 'runtime', 'retry_of', 'reuse', 'extra'):
                events = fixture()
                events[stage][key] = None
                with self.subTest(stage=stage, key=key), self.assertRaises(ValueError):
                    m.summarize_observations(events)

    def test_integer_types_and_bounds(self):
        for stage, key in ((1, 'pid'), (1, 'start_ticks'), (1, 'monotonic_ns'),
                           (2, 'pid'), (2, 'start_ticks'), (2, 'monotonic_ns'), (2, 'returncode')):
            for bad in (True, False, 1.5, '1', None, 2**63, -2**63-1):
                events = fixture()
                events[stage][key] = bad
                with self.subTest(stage=stage, key=key, bad=bad), self.assertRaises(ValueError):
                    m.summarize_observations(events)
        for key in ('pid', 'start_ticks'):
            events = fixture()
            events[1][key] = 0
            with self.assertRaises(ValueError):
                m.summarize_observations(events)

    def test_bad_bindings(self):
        changes = [(0, 'circuit', 'toy'), (0, 'circuit', []), (0, 'cost_role', 'free'),
                   (0, 'command_sha256', 'A'*64), (0, 'input_binding_sha256', 'b'*65),
                   (0, 'command_sha256', ['a']*1000), (1, 'host', 'x'*129),
                   (1, 'boot_id', 'bad\n'), (2, 'host', 'other'), (2, 'boot_id', 'other'),
                   (2, 'pid', 2), (2, 'start_ticks', 2), (2, 'monotonic_ns', 9),
                   (2, 'termination_verified', 1), (2, 'returncode', 1),
                   (2, 'status', 'failed'), (2, 'status', []), (2, 'status', 'SUCCESS')]
        for stage, key, value in changes:
            events = fixture()
            events[stage][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                m.summarize_observations(events)
        for status in ('failed', 'timeout', 'cancelled'):
            events = fixture(status=status)
            events[2]['returncode'] = 0
            if status == 'failed':
                with self.assertRaises(ValueError):
                    m.summarize_observations(events)
            else:
                result = m.summarize_observations(events)
                self.assertEqual(result['attempts'][0]['status'], status)
                self.assertEqual(result['attempts'][0]['returncode'], 0)
                self.assertTrue(result['cost_complete'])

    def test_sequence_and_duplicate_rejection(self):
        base = fixture()
        invalid = [base[1:], [base[0], base[2]], [base[0], base[0]],
                   [base[0], base[1], base[1]], base + [base[2]], base + base,
                   base[:1] + fixture('a2', 2)[:1], base[:2] + fixture('a2', 2),
                   base + fixture('a2', 1, start=30)]
        for events in invalid:
            with self.subTest(events=events), self.assertRaises(ValueError):
                m.summarize_observations(events)
        events = fixture()
        events[-1]['termination_verified'] = False
        with self.assertRaises(ValueError):
            m.summarize_observations(events + fixture('a2', 2, start=30))

    def test_cross_attempt_clock_and_identity(self):
        for key, value in (('boot_id', 'new-boot'), ('host', 'new-host')):
            second = fixture('a2', 2, start=30, end=40)
            second[1][key] = second[2][key] = value
            with self.assertRaises(ValueError):
                m.summarize_observations(fixture() + second)
        with self.assertRaises(ValueError):
            m.summarize_observations(fixture() + fixture('a2', 2, start=24, end=40))
        second = fixture('a2', 2, start=30, end=40)
        for event in second[1:]:
            event.update(pid=1, start_ticks=100)
        with self.assertRaises(ValueError):
            m.summarize_observations(fixture() + second)

    def test_fresh_repeated_command_is_independently_charged(self):
        second = fixture('a2', 2, start=30, end=40)
        second[0]['command_sha256'] = fixture()[0]['command_sha256']
        result = m.summarize_observations(fixture() + second)
        self.assertEqual(result['attempt_count'], 2)
        self.assertEqual(result['raw_observed_interval_ns_sum'], 25)

    def test_boundaries_and_containers(self):
        events = []
        for i in range(1, 65):
            events.extend(fixture('a'+str(i), i, start=i*100, end=i*100+1))
        self.assertEqual(m.summarize_observations(events)['raw_observed_interval_ns_sum'], 64)
        with self.assertRaises(ValueError):
            m.summarize_observations(events + fixture('a65', 65, start=6500, end=6501))
        for bad in ([], {}, (), iter(events), [None], [[]], [{}]*257,
                    [dict((str(i), i) for i in range(1000))]):
            with self.subTest(kind=type(bad)), self.assertRaises(ValueError):
                m.summarize_observations(bad)

    def test_zero_interval_and_signed_returncode(self):
        events = fixture(status='failed', start=0, end=0)
        events[2]['returncode'] = -2**63
        result = m.summarize_observations(events)
        self.assertTrue(result['cost_complete'])
        self.assertEqual(result['raw_observed_interval_ns_sum'], 0)


if __name__ == '__main__':
    unittest.main()
