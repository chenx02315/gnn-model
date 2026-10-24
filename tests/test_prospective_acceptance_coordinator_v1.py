"""Local mocks + temporary journal only; no real job or process launches."""
import ast
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from src.data import prospective_acceptance_coordinator_v1 as m

ROOT = Path(__file__).resolve().parents[1]
E85 = (ROOT / 'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes()
E93 = (ROOT / 'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes()
PLAN = m.recipes.compile_acceptance(E85, E93, m.recipes.E85_SHA256, m.recipes.E93_SHA256)


def authority():
    return dict(schema=m.AUTH_SCHEMA, approved=True, job_id=123,
        memory_cap_bytes=536870912, recipe_sha256=PLAN['recipe_sha256'], scope=m.SCOPE)


class FakeJournal:
    instances = []
    fail_kind = None
    def __init__(self, fd):
        self.rows = []; self.closed = False
        self.instances.append(self)
    def append(self, kind, payload):
        if kind == self.fail_kind:
            raise OSError('simulated fsync failure')
        self.rows.append((kind, payload))
        return {'seq': len(self.rows), 'sha256': 'a' * 64}
    def close(self):
        self.closed = True


class FakeMaterializer:
    instances = []
    close_error = False
    def __init__(self, *args):
        self.calls = []; self.closed = False
        self.instances.append(self)
    def initialize_bundle(self):
        self.initialized = True
    def journal_directory_fd(self):
        return 100
    def materialize_item(self, circuit, transition):
        self.calls.append((circuit, transition))
        return next(x for x in PLAN['items'] if
                    (x['circuit'], x['transition']) == (circuit, transition))
    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError('simulated close failure')


class FakeProcess:
    instances = []
    fail_ordinal = None
    no_launch_ack = False
    cleanup = True
    def __init__(self, *args, **kwargs):
        self.sink = kwargs['event_sink']; self.calls = []
        self.instances.append(self)
    def run_item(self, circuit, transition):
        self.calls.append((circuit, transition))
        journal = FakeJournal.instances[-1]
        assert journal.rows[-1][0] == 'INTENT'
        if not self.no_launch_ack:
            self.sink('PREFLIGHT', {'job_id': 123, 'mock_only': True})
            self.sink('LAUNCHED', {'pid': 77})
        accepted = len(self.calls) != self.fail_ordinal
        return dict(circuit=circuit, transition=transition, accepted=accepted,
            cleanup_verified=self.cleanup, returncode=0 if accepted else 7,
            status='PASS' if accepted else 'FAIL', tessent_calls=1,
            actual_atpg_calls=0, execution_ready=False, training_release=False)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        for cls in (FakeMaterializer, FakeProcess, FakeJournal):
            cls.instances = []
        FakeJournal.fail_kind = None
        FakeProcess.fail_ordinal = None
        FakeProcess.no_launch_ack = False
        FakeProcess.cleanup = True
        FakeMaterializer.close_error = False

    def run_fake(self, auth=None):
        with mock.patch.object(m, '_components', return_value=(FakeMaterializer, FakeProcess)), \
             mock.patch.object(m, '_DurableJournal', FakeJournal):
            return m.run_package(E85, E93, authority() if auth is None else auth)

    def test_exact_four_cases_with_durable_intent_and_launch_order(self):
        result = self.run_fake()
        self.assertEqual(result['status'], 'FOUR_ACCEPTANCE_CASES_COMPLETE_ONLY')
        self.assertEqual(FakeProcess.instances[0].calls,
                         [(c, t) for c, t, _ in m.recipes.ROSTER])
        kinds = [x[0] for x in FakeJournal.instances[0].rows]
        self.assertEqual(kinds, ['HEADER'] +
            ['MATERIALIZED', 'INTENT', 'PREFLIGHT', 'LAUNCHED', 'TERMINAL'] * 4 + ['CLOSE'])
        self.assertFalse(result['execution_ready'])
        self.assertFalse(result['training_release'])

    def test_intent_fsync_consumes_package_budget_before_process(self):
        now = [0.0]
        original = FakeJournal.append
        def slow_append(journal, kind, payload):
            result = original(journal, kind, payload)
            if kind == 'INTENT':
                now[0] = 2701.0
            return result
        with mock.patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), \
             mock.patch.object(FakeJournal, 'append', slow_append):
            with self.assertRaisesRegex(m.CoordinatorError, 'INSUFFICIENT_ITEM_WALL_BUDGET'):
                self.run_fake()
        self.assertEqual(FakeProcess.instances[0].calls, [])

    def test_external_entry_deadline_cannot_be_reset(self):
        with mock.patch.object(m.time, 'monotonic', return_value=1000), \
             mock.patch.object(m, '_components', return_value=(FakeMaterializer, FakeProcess)), \
             mock.patch.object(m, '_DurableJournal', FakeJournal):
            with self.assertRaisesRegex(m.CoordinatorError, 'INSUFFICIENT_ITEM_WALL_BUDGET'):
                m.run_package(E85, E93, authority(), package_deadline=1599)
        self.assertEqual(FakeProcess.instances[0].calls, [])

    def test_no_authority_or_excess_cap_before_components(self):
        for changes in ({'approved': False}, {'memory_cap_bytes': None},
                        {'memory_cap_bytes': True}, {'memory_cap_bytes': m.MAX_MEMORY + 1},
                        {'scope': 'TRAIN'}, {'job_id': 0}):
            with mock.patch.object(m, '_components') as components:
                with self.assertRaises(m.CoordinatorError):
                    m.run_package(E85, E93, dict(authority(), **changes))
                components.assert_not_called()

    def test_failure_stops_entire_roster_without_retry(self):
        FakeProcess.fail_ordinal = 2
        with self.assertRaisesRegex(m.CoordinatorError, 'ACCEPTANCE_OR_CLEANUP_FAILED'):
            self.run_fake()
        self.assertEqual(len(FakeProcess.instances[0].calls), 2)
        self.assertEqual(FakeJournal.instances[0].rows[-1][0], 'STOP')
        self.assertTrue(FakeMaterializer.instances[0].closed)

    def test_unknown_cleanup_and_missing_launch_ack_stop(self):
        FakeProcess.cleanup = False
        with self.assertRaises(m.CoordinatorError):
            self.run_fake()
        self.assertEqual(len(FakeProcess.instances[0].calls), 1)
        self.setUp(); FakeProcess.no_launch_ack = True
        with self.assertRaises(m.CoordinatorError):
            self.run_fake()
        self.assertEqual(len(FakeProcess.instances[0].calls), 1)

    def test_failed_launch_ack_no_next_item(self):
        FakeJournal.fail_kind = 'LAUNCHED'
        with self.assertRaises(OSError):
            self.run_fake()
        self.assertEqual(len(FakeProcess.instances[0].calls), 1)
        self.assertEqual(FakeJournal.instances[0].rows[-1][0], 'STOP')

    def test_close_failure_still_releases_worker(self):
        FakeMaterializer.close_error = True
        with self.assertRaises(OSError):
            self.run_fake()
        self.assertTrue(m._WORKER.acquire(False))
        m._WORKER.release()

    def test_temporary_fd_journal_fsync_readback_and_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / m.JOURNAL_NAME
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_BINARY', 0), 0o600)
            journal = object.__new__(m._DurableJournal)
            journal.parent = None; journal.fd = fd
            journal.head = '0' * 64; journal.count = 0; journal.bytes = 0
            journal.prefix_sha256 = m.sha(b'')
            real_stat = os.stat
            real_read = os.read
            def named(name, *args, **kwargs):
                return real_stat(str(path))
            def pread(handle, size, offset):
                current = os.lseek(handle, 0, os.SEEK_CUR)
                os.lseek(handle, offset, os.SEEK_SET)
                data = real_read(handle, size)
                os.lseek(handle, current, os.SEEK_SET)
                return data
            try:
                with mock.patch.object(m.os, 'stat', side_effect=named), \
                     mock.patch.object(m.os, 'pread', side_effect=pread, create=True):
                    journal.identity = journal._check()
                    ack = journal.append('HEADER', {'test_fixture': True})
                    row = json.loads(path.read_bytes())
                    self.assertEqual(ack['sha256'], row['sha256'])
                    self.assertEqual(row['prev'], '0' * 64)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, b'X')
                    with self.assertRaisesRegex(m.CoordinatorError, 'JOURNAL_PREFIX_CHANGED'):
                        journal.append('INTENT', {})
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, b'{')
                    os.lseek(fd, 0, os.SEEK_END)
                    os.write(fd, b'x')
                    with self.assertRaisesRegex(m.CoordinatorError, 'JOURNAL_CHANGED'):
                        journal.append('INTENT', {})
            finally:
                journal.close()

    def test_python36_and_no_direct_process_or_scheduler_calls(self):
        source = Path(m.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source, **({'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}))
        attrs = {x.func.attr for x in ast.walk(tree) if isinstance(x, ast.Call)
                 and isinstance(x.func, ast.Attribute)}
        self.assertFalse(attrs & {'Popen', 'system', 'kill', 'killpg'})
        self.assertNotIn('bsub', source)


if __name__ == '__main__':
    unittest.main()
