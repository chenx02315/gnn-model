"""E76 in-process fake-only checks. No subprocess, Linux, Docker or remote I/O."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from src.data import prospective_lifecycle_journal_v2 as m


class Clock:
    def __init__(self, values=(10, 20), session='synthetic-clock'):
        self.values = iter(values)
        self.session = session

    def capture(self):
        return self.session, next(self.values)


class Backend:
    synthetic_only = True
    os_authenticated = False
    actual_processes = 0

    def __init__(self, number=1):
        self.number = number
        self.calls = []
        self.launch_error = None
        self.finish_error = None
        self.cleanup_error = None
        self.cleanup_value = dict(leader_reaped=True, observed_group_empty=True)

    def launch(self, profile):
        self.calls.append('launch')
        if self.launch_error:
            raise self.launch_error
        identity = dict(host='synthetic-local', boot_id='synthetic-boot',
                        pid=self.number, start_ticks=self.number)
        return object(), identity

    def finish(self, handle, profile):
        self.calls.append('finish')
        if self.finish_error:
            raise self.finish_error
        status, code, timed_out = m.EXPECTED[profile]
        return dict(status=status, returncode=code, timed_out=timed_out)

    def cleanup(self, handle):
        self.calls.append('cleanup')
        if self.cleanup_error:
            raise self.cleanup_error
        return self.cleanup_value


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'journal.jsonl')

    def test_three_profiles_serial_live_ack_and_replay_not_ack(self):
        with m.Journal.create(self.path) as journal:
            for index, profile in enumerate(m.FIXED_PROFILES, 1):
                out = journal.run('a'+str(index), profile, Backend(index), Clock((index*10,index*10+3)))
                self.assertTrue(out['complete_live_acknowledged'])
                self.assertEqual(out['attempt_count'], index)
            self.assertEqual(out['observed_interval_ns_sum_or_None'], 9)
            head = out['head_sha256']
        replay = m.load(self.path)
        self.assertEqual(replay['head_sha256'], head)
        self.assertTrue(replay['structural_complete'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])
        self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_backend_mutates_original_identity_but_live_matches_replay(self):
        class MutatingBackend(Backend):
            def launch(self, profile):
                handle, self.original_identity = super().launch(profile)
                return handle, self.original_identity

            def finish(self, handle, profile):
                self.original_identity['pid'] = 999
                self.original_identity['host'] = 'synthetic-mutated'
                return super().finish(handle, profile)

        backend = MutatingBackend()
        with m.Journal.create(self.path) as journal:
            live = journal.run('a1', 'success', backend, Clock())
            self.assertTrue(live['complete_live_acknowledged'])
            self.assertEqual(live['attempts']['a1']['identity']['pid'], 1)
        replay = m.load(self.path)
        self.assertTrue(replay['structural_complete'])
        self.assertEqual(replay['attempts']['a1']['identity'], live['attempts']['a1']['identity'])

    def test_append_deepcopies_caller_payload(self):
        with m.Journal.create(self.path) as journal:
            payload = dict(profile='success',clock_session='synthetic-clock',prelaunch_ns=10)
            row = journal.append('INTENT','a1',payload)
            payload['profile'] = 'failure'
            row['payload']['profile'] = 'timeout_group'
            self.assertEqual(journal.snapshot()['attempts']['a1']['profile'], 'success')
        self.assertEqual(m.load(self.path)['attempts']['a1']['profile'], 'success')

    def test_exclusive_create(self):
        with m.Journal.create(self.path):
            with self.assertRaises(FileExistsError):
                m.Journal.create(self.path)

    def test_empty_journal_is_not_zero_cost_complete(self):
        with m.Journal.create(self.path) as journal:
            live = journal.snapshot()
            self.assertFalse(live['complete_live_acknowledged'])
            self.assertIsNone(live['observed_interval_ns_sum_or_None'])
        self.assertFalse(m.load(self.path)['structural_complete'])

    def test_snapshot_detects_external_file_change(self):
        with m.Journal.create(self.path) as journal:
            journal.run('a1', 'success', Backend(), Clock())
            self.assertEqual(journal.snapshot()['observed_interval_ns_sum_or_None'], 10)
            with open(self.path, 'ab') as stream:
                stream.write(b'foreign')
            state = journal.snapshot()
            self.assertFalse(state['complete_live_acknowledged'])
            self.assertIsNone(state['observed_interval_ns_sum_or_None'])

    def test_intent_append_failure_never_launches(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            with mock.patch.object(journal, 'append', side_effect=OSError('intent failed')):
                with self.assertRaises(OSError):
                    journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, [])

    def test_unknown_spawn_blocks_retry_and_cost(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            backend.launch_error = RuntimeError('unknown spawn')
            with self.assertRaises(RuntimeError):
                journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, ['launch'])
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])
            with self.assertRaisesRegex(ValueError, 'UNRESOLVED_OR_DUPLICATE'):
                journal.run('a2', 'success', Backend(2), Clock())

    def test_none_handle_is_unknown_spawn_not_complete(self):
        class NoHandle(Backend):
            def launch(self, profile):
                unused, identity = super().launch(profile)
                return None, identity

        with m.Journal.create(self.path) as journal:
            backend = NoHandle()
            with self.assertRaisesRegex(ValueError, 'UNKNOWN_SPAWN_HANDLE'):
                journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, ['launch'])
            state = journal.snapshot()
            self.assertFalse(state['complete_live_acknowledged'])
            self.assertIsNone(state['observed_interval_ns_sum_or_None'])
            later = Backend(2)
            with self.assertRaisesRegex(ValueError, 'UNRESOLVED_OR_DUPLICATE'):
                journal.run('a2', 'failure', later, Clock())
            self.assertEqual(later.calls, [])

    def test_launched_append_failure_still_cleans_known_handle(self):
        with m.Journal.create(self.path) as journal:
            original = journal.append
            def failing(kind, aid, payload):
                if kind == 'LAUNCHED':
                    raise OSError('ack fail')
                return original(kind, aid, payload)
            backend = Backend()
            with mock.patch.object(journal, 'append', side_effect=failing):
                with self.assertRaises(OSError):
                    journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, ['launch', 'cleanup'])
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_finish_exception_cleans_and_blocks(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            backend.finish_error = RuntimeError('wait failed')
            with self.assertRaises(RuntimeError):
                journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, ['launch', 'finish', 'cleanup'])
            self.assertFalse(journal.snapshot()['complete_live_acknowledged'])

    def test_primary_and_cleanup_exceptions_both_preserved(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            backend.finish_error = KeyboardInterrupt('cancelled')
            backend.cleanup_error = RuntimeError('cleanup failed')
            with self.assertRaises(RuntimeError) as raised:
                journal.run('a1', 'success', backend, Clock())
            self.assertIsInstance(raised.exception.__cause__, KeyboardInterrupt)
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_baseexception_after_launch_cleans_and_propagates(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            backend.finish_error = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                journal.run('a1', 'success', backend, Clock())
            self.assertEqual(backend.calls, ['launch', 'finish', 'cleanup'])

    def test_cleanup_failure_or_residual_group_blocks(self):
        for failure in (RuntimeError('cleanup failed'), False):
            path = str(Path(self.tmp.name) / ('j'+str(bool(failure))))
            with m.Journal.create(path) as journal:
                backend = Backend()
                if failure is False:
                    backend.cleanup_value = dict(leader_reaped=True,
                                                 observed_group_empty=False)
                else:
                    backend.cleanup_error = failure
                with self.assertRaises((RuntimeError, ValueError)):
                    journal.run('a1', 'success', backend, Clock())
                self.assertEqual(backend.calls[-1], 'cleanup')
                self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_terminal_full_row_fsync_failure_replay_cannot_claim_ack(self):
        with m.Journal.create(self.path) as journal:
            real_fsync = os.fsync
            calls = [0]
            def fail_terminal(fd):
                calls[0] += 1
                if calls[0] == 3:
                    raise OSError('terminal fsync uncertain')
                return real_fsync(fd)
            with mock.patch.object(m.os, 'fsync', side_effect=fail_terminal):
                with self.assertRaises(OSError):
                    journal.run('a1', 'success', Backend(), Clock())
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])
        replay = m.load(self.path)
        self.assertTrue(replay['structural_complete'])
        self.assertFalse(replay['fsync_acknowledgments_verified'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])

    def test_short_write_poison(self):
        with m.Journal.create(self.path) as journal:
            stream = journal._stream
            class Short:
                @property
                def closed(self): return stream.closed
                def fileno(self): return stream.fileno()
                def write(self, raw): return stream.write(raw[:-1])
                def close(self): return stream.close()
            journal._stream = Short()
            with self.assertRaisesRegex(ValueError, 'SHORT_WRITE'):
                journal.append('INTENT', 'a1', dict(profile='success', clock_session='toy', prelaunch_ns=1))
            self.assertIsNone(journal.snapshot()['observed_interval_ns_sum_or_None'])

    def test_hardlink_identity_refused(self):
        with m.Journal.create(self.path) as journal:
            os.link(self.path, self.path+'.link')
            with self.assertRaisesRegex(ValueError, 'JOURNAL_IDENTITY_CHANGED'):
                journal.append('INTENT', 'a1', dict(profile='success', clock_session='toy', prelaunch_ns=1))

    def test_torn_tail_rejected(self):
        with m.Journal.create(self.path) as journal:
            journal.append('INTENT','a1',dict(profile='success',clock_session='toy',prelaunch_ns=1))
        with open(self.path, 'ab') as stream:
            stream.write(b'{"broken":')
        with self.assertRaisesRegex(ValueError, 'TORN_OR_OVERSIZE_LINE'):
            m.load(self.path)

    def test_tamper_and_duplicate_rejected(self):
        with m.Journal.create(self.path) as journal:
            row = journal.append('INTENT','a1',dict(profile='success',clock_session='toy',prelaunch_ns=1))
        raw = Path(self.path).read_bytes()
        Path(self.path).write_bytes(raw.replace(b'"success"', b'"failure"'))
        with self.assertRaisesRegex(ValueError, 'EVENT_CHAIN'):
            m.load(self.path)
        Path(self.path).write_bytes(raw + m.canonical(row)+b'\n')
        with self.assertRaisesRegex(ValueError, 'EVENT_CHAIN'):
            m.load(self.path)

    def test_wrong_clock_and_identity_replay_rejected(self):
        state = m.State()
        aid = 'a1'
        for kind, payload in [('INTENT',dict(profile='success',clock_session='toy',prelaunch_ns=10)),
                              ('LAUNCHED',dict(identity=dict(host='synthetic-local',boot_id='boot',pid=1,start_ticks=1)))]:
            body = state.event(kind, aid, payload)
            state.apply(dict(body, sha256=m.sha(m.canonical(body))))
        wrong = dict(identity=dict(host='synthetic-other',boot_id='boot',pid=1,start_ticks=1),
                     clock_session='wrong',end_ns=20,interval_ns=10,status='SUCCESS',
                     returncode=0,timed_out=False,leader_reaped=True,observed_group_empty=True)
        body = state.event('REAPED', aid, wrong)
        with self.assertRaisesRegex(ValueError, 'REAPED_PROOF'):
            state.apply(dict(body,sha256=m.sha(m.canonical(body))))

    def test_cross_attempt_clock_barrier_and_bool_type(self):
        state = m.State()
        identity = dict(host='synthetic-local',boot_id='boot',pid=1,start_ticks=1)
        for kind,payload in [('INTENT',dict(profile='success',clock_session='toy',prelaunch_ns=10)),
                             ('LAUNCHED',dict(identity=identity))]:
            body=state.event(kind,'a1',payload)
            state.apply(dict(body,sha256=m.sha(m.canonical(body))))
        terminal=dict(identity=identity,clock_session='toy',end_ns=20,interval_ns=10,
                      status='SUCCESS',returncode=0,timed_out=0,
                      leader_reaped=True,observed_group_empty=True)
        body=state.event('REAPED','a1',terminal)
        with self.assertRaisesRegex(ValueError,'REAPED_PROOF'):
            state.apply(dict(body,sha256=m.sha(m.canonical(body))))
        terminal['timed_out']=False
        body=state.event('REAPED','a1',terminal)
        state.apply(dict(body,sha256=m.sha(m.canonical(body))))
        for session,start in [('other',20),('toy',19)]:
            body=state.event('INTENT','a2',dict(profile='failure',clock_session=session,prelaunch_ns=start))
            with self.assertRaisesRegex(ValueError,'INTENT_STATE'):
                state.apply(dict(body,sha256=m.sha(m.canonical(body))))

    def test_incomplete_replay_never_zero_fills(self):
        with m.Journal.create(self.path) as journal:
            journal.append('INTENT','a1',dict(profile='success',clock_session='toy',prelaunch_ns=1))
        replay = m.load(self.path)
        self.assertFalse(replay['structural_complete'])
        self.assertIsNone(replay['observed_interval_ns_sum_or_None'])

    def test_reject_non_synthetic_backend(self):
        with m.Journal.create(self.path) as journal:
            backend = Backend()
            backend.actual_processes = 1
            with self.assertRaisesRegex(ValueError, 'SYNTHETIC_BACKEND_ONLY'):
                journal.run('a1','success',backend,Clock())
            self.assertEqual(backend.calls, [])


if __name__ == '__main__':
    unittest.main()
