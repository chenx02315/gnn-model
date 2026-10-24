"""Mock-only fixed-ID retirement. Never calls a scheduler or remote host."""
import ast
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/retire_acceptance_job_e98.py'
SPEC = importlib.util.spec_from_file_location('retire_e98_tests', str(SOURCE))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def raw(state='PEND'):
    return ('Job <394230>, Job Name <gnn_e97_acceptance_r1>, Status <' + state +
            '>, Command <' + m.base.BINDIR + 'blaunch /usr/bin/python3 -I -S -B ' +
            m.OLD_ROOT + '/scripts/run_acceptance_job_e97.py>\nSpecified CWD <' +
            m.OLD_ROOT + '>\n').encode('ascii')


def client(state='PEND'):
    return dict(status='CLIENT_COMPLETE', returncode=0, stdout=raw(state), stderr=b'')


def fixture():
    obs = dict(schema='e98-retirement-observation-v1', job_id=m.JOB_ID,
               observed_at_epoch=1000, authorization_sha256=m.AUTH_SHA256,
               bkill_metadata={'nlink': 4}, query=m._client_record(client()), state='PEND')
    review = m.canonical(dict(schema='e98-independent-retirement-review-v1',
                              job_id=m.JOB_ID, passed=True, independent=True,
                              observation_sha256=m.sha(m.canonical(obs)), issued_at_epoch=1005))
    return obs, review, m.sha(review)


class RetireTests(unittest.TestCase):
    def setup_fakes(self, stack, results):
        stack.enter_context(mock.patch.object(m, '_host'))
        stack.enter_context(mock.patch.object(m.time, 'time', return_value=1010))
        stack.enter_context(mock.patch.object(m, '_metadata', return_value={'nlink': 4}))
        stack.enter_context(mock.patch.object(m.base, '_directory', return_value=10))
        stack.enter_context(mock.patch.object(m.os, 'mkdir'))
        stack.enter_context(mock.patch.object(m.os, 'fsync'))
        stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
        stack.enter_context(mock.patch.object(m.os, 'close'))
        stack.enter_context(mock.patch.object(m.os, 'getuid', return_value=1000, create=True))
        stack.enter_context(mock.patch.object(m.os, 'fstat', return_value=SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=1000)))
        stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
        stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
        calls = stack.enter_context(mock.patch.object(m.base, '_client', side_effect=results))
        persisted = stack.enter_context(mock.patch.object(m.base, '_persist'))
        return calls, persisted

    def test_exact_identity_and_states(self):
        for state in m.TERMINAL + m.ACTIVE:
            self.assertEqual(m._state(client(state)), state)
        for old, new in ((b'394230', b'394231'), (b'gnn_e97_acceptance_r1', b'other'),
                         (b'run_acceptance_job_e97.py', b'evil.py'),
                         (b'Specified CWD', b'CWD'), (b'PEND', b'OTHER')):
            result = client()
            result['stdout'] = result['stdout'].replace(old, new)
            with self.assertRaises(m.RetireError):
                m._state(result)
        result = client(); result['stdout'] += b'Job <394230>\n'
        with self.assertRaises(m.RetireError):
            m._state(result)

    def test_already_terminal_new_proof_no_kill(self):
        for state in m.TERMINAL:
            with ExitStack() as stack:
                calls, persisted = self.setup_fakes(stack, [client(state)])
                result = m.retire_once(*fixture())
                self.assertEqual(result['status'], 'ALREADY_TERMINAL')
                self.assertEqual(result['cancellation_calls'], 0)
                self.assertTrue(result['terminal_confirmed'])
                calls.assert_called_once_with([m.base.BINDIR + 'bjobs', '-l', '394230'])
                names = [c[0][1] for c in persisted.call_args_list]
                self.assertIn('retirement_result.json', names)
                self.assertNotIn('cancellation_intent.json', names)
                self.assertFalse(result['terminal_proof']['cancellation_attempted'])
                self.assertEqual(result['terminal_proof']['terminal_state'], state)

    def test_one_kill_intent_before_call_and_terminal_confirmation(self):
        with ExitStack() as stack:
            calls, persisted = self.setup_fakes(stack, [client(), client(), client('EXIT')])
            events = []
            persisted.side_effect = lambda fd, name, body: events.append(name)
            results = iter([client(), client(), client('EXIT')])
            def launch(argv):
                events.append(argv[0].rsplit('/', 1)[-1])
                return next(results)
            calls.side_effect = launch
            result = m.retire_once(*fixture())
            self.assertEqual(result['status'], 'TERMINAL_CONFIRMED')
            self.assertEqual(calls.call_args_list, [
                mock.call([m.base.BINDIR + 'bjobs', '-l', '394230']),
                mock.call([m.base.BINDIR + 'bkill', '394230']),
                mock.call([m.base.BINDIR + 'bjobs', '-l', '394230'])])
            self.assertLess(events.index('cancellation_intent.json'), events.index('bkill'))
            self.assertLess(events.index('bkill_outcome.json'), len(events) - 1)
            self.assertLess(len(m.canonical(result)), m.OUTPUT_CAP)

    def test_pending_or_unknown_kill_never_retried(self):
        unknown = dict(status='CLIENT_FAILURE_UNKNOWN', returncode=None, stdout=b'', stderr=b'')
        for after in (client(), client('RUN'), unknown, RuntimeError('secret')):
            with ExitStack() as stack:
                calls, persisted = self.setup_fakes(stack, [client(), unknown, after])
                result = m.retire_once(*fixture())
                self.assertEqual(result['status'], 'CANCELLATION_PENDING_CONFIRMATION')
                self.assertFalse(result['terminal_confirmed'])
                self.assertEqual(result['cancellation_calls'], 1)
                self.assertEqual(calls.call_count, 3)
                self.assertNotIn('secret', m.canonical(result).decode('ascii'))
                self.assertIn('bkill_outcome.json', [c[0][1] for c in persisted.call_args_list])
                self.assertNotIn('retirement_result.json', [c[0][1] for c in persisted.call_args_list])

    def test_existing_control_fails_before_mutation(self):
        with ExitStack() as stack:
            calls, persisted = self.setup_fakes(stack, [client()])
            m.os.mkdir.side_effect = FileExistsError()
            with self.assertRaises(FileExistsError):
                m.retire_once(*fixture())
            self.assertEqual(calls.call_count, 1)
            persisted.assert_not_called()

    def test_review_pin_age_and_metadata_drift_fail_before_mutation(self):
        for issue in ('pin', 'age', 'metadata', 'unbound'):
            with ExitStack() as stack:
                calls, persisted = self.setup_fakes(stack, [])
                args = list(fixture())
                if issue == 'pin':
                    args[2] = '0' * 64
                elif issue == 'age':
                    m.time.time.return_value = 1400
                elif issue == 'metadata':
                    m._metadata.return_value = {'nlink': 5}
                else:
                    args[0]['state'] = 'RUN'
                with self.assertRaises(m.RetireError):
                    m.retire_once(*args)
                calls.assert_not_called()
                persisted.assert_not_called()

    def test_observe_readonly(self):
        with mock.patch.object(m, '_host'), \
                mock.patch.object(m.time, 'time', return_value=1000), \
                mock.patch.object(m, '_metadata', return_value={'nlink': 4}), \
                mock.patch.object(m.base, '_client', return_value=client()) as calls, \
                mock.patch.object(m.base, '_persist') as persisted, \
                mock.patch.object(m.os, 'mkdir') as mkdir:
            result = m.observe()
            self.assertEqual(result['remote_writes'], 0)
            self.assertEqual(result['bkill_metadata']['nlink'], 4)
            calls.assert_called_once_with([m.base.BINDIR + 'bjobs', '-l', '394230'])
            persisted.assert_not_called(); mkdir.assert_not_called()

    def test_metadata_observation_accepts_real_link_count_not_assumed_one(self):
        row = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_nlink=4, st_size=42,
                              st_dev=1, st_ino=2, st_uid=0, st_gid=10007,
                              st_mtime_ns=3, st_ctime_ns=4)
        with mock.patch.object(m.base, '_directory', return_value=10), \
                mock.patch.object(m.os, 'stat', return_value=row) as read, \
                mock.patch.object(m.os, 'close'):
            self.assertEqual(m._metadata()['nlink'], 4)
            read.assert_called_once_with('bkill', dir_fd=10, follow_symlinks=False)
            row.st_mode = stat.S_IFLNK | 0o755
            with self.assertRaises(m.RetireError):
                m._metadata()

    def test_finalize_queries_only_and_never_overwrites_pending_receipt(self):
        for state in ('PEND', 'EXIT'):
            with ExitStack() as stack:
                calls, persisted = self.setup_fakes(stack, [client(state)])
                prior = m.canonical(m._result('CANCELLATION_PENDING_CONFIRMATION', 'PEND', 1))
                stack.enter_context(mock.patch.object(m.base, '_read', return_value=(prior, None)))
                result = m.finalize_terminal()
                calls.assert_called_once_with([m.base.BINDIR + 'bjobs', '-l', '394230'])
                names = [c[0][1] for c in persisted.call_args_list]
                self.assertNotIn('cancel_result.json', names)
                self.assertEqual(result['terminal_confirmed'], state == 'EXIT')
                if state == 'EXIT':
                    self.assertIn('retirement_result.json', names)
                    self.assertTrue(result['terminal_proof']['cancellation_attempted'])
                else:
                    persisted.assert_not_called()

    def test_finalize_missing_or_wrong_prior_fails_before_query(self):
        for value in ({}, {'schema': 'e98-retirement-result-v1', 'job_id': 394231,
                          'cancellation_calls': 1}):
            with ExitStack() as stack:
                calls, persisted = self.setup_fakes(stack, [])
                stack.enter_context(mock.patch.object(m.base, '_read',
                                                      return_value=(m.canonical(value), None)))
                with self.assertRaises(m.RetireError):
                    m.finalize_terminal()
                calls.assert_not_called(); persisted.assert_not_called()

    def test_python36_no_main_and_no_registration_or_resume_calls(self):
        source = SOURCE.read_text(encoding='utf-8')
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        tree = ast.parse(source, **kwargs)
        forbidden = {'register', '_argv', '_verify', 'resume_once'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
        self.assertNotIn("if __name__", source)
        with self.assertRaises(m.RetireError):
            m._client_record(dict(stdout=b'x' * 8193, stderr=b'', status='x', returncode=0))


if __name__ == '__main__':
    unittest.main()
