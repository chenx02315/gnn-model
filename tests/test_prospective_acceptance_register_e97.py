"""One-shot registration mocks only. Never call a real scheduler or remote host."""
import ast
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/register_acceptance_job_e97.py'
SPEC = importlib.util.spec_from_file_location('register_e97_test', str(PATH))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def client(stdout=b'Job <123> is submitted to queue <normal>.\n', status='CLIENT_COMPLETE', rc=0):
    return dict(stdout=stdout, stderr=b'', status=status, returncode=rc)


class RegisterTests(unittest.TestCase):
    def invoke(self, responses):
        events = []
        artifacts = {}
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.sys, 'platform', 'linux'))
            stack.enter_context(mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'))
            stack.enter_context(mock.patch.object(m, '_verify', side_effect=lambda:
                events.append('verified') or 230684))
            stack.enter_context(mock.patch.object(m, '_directory', return_value=10))
            stack.enter_context(mock.patch.object(m.os, 'O_DIRECTORY', 1, create=True))
            stack.enter_context(mock.patch.object(m.os, 'O_NOFOLLOW', 2, create=True))
            stack.enter_context(mock.patch.object(m.os, 'mkdir', side_effect=lambda *a, **kw: events.append('mkdir')))
            stack.enter_context(mock.patch.object(m.os, 'fsync'))
            stack.enter_context(mock.patch.object(m.os, 'open', return_value=11))
            stack.enter_context(mock.patch.object(m.os, 'fstat', return_value=directory))
            stack.enter_context(mock.patch.object(m.os, 'getuid', return_value=1000, create=True))
            stack.enter_context(mock.patch.object(m.os, 'close'))
            def persist(fd, name, raw):
                events.append(name)
                self.assertNotIn(name, artifacts)
                artifacts[name] = raw
            stack.enter_context(mock.patch.object(m, '_persist', side_effect=persist))
            calls = stack.enter_context(mock.patch.object(m, '_client', side_effect=responses))
            result = m.register()
        return result, calls.call_args_list, events, artifacts

    def test_fixed_exact_command(self):
        argv = m._argv()
        self.assertEqual(argv, [m.BINDIR + 'bsub', '-H', '-rn', '-n', '1', '-q', 'normal',
            '-m', 'bupt-vncs2', '-J', 'gnn_e97_acceptance_r1', '-M', '512', '-R',
            'rusage[mem=512] span[hosts=1]', '-W', '45', '-cwd', m.ROOT,
            '-oo', m.ROOT + '/registration/stdout.log', '-eo', m.ROOT + '/registration/stderr.log',
            m.BINDIR + 'blaunch', '/usr/bin/python3', '-I', '-S', '-B',
            m.ROOT + '/scripts/run_acceptance_job_e97.py'])

    def test_known_id_then_only_exact_query_and_no_review_claim(self):
        result, calls, events, artifacts = self.invoke([client(), client(b'held metadata')])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0][0], [m.BINDIR + 'bjobs', '-l', '123'])
        self.assertLess(events.index('intent.json'), events.index('bsub_stdout.bin'))
        self.assertEqual(events[:2], ['verified', 'mkdir'])
        self.assertFalse(result['registration_review_passed'])
        self.assertFalse(result['automatic_resume'])
        self.assertEqual(result['status'], 'REGISTERED_HELD_REVIEW_PENDING')
        self.assertEqual(artifacts['bjobs_stdout.bin'], b'held metadata')

    def test_unknown_submission_consumes_attempt_and_preserves_failure(self):
        for response in (client(b''), client(b'ambiguous'), client(status='CLIENT_FAILURE_UNKNOWN', rc=None),
                         client(rc=1), client(b'Job <123> is submitted to queue <normal>.\n' * 2)):
            result, calls, _, artifacts = self.invoke([response])
            self.assertEqual(len(calls), 1)
            self.assertIsNone(result['jobs_submitted'])
            self.assertTrue(result['submission_attempted'])
            self.assertEqual(result['status'], 'UNKNOWN_SUBMISSION_CONSUMED_NO_RETRY')
            self.assertIn('result.json', artifacts)
            self.assertNotIn('bjobs_stdout.bin', artifacts)

    def test_query_failure_keeps_known_job_and_review_pending(self):
        result, calls, _, _ = self.invoke([client(), client(status='CLIENT_FAILURE_UNKNOWN', rc=None)])
        self.assertEqual(result['job_id'], 123)
        self.assertEqual(result['jobs_submitted'], 1)
        self.assertFalse(result['registration_review_passed'])
        self.assertEqual(len(calls), 2)

    def test_wrong_host_before_any_write(self):
        with mock.patch.object(m.platform, 'node', return_value='elsewhere'), \
                mock.patch.object(m, '_verify') as verify, mock.patch.object(m, '_client') as run:
            with self.assertRaises(m.RegisterError):
                m.register()
            verify.assert_not_called(); run.assert_not_called()

    def test_verification_failure_never_submits(self):
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m, '_verify', side_effect=m.RegisterError('PIN')), \
                mock.patch.object(m.os, 'mkdir') as mkdir, mock.patch.object(m, '_client') as run:
            with self.assertRaises(m.RegisterError):
                m.register()
            mkdir.assert_not_called(); run.assert_not_called()

    def test_collision_never_submits_or_overwrites(self):
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m, '_verify'), mock.patch.object(m, '_directory', return_value=10), \
                mock.patch.object(m.os, 'mkdir', side_effect=FileExistsError()), \
                mock.patch.object(m.os, 'close'), mock.patch.object(m, '_client') as run:
            with self.assertRaises(FileExistsError):
                m.register()
            run.assert_not_called()

    def test_client_spawn_unknown_no_retry(self):
        with mock.patch.object(m.subprocess, 'Popen', side_effect=OSError('unknown')) as spawn:
            result = m._client(m._argv())
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(result['status'], 'CLIENT_FAILURE_UNKNOWN')
        self.assertEqual(result['stdout'], b'')

    def test_client_output_cap_kills_only_client(self):
        child = mock.Mock()
        child.stdout.fileno.return_value = 10
        child.poll.side_effect = [None, -9]
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: 1}
        selector.select.return_value = [(types.SimpleNamespace(fileobj=child.stdout, data='stdout'), 1)]
        with mock.patch.object(m.subprocess, 'Popen', return_value=child), \
                mock.patch.object(m.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(m.time, 'monotonic', return_value=0), \
                mock.patch.object(m.os, 'read', side_effect=lambda fd, count: b'x' * count):
            result = m._client(m._argv())
        self.assertEqual(len(result['stdout']), 8192)
        self.assertEqual(result['status'], 'CLIENT_FAILURE_UNKNOWN')
        child.kill.assert_called_once()
        child.wait.assert_called_once()

    def test_client_timeout_preserves_unknown_and_kills_only_client(self):
        child = mock.Mock(); child.poll.side_effect = [None, -9]
        selector = mock.MagicMock(); selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: 1}
        with mock.patch.object(m.subprocess, 'Popen', return_value=child), \
                mock.patch.object(m.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(m.time, 'monotonic', side_effect=[0, 26, 26]):
            result = m._client(m._argv())
        self.assertEqual(result['status'], 'CLIENT_FAILURE_UNKNOWN')
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_args[1]['timeout'], 4)

    def test_manifest_pin_before_json(self):
        with mock.patch.object(m, '_read', return_value=(b'bad', None)), \
                mock.patch.object(m.json, 'loads') as parse:
            with self.assertRaisesRegex(m.RegisterError, 'MANIFEST_PIN'):
                m._verify()
            parse.assert_not_called()

    def test_submission_id_strict_types_and_range(self):
        for response in (client(rc=False), client(b'Job <0> is submitted to queue <normal>.\n'),
                         client(b'Job <9999999999999999999> is submitted to queue <normal>.\n'),
                         client(b'Job <123[1]> is submitted to queue <normal>.\n')):
            self.assertIsNone(m._submission_id(response))

    def test_python36_no_automatic_entry_no_resume(self):
        source = PATH.read_text()
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(source, **kwargs)
        self.assertNotIn('__main__', source)
        self.assertNotIn('bresume', source)
        self.assertNotIn('killpg', source)
        self.assertEqual(m.CLIENT_CAP * 2, 16384)


if __name__ == '__main__':
    unittest.main()
