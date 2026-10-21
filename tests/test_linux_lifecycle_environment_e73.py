"""Pure fake-pipe tests: never run Docker or connect to any endpoint."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import probe_linux_lifecycle_environment_e73 as probe


INFO = b'{"CgroupVersion":"2","OSType":"linux","ServerVersion":"26.1"}\n'
IMAGE = json.dumps(dict(Repository='python', Tag='3.6', ID='sha256:' + 'a' * 64,
                       Size='not returned', CreatedAt='not returned')).encode() + b'\n'


class Pipe:
    def __init__(self, number):
        self.number = number
        self.closed = False

    def fileno(self):
        return self.number

    def close(self):
        self.closed = True


class FakeDocker:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.buffers = {}
        self.consumed = {}
        self.processes = []

    def popen(self, command, **kwargs):
        self.calls.append((command, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        out, err, code = response
        number = 2 * len(self.calls)
        process = SimpleNamespace(stdout=Pipe(number), stderr=Pipe(number + 1),
                                  returncode=None, terminated=False, killed=False)
        self.buffers[number] = out
        self.buffers[number + 1] = err
        self.consumed[number] = self.consumed[number + 1] = 0

        def wait(timeout):
            self.assert_positive(timeout)
            if process.returncode is None:
                process.returncode = code
            return process.returncode

        def terminate():
            process.terminated = True
            process.returncode = -15

        def kill():
            process.killed = True
            process.returncode = -9

        process.wait, process.poll = wait, lambda: process.returncode
        process.terminate, process.kill = terminate, kill
        self.processes.append(process)
        return process

    @staticmethod
    def assert_positive(timeout):
        assert 0 < timeout <= 8

    def read(self, number, size):
        assert size == 1
        chunk = self.buffers[number][:size]
        self.buffers[number] = self.buffers[number][size:]
        self.consumed[number] += len(chunk)
        return chunk


class FakeSelector:
    def __init__(self):
        self.items = {}

    def register(self, pipe, events, data):
        self.items[pipe] = SimpleNamespace(fileobj=pipe, data=data)

    def unregister(self, pipe):
        del self.items[pipe]

    def get_map(self):
        return self.items

    def select(self, timeout):
        assert timeout <= 8
        return [(key, 1) for key in self.items.values()]

    def close(self):
        self.items.clear()


class ProbeTests(unittest.TestCase):
    def fake(self, responses, selector=FakeSelector):
        docker = FakeDocker(responses)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(probe.sys, 'platform', 'linux'))
        stack.enter_context(patch.object(probe.socket, 'gethostname', return_value='bupt-gpus1'))
        stack.enter_context(patch.object(probe.subprocess, 'Popen', side_effect=docker.popen))
        stack.enter_context(patch.object(probe.os, 'read', side_effect=docker.read))
        stack.enter_context(patch.object(probe.selectors, 'DefaultSelector', selector))
        return docker

    def test_fixed_projection_and_no_python_capability_claim(self):
        fake = self.fake([(INFO, b'', 0), (IMAGE, b'', 0)])
        value = probe.probe()
        self.assertEqual(value['status'], 'metadata_collected')
        self.assertEqual(value['images'], [dict(name='python', tag='3.6', immutable_id='sha256:' + 'a' * 64)])
        self.assertFalse(value['python_image_capability_verified'])
        self.assertFalse(value['lifecycle_gate_pass'])
        self.assertFalse(value['full_inventory_claimed'])
        self.assertEqual([call[0] for call in fake.calls], [probe.COMMANDS['info'], probe.COMMANDS['images']])
        self.assertEqual(fake.calls[1][0], ('docker', 'image', 'ls', '--no-trunc', '--format', '{{json .}}'))
        self.assertEqual(fake.calls[0][0], ('docker', 'info', '--format',
                         '{"CgroupVersion":{{json .CgroupVersion}},"OSType":{{json .OSType}},"ServerVersion":{{json .ServerVersion}}}'))
        for _, options in fake.calls:
            self.assertFalse(options['shell'])
            self.assertEqual(options['stdin'], probe.subprocess.DEVNULL)
        self.assertTrue(all(p.stdout.closed and p.stderr.closed for p in fake.processes))

    def test_row_32_stops_before_any_byte_of_33_and_accepts_deliberate_cli_stop(self):
        fake = self.fake([(INFO, b'', 0), (IMAGE * 33, b'', 0)])
        value = probe.probe()
        self.assertEqual(value['status'], 'metadata_collected')
        self.assertEqual(len(value['images']), 32)
        self.assertTrue(value['inventory_truncated'])
        self.assertTrue(value['image_cli_stopped_at_row_cap'])
        self.assertEqual(value['image_cli_returncode'], -15)
        self.assertEqual(fake.consumed[4], len(IMAGE) * 32)
        self.assertEqual(fake.buffers[4], IMAGE)

    def test_exactly_32_also_reports_conservative_truncation(self):
        self.fake([(INFO, b'', 0), (IMAGE * 32, b'', 0)])
        self.assertTrue(probe.probe()['inventory_truncated'])

    def test_combined_stdout_stderr_cap(self):
        fake = self.fake([(INFO, b'', 0), (b'x' * 33000, b'y' * 33000, 0)])
        result = probe.probe()
        self.assertEqual(result['reason'], 'METADATA_BYTE_CAP')
        self.assertEqual(result['metadata_bytes'], 32768)
        self.assertEqual(sum(fake.consumed.values()), 32768)
        self.assertIsNone(result['docker'])
        self.assertEqual(result['images'], [])

    def test_missing_or_permission_denied_has_no_guesses(self):
        for response in (FileNotFoundError(), (b'', b'permission denied', 1)):
            with self.subTest(response=response):
                fake = self.fake([response])
                result = probe.probe()
                self.assertEqual(result['status'], 'blocked')
                self.assertIsNone(result['docker'])
                self.assertEqual(result['images'], [])
                self.assertEqual(len(fake.calls), 1)

    def test_bad_identity_never_launches(self):
        fake = self.fake([])
        with patch.object(probe.socket, 'gethostname', return_value='other'):
            self.assertEqual(probe.probe()['reason'], 'B_HOST_IDENTITY_REQUIRED')
        with patch.object(probe.sys, 'platform', 'win32'):
            self.assertEqual(probe.probe()['reason'], 'LINUX_REQUIRED')
        self.assertEqual(fake.calls, [])

    def test_timeout_reaps_cli(self):
        class TimeoutSelector(FakeSelector):
            def select(self, timeout):
                return []
        fake = self.fake([(INFO, b'', 0)], TimeoutSelector)
        self.assertEqual(probe.probe()['reason'], 'DOCKER_COMMAND_TIMEOUT')
        self.assertTrue(fake.processes[0].terminated)

    def test_cleanup_escalates_only_our_cli(self):
        calls = []
        process = SimpleNamespace(poll=lambda: None,
                                  terminate=lambda: calls.append('terminate'),
                                  kill=lambda: calls.append('kill'))

        def wait(timeout):
            calls.append(('wait', timeout))
            if 'kill' not in calls:
                raise probe.subprocess.TimeoutExpired('fixed-cli', timeout)

        process.wait = wait
        probe._stop(process)
        self.assertEqual(calls, ['terminate', ('wait', 0.5), 'kill', ('wait', 0.5)])

    def test_failed_image_list_clears_all_docker_claims(self):
        self.fake([(INFO, b'', 0), (IMAGE, b'permission denied with private detail', 1)])
        result = probe.probe()
        self.assertEqual(result['reason'], 'DOCKER_COMMAND_FAILED')
        self.assertIsNone(result['docker'])
        self.assertEqual(result['images'], [])
        self.assertNotIn('private detail', json.dumps(result))

    def test_info_values_are_observations_not_guesses(self):
        for value in (dict(CgroupVersion='', OSType='linux', ServerVersion='26'),
                      dict(CgroupVersion='2', OSType='windows', ServerVersion='26'),
                      dict(CgroupVersion='2', OSType='linux', ServerVersion='26', Env='secret')):
            fake = self.fake([(json.dumps(value).encode(), b'', 0)])
            result = probe.probe()
            self.assertEqual(result['status'], 'blocked')
            self.assertIsNone(result['docker'])
            self.assertEqual(len(fake.calls), 1)

    def test_invalid_projection_is_blocked(self):
        for image in (dict(Repository='x' * 129, Tag='t', ID='sha256:' + 'a' * 64),
                      dict(Repository='x', Tag='t' * 129, ID='sha256:' + 'a' * 64),
                      dict(Repository='x', Tag='t', ID='short')):
            self.fake([(INFO, b'', 0), (json.dumps(image).encode(), b'', 0)])
            self.assertEqual(probe.probe()['status'], 'blocked')
        self.fake([(b'not json', b'', 0)])
        self.assertEqual(probe.probe()['reason'], 'MALFORMED_DOCKER_METADATA')

    def test_cli_rejects_all_arguments_and_bounds_return(self):
        with patch.object(probe, 'probe') as call, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(['docker', 'inspect']), 2)
        call.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['reason'], 'NO_ARGUMENTS_ACCEPTED')
        with patch.object(probe, 'probe', return_value=dict(status='metadata_collected', huge='x' * 9000)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main([]), 2)
        self.assertLessEqual(len(output.getvalue().encode()), 8192)

    def test_import_has_no_probe_io(self):
        spec = importlib.util.spec_from_file_location('e73_import_test', Path(probe.__file__))
        module = importlib.util.module_from_spec(spec)
        with patch.object(probe.subprocess, 'Popen') as popen, \
                patch.object(probe.socket, 'gethostname') as hostname, \
                patch.object(probe.os, 'read') as read:
            spec.loader.exec_module(module)
        popen.assert_not_called()
        hostname.assert_not_called()
        read.assert_not_called()

    def test_create_help_is_read_only_and_missing_flag_not_guessed(self):
        fake = self.fake([(INFO, b'', 0), (IMAGE, b'', 0),
                          (b'  --memory bytes\n  --cgroup-parent string\n --cgroupns string\n', b'', 0)])
        result = probe.probe(include_capabilities=True)
        self.assertEqual(fake.calls[-1][0], ('docker', 'create', '--help'))
        self.assertFalse(result['docker_create_capabilities']['--cgroup-conf'])
        self.assertTrue(result['docker_create_capabilities']['--memory'])
        self.assertTrue(result['docker_create_capabilities']['--cgroupns'])

    def test_create_help_failure_cannot_keep_accepted_status(self):
        self.fake([(INFO, b'', 0), (IMAGE, b'', 0), (b'', b'failed', 1)])
        result = probe.probe(include_capabilities=True)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['reason'], 'DOCKER_COMMAND_FAILED')
        self.assertIsNone(result['docker'])
        self.assertEqual(result['images'], [])

    def test_create_help_timeout_and_bytecap_are_blocked(self):
        self.fake([])
        for reason in ('DOCKER_COMMAND_TIMEOUT','METADATA_BYTE_CAP'):
            with patch.object(probe,'_capture',side_effect=[(INFO.decode(),False,0),
                    (IMAGE.decode(),False,0),probe.ProbeBlocked(reason)]):
                result=probe.probe(include_capabilities=True)
                self.assertEqual(result['status'],'blocked')
                self.assertEqual(result['reason'],reason)
                self.assertIsNone(result['docker'])


if __name__ == '__main__':
    unittest.main()
