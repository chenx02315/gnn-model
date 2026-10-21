import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import run_linux_lifecycle_phase_e73 as phase


class PhaseTests(unittest.TestCase):
    def setup_fake(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        temporary = stack.enter_context(tempfile.TemporaryDirectory())
        stack.enter_context(patch.object(phase, 'STAGING', Path(temporary)))
        original = phase.read_fixed
        def read(relative, maximum):
            if relative.endswith('probe_prerun_review_20261021_r1.json'):
                return json.dumps(dict(verdict='PASS_INDEPENDENT_PREEXECUTION_REVIEW', mode='probe',
                    source_sha256=phase.sha(original(phase.SOURCES['probe'],12288)),
                    controller_sha256=phase.sha(original('scripts/run_linux_lifecycle_phase_e73.py',12288)),
                    authorization_sha256=phase.AUTH_SHA)).encode('ascii')
            return original(relative, maximum)
        stack.enter_context(patch.object(phase, 'read_fixed', side_effect=read))
        host = stack.enter_context(patch.object(phase.transport_api, 'verify_cached_host', return_value='synthetic-pin'))
        response = dict(schema='e73-environment-probe-v1', status='metadata_collected',
            platform='linux', host='bupt-gpus1', lifecycle_gate_pass=False,
            docker_create_capabilities={flag: False for flag in ('--cgroup-conf','--cgroupns',
                '--memory','--memory-swap','--pids-limit','--pull','--read-only','--tmpfs','--cap-drop')})
        result = dict(stdout=json.dumps(response).encode('ascii'), stderr=b'', exit_code=0,
                      timeout=False, overflow=False, write_failed=False, threads_incomplete=False,
                      remote_termination_verified=False)
        transport = stack.enter_context(patch.object(phase.transport_api, 'transport', return_value=result))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return Path(temporary)/phase.PHASE_NAME, host, transport

    def test_single_probe_dispatch_and_no_reset(self):
        root, host, transport = self.setup_fake()
        self.assertEqual(phase.run('probe'), 0)
        with self.assertRaisesRegex(ValueError,'NO_REPEAT_DISPATCH'): phase.run('probe')
        self.assertEqual(transport.call_count, 1)
        events=[json.loads(line) for line in (root/'sessions.jsonl').read_text().splitlines()]
        self.assertEqual([e['event'] for e in events], ['START','END'])
        self.assertTrue(events[-1]['accepted'])

    def test_unresolved_session_blocks(self):
        root, host, transport = self.setup_fake()
        phase.run('probe')
        phase.transport_api.append_event(root/'sessions.jsonl',dict(event='START',mode='execute',stdin_bytes=1,output_cap=1))
        with self.assertRaisesRegex(ValueError,'UNRESOLVED_SESSION_STOP'): phase.run('probe')
        self.assertEqual(transport.call_count,1)

    def test_transport_failure_recorded_without_retry(self):
        root, host, transport = self.setup_fake()
        transport.return_value['timeout']=True
        self.assertEqual(phase.run('probe'),2)
        with self.assertRaises(ValueError):phase.run('probe')
        self.assertEqual(transport.call_count,1)
        self.assertFalse(json.loads((root/'01_probe/transport.json').read_text())['accepted'])

    def test_source_review_and_auth_are_before_ssh(self):
        root, host, transport = self.setup_fake()
        with patch.object(phase,'AUTH_SHA','f'*64):
            with self.assertRaisesRegex(ValueError,'AUTH_SCOPE_PIN'):phase.run('probe')
        host.assert_not_called()
        transport.assert_not_called()

    def test_other_host_or_malformed_response_not_accepted(self):
        root, host, transport = self.setup_fake()
        transport.return_value['stdout']=b'{"status":"metadata_collected","host":"other"}'
        self.assertEqual(phase.run('probe'),2)

    def test_fixed_mode_no_io(self):
        with patch.object(phase,'read_fixed') as read:
            for mode in ('A','train','cleanup','anything',None,[]):
                with self.assertRaises(ValueError):phase.run(mode)
        read.assert_not_called()

    def test_reason_or_missing_capability_response_not_accepted(self):
        root, host, transport = self.setup_fake()
        response=json.loads(transport.return_value['stdout'])
        response['reason']='DOCKER_COMMAND_FAILED'
        transport.return_value['stdout']=json.dumps(response).encode('ascii')
        self.assertEqual(phase.run('probe'),2)


if __name__=='__main__':
    unittest.main()
