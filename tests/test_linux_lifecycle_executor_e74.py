"""Fake-only tests: never contact B or Docker."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'execute_linux_lifecycle_e74.py'
SPEC = importlib.util.spec_from_file_location('e74_executor', PATH)
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class ExecutorTests(unittest.TestCase):
    def test_cumulative_read_and_cleanup_reserve(self):
        budget = executor.Budget()
        budget.consume(executor.NORMAL_READ_CAP)
        with self.assertRaisesRegex(ValueError, 'CUMULATIVE_READ_CAP'):
            budget.allowance()
        budget.consume(2000, cleanup=True)
        self.assertEqual(budget.read_bytes, executor.READ_CAP)
        with self.assertRaisesRegex(ValueError, 'CUMULATIVE_READ_CAP'):
            budget.allowance(cleanup=True)

    def test_global_deadline_reserves_cleanup(self):
        budget = executor.Budget()
        budget.deadline = executor.time.monotonic() + 5
        with self.assertRaisesRegex(ValueError, 'SESSION_DEADLINE'):
            budget.time(30)
        self.assertLessEqual(budget.time(30, cleanup=True), 5)

    def test_checked_failure_preserves_bounded_raw(self):
        with mock.patch.object(executor, 'run', return_value=(1, b'error detail')):
            with self.assertRaises(executor.CommandError) as raised:
                executor.checked(['docker', 'fake'])
            self.assertEqual(raised.exception.raw, b'error detail')

    def test_cleanup_projection_is_narrow_and_bounded(self):
        cid = 'b'*64
        image = 'sha256:'+'a'*64
        raw = ('"'+cid+'"\n"'+image+'"\n"'+executor.MARK+'"\nfalse\n0\n').encode()
        with mock.patch.object(executor, 'checked', return_value=raw) as checked:
            result = executor.cleanup_state(cid, executor.Budget())
        self.assertEqual(result['label'], executor.MARK)
        self.assertFalse(result['running'])
        self.assertEqual(checked.call_args.kwargs['limit'], 512)
        self.assertTrue(checked.call_args.kwargs['cleanup'])
        self.assertNotIn('HostConfig', checked.call_args.args[0][4])
        self.assertIn('{{json (index .Config.Labels "gnn.e74.attempt")}}',
                      checked.call_args.args[0][4])

    def test_post_pass_receipt_bound_failure_cannot_report_pass(self):
        image = 'sha256:'+'a'*64
        cid = 'b'*64
        real_encode = executor.encode

        def fail_only_final_receipt(value):
            if type(value) is dict and value.get('status') == 'PASS_LINUX_SYNTHETIC_GATE':
                raise ValueError('RECEIPT_BOUND')
            return real_encode(value)

        with mock.patch.object(executor, 'validate', return_value=(image, b'gate', {})), \
             mock.patch.object(executor.sys, 'platform', 'linux'), \
             mock.patch.object(executor.os, 'uname', create=True) as uname, \
             mock.patch.object(executor.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(executor.os, 'getgid', return_value=1001, create=True), \
             mock.patch.object(executor, 'checked') as checked, \
             mock.patch.object(executor, 'root_new', return_value=55), \
             mock.patch.object(executor, 'write_at', return_value=(1, 2)), \
             mock.patch.object(executor, 'cid_from_file', return_value=cid), \
             mock.patch.object(executor, 'inspect') as inspect, \
             mock.patch.object(executor, 'verify'), \
             mock.patch.object(executor, 'run', return_value=(0, b'{}')), \
             mock.patch.object(executor, 'gate_valid'), \
             mock.patch.object(executor, 'cleanup_state', return_value={
                 'image':image, 'label':executor.MARK, 'running':False, 'exit_code':0}), \
             mock.patch.object(executor, 'encode', side_effect=fail_only_final_receipt), \
             mock.patch.object(executor.os, 'close'):
            uname.return_value.nodename = 'bupt-gpus1'
            checked.side_effect = [b'"2"\n"linux"\ntrue\n',
                                   ('"'+image+'"\nnull\n"linux"\n').encode(),
                                   (cid+'\n').encode()]
            inspect.side_effect = [{'State.Running':False, 'State.Status':'created'},
                                   {'State.Running':False, 'State.ExitCode':0,
                                    'State.Status':'exited'}]
            result = executor.execute({})
        self.assertEqual(result['status'], 'BLOCKED_OR_FAILED_NO_RETRY')
        self.assertFalse(result['gate_pass'])
        self.assertEqual(result['phase'], 'FAILED')

    def test_strict_json(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            executor.parse('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, 'NONFINITE_JSON'):
            executor.parse('{"a":NaN}')

    def test_request_validation_before_io(self):
        request = {'image_id': 'sha256:' + 'a'*64, 'source_b64': base64.b64encode(b'fake').decode(),
                   'manifest': {}}
        with mock.patch.object(executor, 'run', side_effect=AssertionError('Docker called')):
            with self.assertRaisesRegex(ValueError, 'SOURCE_SHA'):
                executor.execute(request)

    def test_image_volume_preflight_gate(self):
        request = {'image_id': 'sha256:' + 'a'*64, 'source_b64': '',
                   'manifest': {'image_id': 'sha256:'+'a'*64,
                                'source_sha256': executor.SOURCE_SHA,
                                'auth_sha256': executor.NEW_AUTH_SHA,
                                'amendment_sha256': executor.AMEND_SHA}}
        with mock.patch.object(executor.hashlib, 'sha256') as hash_mock:
            hash_mock.return_value.hexdigest.return_value = executor.SOURCE_SHA
            with mock.patch.object(executor.sys, 'platform', 'linux'), \
                 mock.patch.object(executor.os, 'uname', create=True) as uname, \
                 mock.patch.object(executor.os, 'getuid', return_value=1001, create=True), \
                 mock.patch.object(executor, 'checked') as checked, \
                 mock.patch.object(executor, 'root_new', side_effect=AssertionError('root created')):
                uname.return_value.nodename = 'bupt-gpus1'
                checked.side_effect = [b'"2"\n"linux"\ntrue\n',
                                       ('"sha256:'+'a'*64+'"\n{"/data":{}}\n"linux"\n').encode()]
                with self.assertRaisesRegex(ValueError, 'IMAGE_ID_VOLUMES_OS'):
                    executor.execute(request)

    def test_gate_positive_and_reject_missing_or_wrong_values(self):
        env = dict(platform='linux', memory_limit_bytes=134217728, swap_limit_bytes=0,
                   pids_max=16, oom_group=0, oom_group_atomic_kill_guaranteed=False,
                   kernel_configuration_observed=True, active_oom_test=False,
                   production_atpg_limits_verified=False)
        rows = [dict(profile=p, leader_reaped=True, observed_group_empty=True,
                     observed_interval_ns=1, returncode=rc, timed_out=timeout,
                     grandchild_pid=pid)
                for p, rc, timeout, pid in [('success', 0, False, None),
                                           ('failure', 7, False, None),
                                           ('timeout_group', -9, True, 4)]]
        gate = dict(schema='prospective-linux-lifecycle-gate-v2',
                    status='PASS_SYNTHETIC_GROUP_ONLY', gate_pass=True,
                    environment=env, profiles=rows,
                    universal_process_tree_termination_proved=False,
                    durable_runner_integrated=False, real_atpg_jobs=0,
                    training=False, execution_ready=False, training_release=False)
        executor.gate_valid(gate)
        env['oom_group'] = 2
        with self.assertRaisesRegex(ValueError, 'GATE_ENVIRONMENT'):
            executor.gate_valid(gate)
        env['oom_group'] = 1
        rows.pop()
        with self.assertRaisesRegex(ValueError, 'GATE_PROFILES'):
            executor.gate_valid(gate)

    def test_container_config_rejects_device_or_volume(self):
        image = 'sha256:' + 'a'*64
        config = {'Image': image, 'HostConfig.Memory': 134217728,
                  'HostConfig.MemorySwap': 134217728, 'HostConfig.PidsLimit': 16,
                  'HostConfig.ReadonlyRootfs': True, 'HostConfig.Privileged': False,
                  'HostConfig.NetworkMode': 'none', 'HostConfig.CgroupnsMode': 'private',
                  'Config.User': '1001:1001', 'Config.Entrypoint': ['python3'],
                  'Config.Cmd': ['-I', '-S', '-B', '/gate.py'],
                  'HostConfig.CapDrop': ['ALL'], 'HostConfig.SecurityOpt': ['no-new-privileges'],
                  'HostConfig.Runtime': 'runc', 'Config.WorkingDir': '/tmp',
                  'HostConfig.IpcMode': 'none', 'HostConfig.PidMode': '',
                  'HostConfig.CgroupParent': '', 'Config.Healthcheck': {'Test': ['NONE']},
                  'HostConfig.Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=1048576,mode=1777'},
                  'Config.Labels': {executor.LABEL: executor.MARK},
                  'HostConfig.DeviceRequests': None, 'HostConfig.Devices': None,
                  'HostConfig.Init': False,
                  'Mounts': [{'Type':'bind', 'Source':executor.ROOT+'/gate.py',
                              'Destination':'/gate.py', 'RW':False}]}
        executor.verify(config, image, '1001:1001')
        config['Mounts'].append({'Type':'volume', 'Destination':'/data'})
        with self.assertRaisesRegex(ValueError, 'TMPFS_MOUNT'):
            executor.verify(config, image, '1001:1001')
        config['Mounts'].pop()
        config['HostConfig.DeviceRequests'] = [{'Driver':'nvidia'}]
        with self.assertRaisesRegex(ValueError, 'DEVICES_INIT'):
            executor.verify(config, image, '1001:1001')

    def test_cidfile_bad_contents(self):
        with mock.patch.object(executor.os, 'O_NOFOLLOW', 0, create=True), \
             mock.patch.object(executor.os, 'open', return_value=42), \
             mock.patch.object(executor.os, 'fstat') as fstat, \
             mock.patch.object(executor.os, 'read', return_value=b'foreign-name\n'), \
             mock.patch.object(executor.os, 'close'):
            fstat.return_value.st_mode = 0o100600
            fstat.return_value.st_nlink = 1
            fstat.return_value.st_size = 13
            with self.assertRaisesRegex(ValueError, 'CID_FILE_CONTENT'):
                executor.cid_from_file(8)

    def test_create_response_lost_unknown_id_never_kills_by_name(self):
        image = 'sha256:' + 'a'*64
        with mock.patch.object(executor, 'validate', return_value=(image, b'gate', {})), \
             mock.patch.object(executor.sys, 'platform', 'linux'), \
             mock.patch.object(executor.os, 'uname', create=True) as uname, \
             mock.patch.object(executor.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(executor.os, 'getgid', return_value=1001, create=True), \
             mock.patch.object(executor, 'checked') as checked, \
             mock.patch.object(executor, 'root_new', return_value=55), \
             mock.patch.object(executor, 'write_at', return_value=(1, 2)), \
             mock.patch.object(executor, 'cid_from_file', return_value=None), \
             mock.patch.object(executor, 'run', side_effect=AssertionError('KILL_CALLED')), \
             mock.patch.object(executor.os, 'close'):
            uname.return_value.nodename = 'bupt-gpus1'
            checked.side_effect = [b'"2"\n"linux"\ntrue\n',
                                   ('"'+image+'"\nnull\n"linux"\n').encode(),
                                   ValueError('CREATE_RESPONSE_LOST')]
            result = executor.execute({})
            self.assertFalse(result['gate_pass'])
            self.assertFalse(result['cleanup_verified'])
            self.assertNotIn('container_id', result)
            create_argv = checked.call_args_list[2].args[0]
            self.assertIn('--cidfile', create_argv)
            self.assertIn('--no-healthcheck', create_argv)
            self.assertIn('--init=false', create_argv)
            self.assertIn('--runtime', create_argv)
            self.assertNotIn('--cgroup-conf', create_argv)

    def test_create_response_lost_cidfile_identity_before_kill(self):
        image = 'sha256:' + 'a'*64
        cid = 'b'*64
        with mock.patch.object(executor, 'validate', return_value=(image, b'gate', {})), \
             mock.patch.object(executor.sys, 'platform', 'linux'), \
             mock.patch.object(executor.os, 'uname', create=True) as uname, \
             mock.patch.object(executor.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(executor.os, 'getgid', return_value=1001, create=True), \
             mock.patch.object(executor, 'checked') as checked, \
             mock.patch.object(executor, 'root_new', return_value=55), \
             mock.patch.object(executor, 'write_at', return_value=(1, 2)), \
             mock.patch.object(executor, 'cid_from_file', return_value=cid), \
             mock.patch.object(executor, 'cleanup_state', return_value={
                 'image': image, 'label': 'foreign', 'running': False, 'exit_code': 0}), \
             mock.patch.object(executor, 'run', side_effect=AssertionError('KILL_CALLED')), \
             mock.patch.object(executor.os, 'close'):
            uname.return_value.nodename = 'bupt-gpus1'
            checked.side_effect = [b'"2"\n"linux"\ntrue\n',
                                   ('"'+image+'"\nnull\n"linux"\n').encode(),
                                   ValueError('CREATE_RESPONSE_LOST')]
            result = executor.execute({})
            self.assertEqual(result['container_id'], cid)
            self.assertFalse(result['cleanup_verified'])


if __name__ == '__main__':
    unittest.main()
