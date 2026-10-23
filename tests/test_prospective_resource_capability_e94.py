import ast
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/probe_tessent_resource_capability_e94.py'
spec = importlib.util.spec_from_file_location('capability_e94', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
controller_path = SOURCE.with_name('execute_tessent_resource_capability_e94.py')
cspec = importlib.util.spec_from_file_location('capability_e94_controller', controller_path)
c = importlib.util.module_from_spec(cspec); cspec.loader.exec_module(c)


class ResourceCapabilityTests(unittest.TestCase):
    def test_v1_memberships_without_exporting_group_path(self):
        rows = m.parse_memberships(b'4:memory:/user.slice/session-1.scope\n3:pids:/\n')
        self.assertEqual(rows[0]['controllers'], ['memory'])
        self.assertNotIn('user.slice', str(rows))
        self.assertFalse(rows[0]['at_hierarchy_root'])
        self.assertTrue(rows[1]['at_hierarchy_root'])

    def test_v2_and_hybrid_are_observations_not_release(self):
        rows = m.parse_memberships(b'0::/user.slice\n4:memory:/\n')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['controllers'], [])

    def test_invalid_duplicate_membership_and_traversal(self):
        for raw in (b'', b'1:memory:/\n1:cpu:/\n', b'1:memory:/../etc\n',
                    b'1:bad$:/\n', b'1:memory:/bad\x00path\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.parse_memberships(raw)

    def test_mounts_do_not_decode_or_derive_paths(self):
        rows = m.parse_mounts(b'1 0 0:1 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n'
            b'2 0 0:2 / /other\\040mount ro - cgroup2 cgroup rw\n')
        self.assertEqual(rows[0]['conventional_mount'], '/sys/fs/cgroup/memory')
        self.assertEqual(rows[0]['controllers'], ['memory'])
        self.assertIsNone(rows[1]['conventional_mount'])
        self.assertTrue(rows[1]['mount_read_only'])

    def test_malformed_mounts_fail(self):
        for raw in (b'bad\n', b'1 - cgroup\n', b'x' * 8193 + b' - y\n'):
            with self.assertRaises(ValueError):
                m.parse_mounts(raw)

    def test_enabled_controller_not_installed_guard(self):
        value = m.parse_controller_support(b'#subsys_name hierarchy num_cgroups enabled\n'
                                          b'memory 4 12 1\nfreezer 5 1 0\n')
        self.assertEqual(value, {'memory': True, 'freezer': False, 'pids': None})
        for raw in (b'memory 4 12 2\n', b'memory 1 1 1\nmemory 1 1 1\n'):
            with self.assertRaises(ValueError):
                m.parse_controller_support(raw)

    def test_scope_rejected_before_open(self):
        with mock.patch.object(m.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'FIXED_PROC_SCOPE'):
                m.read_proc('/etc/passwd', [0])
            opened.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'FIXED_ROOT_SCOPE'):
            m.root_metadata('/tmp')

    def test_stream_bound_even_when_proc_size_zero(self):
        regular = mock.Mock(st_mode=0o100444)
        with mock.patch.object(m.os, 'open', return_value=9), \
             mock.patch.object(m.os, 'O_NOFOLLOW', 0, create=True), \
             mock.patch.object(m.os, 'O_NONBLOCK', 0, create=True), \
             mock.patch.object(m.os, 'close') as closed, \
             mock.patch.object(m.os, 'fstat', return_value=regular), \
             mock.patch.object(m.os, 'read', return_value=b'x' * 4096), \
             mock.patch.object(m, 'MAX_FILE', 10):
            with self.assertRaisesRegex(ValueError, 'READ_BOUND'):
                m.read_proc(m.PROC_FILES[0], [0])
            closed.assert_called_once_with(9)

    def test_python36_no_scan_write_launch(self):
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'), feature_version=(3, 6))
        calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)}
        self.assertFalse(calls & {'mkdir', 'makedirs', 'system', 'run',
                                 'Popen', 'listdir', 'walk', 'scandir'})
        writes = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and n.func.attr == 'write']
        self.assertEqual(len(writes), 1)
        self.assertEqual(ast.unparse(writes[0].func.value), 'sys.stdout')

    def test_controller_requires_reviewed_sha_before_phase(self):
        with mock.patch.object(c.sys, 'argv', ['controller']), \
             mock.patch.object(c, 'PHASE') as phase:
            with self.assertRaisesRegex(ValueError, 'REVIEWED_READER_SHA_REQUIRED'):
                c.main()
            phase.mkdir.assert_not_called()

    def test_controller_rejects_release_and_mutation_claims(self):
        value = dict(schema='e94-tessent-resource-capability-v1',
            status='OBSERVED_CAPABILITY_HINTS_NOT_RESOURCE_ADMISSION',
            hostname='bupt-vncs2', files_read=4, body_bytes=4,
            guard_installed=False, limit_write_tested=False, group_kill_tested=False,
            execution_ready=False, training_release=False, directory_scans=0,
            external_programs_launched=0, remote_writes=0, actual_atpg_calls=0,
            training_runs=0, actual_atpg_memory_limit_bytes=None,
            actual_atpg_timeout_s=None, helper_address_space_bytes=134217728,
            helper_cpu_seconds=5, input_metadata=[{'path': p, 'bytes': 1,
                'sha256': 'a' * 64} for p in m.PROC_FILES], uid=1000,
            memberships=m.parse_memberships(b'4:memory:/\n'), mounts=[],
            controller_enabled={'memory': True, 'freezer': None, 'pids': None},
            root_metadata=[{'path': p, 'exists': False,
                'is_directory_not_symlink': False, 'write_access_hint': False,
                'owner_uid': None, 'mode': None} for p in m.ROOTS])
        self.assertEqual(c.validate(json.dumps(value).encode('ascii'))['files_read'], 4)
        for key, bad in (('execution_ready', True), ('remote_writes', 1),
                         ('actual_atpg_memory_limit_bytes', 134217728),
                         ('body_bytes', 5)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.validate(json.dumps(dict(value, **{key: bad})).encode('ascii'))
        for field in ('uid', 'memberships', 'mounts', 'controller_enabled', 'root_metadata'):
            altered = dict(value); del altered[field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, 'EXACT_OBSERVATION_KEYS'):
                c.validate(json.dumps(altered).encode('ascii'))
        with self.assertRaisesRegex(ValueError, 'EXACT_OBSERVATION_KEYS'):
            c.validate(json.dumps(dict(value, unexpected_resource_admission=True)).encode('ascii'))
        for field, bad in (('uid', True), ('memberships', []),
                           ('mounts', [{'version': 1}]),
                           ('controller_enabled', {'memory': 1}),
                           ('root_metadata', [])):
            with self.subTest(nested=field), self.assertRaises(ValueError):
                c.validate(json.dumps(dict(value, **{field: bad})).encode('ascii'))

    def test_controller_duplicate_json_and_python36(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            c.validate(b'{"a":1,"a":2}')
        ast.parse(controller_path.read_text(encoding='utf-8'), feature_version=(3, 6))


if __name__ == '__main__':
    unittest.main()
