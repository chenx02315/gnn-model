"""Entry boundary tests: mocks only, no real proc, scheduler, or tool calls."""
import ast
import importlib.util
import json
import stat
from pathlib import Path
import types
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/run_acceptance_job_e97.py'
SPEC = importlib.util.spec_from_file_location('e97_entry_under_test', str(PATH))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def permit():
    return dict(schema='e97-resume-permit-v1', job_id=123,
        registration_review_passed=True, pre_resume_review_passed=True,
        authorization_sha256=m.AUTH_SHA256, code_manifest_sha256='a' * 64,
        issued_at_epoch=1000)


class EntryTests(unittest.TestCase):
    def validation(self, value):
        with mock.patch.object(m.time, 'time', return_value=1050), \
                mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.dict(m.os.environ, {'LSB_JOBID': '123', 'LSB_JOBINDEX': '0'}, clear=True):
            m.validate_permit(value)

    def test_exact_valid_permit(self):
        self.validation(permit())

    def test_consent_default_is_false(self):
        for key in ('registration_review_passed', 'pre_resume_review_passed'):
            value = permit(); value[key] = False
            with self.assertRaises(m.EntryError):
                self.validation(value)

    def test_strict_keys_types_and_pins(self):
        mutations = [('job_id', True), ('job_id', 0), ('issued_at_epoch', True),
                     ('schema', 'other'), ('authorization_sha256', 'b' * 64),
                     ('code_manifest_sha256', '../x'), ('extra', True)]
        for key, item in mutations:
            value = permit(); value[key] = item
            with self.assertRaises(m.EntryError):
                self.validation(value)

    def test_expired_and_future_permits(self):
        for issued in (449, 1051):
            value = permit(); value['issued_at_epoch'] = issued
            with self.assertRaisesRegex(m.EntryError, 'FRESHNESS'):
                self.validation(value)

    def test_array_and_job_mismatch_rejected(self):
        for env in ({'LSB_JOBID': '123', 'LSB_JOBINDEX': '1'},
                    {'LSB_JOBID': '123[1]'}, {'LSB_JOBID': '124'}):
            with mock.patch.object(m.time, 'time', return_value=1050), \
                    mock.patch.object(m.sys, 'platform', 'linux'), \
                    mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                    mock.patch.dict(m.os.environ, env, clear=True):
                with self.assertRaises(m.EntryError):
                    m.validate_permit(permit())

    def test_wrong_host_rejected(self):
        with mock.patch.object(m.time, 'time', return_value=1050), \
                mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='elsewhere'):
            with self.assertRaisesRegex(m.EntryError, 'HOST'):
                m.validate_permit(permit())

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(m.EntryError, 'DUPLICATE'):
            m.parse(b'{"job_id":1,"job_id":2}')

    def test_fixed_root_before_io(self):
        with mock.patch.object(m, '_directory') as opened:
            with self.assertRaisesRegex(m.EntryError, 'FIXED_BUNDLE'):
                m.execute(permit(), '/other')
            opened.assert_not_called()

    def test_manifest_unknown_member_and_wrong_pin(self):
        raw = json.dumps({'schema': 'e97-code-manifest-v1', 'files': {'../evil': 'a' * 64}}).encode('ascii')
        value = permit(); value['code_manifest_sha256'] = m.sha(raw)
        with mock.patch.object(m, '_read', return_value=raw):
            with self.assertRaisesRegex(m.EntryError, 'MEMBERS'):
                m.verify_bundle(1, value)
            value['code_manifest_sha256'] = '0' * 64
            with self.assertRaisesRegex(m.EntryError, 'DIGEST'):
                m.verify_bundle(1, value)

    def test_manifest_member_digest_failure(self):
        files = dict((name, m.sha(b'')) for name in m.FILES)
        raw = json.dumps(dict(schema='e97-code-manifest-v1', files=files)).encode('ascii')
        value = permit(); value['code_manifest_sha256'] = m.sha(raw)
        with mock.patch.object(m, '_read', side_effect=[raw, b'corrupt']):
            with self.assertRaisesRegex(m.EntryError, 'DIGEST'):
                m.verify_bundle(1, value)

    def test_snapshot_loader_blocks_unverified_import(self):
        loader = m.SnapshotLoader({'src/__init__.py': b''})
        with self.assertRaisesRegex(m.EntryError, 'UNVERIFIED'):
            loader.find_spec('src.data.unlisted')
        self.assertIsNone(loader.find_spec('json'))
        self.assertIsNotNone(loader.find_spec('src'))

    def test_log_cap(self):
        log = m.BoundedLog(); log.write('x' * 65536)
        with self.assertRaisesRegex(m.EntryError, 'LOG_BOUND'):
            log.write('x')
        self.assertEqual(len(log.getvalue()), 65536)

    def test_read_exact_cap_without_extra_byte_and_reject_replacement(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_size=3,
            st_mtime_ns=1, st_ctime_ns=1, st_dev=1, st_ino=2)
        replacement = types.SimpleNamespace(st_dev=1, st_ino=3)
        for named, accepted in ((info, True), (replacement, False)):
            with mock.patch.object(m.os, 'dup', return_value=10), \
                    mock.patch.object(m.os, 'open', return_value=11), \
                    mock.patch.object(m.os, 'close'), \
                    mock.patch.object(m.os, 'O_NOFOLLOW', 1, create=True), \
                    mock.patch.object(m.os, 'O_NONBLOCK', 2, create=True), \
                    mock.patch.object(m.os, 'fstat', return_value=info), \
                    mock.patch.object(m.os, 'stat', return_value=named), \
                    mock.patch.object(m.os, 'read', return_value=b'abc') as read:
                if accepted:
                    self.assertEqual(m._read(1, 'file', 3), b'abc')
                else:
                    with self.assertRaisesRegex(m.EntryError, 'MEMBER_CHANGED'):
                        m._read(1, 'file', 3)
                self.assertEqual(read.call_args_list, [mock.call(11, 3)])

    def test_gate_exception_returns_bounded_failure_evidence(self):
        with mock.patch.object(m.unittest.TestLoader, 'loadTestsFromNames',
                               side_effect=RuntimeError('not persisted')):
            evidence = m._gate(123)
        self.assertFalse(evidence['passed'])
        self.assertEqual(evidence['summary']['errors'], 1)
        self.assertNotIn('not persisted', evidence['raw_log'])

    def test_skips_errors_empty_gate_fail_closed(self):
        for count, skips, errors, failures in ((0, [], [], []), (1, [1], [], []),
                                               (1, [], [1], []), (1, [], [], [1])):
            result = types.SimpleNamespace(testsRun=count, skipped=skips,
                                            errors=errors, failures=failures)
            with mock.patch.object(m.unittest.TestLoader, 'loadTestsFromNames'), \
                    mock.patch.object(m.unittest.TextTestRunner, 'run', return_value=result):
                self.assertFalse(m._gate(123)['passed'])

    def test_gate_success_metadata(self):
        result = types.SimpleNamespace(testsRun=5, skipped=[], errors=[], failures=[])
        with mock.patch.object(m.unittest.TestLoader, 'loadTestsFromNames'), \
                mock.patch.object(m.unittest.TextTestRunner, 'run', return_value=result):
            self.assertEqual(m._gate(123)['summary']['tests'], 5)

    def test_execute_orders_preflight_gate_and_original_deadline(self):
        events = []
        fake_system = types.SimpleNamespace(modules={}, meta_path=[])
        preflight = types.SimpleNamespace(collect_preflight=mock.Mock(
            side_effect=lambda *args: events.append('preflight') or
            {'memory_preflight_passed': True}))
        recipes = types.SimpleNamespace(E85_SHA256='85', E93_SHA256='93',
            compile_acceptance=mock.Mock(return_value={'recipe_sha256': 'r'}))
        coordinator = types.SimpleNamespace(recipes=recipes, AUTH_SCHEMA='auth', SCOPE='scope',
            run_package=mock.Mock(side_effect=lambda *args, **kwargs:
                events.append(('run', kwargs['package_deadline'])) or {'done': True}))
        with mock.patch.object(m, 'sys', fake_system), \
                mock.patch.object(m, 'validate_permit'), \
                mock.patch.object(m, '_directory', return_value=10), \
                mock.patch.object(m, 'verify_bundle', return_value={m.E85: b'85', m.E93: b'93'}), \
                mock.patch.object(m.importlib, 'import_module', side_effect=[preflight, coordinator,
                    types.SimpleNamespace(LICENSE_KEYS=('LM_LICENSE_FILE',))]), \
                mock.patch.object(m.time, 'monotonic', side_effect=[100, 150]), \
                mock.patch.object(m.os, 'O_DIRECTORY', 65536, create=True), \
                mock.patch.object(m.os, 'O_NOFOLLOW', 131072, create=True), \
                mock.patch.object(m.os, 'mkdir'), mock.patch.object(m.os, 'fsync'), \
                mock.patch.object(m.os, 'open', return_value=11), mock.patch.object(m.os, 'close'), \
                mock.patch.object(m, '_gate', side_effect=lambda *args:
                    events.append('gate') or {'summary': {}, 'passed': True}), \
                mock.patch.object(m, '_write_gate', side_effect=lambda *args: events.append('write')):
            self.assertEqual(m.execute(permit(), m.ROOT), {'done': True})
        self.assertEqual(events, ['preflight', 'gate', 'write', ('run', 2800)])

    def test_actual_preflight_failure_never_reaches_gate(self):
        preflight = types.SimpleNamespace(collect_preflight=mock.Mock(side_effect=RuntimeError('denied')))
        fake_system = types.SimpleNamespace(modules={}, meta_path=[])
        with mock.patch.object(m, 'sys', fake_system), \
                mock.patch.object(m, 'validate_permit'), \
                mock.patch.object(m, '_directory', return_value=10), \
                mock.patch.object(m, 'verify_bundle', return_value={}), \
                mock.patch.object(m.importlib, 'import_module', return_value=preflight), \
                mock.patch.object(m.os, 'close'), mock.patch.object(m, '_gate') as gate:
            with self.assertRaises(RuntimeError):
                m.execute(permit(), m.ROOT)
            gate.assert_not_called()

    def test_python36_syntax(self):
        import sys
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(PATH.read_text(encoding='utf-8'), **kwargs)


if __name__ == '__main__':
    unittest.main()
