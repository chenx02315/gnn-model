"""Mock-only fixed observation checks; no remote or scheduler executions."""
import ast
import base64
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/inspect_acceptance_job_result_e97.py'
SPEC = importlib.util.spec_from_file_location('result_e97_test', str(PATH))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def metadata(size):
    return types.SimpleNamespace(st_dev=43, st_ino=42, st_size=size, st_mtime_ns=1, st_ctime_ns=2)


def frozen(read):
    return types.SimpleNamespace(CLIENT_CAP=8192, BINDIR='/fixed/bin/',
        _client=mock.Mock(return_value=dict(status='CLIENT_COMPLETE', returncode=0,
                                           stdout=b'Job <394230>, Status <DONE>', stderr=b'')),
        _read=mock.Mock(side_effect=read))


class ResultTests(unittest.TestCase):
    def observe(self, base):
        with mock.patch.object(m.sys, 'platform', 'linux'), \
                mock.patch.object(m.platform, 'node', return_value='bupt-vncs2'), \
                mock.patch.object(m, '_base', return_value=base):
            return m.observe(b'not executed')

    def test_exact_query_and_three_fixed_paths_no_pass_claim(self):
        base = frozen(lambda path, cap: (b'PASS', metadata(4)))
        result = self.observe(base)
        base._client.assert_called_once_with(['/fixed/bin/bjobs', '-l', '394230'])
        self.assertEqual(base._read.call_args_list, [mock.call(path, cap) for path, cap in m.FIXED_FILES])
        self.assertFalse(result['kernel_gate_pass_claimed'])
        self.assertFalse(result['execution_success_claimed'])
        self.assertEqual(result['resume_calls'], 0)
        self.assertEqual(result['jobs_submitted'], 0)

    def test_missing_files_explicit(self):
        result = self.observe(frozen(FileNotFoundError()))
        self.assertEqual([row['status'] for row in result['files']], ['MISSING'] * 3)
        self.assertNotIn('body', result['files'][0])

    def test_nonmissing_error_is_fatal_and_stops_reads(self):
        for error in (PermissionError(), OSError('symlink'), ValueError('identity changed')):
            base = frozen(error)
            with self.assertRaises(type(error)):
                self.observe(base)
            self.assertEqual(base._read.call_count, 1)
            self.assertEqual(base._client.call_count, 1)

    def test_body_hashes_and_exact_lengths(self):
        result = self.observe(frozen(lambda path, cap: (b'body', metadata(4))))
        for row in result['files']:
            self.assertEqual(row['body']['sha256'], m.sha(b'body'))
            self.assertEqual(row['body']['bytes'], 4)
            self.assertEqual(base64.b64decode(row['body']['base64']), b'body')

    def test_worst_case_response_within_cap(self):
        base = frozen(lambda path, cap: (b'x' * cap, metadata(cap)))
        base._client.return_value['stdout'] = b'x' * 8192
        result = self.observe(base)
        self.assertLessEqual(len(m.encode(result)), 262144)

    def test_oversized_file_or_client_is_rejected(self):
        with self.assertRaisesRegex(m.InspectionError, 'FILE_BOUND'):
            self.observe(frozen(lambda path, cap: (b'x' * (cap + 1), metadata(cap + 1))))
        base = frozen(lambda path, cap: (b'', metadata(0)))
        base._client.return_value['stdout'] = b'x' * 8193
        with self.assertRaisesRegex(m.InspectionError, 'CLIENT_OUTPUT_BOUND'):
            self.observe(base)
        base._read.assert_not_called()

    def test_failed_query_never_claims_outcome_or_retries(self):
        base = frozen(FileNotFoundError())
        base._client.return_value.update(status='CLIENT_FAILURE_UNKNOWN', returncode=None)
        result = self.observe(base)
        self.assertEqual(result['scheduler_client_status'], 'CLIENT_FAILURE_UNKNOWN')
        self.assertFalse(result['execution_success_claimed'])
        base._client.assert_called_once()

    def test_wrong_host_before_load_or_query(self):
        with mock.patch.object(m.platform, 'node', return_value='other'), \
                mock.patch.object(m, '_base') as loader:
            with self.assertRaises(m.InspectionError):
                m.observe(b'')
            loader.assert_not_called()

    def test_frozen_source_pin_before_execution(self):
        with self.assertRaisesRegex(m.InspectionError, 'FROZEN_BASE_PIN'):
            m._base(b'raise RuntimeError("must not execute")')

    def test_pinned_base_load_definitions_without_launch(self):
        source = PATH.with_name('register_acceptance_job_e97.py').read_bytes()
        with mock.patch('subprocess.Popen') as spawn:
            base = m._base(source)
        self.assertEqual(base.ROOT, m.ROOT)
        self.assertIsNot(base.__dict__, m.__dict__)
        spawn.assert_not_called()

    def test_prepare_only_explicit_review_and_four_fixed_phases(self):
        for index in (1, 2, 3, 4):
            plan = m.prepare_payload(m.sha(PATH.read_bytes()), index)
            self.assertTrue(plan['phase_name'].endswith('_r' + str(index)))
            self.assertEqual(plan['resume_calls'], 0)
            self.assertTrue(plan['exclusive_phase_required'])
            compile(plan['payload'], '<test-only-not-executed>', 'exec')
        for index in (True, 0, 5):
            with self.assertRaises(m.InspectionError):
                m.prepare_payload(m.sha(PATH.read_bytes()), index)
        with self.assertRaisesRegex(m.InspectionError, 'HELPER_REVIEW_PIN'):
            m.prepare_payload('0' * 64)

    def test_python36_and_no_automatic_entry(self):
        source = PATH.read_text()
        kwargs = {'feature_version': (3, 6)} if sys.version_info >= (3, 8) else {}
        ast.parse(source, **kwargs)
        self.assertNotIn('__main__', source)
        self.assertNotIn('transport(', source)
        self.assertNotIn('os.listdir', source)


if __name__ == '__main__':
    unittest.main()
