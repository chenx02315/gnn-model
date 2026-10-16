"""Local-only checks; never invoke SSH."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import subprocess
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('e34_transport',
    Path(__file__).resolve().parents[1] / 'scripts' / 'run_ranking_v6_e34_readonly.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class TransportTests(unittest.TestCase):
    def test_empty_banner_duplicate_or_missing_json_never_accepted(self):
        for raw in (b'', b'banner\n{}', b'{} {}', b'{"x":1,"x":2}', b'{}', b'[]'):
            self.assertFalse(M.validate_response(raw))

    def test_bounded_metadata_shape_not_training_release(self):
        payload = dict(status='PARTIAL_PINNED_TRAIN_METADATA_AUDIT', file_count=12,
                       files=[{}] * 12, circuits={c: {} for c in M.CIRCUITS},
                       real_training_release=False, candidate_quality_accessed=False,
                       resource=dict(address_space_limit_imposed=True,
                                     address_space_soft_bytes=1073741824))
        self.assertTrue(M.validate_response(json.dumps(payload).encode()))
        for constant in ('NaN', 'Infinity', '-Infinity'):
            raw = json.dumps(payload)[:-1] + ', "unexpected":' + constant + '}'
            self.assertFalse(M.validate_response(raw.encode()))
        payload['real_training_release'] = True
        self.assertFalse(M.validate_response(json.dumps(payload).encode()))

    def test_exact_command_is_isolated_stdin_only(self):
        self.assertEqual(M.COMMAND[-2:], ['vnc.buptic.top', '/usr/bin/python3 -I -S -B -'])
        self.assertIn('BatchMode=yes', M.COMMAND)
        self.assertIn('StrictHostKeyChecking=yes', M.COMMAND)
        self.assertEqual(M.LIMIT, 65536)
        self.assertEqual(M.TIMEOUT, 120)

    def test_wrong_source_hash_rejected_before_any_process(self):
        with patch.object(M.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(ValueError, 'REVIEWED_SOURCE_SHA_MISMATCH'):
                M.run('0' * 64, 'anything')
            process.assert_not_called()

    def test_outside_receipt_root_rejected_before_any_process(self):
        digest = hashlib.sha256(M.SOURCE.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(M.subprocess, 'Popen') as process:
                with self.assertRaisesRegex(ValueError, 'LOCAL_RECEIPT_PATH_REJECTED'):
                    M.run(digest, Path(folder) / 'v6_e34_train_metadata_not_allowed')
                process.assert_not_called()

    def test_stalled_stdin_is_covered_by_deadline(self):
        killed = threading.Event()

        class StalledInput:
            def write(self, data):
                killed.wait(2)
                raise BrokenPipeError()

            def close(self):
                pass

        class Process:
            stdin = StalledInput()
            stdout = io.BytesIO(b'')
            stderr = io.BytesIO(b'')
            returncode = None

            def wait(self, timeout):
                if not killed.is_set():
                    raise subprocess.TimeoutExpired('fake', timeout)
                return self.returncode

            def kill(self):
                self.returncode = -9
                killed.set()

        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'source.py'
            source.write_bytes(b'pass\n')
            (base / 'runtime_training_staging_20260928').mkdir()
            target = base / 'runtime_training_staging_20260928' / 'v6_e34_train_metadata_test'
            with patch.object(M, '__file__', str(base / 'repo' / 'scripts' / 'run.py')), \
                 patch.object(M, 'SOURCE', source), \
                 patch.object(M.subprocess, 'Popen', return_value=Process()):
                self.assertEqual(M.run(hashlib.sha256(b'pass\n').hexdigest(), target), 2)
            self.assertTrue(killed.is_set())
            self.assertTrue((target / 'transport.json').is_file())


if __name__ == '__main__':
    unittest.main()
