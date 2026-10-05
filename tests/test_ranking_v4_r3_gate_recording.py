import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from scripts import record_ranking_v4_r3_linux_gate as gate


class GateRecordingTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'code').mkdir()
            (root / 'code/keep.py').write_bytes(b'keep')
            archive = root / 'archive'; archive.write_bytes(b'archive')
            archive_sha = hashlib.sha256(b'archive').hexdigest()
            prep = dict(archive_sha256=archive_sha, overlay=[str(n) for n in range(7)],
                code_sha256={'keep.py': hashlib.sha256(b'keep').hexdigest()})
            raw = json.dumps(prep).encode(); (root / 'code_preparation.json').write_bytes(raw)
            def run(*args, **kwargs):
                if mode == 'spawn_error': raise OSError('test')
                kwargs['stdout'].write(b'Ran 14 tests in 1.0s\n\nOK\n')
                return Mock(returncode=0)
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'ARCHIVE', archive), \
                 patch.object(gate, 'ARCHIVE_SHA', archive_sha), patch.object(gate, 'PREP_SHA', hashlib.sha256(raw).hexdigest()), \
                 patch.object(gate.sys, 'platform', 'linux'), patch.object(gate.subprocess, 'run', side_effect=run):
                if mode == 'drift': (root / 'code/keep.py').write_bytes(b'changed')
                if mode == 'extra': (root / 'code/sitecustomize.py').write_bytes(b'new import hook')
                result = gate.main()
            receipt = json.loads((root / 'linux_gate_exit.json').read_text())
            self.assertEqual(0 if mode == 'pass' else 1, result)
            self.assertEqual(mode == 'pass', receipt['gate_pass'])

    def test_actual_exit_and_log_are_bound(self): self.exercise('pass')
    def test_prelaunch_code_drift_has_failure_receipt(self): self.exercise('drift')
    def test_subprocess_error_has_failure_receipt(self): self.exercise('spawn_error')
    def test_extra_importable_file_has_failure_receipt(self): self.exercise('extra')


if __name__ == '__main__': unittest.main()
