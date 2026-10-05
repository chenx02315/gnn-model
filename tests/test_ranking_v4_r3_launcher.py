import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from scripts import launch_ranking_v4_r3 as launch
from scripts.run_ranking_v4_real_experiment import _valid_destination_value


class R3LauncherTests(unittest.TestCase):
    def test_destination_agrees_with_runner(self):
        self.assertTrue(_valid_destination_value((launch.ROOT / 'experiment').as_posix()))

    def test_sha_refusal_and_intent_block_no_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'execution_release.json').write_bytes(b'{}')
            sha = hashlib.sha256(b'{}').hexdigest()
            with patch.object(launch, 'ROOT', root), patch.object(launch.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'RELEASE_SHA'):
                    launch.main('0' * 64)
                (root / 'launch_intent.json').write_bytes(b'{}')
                with self.assertRaisesRegex(ValueError, 'NO_RETRY'):
                    launch.main(sha)
                spawn.assert_not_called()

    def test_supervisor_argv_and_exit_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'execution_release.json').write_bytes(b'{}')
            sha = hashlib.sha256(b'{}').hexdigest()
            (root / 'launch_intent.json').write_text(json.dumps(dict(release_sha256=sha, retries=0,
                code_root=str(launch.CODE), expected_evaluations=18, started_unix=1)))
            with patch.object(launch, 'ROOT', root), patch.object(launch.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                launch.main(sha, supervise=True)
            argv = run.call_args.args[0]
            self.assertEqual(str(root / 'experiment'), argv[argv.index('--output') + 1])
            self.assertEqual(launch.PACKAGE, argv[argv.index('--package') + 1])
            self.assertEqual(launch.CODE, run.call_args.kwargs['cwd'])
            self.assertEqual(0, json.loads((root / 'exit_receipt.json').read_text())['retries'])

    def test_supervisor_intent_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'execution_release.json').write_bytes(b'{}')
            sha = hashlib.sha256(b'{}').hexdigest()
            (root / 'launch_intent.json').write_text(json.dumps(dict(release_sha256=sha, retries=0,
                code_root='wrong', expected_evaluations=18, started_unix=1)))
            with patch.object(launch, 'ROOT', root), patch.object(launch.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'INTENT'):
                    launch.main(sha, supervise=True)
                run.assert_not_called()

    def test_spawn_failure_is_sealed_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'execution_release.json').write_bytes(b'{}')
            sha = hashlib.sha256(b'{}').hexdigest()
            with patch.object(launch, 'ROOT', root), patch.object(launch.subprocess, 'Popen', side_effect=OSError('test spawn failure')):
                with self.assertRaises(OSError):
                    launch.main(sha)
            self.assertEqual('STOPPED_NO_RETRY', json.loads((root / 'launch_failure.json').read_text())['status'])


if __name__ == '__main__':
    unittest.main()
