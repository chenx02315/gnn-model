import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import launch_ranking_v4_r4 as launch
from scripts import monitor_ranking_v4_r4 as monitor


class R4LauncherTests(unittest.TestCase):
    def _root_and_sha(self, directory):
        root = Path(directory)
        (root / 'execution_release.json').write_bytes(b'{}')
        return root, hashlib.sha256(b'{}').hexdigest()

    def _handshake(self, root, sha, pid=31337):
        intent = launch._intent(sha)
        (root / 'launch_intent.json').write_text(json.dumps(intent))
        (root / 'launch_receipt.json').write_text(json.dumps(dict(intent, pid=pid)))
        return intent

    def test_pythonpath_refuses_before_spawn(self):
        with patch.dict(launch.os.environ, {'PYTHONPATH': 'bad'}, clear=False), patch.object(launch.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):
                launch.safe_env()
            spawn.assert_not_called()

    def test_release_sha_and_supervisor_intent_mismatch_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    launch.main('0' * 64)
                intent = launch._intent(sha); intent['code_root'] = 'wrong'
                (root / 'launch_intent.json').write_text(json.dumps(intent))
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_INTENT'):
                    launch.main(sha, supervise=True)
                run.assert_not_called()

    def test_supervisor_uses_B_claim_and_exit_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.os, 'getpid', return_value=31337), \
                 patch.object(launch.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                intent = self._handshake(root, sha)
                launch.main(sha, supervise=True)
            argv = run.call_args.args[0]
            self.assertIn('-B', argv)
            self.assertEqual(str(root / 'experiment'), argv[argv.index('--output') + 1])
            self.assertEqual(0, json.loads((root / 'exit_receipt.json').read_text())['retries'])
            claim = json.loads((root / 'supervisor_claim.json').read_text())
            self.assertEqual(31337, claim['pid'])
            self.assertEqual(launch._canonical_sha256(intent), claim['intent_sha256'])

    def test_popen_failure_keeps_intent_and_rejects_supervise_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.subprocess, 'Popen', side_effect=OSError('spawn fail')):
                with self.assertRaises(OSError):
                    launch.main(sha)
                self.assertTrue((root / 'launch_intent.json').is_file())
                self.assertEqual('STOPPED_NO_RETRY', json.loads((root / 'launch_failure.json').read_text())['status'])
                with self.assertRaisesRegex(ValueError, 'R4_ALREADY_LAUNCHED_NO_RETRY'):
                    launch.main(sha)
                with self.assertRaisesRegex(ValueError, 'R4_PARENT_LAUNCH_FAILURE'):
                    launch.main(sha, supervise=True)

    def test_parent_publishes_complete_final_receipt_and_pending_blocks_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.subprocess, 'Popen', return_value=Mock(pid=31337)):
                launch.main(sha)
                receipt = json.loads((root / 'launch_receipt.json').read_text())
                intent = json.loads((root / 'launch_intent.json').read_text())
                self.assertEqual(dict(intent, pid=31337), receipt)
                self.assertTrue((root / 'launch_receipt.pending.json').is_file())
            with tempfile.TemporaryDirectory() as blocked:
                blocked_root, blocked_sha = self._root_and_sha(blocked)
                (blocked_root / 'launch_receipt.pending.json').write_text('{}')
                with patch.object(launch, 'ROOT', blocked_root), patch.dict(launch.os.environ, {}, clear=True), \
                     patch.object(launch.subprocess, 'Popen') as spawn:
                    with self.assertRaisesRegex(ValueError, 'R4_ALREADY_LAUNCHED_NO_RETRY'):
                        launch.main(blocked_sha)
                    spawn.assert_not_called()

    def test_receipt_link_collision_stops_without_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.subprocess, 'Popen', return_value=Mock(pid=31337)), \
                 patch.object(launch.os, 'link', side_effect=FileExistsError()), \
                 patch.object(launch.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'R4_LAUNCH_RECEIPT_EXISTS'):
                    launch.main(sha)
                self.assertEqual('STOPPED_NO_RETRY', json.loads((root / 'launch_failure.json').read_text())['status'])
                run.assert_not_called()

    def test_wrong_pid_or_receipt_binding_refuses_before_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.os, 'getpid', return_value=31337), \
                 patch.object(launch.subprocess, 'run') as run:
                intent = self._handshake(root, sha, pid=44)
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_RECEIPT'):
                    launch.main(sha, supervise=True)
                (root / 'launch_receipt.json').unlink()
                (root / 'launch_receipt.json').write_text(json.dumps(dict(intent, pid=31337, package_sha256='0' * 64)))
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_RECEIPT'):
                    launch.main(sha, supervise=True)
                (root / 'launch_receipt.json').unlink()
                (root / 'launch_receipt.json').write_text(json.dumps(dict(intent, pid=31337, launcher_sha256='0' * 64)))
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_RECEIPT'):
                    launch.main(sha, supervise=True)
                run.assert_not_called()

    def test_manual_supervise_without_final_receipt_never_reads_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch, 'RECEIPT_WAIT_SECONDS', 0), \
                 patch.object(launch.subprocess, 'run') as run:
                intent = launch._intent(sha)
                (root / 'launch_intent.json').write_text(json.dumps(intent))
                (root / 'launch_receipt.pending.json').write_text(json.dumps(dict(intent, pid=31337)))
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_RECEIPT_TIMEOUT'):
                    launch.main(sha, supervise=True)
                run.assert_not_called()

    def test_duplicate_supervise_claim_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True), \
                 patch.object(launch.os, 'getpid', return_value=31337), \
                 patch.object(launch.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                self._handshake(root, sha)
                launch.main(sha, supervise=True)
                with self.assertRaisesRegex(ValueError, 'R4_SUPERVISOR_ALREADY_CLAIMED'):
                    launch.main(sha, supervise=True)
                self.assertEqual(1, run.call_count)

    def test_intent_block_and_monitor_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root, sha = self._root_and_sha(directory)
            (root / 'launch_intent.json').write_text('{}')
            with patch.object(launch, 'ROOT', root), patch.dict(launch.os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    launch.main(sha)
            (root / 'launch_receipt.json').write_text(json.dumps({'pid': 1})); (root / 'experiment').mkdir()
            for index in range(19):
                (root / 'experiment' / (str(index) + '.memory.json')).write_text('{}')
            with patch.object(monitor, 'ROOT', root):
                with self.assertRaises(ValueError):
                    monitor.snapshot()

    def test_monitor_symlink_and_receipt_bounds_refuse_before_json_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'experiment').mkdir()
            (root / 'launch_receipt.json').write_bytes(b'x' * (monitor.MAX_RECEIPT_BYTES + 1))
            with patch.object(monitor, 'ROOT', root):
                with self.assertRaises(ValueError):
                    monitor.snapshot()
            with patch.object(Path, 'is_symlink', return_value=True):
                with self.assertRaisesRegex(ValueError, 'R4_MONITOR_SYMLINK'):
                    monitor._reject_symlink(root)


if __name__ == '__main__':
    unittest.main()
