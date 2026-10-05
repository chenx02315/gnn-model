import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import prepare_ranking_v4_r4_release as preparation


class R4ReleasePreparationTests(unittest.TestCase):
    def test_smoke_symlink_refused_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            smoke = Path(directory) / 'smoke.json'
            original = Path.is_symlink
            def symlink(path):
                return path == smoke or original(path)
            with patch.object(preparation, 'ROOT', root), patch.object(preparation, 'CODE', Path.cwd()), \
                 patch.object(preparation, 'SMOKE', smoke), patch.object(Path, 'is_symlink', symlink):
                with self.assertRaisesRegex(ValueError, 'SYMLINK'):
                    preparation.prepare('unused', '0' * 64)
            self.assertFalse(root.exists())

    def test_fresh_release_writes_exact_review_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            code = Path.cwd()
            review = Path(directory) / 'review.json'
            smoke = Path(directory) / 'smoke.json'
            smoke.write_text(json.dumps(dict(status='PASS_GUARDED_SYNTHETIC_ML', memory=dict(status='PASS_BOUNDED_WORKER'))))
            review.write_text(json.dumps(dict(status='PASS_LOW_MEMORY_REAL_V4_CODE_GATE',
                real_training_authorized=True, independent_audit='PASS_R4_REAL_RELEASE_PRECONDITION',
                execution_root=str(root), code_root=str(code), fourth_run_explicitly_authorized=True,
                authorization='explicit fourth TRAIN', reviewed_sources={},
                guarded_smoke_sha256=hashlib.sha256(smoke.read_bytes()).hexdigest())))
            raw = review.read_bytes()
            with patch.object(preparation, 'ROOT', root), patch.object(preparation, 'CODE', code), patch.object(preparation, 'SMOKE', smoke), \
                 patch('src.models.ranking_v4_real_worker.verify_reviewed_sources'), \
                 patch('src.models.ranking_v4_memory_guard.available_memory', return_value=(100, 90)), \
                 patch('src.models.ranking_v4_memory_guard.check_available'), \
                 patch('src.models.ranking_v4_real_worker.check_release'):
                result = preparation.prepare(review, hashlib.sha256(raw).hexdigest())
                self.assertFalse(result['launch_started'])
                self.assertEqual(raw, (root / 'independent_review.json').read_bytes())
                self.assertTrue((root / 'release_preparation.json').is_file())
                with self.assertRaises(FileExistsError):
                    preparation.prepare(review, hashlib.sha256(raw).hexdigest())
                self.assertEqual('explicit fourth TRAIN', json.loads((root / 'execution_release.json').read_text())['user_authorization'])

    def test_wrong_cwd_refuses_without_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            with patch.object(preparation, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'CWD'):
                    preparation.prepare('unused', '0' * 64)
            self.assertFalse(root.exists())

    def test_review_hash_and_fourth_authorization_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            review = Path(directory) / 'review.json'
            review.write_text(json.dumps({'status': 'PASS_LOW_MEMORY_REAL_V4_CODE_GATE'}))
            raw = review.read_bytes()
            with patch.object(preparation, 'ROOT', root), patch.object(preparation, 'CODE', Path.cwd()):
                with self.assertRaisesRegex(ValueError, 'REVIEW_SHA'):
                    preparation.prepare(review, '0' * 64)
                with self.assertRaisesRegex(ValueError, 'REVIEW_SCOPE'):
                    preparation.prepare(review, hashlib.sha256(raw).hexdigest())
            self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main()
