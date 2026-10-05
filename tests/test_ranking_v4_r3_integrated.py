import hashlib
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from scripts import prepare_ranking_v4_r3_integrated as prep


class R3IntegratedPreparationTests(unittest.TestCase):
    def make_base(self, root):
        base = Path(root) / 'base'; (base / 'src/models').mkdir(parents=True)
        (base / 'src/models/ranking_v4_memory_guard.py').write_text('old guard', encoding='utf-8')
        (base / 'keep.py').write_text('base-only', encoding='utf-8')
        (base / '__pycache__').mkdir(); (base / '__pycache__/keep.pyc').write_bytes(b'cache')
        return base

    def test_build_hash_entries_and_create_once(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'overlay.tgz'
            receipt = prep.build(archive)
            self.assertEqual(7, receipt['entry_count']); self.assertEqual(set(prep.OVERLAY), set(receipt['entries']))
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), receipt['archive_sha256'])
            with self.assertRaises(FileExistsError): prep.build(archive)

    def test_deploy_copies_base_and_replaces_only_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / 'overlay.tgz'; built = prep.build(archive); base = self.make_base(root)
            with patch.object(prep, 'ROOT', root / 'new'), patch.object(prep, 'BASE', base):
                deployed = prep.deploy_b(archive, built['archive_sha256'])
            self.assertTrue((root / 'new/code/keep.py').is_file())
            self.assertNotEqual('old guard', (root / 'new/code/src/models/ranking_v4_memory_guard.py').read_text(encoding='utf-8'))
            self.assertFalse((root / 'new/code/__pycache__').exists())
            self.assertEqual(7, len(deployed['overlay'])); self.assertFalse(deployed['real_training_started'])
            self.assertIn('keep.py', deployed['base_code_sha256'])

    def test_existing_root_refuses_and_failure_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / 'overlay.tgz'; built = prep.build(archive); base = self.make_base(root)
            existing = root / 'existing'; existing.mkdir(); marker = existing / 'marker'; marker.write_text('keep')
            with patch.object(prep, 'ROOT', existing), patch.object(prep, 'BASE', base):
                with self.assertRaises(FileExistsError): prep.deploy_b(archive, built['archive_sha256'])
            self.assertEqual('keep', marker.read_text())
            with patch.object(prep, 'ROOT', root / 'failed'), patch.object(prep, 'BASE', base):
                with self.assertRaises(ValueError): prep.deploy_b(archive, '0' * 64)
            failure = json.loads((root / 'failed/code_preparation_failure.json').read_text())
            self.assertEqual('STOPPED_CODE_ONLY_PREPARATION', failure['status'])
            self.assertFalse(failure['real_training_started'])

    def test_fixed_root_api_and_parsed_archive_tamper_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); base = self.make_base(root); archive = root / 'tampered.tgz'
            with tarfile.open(archive, 'w:gz') as content:
                path = root / 'unexpected.py'; path.write_text('x')
                content.add(path, arcname='unexpected.py')
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(prep, 'ROOT', root / 'failed'), patch.object(prep, 'BASE', base):
                with self.assertRaises(ValueError): prep.deploy_b(archive, sha)
            self.assertTrue((root / 'failed/code_preparation_failure.json').is_file())
            with self.assertRaises(TypeError): prep.deploy_b(archive, sha, root=root)  # no arbitrary deployment target

    def test_base_bounds_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); base = self.make_base(root)
            for index in range(prep.MAX_FILES + 1): (base / ('f%d' % index)).write_text('x')
            with self.assertRaises(ValueError): prep._base_files(base)


if __name__ == '__main__':
    unittest.main()
