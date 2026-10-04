import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from scripts import audit_ranking_v3_synthetic_evidence as verifier

class EvidenceTests(unittest.TestCase):
    def make_stage(self, root):
        (root / 'followup').mkdir()
        names = ['src/file%d.py' % i for i in range(17)]
        inventory = {}
        with tarfile.open(root / 'source.tar.gz', 'w:gz') as archive:
            import io
            for name in names:
                data = b'# generated\n'
                info = tarfile.TarInfo(name); info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
                inventory[name] = hashlib.sha256(data).hexdigest()
        for name in ('src/__init__.py', 'src/models/__init__.py', 'src/data/__init__.py', 'tests/__init__.py'):
            inventory[name] = hashlib.sha256(b'').hexdigest()
        (root / 'extension.py').write_bytes(b'# extension\n')
        base = dict(scope='GENERATED_SYNTHETIC_NO_EXTERNAL_DATA', status='PASS',
                    skipped=0, failures=0, errors=0, real_circuit_rows_read=False,
                    blind_accessed=False, formal_training=False)
        for sub, count in (('', 30), ('followup/', 3)):
            (root / (sub + 'tests.log')).write_bytes(b'OK\n')
            record = dict(base, testsRun=count, log_sha256=verifier.digest(root / (sub + 'tests.log')))
            if not sub:
                record['source_sha256'] = inventory
            else:
                record['parent_receipt_sha256'] = verifier.digest(root / 'receipt.json')
                record['extension_sha256'] = verifier.digest(root / 'extension.py')
            (root / (sub + 'receipt.json')).write_text(json.dumps(record))

    def test_pass_and_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.make_stage(root)
            with patch.object(verifier, 'ARCHIVE_SHA', verifier.digest(root / 'source.tar.gz')), \
                 patch.object(verifier, 'PARENT_SHA', verifier.digest(root / 'receipt.json')):
                self.assertEqual(verifier.audit(root, root / 'extension.py')['status'], 'PASS_SYNTHETIC_EVIDENCE_INTEGRITY')
                (root / 'followup/tests.log').write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError, 'log digest'):
                    verifier.audit(root, root / 'extension.py')

    def test_skip_is_not_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.make_stage(root)
            record = json.loads((root / 'followup/receipt.json').read_text())
            record['skipped'] = 1
            (root / 'followup/receipt.json').write_text(json.dumps(record))
            with patch.object(verifier, 'ARCHIVE_SHA', verifier.digest(root / 'source.tar.gz')), \
                 patch.object(verifier, 'PARENT_SHA', verifier.digest(root / 'receipt.json')):
                with self.assertRaisesRegex(ValueError, 'failures/skips'):
                    verifier.audit(root, root / 'extension.py')

if __name__ == '__main__':
    unittest.main()
