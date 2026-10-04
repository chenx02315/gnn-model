import tempfile
import unittest
from pathlib import Path
from src.models.ranking_v3_freeze_io import persist_freeze,read_freeze
from src.models.runtime_ranking_v3 import digest

class FreezeIOTests(unittest.TestCase):
    def test_create_readback_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'freeze.json'; payload={'fixture':True}; sha=digest(payload)
            self.assertEqual(persist_freeze(path,payload,sha),sha)
            self.assertEqual(read_freeze(path,sha),payload)
            with self.assertRaises(FileExistsError): persist_freeze(path,payload,sha)
            with self.assertRaises(ValueError): read_freeze(path,'0'*64)
    def test_bad_payload_leaves_no_artifact(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'freeze.json'
            with self.assertRaises(ValueError): persist_freeze(path,{'fixture':True},'0'*64)
            self.assertFalse(path.exists())

if __name__=='__main__': unittest.main()
