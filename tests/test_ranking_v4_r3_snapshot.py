import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import snapshot_ranking_v4_r3_code as snap


class SnapshotTests(unittest.TestCase):
    def test_cache_is_preserved_only_sources_are_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            source, dest = Path(directory) / 'source', Path(directory) / 'dest'
            code = source / 'code'; code.mkdir(parents=True)
            sha = hashlib.sha256(b'code').hexdigest()
            sources = {f'f{n}.py': sha for n in range(43)}
            for name in sources: (code / name).write_bytes(b'code')
            (code / '__pycache__').mkdir(); cache = code / '__pycache__/f0.pyc'; cache.write_bytes(b'cache')
            raw = json.dumps(dict(code_sha256=sources)).encode()
            (source / 'code_preparation.json').write_bytes(raw)
            with patch.object(snap, 'ROOT', dest), patch.object(snap, 'SOURCE', source), patch.object(snap, 'PREP_SHA', hashlib.sha256(raw).hexdigest()):
                snap.main()
                self.assertTrue(cache.exists())
                self.assertEqual(43, len(list((dest / 'code').glob('*.py'))))
                self.assertFalse((dest / 'code/__pycache__').exists())
                with self.assertRaisesRegex(ValueError, 'NEW_ROOT'): snap.main()


if __name__ == '__main__': unittest.main()
