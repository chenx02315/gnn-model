import gzip
import hashlib
import io
import json
import tarfile
import unittest
from scripts.build_v5_physical_packet import packet_bytes, MAX_ARCHIVE
from scripts.launch_v5_physical_gate import FILES


class PacketTests(unittest.TestCase):
    def test_bounded_deterministic_exact_source_archive(self):
        raw,metadata=packet_bytes()
        self.assertEqual((raw,metadata),packet_bytes())
        self.assertLess(len(raw),MAX_ARCHIVE)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw))) as archive:
            entries=archive.getmembers()
            self.assertEqual(17,len(entries))
            self.assertEqual(set(FILES)|{'packet_manifest.json'},{e.name for e in entries})
            self.assertTrue(all(e.isfile() and e.size<=30000 for e in entries))
            manifest=archive.extractfile('packet_manifest.json').read()
            self.assertEqual(hashlib.sha256(manifest).hexdigest(),metadata['manifest_sha256'])
            self.assertFalse(json.loads(manifest)['formal'])
            for name,sha in metadata['sources'].items():
                self.assertEqual(sha,hashlib.sha256(archive.extractfile(name).read()).hexdigest())
