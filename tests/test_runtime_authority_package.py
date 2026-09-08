from __future__ import print_function

import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "data"))
import audit_runtime_authority_package as package_audit


class RuntimeAuthorityPackageTest(unittest.TestCase):
    def test_valid_small_package_and_traversal_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            payload = os.path.join(root, "payload.tsv")
            with open(payload, "wb") as stream:
                stream.write(b"safe\n")
            digest = hashlib.sha256(b"safe\n").hexdigest()
            manifest = os.path.join(root, "MANIFEST.sha256")
            with open(manifest, "w") as stream:
                stream.write("%s  payload.tsv\n" % digest)
            archive = os.path.join(root, "valid.tar.gz")
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(payload, arcname="payload.tsv")
                bundle.add(manifest, arcname="MANIFEST.sha256")
            result = package_audit.audit(
                archive, root, "MANIFEST.sha256", ["payload.tsv"], 3, 1024)
            self.assertEqual("PASS", result["bounded_extract_status"])
            self.assertEqual(digest, result["payload_sha256"]["payload.tsv"])

            unsafe = os.path.join(root, "unsafe.tar.gz")
            with tarfile.open(unsafe, "w:gz") as bundle:
                member = tarfile.TarInfo("../escape")
                member.size = 1
                bundle.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                package_audit.audit(
                    unsafe, root, "MANIFEST.sha256", ["payload.tsv"], 3, 1024)

            tampered = os.path.join(root, "tampered.tar.gz")
            with tarfile.open(tampered, "w:gz") as bundle:
                member = tarfile.TarInfo("payload.tsv")
                member.size = len(b"wrong\n")
                bundle.addfile(member, io.BytesIO(b"wrong\n"))
                bundle.add(manifest, arcname="MANIFEST.sha256")
            with self.assertRaises(ValueError):
                package_audit.audit(
                    tampered, root, "MANIFEST.sha256", ["payload.tsv"], 3, 1024)


if __name__ == "__main__":
    unittest.main()
