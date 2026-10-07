import ast
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from scripts.build_v5_physical_packet import packet_bytes
from scripts.deploy_v5_physical_packet import deploy_packet, program, read_archive, validate_archive
from scripts.launch_v5_physical_gate import bounded_read


class DeploymentTests(unittest.TestCase):
    def test_exact_bounded_program(self):
        source = program('/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1')
        ast.parse(source)
        for required in ('V5_DEPLOY_CREATE_ONCE', 'V5_DEPLOY_SOURCE_SHA', 'V5_DEPLOY_ENTRY_TYPE_BOUND',
                         'V5_DEPLOY_EXACT_ENTRIES', 'stream.read(200001)', "path.open('xb')",
                         'V5_DEPLOY_EXACT_RUNTIME_TARGET', 'stat.S_ISREG'):
            self.assertIn(required, source)
        self.assertNotIn('extractall', source)
        self.assertLess(len(source.encode()), 20000)

    def test_wrong_target_rejected(self):
        for target in ('/ssd/cjc/multimode_ate_gnn_v1', '/ssd/cjc/gnn_model_ranking_v5_worker_gate_bad'):
            with self.assertRaises(ValueError):
                program(target)
            with self.assertRaises(ValueError):
                deploy_packet(Path(target), {})

    def test_positive_and_create_once(self):
        raw, metadata = packet_bytes()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixture'
            Path(str(target) + '.tar.gz').write_bytes(raw)
            receipt = deploy_packet(target, metadata, allow_test_root=True)
            self.assertEqual(receipt['files'], 17)
            for name, sha in metadata['sources'].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), sha)
            with self.assertRaisesRegex(ValueError, 'CREATE_ONCE'):
                deploy_packet(target, metadata, allow_test_root=True)

    def test_tampered_sha_has_no_output(self):
        raw, metadata = packet_bytes()
        metadata['archive_sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixture'
            Path(str(target) + '.tar.gz').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'ARCHIVE_SHA_BOUND'):
                deploy_packet(target, metadata, allow_test_root=True)
            self.assertFalse(target.exists())

    def test_expansion_limit(self):
        _, metadata = packet_bytes()
        raw = gzip.compress(b'x' * 200001)
        metadata['archive_sha256'] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, 'EXPANDED_BOUND'):
            validate_archive(raw, metadata)

    def test_extra_missing_symlink_and_source_damage(self):
        original, metadata = packet_bytes()
        for mutation, error in (('extra', 'EXACT_ENTRIES'), ('missing', 'EXACT_ENTRIES'),
                                ('symlink', 'ENTRY_TYPE_BOUND'), ('damage', 'SOURCE_SHA')):
            with self.subTest(mutation=mutation):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=io.BytesIO(gzip.decompress(original))) as source:
                    members = source.getmembers()
                    with tarfile.open(fileobj=buffer, mode='w:') as output:
                        for index, member in enumerate(members):
                            if mutation == 'missing' and index == 0:
                                continue
                            value = source.extractfile(member).read()
                            if mutation == 'symlink' and index == 0:
                                member.type = tarfile.SYMTYPE
                                member.linkname = '/forbidden'
                                member.size = 0
                                output.addfile(member)
                            else:
                                if mutation == 'damage' and index == 0:
                                    value = b'x' + value[1:]
                                output.addfile(member, io.BytesIO(value))
                        if mutation == 'extra':
                            item = tarfile.TarInfo('extra'); item.size = 1
                            output.addfile(item, io.BytesIO(b'x'))
                raw = gzip.compress(buffer.getvalue())
                changed = dict(metadata, archive_sha256=hashlib.sha256(raw).hexdigest())
                with self.assertRaisesRegex(ValueError, error):
                    validate_archive(raw, changed)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Linux FIFO test')
    def test_fifo_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fifo'
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'NOT_REGULAR'):
                read_archive(path)
            with self.assertRaisesRegex(ValueError, 'NOT_REGULAR'):
                bounded_read(path, 20)
