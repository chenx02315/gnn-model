import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from scripts import build_v5_import_gate_packet as builder
from scripts import deploy_v5_import_gate_packet as deployer

CORE_SHA = '5394779faac5c77800a0a9d8ed52bf9f24ba2dd701f499a49754e51e7ddceae7'


def receiver():
    namespace = {'__name__':'unit_receiver_only'}
    exec(compile(deployer.RECEIVER,'receiver-fixture','exec'),namespace)
    return namespace


class ImportPacketTransportTests(unittest.TestCase):
    def test_deployment_receipt_strict_schema_types_counts_and_output_caps(self):
        root = '/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1'
        packet = b'synthetic-local-packet'
        sha = hashlib.sha256(packet).hexdigest()
        good = dict(status='PASS_SOURCE_ONLY_IMPORT_GATE_DEPLOYMENT',root=root,archive_sha256=sha,
                    entries=31,archive_bytes=len(packet),tar_bytes=10240,
                    formal_training_release=False,real_fits=0,automatic_retries=0)
        bads = []
        for field,value in (('entries',31.0),('real_fits',9),('real_fits',False),
                             ('automatic_retries',3),('archive_bytes',-1),('tar_bytes',-1),
                             ('tar_bytes',512*1024+1),('formal_training_release',0)):
            changed = dict(good); changed[field]=value; bads.append(json.dumps(changed).encode())
        changed = dict(good); changed['unknown']=0; bads.append(json.dumps(changed).encode())
        bads += [b'{"status":1,"status":2}',b'['*3000+b']'*3000,b'x'*20001]
        for raw in bads:
            with patch.object(deployer,'bounded_read',return_value=packet), \
                 patch.object(deployer.subprocess,'run',return_value=subprocess.CompletedProcess(
                     [],0,raw,b'')) as child:
                with self.assertRaises(ValueError): deployer.deploy('unused',archive_sha256=sha,root=root)
                self.assertEqual(child.call_count,1)
        with patch.object(deployer,'bounded_read',return_value=packet), \
             patch.object(deployer.subprocess,'run',return_value=subprocess.CompletedProcess(
                 [],0,json.dumps(good).encode(),b'')):
            self.assertEqual(deployer.deploy('unused',archive_sha256=sha,root=root),good)

    def test_actual_source_packet_deterministic_small_and_exact_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory)/'first.tar.gz'; second = Path(directory)/'second.tar.gz'
            result = builder.build(first,trusted_core_manifest_sha256=CORE_SHA)
            other = builder.build(second,trusted_core_manifest_sha256=CORE_SHA)
            self.assertEqual(result,other)
            self.assertLessEqual(result['archive_bytes'],256*1024)
            self.assertLessEqual(result['tar_bytes'],512*1024)
            self.assertEqual(result['entries'],31)
            with tarfile.open(first,'r:gz') as archive:
                members = archive.getmembers()
                self.assertEqual(len(members),31)
                self.assertEqual({m.name for m in members},builder.NAMES|{builder.PACKET_MANIFEST})
                self.assertTrue(all(m.isfile() for m in members))
            with self.assertRaises(FileExistsError): builder.build(first,trusted_core_manifest_sha256=CORE_SHA)

    def test_real_receiver_validates_all_before_create_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory)/'fixture.tar.gz'
            result = builder.build(packet,trusted_core_manifest_sha256=CORE_SHA)
            encoded = base64.b64encode(packet.read_bytes()); target = Path(directory)/'new-root'
            ns = receiver(); ns['allowed_root'] = lambda text: text == str(target)  # test-only local filesystem
            evidence = ns['receive'](encoded,result['archive_sha256'],str(target))
            self.assertEqual(evidence['entries'],31)
            self.assertFalse(evidence['formal_training_release'])
            self.assertTrue((target/'deployment_receipt.json').is_file())
            with self.assertRaises(FileExistsError): ns['receive'](encoded,result['archive_sha256'],str(target))
            wrong = Path(directory)/'never-created'
            ns['allowed_root'] = lambda text: text == str(wrong)
            with self.assertRaisesRegex(ValueError,'ARCHIVE_SHA'):
                ns['receive'](encoded,'a'*64,str(wrong))
            self.assertFalse(wrong.exists())

    def test_invalid_target_before_any_local_read_or_network(self):
        with patch.object(deployer,'bounded_read',side_effect=AssertionError('no read')), \
             patch.object(deployer.subprocess,'run',side_effect=AssertionError('no SSH')):
            for root in ('/ssd/cjc/multimode_ate_gnn_v1','/ssd/cjc','/tmp/x',
                         '/ssd/cjc/gnn_model_ranking_v5_import_gate_20261008_r1/../bad'):
                with self.assertRaisesRegex(ValueError,'ROOT_OR_SHA'):
                    deployer.deploy('unused',archive_sha256='a'*64,root=root)
        ns = receiver(); ns['Path'] = lambda _: (_ for _ in ()).throw(AssertionError('no path'))
        with self.assertRaisesRegex(ValueError,'FIXED_ROOT'):
            ns['receive'](b'', 'a'*64, '/ssd/cjc/multimode_ate_gnn_v1')

    def test_receiver_bomb_duplicate_unknown_and_link_refused_before_create(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'absent'; ns = receiver()
            ns['allowed_root'] = lambda text: text == str(target)
            bomb = gzip.compress(b'x'*(512*1024+1))
            with self.assertRaisesRegex(ValueError,'TAR_BOUND'):
                ns['receive'](base64.b64encode(bomb),hashlib.sha256(bomb).hexdigest(),str(target))
            for name, kind in (('../bad',tarfile.REGTYPE),
                               ('src/models/runtime_ranking_v3.py',tarfile.SYMTYPE)):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream,mode='w') as archive:
                    item = tarfile.TarInfo(name); item.type=kind; item.size=1 if kind==tarfile.REGTYPE else 0
                    archive.addfile(item,io.BytesIO(b'x') if item.size else None)
                packet=gzip.compress(stream.getvalue())
                with self.assertRaisesRegex(ValueError,'ENTRY_GATE'):
                    ns['receive'](base64.b64encode(packet),hashlib.sha256(packet).hexdigest(),str(target))
            self.assertFalse(target.exists())


if __name__ == '__main__': unittest.main()
