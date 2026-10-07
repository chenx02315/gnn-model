import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scripts import launch_v5_physical_gate as launcher


class LauncherTests(unittest.TestCase):
    def test_fixed_root_text(self):
        self.assertTrue(launcher.allowed_root_text('/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1'))
        for text in ('/tmp/gnn_model_ranking_v5_worker_gate_20261007_r1',
                     '/ssd/cjc/multimode_ate_gnn_v1',
                     '/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1/../x',
                     '/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r1/sub',
                     '/ssd/cjc/gnn_model_ranking_v5_worker_gate_20261007_r0'):
            self.assertFalse(launcher.allowed_root_text(text))

    def test_packet_exact_inventory_and_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); sources={}
            for name in launcher.FILES:
                path=root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'fixture')
                sources[name]=hashlib.sha256(b'fixture').hexdigest()
            packet={'schema':'v5-generated-physical-sources-v1','formal':False,'sources':sources}
            raw=json.dumps(packet).encode(); (root/'packet_manifest.json').write_bytes(raw)
            sha=hashlib.sha256(raw).hexdigest()
            self.assertEqual(packet,launcher.verify_packet(root,sha))
            (root/next(iter(launcher.FILES))).write_bytes(b'drift')
            with self.assertRaises(ValueError): launcher.verify_packet(root,sha)
            with self.assertRaises(ValueError): launcher.verify_packet(root,'0'*64)

    def test_read_bound_and_nonlinux_no_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'file'; path.write_bytes(b'123')
            with self.assertRaises(ValueError): launcher.bounded_read(path,2)
            with self.assertRaises(ValueError): launcher.execute(Path(tmp),'a'*64)
