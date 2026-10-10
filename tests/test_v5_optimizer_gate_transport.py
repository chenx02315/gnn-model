import unittest
from unittest import mock
from scripts import v5_optimizer_gate_transport as gate


class TransportTests(unittest.TestCase):
    def fixture(self):
        payloads = {p: p.encode() for p in gate.FILES}
        pins = {p: gate.sha(raw) for p, raw in payloads.items()}
        return payloads, pins

    def test_pure_validation_and_base64_roundtrip(self):
        payloads, pins = self.fixture()
        with mock.patch.object(gate, 'FIXED', {}):
            self.assertEqual(gate.validate('/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1', payloads, pins), payloads)
        self.assertEqual(gate.decode(gate.envelope(payloads)), payloads)

    def test_reject_before_destination_io(self):
        payloads, pins = self.fixture()
        with mock.patch.object(gate.Path, 'mkdir') as mkdir:
            for root in ('/ssd/cjc', '/ssd/cjc/multimode_ate_gnn_v1', '/tmp/x'):
                with self.assertRaises(ValueError): gate.receive(root, payloads, pins)
            with self.assertRaises(ValueError):
                gate.receive('/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1', payloads, pins)
        mkdir.assert_not_called()

    def test_exact_set_tamper_bounds(self):
        payloads, pins = self.fixture()
        root = '/ssd/cjc/gnn_model_ranking_v5_optimizer_gate_20261010_r1'
        with mock.patch.object(gate, 'FIXED', {}):
            for bad in ({**payloads, 'x': b'x'}, {**payloads, gate.PROGRAM: b'bad'},
                        {**payloads, gate.PROGRAM: b'x' * (gate.CAP + 1)}):
                with self.assertRaises(ValueError): gate.validate(root, bad, pins)

    def test_duplicate_and_invalid_base64(self):
        with self.assertRaises(ValueError): gate.decode(b'{"x":"a","x":"a"}')
        raw = gate.envelope({p: b'x' for p in gate.FILES}).replace(b'eA==', b'!!!!')
        with self.assertRaises(ValueError): gate.decode(raw)


if __name__ == '__main__':
    unittest.main()
