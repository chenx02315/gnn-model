"""No remote calls: fixed bundle count and extraction guard regression."""
import importlib.util
from pathlib import Path
import unittest

class StageProtocol(unittest.TestCase):
    def test_fixed_counts_match_remote_gate(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/stage_v6_synthetic_fit_container.py'
        spec = importlib.util.spec_from_file_location('e12_stage', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = path.read_text(encoding='utf-8')
        self.assertEqual(len(module.MAPPING) + 1, 11)
        self.assertIn('len(members)!=11', source)
        self.assertIn('len(set(m.name for m in members))!=11', source)
        self.assertIn('len(sources) != 11', source)
        self.assertIn("os.O_EXCL|os.O_NOFOLLOW", source)

if __name__ == '__main__':
    unittest.main()
